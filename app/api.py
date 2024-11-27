from flask import request, jsonify, make_response, session,url_for
from functools import wraps
from flask_login import LoginManager, logout_user
from dotenv import load_dotenv
import os
import urllib.parse
import json
import jwt
from datetime import datetime, timedelta
import stripe
from db_setup import create_app,get_db_connection
from db_config import (get_all_users,check_credentials,get_superuser_details,get_users_details)
from user_management import (confirm_user_email, change_username, change_email,change_phone_number,
    change_password, register_user,get_user_by_email, upload_profile_picture)
from purchase_management import get_purchases_by_session_id , get_purchases_by_user_id,purchase_product
from terms_of_service import TermsOfServiceManager,manage_terms
import logging
from send_mail import send_contact_email,send_password_reset_email,send_confirmation_email
from itsdangerous import URLSafeTimedSerializer
import base64
# Load environment variables
load_dotenv()

# Secret key for encoding and decoding the JWT token
SECRET_KEY = os.getenv('SECRET_KEY')

app = create_app()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)



# Route for user registration
@app.route('/api/create-account', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return make_response('', 200)

    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided."}), 400
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    country = data.get('country')
    address = data.get('address')

    return register_user(first_name,last_name,username, email, password, phone_number,country,address)

@app.route('/api/terms', methods=['GET'])
def terms_of_services():
    """
    Handles fetching terms of service based on query parameters
    """
    try:
        response = manage_terms()  # Assuming this returns plain text
        return jsonify(success=True, terms_text=response)  # Wrap the plain text in a JSON response
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# Simplified token generation
def generate_token(user_id, is_superuser):
    payload = {
        'user_id': user_id,
        'is_superuser': is_superuser,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


# Token-required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            token = token.split(" ")[1] if " " in token else token
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = {
                "user_id": payload.get('user_id'),
                "is_superuser": payload.get('is_superuser', False)
            }
            # Fetch user details based on user type
            user = (get_superuser_details(current_user['user_id'])
                    if current_user["is_superuser"]
                    else get_users_details(current_user['user_id']))
            if not user:
                return jsonify({"message": "User not found"}), 404

            current_user.update(user)  # Include fetched user details in `current_user`
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401
        except Exception as e:
            logging.error(f"Token validation error: {e}")
            return jsonify({"message": "Internal server error"}), 500
        # Pass the current user to the route
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    identifier, password = data.get('identifier'), data.get('password')

    logging.debug(f"Login attempt with identifier: {identifier}")

    if not identifier or not password:
        return jsonify({"message": "Username/Email and password are required."}), 400

    credentials_result = check_credentials(identifier, password)

    if not credentials_result:
        return jsonify({"message": "Invalid credentials."}), 401

    user_id = (credentials_result.get('superuser_id')
               if credentials_result['user_type'] == 'superuser'
               else credentials_result.get('user_id'))
    if user_id is None:
        return jsonify({"message": "User type or ID not recognized."}), 400

    is_superuser = credentials_result['user_type'] == 'superuser'
    token = generate_token(user_id, is_superuser)
    
    # Return the token and superuser status
    return jsonify({
        "message": "Login successful!",
        "token": token,
        "is_superuser": is_superuser  # Return whether the user is a superuser or not
    }), 200
@app.route('/api/superuser-dashboard', methods=['GET', 'PUT'])
@token_required
def superuser_dashboard(current_user):
    if not current_user.get('is_superuser', False):
        return jsonify({"message": "Unauthorized access. Admins only."}), 403

    try:
        # Establish a database connection
        connection = get_db_connection()
        tos_manager = TermsOfServiceManager(connection)

        if request.method == 'GET':
            # Handle GET requests to fetch dashboard data
            all_users = get_all_users()
            
            # Prepare detailed dashboard data with purchases
            dashboard_data = []
            for user in all_users:
                # Fetch purchases for each user
                purchases = get_purchases_by_user_id(user['user_id'])
                
                # Create user data dictionary
                user_data = {
                    "user_id": user['user_id'], 
                    "first_name": user['first_name'],
                    "last_name": user['last_name'],
                    "username": user['username'], 
                    "email": user['email'],
                    "phone_number": user['phone_number'],
                    "profile_picture": user['profile_picture'],
                    "country": user['country'],
                    "address": user['address'],
                    "created_at": user['created_at'],
                    "updated_at": user['updated_at'],
                    "purchases": purchases
                }
                dashboard_data.append(user_data)
            
            # Fetch Terms of Service text for the dashboard (default to English)
            terms_text = tos_manager.get_terms_text(language='en')  # Get terms text directly
            print(terms_text)

            # Prepare dashboard response
            response_data = {
                "users": dashboard_data,
                "total_users": len(dashboard_data),
                "terms_of_service": terms_text if terms_text else "Terms of Service not available."
            }

            return jsonify(response_data), 200

        elif request.method == 'PUT':
            # Handle PUT requests to update the terms
            data = request.get_json()
            
            # Only the content is required for the update
            if 'content' not in data:
                return jsonify({'success': False, 'message': 'Content is required'}), 400

            # Call the update_terms method, passing only the content
            result = tos_manager.update_terms(content=data['content'], language=data.get('language', 'en'))
            
            if result['success']:
                return jsonify({'success': True, 'message': result['message']}), 200
            else:
                return jsonify({'success': False, 'message': result['message']}), 500

    except Exception as e:
        logging.error(f"Error in superuser_dashboard: {e}")
        return jsonify({'message': 'An error occurred.'}), 500
    finally:
        # Ensure the connection is closed properly
        connection.close()
        logging.info("Database connection closed")
@app.route('/api/user/details', methods=['GET', 'PUT'])
@token_required
def user_details(current_user):
    if request.method == 'GET':
        # Existing GET logic
        purchases = get_purchases_by_user_id(current_user['user_id'])
        profile_picture_blob = current_user.get('profile_picture')
        profile_picture_base64 = None
        if profile_picture_blob:
            profile_picture_base64 = base64.b64encode(profile_picture_blob).decode('utf-8')
        response = {
            "first_name": current_user.get('first_name'),
            "last_name": current_user.get('last_name'),
            "user_id": current_user['user_id'],
            "username": current_user.get('username'),
            "email": current_user.get('email'),
            "phone_number": current_user.get('phone_number'),
            "profile_picture": profile_picture_base64,
            "country": current_user.get('country'),
            "address": current_user.get('address'),
            "created_at": current_user.get('created_at'),
            "updated_at": current_user.get('updated_at'),
            "purchases": purchases
        }
        return jsonify(response), 200

    elif request.method == 'PUT':
        data = request.json  
        changes_made = False
        errors = []
        # Handle Profile Picture Update
        profile_picture_base64 = data.get('profilePicture')
        new_username = data.get('username')
        new_email = data.get('email')
        new_phone_number = data.get('phone_number')
        password = data.get('password')
        old_password = data.get('oldPassword')
        new_password = data.get('newPassword')

        if profile_picture_base64:
            try:
                profile_picture_blob = base64.b64decode(profile_picture_base64)
            
                
                success, message = upload_profile_picture(current_user['user_id'], profile_picture_blob)
                
                if success:
                    changes_made = True
                else:
                    errors.append(message)
            except Exception as e:
                error_message = f"Failed to process profile picture: {str(e)}"
                errors.append(error_message)
                
        # Username change
        if new_username:
            result = change_username(current_user['user_id'], new_username, password)
            if result is True:
                changes_made = True
            else:
                errors.append(result)

        # Email change
        if new_email:
            result = change_email(current_user['user_id'], new_email, password)
            if result is True:
                changes_made = True
            else:
                errors.append(result)

        # Phone number change
        if new_phone_number:
            result = change_phone_number(current_user['user_id'], new_phone_number, password)
            if result is True:
                changes_made = True
            else:
                errors.append(result)

        # Password change
        if old_password and new_password:
            if len(new_password) < 6:
                errors.append("New password must be at least 6 characters long.")
            elif not change_password(current_user['user_id'], old_password, new_password):
                errors.append("Failed to update password. Incorrect old password.")
            else:
                changes_made = True

        # Final response based on changes and errors
        if changes_made:
            return jsonify({"message": "User details updated successfully."}), 200
        elif errors:
            return jsonify({"message": "Errors occurred", "errors": errors}), 400
        else:
            return jsonify({"message": "No changes were made."}), 400

    
@app.route('/api/send-confirmation-email', methods=['POST'])
def request_confirmation_email():
    current_user = request.json  # Assuming you're sending JSON data
    user_email = current_user.get('email')
    
    # Generate the confirmation URL
    confirm_link = url_for('confirm_email', token=user_email, _external=True)  # Adjust this as needed
    
    # Send the confirmation email
    email_sent = send_confirmation_email(user_email, confirm_link)
    
    if email_sent:
        return jsonify({"message": "Confirmation email sent successfully."}), 200
    else:
        return jsonify({"message": "Failed to send confirmation email."}), 500
    

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    
    # Validate input
    if not data or 'email' not in data:
        return {"message": "Email is required"}, 400
    
    email = data['email']
    
    # Fetch the user by email and handle potential errors
    new_password = get_user_by_email(email)
    
    if not new_password:
        return {"message": "User Not Found"}, 500
    
    email_sent = send_password_reset_email(new_password, email)
    
    if email_sent:
        return {"message": "Password reset email sent successfully"}, 200
    else:
        return {"message": "Failed to send password reset email"}, 500


# Route to confirm the email
@app.route('/api/confirm-email/<token>', methods=['GET', 'OPTIONS'])
def confirm_email(token):
    if request.method == 'OPTIONS':
        return '', 204
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    try:
        payload = serializer.loads(token)
        user_email = payload['email']
        user_confirmed = confirm_user_email(user_email)
        
        if user_confirmed is True:
            return jsonify({"message": "Email confirmed successfully!"}), 200 
        elif user_confirmed is False:
            return jsonify({"message": "Email already confirmed or user not found."}), 400
        else:
            return jsonify({"message": "Failed to confirm email."}), 500
    
    except Exception as e:
        logging.error(f"Error confirming email: {e}")
        return jsonify({"message": "Invalid or expired confirmation link."}), 400


@app.route('/api/create-checkout-session', methods=['POST', 'OPTIONS'])
def create_checkout_session():
    if request.method == 'OPTIONS':
        return make_response('', 200)

    data = request.json
    user_id = data.get('user_id')
    cart_items = data.get('cartItems', [])
    allowed_origin = os.getenv('ALLOWED_ORIGIN', 'http://localhost:3000')  # Make sure you have this in .env
    
    try:
        # Create Stripe session
        stripe_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': item['product_name']},
                    'unit_amount': item['amount'],
                },
                'quantity': 1,
            } for item in cart_items],
            mode='payment',
            success_url=f'{allowed_origin}/success?session_id={{CHECKOUT_SESSION_ID}}&items=' +
                        urllib.parse.quote(json.dumps(cart_items)) +
                        f'&user_id={user_id if user_id else ""}',  # Add user_id to success_url
            cancel_url=f'{allowed_origin}/cancel',
        )

        return jsonify({'id': stripe_session.id})

    except stripe.error.StripeError as e:
        # Catch specific Stripe exceptions
        return jsonify(error=str(e)), 400
    except Exception as e:
        # Catch all other exceptions
        return jsonify(error=f"An error occurred: {str(e)}"), 500

@app.route('/api/record-purchase', methods=['POST'])
def record_purchase():
    data = request.json
    session_id = data.get('session_id')
    user_id = data.get('user_id') 
    if not session_id:
        return jsonify({"message": "Session ID is required."}), 400

    try:
        session = stripe.checkout.Session.retrieve(session_id)

        if session.payment_status == 'paid':
            # Clean up the URL parsing
            success_url = session.success_url
            items_param = success_url.split("items=")[1].split("&user_id=")[0]
            try:
                cart_items = json.loads(urllib.parse.unquote(items_param))
            except json.JSONDecodeError as e:
                return jsonify({"message": "Invalid cart items data"}), 400

            successful_purchases = []
            failed_purchases = []

            for item in cart_items:
                product_name = item.get('product_name')
                price = item.get('amount')

                # Call purchase_product to save the purchase in the database
                if purchase_product(user_id, product_name, session_id,price):
                    successful_purchases.append(product_name)
                else:
                    failed_purchases.append(product_name)

            # After successfully recording the purchases, retrieve them based on session_id or user_id
            if user_id:
                # Query purchases by user_id if the user is logged in
                purchases = get_purchases_by_user_id(user_id)
            else:
                # Query purchases by session_id for guest users
                purchases = get_purchases_by_session_id(session_id)

            response = {
                "message": "Purchase recording completed",
                "successful_purchases": successful_purchases,
                "failed_purchases": failed_purchases,
                "purchases": purchases  # Include the retrieved purchases in the response
            }

            if failed_purchases:
                return jsonify(response), 400
            return jsonify(response), 200
        else:
            return jsonify({"message": "Payment not successful."}), 400
    except Exception as e:
        return jsonify(error=str(e)), 400

@app.route('/api/contact-us', methods=['POST', 'OPTIONS'])
def contact_us():
    if request.method == 'OPTIONS':
        return make_response('', 200)

    # Get the JSON data from the request
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided."}), 400

    name = data.get('name')
    email = data.get('email')
    message = data.get('message')

    # Check for required fields
    if not name or not email or not message:
        return jsonify({"message": "Name, email, and message are required."}), 400

    # Send the email using the send_contact_email function
    email_sent = send_contact_email(name, email, message)
    if email_sent:
        return jsonify({"message": "Your message has been sent successfully!"}), 200
    else:
        return jsonify({"message": "Failed to send your message. Please try again later."}), 500


# Logout route
@app.route('/api/logout', methods=['POST'])
def logout():
    logout_user()
    session.clear()
    return jsonify({"message": "Logged out successfully!"}), 200

# Run the application
if __name__ == '__main__':
    with app.app_context():
        app.run(debug=True, host='127.0.0.1', port=5000)

from werkzeug.security import generate_password_hash, check_password_hash
from .db_setup import get_db_connection
from .self_utils import is_valid_email,create_new_password
from flask import flash, jsonify
from pymysql import MySQLError
import logging
import os
import pymysql

DEFAULT_PICTURE_PATH = os.path.join(os.path.dirname(__file__), 'static', 'images', 'default_profile_picture.jpg')

def confirm_user_email(email):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.callproc('get_user_by_email', (email,))
            result = cursor.fetchone()

            if result:
                if result['confirmed'] == 1:
                    logging.info(f"User with email {email} is already confirmed.")
                    return False  
                else:
                    update_query = "UPDATE users SET confirmed = 1 WHERE email = %s"
                    cursor.execute(update_query, (email,))
                    connection.commit()
                    logging.info(f"User with email {email}'s email confirmed successfully.")
                    return True
            else:
                logging.warning(f"User with email {email} not found.")
                return False
    except Exception as e:
        connection.rollback()
        logging.error(f"Error confirming email for user {email}: {e}")
        return False
    finally:
        connection.close()

def upload_profile_picture(user_id, file):
    if not file:
        return False, "No file provided."

    max_size = 50 * 1024 * 1024  
    if len(file) > max_size:
        return False, "File size exceeds the limit for profile picture."

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = '''
            UPDATE users SET profile_picture = %s WHERE user_id = %s
            '''
            cursor.execute(query, (file, user_id))
            connection.commit()
            return True, "Profile picture updated successfully."
    except pymysql.MySQLError as e:
        connection.rollback()
        return False, f"Database error: {e.args[1]}"
    except Exception as e:
        connection.rollback()
        return False, f"An error occurred: {e}"
    finally:
        connection.close()
def change_username(user_id, new_username, current_password):
    connection = get_db_connection()  
    try:
        with connection.cursor() as cursor:  
            cursor.callproc('get_user_by_ID', (user_id,))
            user_info = cursor.fetchone()  
            if user_info is None:
                print("User not found.")
                return "User not found." 

            current_username = user_info['username']
            stored_password_hash = user_info['password_hash'] 

            if not check_password_hash(stored_password_hash, current_password):
                return "Current password is incorrect." 

            cursor.execute('SELECT username FROM users WHERE username = %s AND user_id != %s', (new_username, user_id))
            existing_user = cursor.fetchone()

            if existing_user:
                return f"Username '{new_username}' already exists. Cannot update."

            cursor.callproc('UpdateUsername', (user_id, new_username))
            connection.commit()

            return True            
    except Exception as e:
        connection.rollback()
        return f"Error updating username: {e}"  
    finally:
        connection.close()

        
def change_email(user_id, new_email, current_password):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:

            cursor.callproc('get_user_by_ID', (user_id,))
            user_info = cursor.fetchone()
            if user_info is None:
                return "User not found."  
            current_email = user_info['email']  
            stored_password_hash = user_info['password_hash'] 
            if not check_password_hash(stored_password_hash, current_password):
                return "Current password is incorrect." 
            # Validate the new email format
            if not is_valid_email(new_email):
                return 'Invalid email format.' 
            cursor.callproc('UpdateEmail', (user_id, new_email))
            connection.commit()
            return True
    except Exception as e:
        connection.rollback()
        return f'Error updating email: {e}' 
    finally:
        connection.close()

def change_phone_number(user_id, new_phone_number, current_password):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.callproc('get_user_by_ID', (user_id,))
            user_info = cursor.fetchone()  
            if user_info is None:
                return "User not found." 
            current_phone_number = user_info['phone_number']  
            stored_password_hash = user_info['password_hash'] 

            if not check_password_hash(stored_password_hash, current_password):
                return "Current password is incorrect." 
            cursor.callproc('UpdatePhoneNumber', (user_id, new_phone_number))
            connection.commit()
            return True
    except Exception as e:
        connection.rollback()
        return f'Error updating Phone Number: {e}' 
    finally:
        connection.close()

def change_password(user_id, old_password, new_password):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.callproc('get_user_by_ID', (user_id,))
            result = cursor.fetchone()
            if not result or not check_password_hash(result['password_hash'], old_password):
                flash('Old password is incorrect.', 'error')
                return False
            new_password_hash = generate_password_hash(new_password)
            cursor.callproc('UpdatePassword', (user_id, new_password_hash))  # Corrected name
            connection.commit()
            flash('Password updated successfully.', 'success')
            return True
    except Exception as e:
        connection.rollback()
        flash(f'Error updating password: {e}', 'error')
        return False
    finally:
        connection.close()
        

def get_user_by_email(email):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.callproc('get_user_by_email', (email,))
            user = cursor.fetchone()         
            if user: 
                new_password = create_new_password()
                hashed_password = generate_password_hash(new_password)
                cursor.callproc('update_forgotten_password', (email, hashed_password))
                connection.commit()
                return user,new_password
    finally:
        connection.close()
     # Helper function to register user using the RegisterUser stored procedure
def register_user(first_name, last_name, username, email, password, phone_number, country, address, profile_picture=None):
    # Initial validations
    if not first_name or not last_name or not username or not email or not password or not phone_number or not country:
        return jsonify({"message": "All fields are required."}), 400

    if not is_valid_email(email):
        return jsonify({"message": "Invalid email format."}), 400

    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long."}), 400

    hashed_password = generate_password_hash(password)

    # Profile picture handling
    if profile_picture is None:
        if os.path.exists(DEFAULT_PICTURE_PATH):
            with open(DEFAULT_PICTURE_PATH, 'rb') as image_file:
                profile_picture = image_file.read()
        else:
            return jsonify({"message": "Default profile picture file not found."}), 500

    
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            try:
                cursor.callproc('RegisterUser', (
                    first_name, last_name, username, email, hashed_password,
                    profile_picture, phone_number, country, address
                ))

                # Commit the changes
                connection.commit()
                return jsonify({
                    "message": "User registered successfully!", 
                    "user": {
                        "first_name": first_name,
                        "last_name": last_name,
                        "username": username,
                        "email": email
                    }
                }), 201

            except MySQLError as mysql_err:

                # Extract and return specific error messages from the stored procedure
                if mysql_err.args[0] == 1644:  # Error signal from the stored procedure
                    error_message = mysql_err.args[1]
                    if "The provided username is already taken" in error_message:
                        return jsonify({"message": "The provided username is already taken. Please choose a different one."}), 400
                    elif "The provided email is already in use" in error_message:
                        return jsonify({"message": "The provided email is already in use. Please use a different email address."}), 400

                # Log and return a general database error message
                logging.error(f"MySQL Error: {mysql_err}")
                return jsonify({"message": "An unexpected database error occurred."}), 500

    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({"message": "An unexpected error occurred."}), 500
    finally:
        connection.close()

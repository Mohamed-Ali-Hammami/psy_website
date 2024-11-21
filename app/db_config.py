from .db_setup import get_db_connection
import logging
#for superuser password check 
from .self_utils import check_password
#for simple users check 
from werkzeug.security import check_password_hash
import base64
import pymysql

def check_credentials(identifier, password):
    """
    Checks credentials for both users and superusers using the CheckCredentials stored procedure.
    :param identifier: The username or email to check.
    :param password: The password to check.
    :return: A dictionary containing user_type and user_id (or superuser_id) or None if invalid.
    """
    print(f"Starting credential check for identifier: {identifier}")
    logging.info(f"Checking credentials for identifier: {identifier}")
    
    connection = get_db_connection()
    
    try:
        with connection.cursor() as cursor:
            # Call the stored procedure
            print("Calling stored procedure CheckCredentials...")
            cursor.execute("CALL CheckCredentials(%s)", (identifier,))
            result = cursor.fetchone()
            
            print(f"Stored procedure result: {result}")
            logging.info(f"Stored procedure result: {result}")

            # Check if a user or superuser was found
            if result:
                user_type = result.get('user_type')
                password_hash = result.get('password_hash')
                user_id = result.get('user_id')
                superuser_id = result.get('superuser_id')
               
                print(f"Retrieved data - User type: {user_type}, User ID: {user_id}, Superuser ID: {superuser_id}")
                logging.info(f"User type: {user_type}, User ID: {user_id}, Superuser ID: {superuser_id}")
                print("Validating password...")
                if user_type == 'user':
                    if user_id is not None and check_password_hash(password_hash,password):
                        return {
                            'user_type': 'user',
                            'user_id': user_id
                        }
                elif user_type == 'superuser':
                    if superuser_id is not None and check_password(password,password_hash ):
                        return {
                            'user_type': 'superuser',
                            'superuser_id': superuser_id
                        }
                elif user_type == 'not_found':
                    print("User not found.")
                    logging.info("User not found.")
                    return None
                else:
                    print(f"Unexpected user type: {user_type}")
                    logging.warning(f"Unexpected user type: {user_type}")
                    return None

                print("Password mismatch.")
                logging.info("Password mismatch.")
                return None

            # If no result is returned
            print("Invalid credentials or user not found.")
            logging.info("Invalid credentials or user not found.")
            return None

    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Error checking credentials: {e}")
        return None
    finally:
        print("Closing database connection.")
        connection.close()
def get_superuser_details(identifier):
    logging.info(f"Fetching superuser details for identifier: {identifier}")
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = '''
            SELECT superuser_id, username, email, password_hash
            FROM superusers 
            WHERE superuser_id = %s OR username = %s OR email = %s
            '''
            cursor.execute(query, (identifier,identifier, identifier))
            superuser = cursor.fetchone()
            if superuser:
                logging.info(f"Superuser found: {superuser}")
            return superuser
    except Exception as e:
        logging.error(f"Error fetching superuser details: {e}")
        return None
    finally:
        connection.close()
def get_users_details(identifier: str):
    """Fetches user details by user ID, username, or email."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = '''
            SELECT user_id, username, email, password_hash, first_name, last_name,
                   profile_picture, phone_number, country, address, created_at, updated_at
            FROM users 
            WHERE user_id = %s OR username = %s OR email = %s
            '''
            cursor.execute(query, (identifier, identifier, identifier))
            user = cursor.fetchone()

            # Log result or warning if not found
            if user:
                logging.info(f"User found: {user}")
            else:
                logging.warning(f"No user found with identifier: {identifier}")

            return user
    except Exception as e:
        logging.error(f"Error fetching user details for identifier {identifier}: {e}")
        return None
    finally:
        connection.close()
def get_all_users():
    connection = get_db_connection()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            query = '''
            SELECT 
                user_id, 
                first_name, 
                last_name, 
                username, 
                email, 
                profile_picture, 
                phone_number, 
                country, 
                address, 
                created_at, 
                updated_at
            FROM users
            '''
            cursor.execute(query)
            result = cursor.fetchall()
            
            users = []
            for user in result:
                # Convert profile picture to base64 if exists
                profile_picture_base64 = None
                if user['profile_picture']:
                    profile_picture_base64 = base64.b64encode(user['profile_picture']).decode('utf-8')
                
                user_data = {
                    'user_id': user['user_id'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'username': user['username'],
                    'email': user['email'],
                    'profile_picture': profile_picture_base64,
                    'phone_number': user['phone_number'],
                    'country': user['country'],
                    'address': user['address'],
                    'created_at': user['created_at'].isoformat() if user['created_at'] else None,
                    'updated_at': user['updated_at'].isoformat() if user['updated_at'] else None,
                }
                users.append(user_data)
            
            return users
    except Exception as e:
        logging.error(f"Error fetching all users: {e}")
        return []
    finally:
        connection.close()

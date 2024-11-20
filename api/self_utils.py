import random
import string
import re 
from dotenv import load_dotenv
import os
import hashlib
# Load environment variables
load_dotenv()
SECRET_NONCE = os.getenv('SECRET_NONCE', 'default_secret_nonce')

def create_new_password(length=8) -> str:
    """Generate a random new password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password


# Validate email format
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

# Function to hash the password using sha256 and a secret nonce
def hash_password(password):
    # Combine password with the secret nonce
    salted_password = password + SECRET_NONCE
    
    # Hash the salted password using sha256
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    
    return hashed_password
# Function to check if the provided password matches the stored hash
def check_password(entered_password, stored_hash):
    # Hash the entered password with the same nonce
    entered_hash = hash_password(entered_password)
    
    # Compare the hashes
    return entered_hash == stored_hash
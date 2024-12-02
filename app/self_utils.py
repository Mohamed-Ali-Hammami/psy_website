import random
import string
import re 
from dotenv import load_dotenv
import os
import hashlib
load_dotenv()
SECRET_NONCE = os.getenv('SECRET_NONCE', 'default_secret_nonce')

def create_new_password(length=8) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def hash_password(password):
    salted_password = password + SECRET_NONCE
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password

def check_password(entered_password, stored_hash):
    entered_hash = hash_password(entered_password)

    return entered_hash == stored_hash
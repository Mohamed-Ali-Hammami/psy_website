from flask import Flask
from flask_cors import CORS
import os
import pymysql
import stripe
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Dynamically build the path to the SSL certificate
# Directly specify the path to the SSL certificate
SSL_CA_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)),  'instance', 'ca.pem')


# Database connection function
def get_db_connection():
    try:
        # Connect to the MySQL database using SSL
        connection = pymysql.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            db=os.getenv('DB_NAME'),
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            ssl_ca=SSL_CA_PATH,
            port=os.int(getenv('DB_PORT'))
        )
        print(connection)
        return connection
    except pymysql.MySQLError as e:
        print(f"Error connecting to the database: {e}")
        raise RuntimeError("Database connection failed") from e

# Initialize database and app settings
def init_db(app):
    # Configure app settings like secret key and upload folder
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'images')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Check database connection
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')  # Simple query to check connection
        connection.close()
    except Exception as e:
        raise RuntimeError("Could not connect to the database.") from e

# Create and configure Flask application
def create_app():
    app = Flask(__name__)

    # Configure CORS to allow requests from the specified origin
    allowed_origin = os.getenv('ALLOWED_ORIGIN', 'http://localhost:3000')
    CORS(app, resources={r"/api/*": {"origins": allowed_origin}}, supports_credentials=True, automatic_options=True)

    # Initialize Stripe API with the secret key from environment
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

    # Initialize the database connection
    init_db(app)

    return app

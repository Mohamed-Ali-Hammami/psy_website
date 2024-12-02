from flask import Flask
from flask_cors import CORS
import os
import pymysql
import stripe
from dotenv import load_dotenv


load_dotenv()

SSL_CA_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)),  'instance', 'ca.pem')

def get_db_connection():
    try:
        connection = pymysql.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            db=os.getenv('DB_NAME'),
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            ssl_ca=SSL_CA_PATH,
            port=int(os.getenv('DB_PORT'))
        )
        return connection
    except pymysql.MySQLError as e:
        raise RuntimeError("Database connection failed") from e
def init_db(app):
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'images')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        connection.close()
    except Exception as e:
        raise RuntimeError("Could not connect to the database.") from e

def create_app():
    app = Flask(__name__)
    allowed_origin = os.getenv('ALLOWED_ORIGIN')
    localhost = 'http://localhost:3000'
    if allowed_origin:
        origins = [allowed_origin, localhost]
    else:
        origins = [localhost]

    CORS(app, resources={r"/api/*": {"origins": origins}}, supports_credentials=True, automatic_options=True)
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
    init_db(app)

    return app


import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')

    # Corrected database URI from environment variable or hardcoded fallback
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://jntu_db_user:40OU1X3HaYcu6UU9ak0nMnLZA7LUPb7z@dpg-d2366kre5dus73aagg8g-a/jntu_db"
    )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = 'static/uploads'

    # Mail configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

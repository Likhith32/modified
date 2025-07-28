import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')

    # Use PostgreSQL DB URL from environment, fallback to SQLite locally for dev
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'postgresql://jntu_db_user:40OU1X3HaYcu6UU9ak0nMnLZA7LUPb7z@dpg-d2366kre5dus73aagg8g-a/jntu_db',
        'sqlite:///jntu_quiz.db'  # fallback local DB if env var not set
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = 'static/uploads'

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

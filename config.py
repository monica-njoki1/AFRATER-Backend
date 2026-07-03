import os
from dotenv import load_dotenv
from datetime import timedelta

# Load .env file
load_dotenv()

class Config:
    # Flask Settings
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"  # False in production

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///afrater.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Uploads
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}

    # JWT
    JWT_SECRET_KEY = SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=30)


    # DARAJA API
    DARAJA_CONSUMER_KEY = os.getenv("skiV8fBNBdK1BBLQMaFCF3IqXK0YynwqLgF3yF5103GObxzX")
    DARAJA_CONSUMER_SECRET = os.getenv("J33KvHgKlFvYZEwGiMkMHV4LwAkhJ2u7XNY6I0Mr5lLsGdFlACB7wlPRNo7TXB73")
    LIPA_PASSKEY = os.getenv("bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919")
    BUSINESS_SHORTCODE = os.getenv("174379")

    # SendGrid Email
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "afrater@example.com")

    @staticmethod
    def validate_mpesa_keys():
        required = [
            "DARAJA_CONSUMER_KEY",
            "DARAJA_CONSUMER_SECRET",
            "LIPA_PASSKEY",
            "BUSINESS_SHORTCODE",
        ]
        missing = [key for key in required if os.getenv(key) is None]

        if missing:
            print(f" M-Pesa Keys Missing in .env: {', '.join(missing)}")
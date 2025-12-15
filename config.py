import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

class Config:
    # Flask Settings
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
    DEBUG = True

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///afrater.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Uploads
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}

    # JWT
    JWT_SECRET_KEY = SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 1 day

    # DARAJA API
    DARAJA_CONSUMER_KEY = os.getenv("DARAJA_CONSUMER_KEY")
    DARAJA_CONSUMER_SECRET = os.getenv("DARAJA_CONSUMER_SECRET")
    LIPA_PASSKEY = os.getenv("LIPA_PASSKEY")
    BUSINESS_SHORTCODE = os.getenv("BUSINESS_SHORTCODE")

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

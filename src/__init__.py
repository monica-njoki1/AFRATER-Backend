import os
from flask import Flask
from config import Config
from .extensions import db, migrate, bcrypt, jwt

def create_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config)

    # Ensure upload folder exists
    os.makedirs(app.config.get("UPLOAD_FOLDER", "uploads"), exist_ok=True)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.mpesa import mpesa_bp
    from .routes.scam import scam_bp
    from .routes.uploads import upload_bp
    from .routes.contacts import contacts_bp
    from .routes.transactions import tx_bp


    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(mpesa_bp, url_prefix='/mpesa')
    app.register_blueprint(scam_bp, url_prefix='/scam')
    app.register_blueprint(upload_bp, url_prefix='/upload')
    app.register_blueprint(contacts_bp, url_prefix='/contacts')
    app.register_blueprint(tx_bp, url_prefix='/transactions')

    return app

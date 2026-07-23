import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

from config import Config
from models import db
from blueprints.auth import auth_bp
from blueprints.trading import trading_bp
from blueprints.fraud import fraud_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    Migrate(app, db)
    JWTManager(app)
    CORS(app, origins=app.config["CORS_ORIGINS"], supports_credentials=True)

    app.register_blueprint(auth_bp)
    app.register_blueprint(trading_bp)
    app.register_blueprint(fraud_bp)

    @app.route("/", methods=["GET"])
    def root():
        return jsonify({"service": "FortiTrade AI", "status": "ok", "docs": "/api/health"}), 200

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "FortiTrade AI"}), 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
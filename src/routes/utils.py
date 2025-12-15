from functools import wraps
from flask import request, jsonify
import jwt
from config import Config
from src.models.models import User, TokenBlocklist

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            # Check if token is blacklisted
            if TokenBlacklist.query.filter_by(token=token).first():
                return jsonify({"error": "Token revoked"}), 401

            data = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            current_user = User.query.get(data["user_id"])
        except:
            return jsonify({"error": "Token invalid"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

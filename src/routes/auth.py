from flask import Blueprint, request, jsonify
from src.models.models import db, User, TokenBlocklist
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from src import bcrypt
import os
from werkzeug.utils import secure_filename
from datetime import datetime

auth_bp = Blueprint("auth_bp", __name__, url_prefix="/auth")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


# ----------- Utility function -----------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------- Register ----------
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.form  # handles form-data (for file uploads)
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    profile_pic = request.files.get("profile_pic")

    if not password:
        return jsonify({"error": "Password cannot be empty"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400

    filename = None
    if profile_pic and allowed_file(profile_pic.filename):
        os.makedirs("uploads/users", exist_ok=True)
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secure_filename(profile_pic.filename)}"
        profile_pic.save(os.path.join("uploads/users", filename))

    user = User(name=name, email=email)
    user.set_password(password)
    user.profile_pic = filename

    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully", "id": user.id}), 201


# ---------- Login ----------
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or request.form
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=user.id)
    return jsonify({
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "profile_pic": user.profile_pic
        }
    })


# ---------- Logout ----------
@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti, created_at=datetime.utcnow()))
    db.session.commit()
    return jsonify({"message": "Successfully logged out"})


# ---------- Get Profile ----------
@auth_bp.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "profile_pic": user.profile_pic
    })


# ---------- Update Profile ----------
@auth_bp.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    data = request.form  # for form-data
    user.name = data.get("name", user.name)
    user.email = data.get("email", user.email)

    profile_pic = request.files.get("profile_pic")
    if profile_pic and allowed_file(profile_pic.filename):
        os.makedirs("uploads/users", exist_ok=True)
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secure_filename(profile_pic.filename)}"
        profile_pic.save(os.path.join("uploads/users", filename))
        # Delete old profile pic if exists
        if user.profile_pic:
            old_path = os.path.join("uploads/users", user.profile_pic)
            if os.path.exists(old_path):
                os.remove(old_path)
        user.profile_pic = filename

    db.session.commit()
    return jsonify({"message": "Profile updated successfully"})


# ---------- Delete Account ----------
@auth_bp.route("/delete", methods=["DELETE"])
@jwt_required()
def delete_account():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    # Delete profile picture if exists
    if user.profile_pic:
        path = os.path.join("uploads/users", user.profile_pic)
        if os.path.exists(path):
            os.remove(path)

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Account deleted successfully"})

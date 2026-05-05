from flask import Blueprint, request, jsonify
from src.models.models import db, User, TokenBlocklist
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from src import bcrypt
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

auth_bp = Blueprint("auth_bp", __name__, url_prefix="/auth")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


# ----------- Utility functions -----------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def send_login_email(to_email, name):
    """Send a login notification email via SendGrid."""
    try:
        api_key = os.getenv("SENDGRID_API_KEY")
        sender = os.getenv("MAIL_DEFAULT_SENDER", "afrater@example.com")

        if not api_key:
            print("SendGrid API key not set, skipping email.")
            return

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        message = Mail(
            from_email=sender,
            to_emails=to_email,
            subject="New Login to Your AFRATER Account",
            html_content=f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #ffffff; padding: 32px; border-radius: 12px;">
                <h1 style="color: #22d3ee; font-size: 24px; margin-bottom: 8px;">AFRATER</h1>
                <h2 style="font-size: 18px; margin-bottom: 16px;">New Login Detected</h2>
                <p style="color: #cbd5e1;">Hi <strong>{name}</strong>,</p>
                <p style="color: #cbd5e1;">A new login to your AFRATER account was detected.</p>
                <div style="background: #1e293b; border-radius: 8px; padding: 16px; margin: 20px 0;">
                    <p style="margin: 0; color: #94a3b8; font-size: 14px;">🕒 Time: <strong style="color: #ffffff;">{now}</strong></p>
                    <p style="margin: 8px 0 0; color: #94a3b8; font-size: 14px;">📧 Account: <strong style="color: #ffffff;">{to_email}</strong></p>
                </div>
                <p style="color: #cbd5e1; font-size: 14px;">If this wasn't you, please change your password immediately.</p>
                <p style="color: #64748b; font-size: 12px; margin-top: 32px;">© 2024 AFRATER — Amok Fraud Terminator</p>
            </div>
            """
        )

        sg = SendGridAPIClient(api_key)
        sg.send(message)
        print(f"Login email sent to {to_email}")

    except Exception as e:
        # Never block login if email fails
        print(f"Failed to send login email: {e}")


# ---------- Register ----------
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.form
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

    # Send login notification email (non-blocking)
    send_login_email(user.email, user.name)

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

    data = request.form
    user.name = data.get("name", user.name)
    user.email = data.get("email", user.email)

    profile_pic = request.files.get("profile_pic")
    if profile_pic and allowed_file(profile_pic.filename):
        os.makedirs("uploads/users", exist_ok=True)
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secure_filename(profile_pic.filename)}"
        profile_pic.save(os.path.join("uploads/users", filename))
        if user.profile_pic:
            old_path = os.path.join("uploads/users", user.profile_pic)
            if os.path.exists(old_path):
                os.remove(old_path)
        user.profile_pic = filename

    db.session.commit()
    return jsonify({
        "message": "Profile updated successfully",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "profile_pic": user.profile_pic
        }
    })


# ---------- Delete Account ----------
@auth_bp.route("/delete", methods=["DELETE"])
@jwt_required()
def delete_account():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    if user.profile_pic:
        path = os.path.join("uploads/users", user.profile_pic)
        if os.path.exists(path):
            os.remove(path)

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Account deleted successfully"})
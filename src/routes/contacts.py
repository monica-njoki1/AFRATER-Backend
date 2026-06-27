"""
src/routes/contacts_bp.py

Trusted contacts — people to alert when fraud is detected on a user's account.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models.models import FraudContact, db

contacts_bp = Blueprint("contacts_bp", __name__, url_prefix="/contacts")


# ---------- Add a trusted contact ----------
@contacts_bp.route("/", methods=["POST"])
@jwt_required()
def add_contact():
    """
    POST /contacts/
    Body: { "name": "Jane", "phone": "0712345678" }
    """
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}

    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()

    if not name or not phone:
        return jsonify({"error": "name and phone are required"}), 400

    # Prevent duplicates for this user
    existing = FraudContact.query.filter_by(
        user_id=current_user_id, phone=phone
    ).first()
    if existing:
        return jsonify({"error": "Contact with this phone already exists"}), 409

    contact = FraudContact(name=name, phone=phone, user_id=current_user_id)
    db.session.add(contact)
    db.session.commit()

    return jsonify({"message": "Contact added", "id": contact.id}), 201


# ---------- List all contacts ----------
@contacts_bp.route("/", methods=["GET"])
@jwt_required()
def get_contacts():
    """
    GET /contacts/
    Returns all trusted contacts for the logged-in user.
    """
    current_user_id = get_jwt_identity()
    contacts = FraudContact.query.filter_by(user_id=current_user_id).all()

    result = [
        {
            "id": c.id,
            "name": c.name,
            "phone": c.phone,
            "created_at": c.created_at.isoformat(),
        }
        for c in contacts
    ]
    return jsonify(result), 200


# ---------- Delete a contact ----------
@contacts_bp.route("/<int:contact_id>", methods=["DELETE"])
@jwt_required()
def delete_contact(contact_id):
    """
    DELETE /contacts/<id>
    Only the owner can delete their own contact.
    """
    current_user_id = get_jwt_identity()
    contact = FraudContact.query.filter_by(
        id=contact_id, user_id=current_user_id
    ).first()

    if not contact:
        return jsonify({"error": "Contact not found"}), 404

    db.session.delete(contact)
    db.session.commit()
    return jsonify({"message": "Contact deleted"}), 200
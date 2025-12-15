from flask import Blueprint, request, jsonify
from src.models.models import FraudContact, db
from src.routes.utils import token_required  # make sure this works with JWT

contacts_bp = Blueprint("contacts_bp", __name__, url_prefix="/contacts")

# ---------- Add Contact ----------
@contacts_bp.route("/", methods=["POST"])
@token_required
def add_contact(current_user):
    data = request.json
    name = data.get("name")
    phone = data.get("phone")

    if not name or not phone:
        return jsonify({"error": "Name and phone are required"}), 400

    contact = FraudContact(
        name=name,
        phone=phone,
        user_id=current_user.id
    )
    db.session.add(contact)
    db.session.commit()
    return jsonify({"message": "Contact added"}), 201

# ---------- Get Contacts ----------
@contacts_bp.route("/", methods=["GET"])
@token_required
def get_contacts(current_user):
    contacts = FraudContact.query.filter_by(user_id=current_user.id).all()
    result = [{"name": c.name, "phone": c.phone} for c in contacts]
    return jsonify(result), 200

# ---------- Delete Contact (Optional) ----------
@contacts_bp.route("/<int:contact_id>", methods=["DELETE"])
@token_required
def delete_contact(current_user, contact_id):
    contact = FraudContact.query.filter_by(id=contact_id, user_id=current_user.id).first()
    if not contact:
        return jsonify({"error": "Contact not found"}), 404

    db.session.delete(contact)
    db.session.commit()
    return jsonify({"message": "Contact deleted"}), 200

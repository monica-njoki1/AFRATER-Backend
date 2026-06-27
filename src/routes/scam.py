"""
src/routes/scam_bp.py

Handles manual message submission for fraud checking.
Uses assess_message() — no Transaction object needed.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models.models import ScamReport, db
from src.services.fraud_engine import assess_message

scam_bp = Blueprint("scam_bp", __name__, url_prefix="/scam")


# ---------- Check a suspicious message ----------
@scam_bp.route("/check", methods=["POST"])
@jwt_required()
def check_scam():
    """
    POST /scam/check
    Body: { "message": "please reverse KES 100 sent by mistake" }

    Returns:
    {
        "score":   40,
        "verdict": "suspicious",
        "reasons": ["keyword match: reverse, sent by mistake"]
    }
    """
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"error": "message is required"}), 400

    result = assess_message(message, user_id=current_user_id)
    return jsonify(result), 200


# ---------- Get all scam reports by current user ----------
@scam_bp.route("/reports", methods=["GET"])
@jwt_required()
def get_reports():
    """
    GET /scam/reports
    Returns all scam reports submitted by the logged-in user.
    """
    current_user_id = get_jwt_identity()
    reports = ScamReport.query.filter_by(user_id=current_user_id)\
                              .order_by(ScamReport.created_at.desc()).all()

    result = [
        {
            "id": r.id,
            "message": r.message,
            "suspicious": r.suspicious,
            "screenshot": r.screenshot,
            "created_at": r.created_at.isoformat(),
        }
        for r in reports
    ]
    return jsonify(result), 200
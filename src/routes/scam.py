from flask import Blueprint, request, jsonify
from src.models.models import ScamReport, db
from src.routes.utils import token_required

scam_bp = Blueprint("scam_bp", __name__, url_prefix="/scam")

@scam_bp.route("/check", methods=["POST"])
@token_required
def check_scam(current_user):
    data = request.json
    msg = data.get("message", "")
    suspicious = any(word in msg.lower() for word in ["enter code", "refund", "reverse"])
    report = ScamReport(message=msg, suspicious=suspicious, user_id=current_user.id)
    db.session.add(report)
    db.session.commit()
    return jsonify({"suspicious": suspicious, "message": msg})

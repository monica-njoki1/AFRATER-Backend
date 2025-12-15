from flask import Blueprint, request, jsonify
from src.models.models import Transaction, db
from src.services.fraud_engine import assess_transaction
from src.routes.utils import token_required
from datetime import datetime

tx_bp = Blueprint("tx_bp", __name__)

@tx_bp.route("/ingest", methods=["POST"])
@token_required
def ingest(current_user):
    payload = request.get_json() or request.form or {}
    trans_id = payload.get("trans_id")
    phone = payload.get("phone")
    amount = payload.get("amount")
    if not trans_id or not phone or amount is None:
        return jsonify({"error": "trans_id, phone and amount required"}), 400
    tx = Transaction(trans_id=trans_id, phone=phone, amount=float(amount), metadata=payload)
    db.session.add(tx)
    db.session.commit()
    score, reasons = assess_transaction(tx)
    return jsonify({"trans_id": trans_id, "score": score, "reasons": reasons}), 201

@tx_bp.route("/<string:trans_id>/score", methods=["GET"])
def score(trans_id):
    tx = Transaction.query.filter_by(trans_id=trans_id).first_or_404()
    events = [{"reason": e.reason, "score": e.score, "created_at": e.created_at.isoformat()} for e in tx.events]
    return jsonify({"transaction": tx.to_dict(), "events": events}), 200

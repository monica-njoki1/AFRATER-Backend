"""
src/routes/tx_bp.py

Manual transaction ingestion and score lookup.
Useful for testing the fraud engine directly or ingesting
transactions from sources other than Daraja callbacks.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from src.models.models import Transaction, SuspiciousEvent, db
from src.services.fraud_engine import assess_transaction

tx_bp = Blueprint("tx_bp", __name__, url_prefix="/transactions")


# ---------- Ingest a transaction manually ----------
@tx_bp.route("/ingest", methods=["POST"])
@jwt_required()
def ingest():
    """
    POST /transactions/ingest
    Body: { "phone": "0712345678", "amount": 500, "reference": "ABC123" }

    Creates a Transaction, runs fraud engine, returns verdict.
    """
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}

    phone     = data.get("phone", "").strip()
    amount    = data.get("amount")
    reference = data.get("reference", "").strip() or None
    message   = data.get("message", "").strip() or None  # optional scam message text

    if not phone or amount is None:
        return jsonify({"error": "phone and amount are required"}), 400

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({"error": "amount must be a number"}), 400

    tx = Transaction(
        user_id=current_user_id,
        phone_number=phone,        # matches model field exactly
        amount=amount,
        reference=reference,
        status="manual",
    )
    db.session.add(tx)
    db.session.commit()

    score, reasons = assess_transaction(tx, message=message)
    verdict = "fraud" if score >= 60 else "suspicious" if score >= 30 else "safe"

    return jsonify({
        "transaction_id": tx.id,
        "phone":          phone,
        "amount":         amount,
        "score":          score,
        "verdict":        verdict,
        "reasons":        reasons,
    }), 201


# ---------- Get score for an existing transaction ----------
@tx_bp.route("/<int:transaction_id>/score", methods=["GET"])
@jwt_required()
def get_score(transaction_id):
    """
    GET /transactions/<id>/score
    Returns the transaction details + all suspicious events linked to it.
    """
    current_user_id = get_jwt_identity()

    tx = Transaction.query.filter_by(
        id=transaction_id, user_id=current_user_id
    ).first_or_404()

    events = [
        {
            "reason":     e.reason,
            "severity":   e.severity,
            "created_at": e.created_at.isoformat(),
        }
        for e in tx.events
    ]

    return jsonify({
        "transaction": {
            "id":           tx.id,
            "phone_number": tx.phone_number,
            "amount":       tx.amount,
            "reference":    tx.reference,
            "status":       tx.status,
            "created_at":   tx.created_at.isoformat(),
        },
        "events": events,
        "event_count": len(events),
    }), 200


# ---------- List all transactions for current user ----------
@tx_bp.route("/", methods=["GET"])
@jwt_required()
def list_transactions():
    """
    GET /transactions/
    Returns all transactions for the logged-in user, newest first.
    """
    current_user_id = get_jwt_identity()
    txs = Transaction.query.filter_by(user_id=current_user_id)\
                           .order_by(Transaction.created_at.desc()).all()

    result = [
        {
            "id":           tx.id,
            "phone_number": tx.phone_number,
            "amount":       tx.amount,
            "reference":    tx.reference,
            "status":       tx.status,
            "created_at":   tx.created_at.isoformat(),
        }
        for tx in txs
    ]
    return jsonify(result), 200
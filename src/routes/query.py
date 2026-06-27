"""
src/routes/query.py

STK push status polling so the frontend can check
whether a payment completed when the Daraja callback is delayed.
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from src.models.models import Transaction, db
from src.utils.daraja import query_stk_status

query_bp = Blueprint("query_bp", __name__, url_prefix="/query")


# ---------- Poll Daraja directly for STK status ----------
@query_bp.route("/stk/<string:checkout_request_id>", methods=["GET"])
@jwt_required()
def poll_stk(checkout_request_id):
    """
    GET /query/stk/<CheckoutRequestID>
    Asks Daraja: did this payment go through?

    ResultCode meanings:
        0     → success
        1032  → cancelled by user
        1037  → timed out
        2001  → wrong PIN
    """
    result = query_stk_status(checkout_request_id)

    if "error" in result:
        return jsonify({"error": result["error"]}), 502

    result_code = result.get("ResultCode")
    result_desc = result.get("ResultDesc", "")

    STATUS_MAP = {
        "0":    "completed",
        "1032": "cancelled",
        "1037": "timed_out",
        "2001": "wrong_pin",
    }
    status = STATUS_MAP.get(str(result_code), "pending")

    # Sync local Transaction record if completed
    if status == "completed":
        tx = Transaction.query.filter_by(reference=checkout_request_id).first()
        if tx and tx.status != "completed":
            tx.status = "completed"
            db.session.commit()

    return jsonify({
        "checkout_request_id": checkout_request_id,
        "result_code":         result_code,
        "result_desc":         result_desc,
        "status":              status,
    }), 200


# ---------- Check local DB transaction ----------
@query_bp.route("/transaction/<int:transaction_id>", methods=["GET"])
@jwt_required()
def get_transaction_status(transaction_id):
    """
    GET /query/transaction/<id>
    Returns transaction status + fraud events from local DB.
    """
    current_user_id = get_jwt_identity()

    tx = Transaction.query.filter_by(
        id=transaction_id,
        user_id=current_user_id
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
        "id":           tx.id,
        "phone_number": tx.phone_number,
        "amount":       tx.amount,
        "reference":    tx.reference,
        "status":       tx.status,
        "flagged":      any(e["severity"] in ("medium", "high") for e in events),
        "events":       events,
        "created_at":   tx.created_at.isoformat(),
    }), 200


# ---------- List pending transactions ----------
@query_bp.route("/pending", methods=["GET"])
@jwt_required()
def list_pending():
    """
    GET /query/pending
    Returns all pending transactions for the current user.
    """
    current_user_id = get_jwt_identity()

    pending = Transaction.query.filter_by(
        user_id=current_user_id,
        status="pending"
    ).order_by(Transaction.created_at.desc()).all()

    result = [
        {
            "id":           tx.id,
            "phone_number": tx.phone_number,
            "amount":       tx.amount,
            "reference":    tx.reference,
            "created_at":   tx.created_at.isoformat(),
        }
        for tx in pending
    ]

    return jsonify({"count": len(result), "pending": result}), 200
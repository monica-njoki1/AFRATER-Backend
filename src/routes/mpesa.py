"""
src/routes/mpesa_bp.py

Single clean version.
- /pay         → initiate STK Push (authenticated)
- /callback    → Daraja webhook (public, called by Safaricom)
"""

import os
import json
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from src.models.models import MPesaUpload, Transaction, FraudContact, db
from src.utils.daraja import stk_push, query_stk_status
from src.services.fraud_engine import assess_transaction

mpesa_bp = Blueprint("mpesa_bp", __name__, url_prefix="/mpesa")


# ---------- Initiate STK Push ----------
@mpesa_bp.route("/pay", methods=["POST"])
@jwt_required()
def pay():
    """
    POST /mpesa/pay
    Body: { "phone": "0712345678", "amount": 500 }

    Runs a pre-flight fraud check BEFORE sending the STK push.
    If verdict is "fraud", the payment is blocked.
    If verdict is "suspicious", it is flagged but still sent.
    """
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}

    phone = data.get("phone", "").strip()
    amount = data.get("amount")

    if not phone or amount is None:
        return jsonify({"error": "phone and amount are required"}), 400

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({"error": "amount must be a number"}), 400

    # ---- Pre-flight fraud check ----
    # Create a temporary Transaction (not committed yet) to run checks
    pre_tx = Transaction(
        user_id=current_user_id,
        phone_number=phone,
        amount=amount,
        status="preflight",
    )
    db.session.add(pre_tx)
    db.session.commit()

    score, reasons = assess_transaction(pre_tx)

    if score >= 60:
        # Hard block — do not send STK push
        pre_tx.status = "blocked"
        db.session.commit()
        return jsonify({
            "blocked": True,
            "score": score,
            "verdict": "fraud",
            "reasons": reasons,
            "message": "Payment blocked: high fraud risk detected.",
        }), 403

    # ---- Send STK Push ----
    stk_response = stk_push(phone, amount)

    # Update the preflight record to pending
    pre_tx.status = "pending"
    pre_tx.reference = stk_response.get("CheckoutRequestID")
    db.session.commit()

    # Log the upload record
    mpesa_record = MPesaUpload(
        user_id=current_user_id,
        filename=f"STK_PENDING_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json",
        amount=amount,
    )
    db.session.add(mpesa_record)
    db.session.commit()

    return jsonify({
        "blocked": False,
        "score": score,
        "verdict": "suspicious" if score >= 30 else "safe",
        "reasons": reasons,
        "stk_response": stk_response,
    }), 200


# ---------- Daraja Callback (public — no JWT) ----------
@mpesa_bp.route("/callback", methods=["POST"])
def mpesa_callback():
    """
    POST /mpesa/callback
    Called by Safaricom after STK push completes.
    Saves result, creates a final Transaction, runs fraud check.
    """
    payload = request.get_json() or {}

    # Save raw callback to disk for audit
    os.makedirs("uploads/mpesa", exist_ok=True)
    filename = f"STK_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    filepath = os.path.join("uploads/mpesa", filename)
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)

    # Parse Daraja response structure
    stk = payload.get("Body", {}).get("stkCallback", {}) if isinstance(payload, dict) else {}
    checkout_id  = stk.get("CheckoutRequestID")
    result_code  = stk.get("ResultCode")
    result_desc  = stk.get("ResultDesc")
    amount       = None
    receipt      = None
    phone        = None

    for item in stk.get("CallbackMetadata", {}).get("Item", []):
        name = item.get("Name")
        value = item.get("Value")
        if name == "Amount":
            amount = value
        elif name == "MpesaReceiptNumber":
            receipt = value
        elif name == "PhoneNumber":
            phone = str(value)

    # Save upload record
    mpesa_record = MPesaUpload(
        filename=filename,
        result_code=result_code,
        result_desc=result_desc,
        amount=amount,
        receipt=receipt,
    )
    db.session.add(mpesa_record)

    # Match the pending Transaction by CheckoutRequestID if possible
    pending_tx = None
    if checkout_id:
        pending_tx = Transaction.query.filter_by(reference=checkout_id).first()

    if result_code == 0 and receipt:
        if pending_tx:
            pending_tx.status = "completed"
            pending_tx.reference = receipt
            db.session.commit()
            assess_transaction(pending_tx)
        else:
            # No pre-flight record — create one and assess
            tx = Transaction(
                phone_number=phone or "unknown",
                amount=amount,
                reference=receipt,
                status="completed",
            )
            db.session.add(tx)
            db.session.commit()
            assess_transaction(tx)
    elif pending_tx:
        pending_tx.status = "failed"
        db.session.commit()

    db.session.commit()
    return jsonify({"message": "Callback received"}), 200
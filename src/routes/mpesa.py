from flask import Blueprint, request, jsonify, current_app
from src.models.models import MPesaUpload, MPesaUpload as MPesaModel, ScamReport, FraudContact, db, Transaction
from src.services.m_pesa import stk_push
from flask_jwt_extended import jwt_required, get_jwt_identity
import os, json
from datetime import datetime
from src.services.fraud_engine import assess_transaction

mpesa_bp = Blueprint("mpesa_bp", __name__)

# Initiate STK Push
@mpesa_bp.route("/pay", methods=["POST"])
@jwt_required()
def pay():
    data = request.get_json() or {}
    phone = data.get("phone")
    amount = data.get("amount")
    if not phone or not amount:
        return jsonify({"error": "Phone and amount required"}), 400

    result = stk_push(phone, amount)

    current_user_id = get_jwt_identity()
    mpesa_record = MPesaUpload(
        user_id=current_user_id,
        filename=f"STK_PENDING_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json",
        metadata=result if isinstance(result, dict) else None
    )
    db.session.add(mpesa_record)
    db.session.commit()

    return jsonify(result), 200

# Daraja Callback (public)
@mpesa_bp.route("/callback", methods=["POST"])
def mpesa_callback():
    payload = request.get_json() or {}
    # Save raw payload
    os.makedirs("uploads/mpesa", exist_ok=True)
    filename = f"STK_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    path = os.path.join("uploads/mpesa", filename)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)

    # Parse common fields if present
    stk = payload.get("Body", {}).get("stkCallback", {}) if isinstance(payload, dict) else {}
    checkout_id = stk.get("CheckoutRequestID")
    result_code = stk.get("ResultCode")
    result_desc = stk.get("ResultDesc")
    amount = None
    receipt = None
    callback_metadata = stk.get("CallbackMetadata", {}).get("Item", []) if stk else []
    for item in callback_metadata:
        if item.get("Name") == "Amount":
            amount = item.get("Value")
        if item.get("Name") == "MpesaReceiptNumber":
            receipt = item.get("Value")

    mpesa_record = MPesaUpload(
        filename=filename,
        result_code=result_code,
        result_desc=result_desc,
        amount=amount,
        receipt=receipt
    )
    db.session.add(mpesa_record)
    db.session.commit()

    # If succeeded, create a Transaction record and run fraud check
    if result_code == 0 and receipt:
        tx = Transaction(trans_id=receipt, phone=None, amount=amount, metadata=payload)
        db.session.add(tx)
        db.session.commit()
        assess_transaction(tx)

    return jsonify({"message": "Callback received"}), 200

# CRUD for scams/contacts left to their own blueprint (scam_bp, contacts_bp)

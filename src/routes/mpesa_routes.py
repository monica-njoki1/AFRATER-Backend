from flask import Blueprint, request, jsonify
from src.models.models import db, MPesaUpload
from src.utils.daraja import stk_push

from flask_jwt_extended import jwt_required, get_jwt_identity
import os, json
from datetime import datetime

mpesa_bp = Blueprint("mpesa_bp", __name__, url_prefix="/mpesa")


# ---------- Initiate STK Push ----------
@mpesa_bp.route("/pay", methods=["POST"])
@jwt_required()
def pay():
    data = request.json
    phone = data.get("phone")
    amount = data.get("amount")

    if not phone or not amount:
        return jsonify({"error": "Phone and amount required"}), 400

    response = stk_push(phone, amount)

    # Log the STK push attempt (optional)
    mpesa_record = MPesaUpload(
        user_id=get_jwt_identity(),
        filename=f"STK_PENDING_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    )
    db.session.add(mpesa_record)
    db.session.commit()

    return jsonify(response), 200


# ---------- Daraja Callback ----------
@mpesa_bp.route("/callback", methods=["POST"])
def mpesa_callback():
    data = request.json
    stk = data.get("Body", {}).get("stkCallback", {})

    checkout_id = stk.get("CheckoutRequestID")
    result_code = stk.get("ResultCode")
    result_desc = stk.get("ResultDesc")

    # Save JSON callback file
    os.makedirs("uploads/mpesa", exist_ok=True)
    filename = f"STK_{checkout_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    filepath = os.path.join("uploads/mpesa", filename)

    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

    # Save to DB
    mpesa_record = MPesaUpload(
        filename=filename,
        result_code=result_code,
        result_desc=result_desc
    )
    db.session.add(mpesa_record)
    db.session.commit()

    return jsonify({"message": "Callback received"}), 200

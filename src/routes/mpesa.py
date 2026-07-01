"""
src/routes/mpesa.py

STK Push with full pre-flight protection:
1. Recipient reputation check
2. Fraud engine assessment
3. Warning level response (block / warn / safe)
4. Callback handling
"""

import os
import json
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from src.models.models import MPesaUpload, Transaction, db
from src.utils.daraja import stk_push, query_stk_status
from src.services.fraud_engine import assess_transaction
from src.services.recipient_reputation import get_recipient_reputation, add_to_community_reports

mpesa_bp = Blueprint("mpesa_bp", __name__, url_prefix="/mpesa")


# ------------------------------------------------------------------ #
#  PRE-FLIGHT CHECK — called BEFORE payment to warn user
# ------------------------------------------------------------------ #
@mpesa_bp.route("/preflight", methods=["POST"])
@jwt_required()
def preflight():
    """
    POST /mpesa/preflight
    Body: { "phone": "0712345678", "amount": 500 }

    Runs reputation + fraud checks WITHOUT initiating payment.
    Frontend calls this when user fills in payment form.

    Returns:
    {
        "safe":        false,
        "risk_level":  "high",
        "warnings":    ["Never sent to this number", "Reported by 2 users"],
        "score":       75,
        "verdict":     "fraud",
        "should_block": true,
        "reputation":  { ... }
    }
    """
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}

    phone  = data.get("phone", "").strip()
    amount = data.get("amount")

    if not phone or amount is None:
        return jsonify({"error": "phone and amount are required"}), 400

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({"error": "amount must be a number"}), 400

    # ── Reputation check ──────────────────────────────────────────
    reputation = get_recipient_reputation(phone, current_user_id)

    # ── Quick fraud score (no DB write yet) ───────────────────────
    from src.services.fraud_engine import (
        check_known_scam_number, check_amount, check_off_hours
    )
    score = 0
    reasons = []

    for s, r in [
        check_known_scam_number(phone),
        check_amount(amount),
        check_off_hours(),
    ]:
        score += s
        reasons.extend(r)

    # Boost score from reputation
    if reputation["is_blacklisted"]:
        score += 50
        reasons.append(f"Phone is community-blacklisted")
    elif reputation["scam_report_count"] > 0:
        score += 25
        reasons.append(f"Phone reported in {reputation['scam_report_count']} scam(s)")

    score = min(score, 100)
    verdict = "fraud" if score >= 60 else "suspicious" if score >= 30 else "safe"

    # Combine all warnings
    all_warnings = reputation["warnings"] + reasons

    should_block = verdict == "fraud" or reputation["is_blacklisted"]

    return jsonify({
        "safe":         len(all_warnings) == 0,
        "risk_level":   reputation["risk_level"],
        "warnings":     all_warnings,
        "score":        score,
        "verdict":      verdict,
        "should_block": should_block,
        "reputation":   {
            "first_time":        reputation["first_time"],
            "scam_report_count": reputation["scam_report_count"],
            "unique_reporters":  reputation["unique_reporters"],
            "is_blacklisted":    reputation["is_blacklisted"],
        },
    }), 200


# ------------------------------------------------------------------ #
#  PAY — initiates STK Push after pre-flight
# ------------------------------------------------------------------ #
@mpesa_bp.route("/pay", methods=["POST"])
@jwt_required()
def pay():
    """
    POST /mpesa/pay
    Body: { "phone": "0712345678", "amount": 500, "override": false }

    override=true means user acknowledged warnings and wants to proceed anyway.
    Hard blocks (blacklisted numbers) cannot be overridden.
    """
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}

    phone    = data.get("phone", "").strip()
    amount   = data.get("amount")
    override = data.get("override", False)

    if not phone or amount is None:
        return jsonify({"error": "phone and amount are required"}), 400

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({"error": "amount must be a number"}), 400

    # ── Full reputation + fraud check ────────────────────────────
    reputation = get_recipient_reputation(phone, current_user_id)

    # Create preflight transaction record
    pre_tx = Transaction(
        user_id=current_user_id,
        phone_number=phone,
        amount=amount,
        status="preflight",
    )
    db.session.add(pre_tx)
    db.session.commit()

    score, reasons = assess_transaction(pre_tx)

    # Boost from reputation
    if reputation["is_blacklisted"]:
        score = min(score + 50, 100)
        reasons.append("Phone is community-blacklisted")

    verdict = "fraud" if score >= 60 else "suspicious" if score >= 30 else "safe"
    all_warnings = reputation["warnings"] + reasons

    # Hard block — blacklisted numbers can NEVER be overridden
    if reputation["is_blacklisted"]:
        pre_tx.status = "blocked"
        db.session.commit()
        return jsonify({
            "blocked":      True,
            "override_allowed": False,
            "score":        score,
            "verdict":      "fraud",
            "warnings":     all_warnings,
            "message":      "Payment blocked: this number is community-blacklisted.",
        }), 403

    # Soft block — high score but user hasn't acknowledged warnings yet
    if score >= 60 and not override:
        pre_tx.status = "warned"
        db.session.commit()
        return jsonify({
            "blocked":          False,
            "requires_override": True,
            "score":            score,
            "verdict":          verdict,
            "warnings":         all_warnings,
            "message":          "High fraud risk detected. Confirm you understand the risk to proceed.",
        }), 200

    # Suspicious but user overrode, or score < 60 — proceed with STK
    if score >= 60:
        pre_tx.status = "override"
    db.session.commit()

    stk_response = stk_push(phone, amount)

    if "error" in stk_response:
        pre_tx.status = "failed"
        db.session.commit()
        return jsonify({"error": stk_response["error"]}), 502

    pre_tx.status    = "pending"
    pre_tx.reference = stk_response.get("CheckoutRequestID")
    db.session.commit()

    mpesa_record = MPesaUpload(
        user_id=current_user_id,
        filename=f"STK_PENDING_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json",
        amount=amount,
    )
    db.session.add(mpesa_record)
    db.session.commit()

    return jsonify({
        "blocked":       False,
        "score":         score,
        "verdict":       verdict,
        "warnings":      all_warnings,
        "reputation":    reputation,
        "stk_response":  stk_response,
        "transaction_id": pre_tx.id,
    }), 200


# ------------------------------------------------------------------ #
#  REPORT — user confirms a completed transaction was fraudulent
# ------------------------------------------------------------------ #
@mpesa_bp.route("/report", methods=["POST"])
@jwt_required()
def report_fraud():
    """
    POST /mpesa/report
    Body: { "phone": "0712345678", "message": "they told me to send money" }

    Adds phone to community reports. After BLACKLIST_THRESHOLD reports
    from different users, the number is auto-blacklisted.
    """
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}

    phone   = data.get("phone", "").strip()
    message = data.get("message", "User reported this number as fraudulent")

    if not phone:
        return jsonify({"error": "phone is required"}), 400

    add_to_community_reports(phone, message, user_id=current_user_id)

    # Check if this pushed it over the blacklist threshold
    reputation = get_recipient_reputation(phone)

    return jsonify({
        "message":       "Report submitted. Thank you for protecting the community.",
        "is_blacklisted": reputation["is_blacklisted"],
        "total_reports":  reputation["scam_report_count"],
    }), 201


# ------------------------------------------------------------------ #
#  CALLBACK — Daraja webhook
# ------------------------------------------------------------------ #
@mpesa_bp.route("/callback", methods=["POST"])
def mpesa_callback():
    payload = request.get_json() or {}

    os.makedirs("uploads/mpesa", exist_ok=True)
    filename = f"STK_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    filepath = os.path.join("uploads/mpesa", filename)
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)

    stk         = payload.get("Body", {}).get("stkCallback", {}) if isinstance(payload, dict) else {}
    checkout_id = stk.get("CheckoutRequestID")
    result_code = stk.get("ResultCode")
    result_desc = stk.get("ResultDesc")
    amount = receipt = phone = None

    for item in stk.get("CallbackMetadata", {}).get("Item", []):
        name  = item.get("Name")
        value = item.get("Value")
        if name == "Amount":           amount  = value
        elif name == "MpesaReceiptNumber": receipt = value
        elif name == "PhoneNumber":    phone   = str(value)

    mpesa_record = MPesaUpload(
        filename=filename,
        result_code=result_code,
        result_desc=result_desc,
        amount=amount,
        receipt=receipt,
    )
    db.session.add(mpesa_record)

    pending_tx = None
    if checkout_id:
        pending_tx = Transaction.query.filter_by(reference=checkout_id).first()

    if result_code == 0 and receipt:
        if pending_tx:
            pending_tx.status    = "completed"
            pending_tx.reference = receipt
            db.session.commit()
            assess_transaction(pending_tx)
        else:
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
    return jsonify({"message": "Callback received"}), 200
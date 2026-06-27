"""
src/routes/upload_bp.py

Screenshot upload endpoint.
Flow: upload → OCR (Claude Vision) → fraud_engine → return verdict
"""

import os
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

from src.models.models import ScamReport, Transaction, db
from src.services.ocr import extract_text_from_screenshot
from src.services.fraud_engine import assess_transaction, assess_message

upload_bp = Blueprint("upload_bp", __name__, url_prefix="/upload")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}


def _allowed_file(filename: str) -> bool:
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------- Upload & Analyse Screenshot ----------
@upload_bp.route("/screenshot", methods=["POST"])
@jwt_required()
def upload_screenshot():
    """
    POST /upload/screenshot
    Form-data: file=<image>

    Flow:
    1. Save image to UPLOAD_FOLDER
    2. Run Claude Vision OCR → extract text, phone, amount
    3. Run fraud engine on extracted data
    4. Return verdict

    Response:
    {
        "filename":   "abc.png",
        "ocr": {
            "raw_text": "...",
            "phone":    "0712345678",
            "amount":   500.0,
            "message":  "please reverse...",
            "is_mpesa": true
        },
        "fraud": {
            "score":   65,
            "verdict": "fraud",
            "reasons": [...]
        }
    }
    """
    current_user_id = get_jwt_identity()

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not _allowed_file(file.filename):
        return jsonify({"error": f"Unsupported file type. Allowed: {ALLOWED_EXTENSIONS}"}), 400

    # Save to disk
    filename = secure_filename(file.filename)
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    # --- OCR via Claude Vision ---
    ocr_result = extract_text_from_screenshot(filepath)

    if ocr_result.get("error"):
        return jsonify({
            "filename": filename,
            "error": f"OCR failed: {ocr_result['error']}",
        }), 500

    # --- Fraud assessment ---
    fraud_result = {}

    phone  = ocr_result.get("phone")
    amount = ocr_result.get("amount")
    message = ocr_result.get("message", "")

    if phone and amount:
        # Full transaction-based assessment
        tx = Transaction(
            user_id=current_user_id,
            phone_number=phone,
            amount=float(amount),
            status="screenshot",
        )
        db.session.add(tx)
        db.session.commit()

        score, reasons = assess_transaction(tx, message=message)
        verdict = "fraud" if score >= 60 else "suspicious" if score >= 30 else "safe"
        fraud_result = {"score": score, "verdict": verdict, "reasons": reasons}

    elif message:
        # Message-only assessment (no phone/amount extracted)
        fraud_result = assess_message(message, user_id=current_user_id)

    else:
        fraud_result = {"score": 0, "verdict": "safe", "reasons": []}

    # Save screenshot reference to ScamReport
    report = ScamReport(
        message=ocr_result.get("raw_text", "")[:500],
        suspicious=(fraud_result.get("verdict") != "safe"),
        screenshot=filename,
        user_id=current_user_id,
    )
    db.session.add(report)
    db.session.commit()

    return jsonify({
        "filename": filename,
        "ocr": ocr_result,
        "fraud": fraud_result,
    }), 200
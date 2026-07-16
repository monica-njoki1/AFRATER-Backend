"""
src/routes/wallet.py
Wallet features: balance, transaction history, receive check, summary
"""
import requests
import base64
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models.models import Transaction, SuspiciousEvent, ScamReport, db
from src.services.recipient_reputation import get_recipient_reputation
from config import Config

wallet_bp = Blueprint("wallet_bp", __name__, url_prefix="/wallet")


def _get_daraja_token():
    from requests.auth import HTTPBasicAuth
    resp = requests.get(
        "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        auth=HTTPBasicAuth(Config.DARAJA_CONSUMER_KEY, Config.DARAJA_CONSUMER_SECRET),
        timeout=10
    )
    resp.raise_for_status()
    return resp.json().get("access_token")


def _fraud_label(events):
    severities = [e.severity for e in events]
    if "high" in severities:   return "fraud"
    if "medium" in severities: return "suspicious"
    return "safe"


def _verdict_color(verdict):
    return {"fraud": "high", "suspicious": "medium", "safe": "low"}.get(verdict, "low")


# ── Balance ──────────────────────────────────────────────────────
@wallet_bp.route("/balance", methods=["GET"])
@jwt_required()
def get_balance():
    try:
        token = _get_daraja_token()
    except Exception as e:
        return jsonify({"error": f"Could not connect to M-Pesa: {str(e)}"}), 502

    try:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        shortcode = Config.BUSINESS_SHORTCODE
        password  = base64.b64encode(
            f"{shortcode}{Config.LIPA_PASSKEY}{timestamp}".encode()
        ).decode()

        payload = {
            "Initiator":          "testapi",
            "SecurityCredential": password,
            "CommandID":          "AccountBalance",
            "PartyA":             shortcode,
            "IdentifierType":     "4",
            "Remarks":            "Balance check",
            "QueueTimeOutURL":    f"{getattr(Config, 'MPESA_CALLBACK_URL', '')}/timeout",
            "ResultURL":          f"{getattr(Config, 'MPESA_CALLBACK_URL', '')}/balance",
        }

        resp = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/accountbalance/v1/query",
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15,
        )
        return jsonify(resp.json()), 200
    except requests.exceptions.Timeout:
        return jsonify({"error": "M-Pesa request timed out."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Transaction history ──────────────────────────────────────────
@wallet_bp.route("/transactions", methods=["GET"])
@jwt_required()
def get_transactions():
    current_user_id = get_jwt_identity()
    page   = int(request.args.get("page",  1))
    limit  = int(request.args.get("limit", 20))
    filter = request.args.get("filter", "all")

    query = Transaction.query.filter_by(user_id=current_user_id)

    if filter == "fraud":
        ids = db.session.query(SuspiciousEvent.transaction_id).filter_by(severity="high").subquery()
        query = query.filter(Transaction.id.in_(ids))
    elif filter == "suspicious":
        ids = db.session.query(SuspiciousEvent.transaction_id).filter_by(severity="medium").subquery()
        query = query.filter(Transaction.id.in_(ids))
    elif filter == "safe":
        ids = db.session.query(SuspiciousEvent.transaction_id).subquery()
        query = query.filter(~Transaction.id.in_(ids))

    total = query.count()
    txs   = query.order_by(Transaction.created_at.desc())\
                 .offset((page - 1) * limit).limit(limit).all()

    result = []
    for tx in txs:
        events  = tx.events
        verdict = _fraud_label(events)
        result.append({
            "id":           tx.id,
            "phone_number": tx.phone_number,
            "amount":       tx.amount,
            "reference":    tx.reference,
            "status":       tx.status,
            "verdict":      verdict,
            "risk_level":   _verdict_color(verdict),
            "flags":        [e.reason for e in events],
            "created_at":   tx.created_at.isoformat(),
        })

    return jsonify({"transactions": result, "total": total, "page": page,
                    "pages": (total + limit - 1) // limit}), 200


# ── Single transaction ───────────────────────────────────────────
@wallet_bp.route("/transactions/<int:tx_id>", methods=["GET"])
@jwt_required()
def get_transaction(tx_id):
    current_user_id = get_jwt_identity()
    tx = Transaction.query.filter_by(id=tx_id, user_id=current_user_id).first_or_404()
    events  = tx.events
    verdict = _fraud_label(events)
    reputation = {}
    if tx.phone_number and tx.phone_number != "unknown":
        reputation = get_recipient_reputation(tx.phone_number, current_user_id)

    return jsonify({
        "id":           tx.id,
        "phone_number": tx.phone_number,
        "amount":       tx.amount,
        "reference":    tx.reference,
        "status":       tx.status,
        "verdict":      verdict,
        "risk_level":   _verdict_color(verdict),
        "flags":        [{"reason": e.reason, "severity": e.severity,
                          "at": e.created_at.isoformat()} for e in events],
        "reputation":   reputation,
        "created_at":   tx.created_at.isoformat(),
    }), 200


# ── Receive check ────────────────────────────────────────────────
@wallet_bp.route("/receive/check", methods=["POST"])
@jwt_required()
def check_incoming():
    current_user_id = get_jwt_identity()
    data  = request.get_json() or {}
    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"error": "phone is required"}), 400

    reputation = get_recipient_reputation(phone, current_user_id)
    advice = []
    if reputation["is_blacklisted"]:
        advice.append("⛔ Do NOT accept — this number is community-blacklisted.")
        advice.append("This is likely a mule scam where you would forward stolen money.")
    elif reputation["scam_report_count"] > 0:
        advice.append("⚠️ Be cautious — this number has been reported before.")
        advice.append("Never accept money from strangers and forward it elsewhere.")
    elif reputation["first_time"]:
        advice.append("👤 You have never interacted with this number before.")
        advice.append("Be careful if they ask you to receive and forward money.")
    else:
        advice.append("✅ This number looks familiar from your history.")

    return jsonify({
        "phone":      phone,
        "reputation": reputation,
        "advice":     advice,
        "safe":       not reputation["is_blacklisted"] and reputation["scam_report_count"] == 0,
    }), 200


# ── Summary ──────────────────────────────────────────────────────
@wallet_bp.route("/summary", methods=["GET"])
@jwt_required()
def get_summary():
    current_user_id = get_jwt_identity()
    since = datetime.utcnow() - timedelta(days=30)
    txs   = Transaction.query.filter(
        Transaction.user_id == current_user_id,
        Transaction.created_at >= since,
        Transaction.status == "completed",
    ).all()

    total_sent    = sum(tx.amount or 0 for tx in txs)
    total_count   = len(txs)
    flagged_count = sum(1 for tx in txs if tx.events)
    blocked_count = Transaction.query.filter_by(user_id=current_user_id, status="blocked").count()
    scam_reports  = ScamReport.query.filter_by(user_id=current_user_id, suspicious=True).count()

    security_score = 100
    if flagged_count > 0: security_score -= min(flagged_count * 10, 40)
    if scam_reports > 0:  security_score -= min(scam_reports * 5, 20)
    security_score = max(security_score, 0)

    return jsonify({
        "period":         "last_30_days",
        "total_sent":     total_sent,
        "total_count":    total_count,
        "flagged_count":  flagged_count,
        "blocked_count":  blocked_count,
        "scam_reports":   scam_reports,
        "security_score": security_score,
        "security_label": "excellent" if security_score >= 80 else "good" if security_score >= 60 else "at risk",
    }), 200
# Add this route to src/routes/wallet.py

@wallet_bp.route("/transactions/clear", methods=["DELETE"])
@jwt_required()
def clear_transactions():
    """
    DELETE /wallet/transactions/clear
    Clears all transaction history and suspicious events for current user.
    """
    current_user_id = get_jwt_identity()

    # Delete suspicious events first (foreign key constraint)
    txs = Transaction.query.filter_by(user_id=current_user_id).all()
    for tx in txs:
        SuspiciousEvent.query.filter_by(transaction_id=tx.id).delete()

    # Delete all transactions
    Transaction.query.filter_by(user_id=current_user_id).delete()

    # Delete scam reports
    ScamReport.query.filter_by(user_id=current_user_id).delete()

    db.session.commit()

    return jsonify({"message": "History cleared successfully"}), 200
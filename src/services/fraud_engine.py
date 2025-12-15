from src.models.models import SuspiciousEvent, Transaction, AuditLog
from src.extensions import db
from datetime import datetime, timedelta

BLACKLISTED_PHONES = ['+254700000000']

def assess_transaction(tx: Transaction, commit=True):
    score = 0.0
    reasons = []

    if tx.amount >= 100000:
        score += 0.6
        reasons.append("very_large_amount")
    elif tx.amount >= 20000:
        score += 0.3
        reasons.append("large_amount")

    if tx.phone in BLACKLISTED_PHONES:
        score += 0.9
        reasons.append("blacklisted_phone")

    one_min = datetime.utcnow() - timedelta(minutes=1)
    recent = Transaction.query.filter(Transaction.phone == tx.phone, Transaction.timestamp >= one_min).count()
    if recent > 3:
        score += 0.5
        reasons.append("rapid_transactions")

    score = min(score, 1.0)

    if score >= 0.25 and commit:
        ev = SuspiciousEvent(transaction_id=tx.id, reason=",".join(reasons) or "rule_match", score=score)
        db.session.add(ev)
        audit = AuditLog(user_id=None, action="suspicious_event", detail={"tx_id": tx.trans_id, "reasons": reasons, "score": score})
        db.session.add(audit)
        db.session.commit()

    return score, reasons

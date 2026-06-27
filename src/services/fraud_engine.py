from datetime import datetime, timedelta
from src import db
from src.models.models import Transaction, SuspiciousEvent, ScamReport, FraudContact


# ------------------------------------------------------------------ #
#  KEYWORD PATTERNS
#  Words/phrases commonly used in M-Pesa social-engineering scams
# ------------------------------------------------------------------ #
SCAM_KEYWORDS = [
    # PIN / code fishing
    "enter pin", "enter your pin", "send pin", "share pin",
    "enter code", "send code", "verification code",

    # Reversal scams (most common in Kenya)
    "reverse", "refund", "sent by mistake", "wrong number",
    "wrong account", "please send back", "kindly send back",

    # Impersonation
    "safaricom agent", "safaricom official", "mpesa agent",
    "customer care", "technical team", "system upgrade",

    # Urgency / pressure
    "urgent", "immediately", "account suspended", "blocked",
    "your account will be", "failure to", "24 hours",

    # Prize / lottery
    "you have won", "congratulations", "claim your",
    "lucky winner", "promotion",
]

# Amounts that are classic scam bait (too round, too small, too large)
SUSPICIOUS_AMOUNTS = {1, 10, 100, 999, 1000, 9999, 99999, 999999}

# Hours considered off-hours (midnight to 5 AM)
OFF_HOURS = range(0, 5)

# How many transactions from the same phone in 10 minutes = suspicious
REPEAT_THRESHOLD = 3
REPEAT_WINDOW_MINUTES = 10


# ------------------------------------------------------------------ #
#  SCORING WEIGHTS
#  Each check adds to a 0–100 score
# ------------------------------------------------------------------ #
WEIGHTS = {
    "keyword_match":      40,   # message contains scam keywords
    "known_scam_number":  35,   # phone already reported
    "suspicious_amount":  10,   # amount is a known bait value
    "off_hours":          10,   # transaction at odd hours
    "repeat_attempts":    25,   # same phone, multiple transactions recently
}


def _verdict(score: int) -> str:
    if score >= 60:
        return "fraud"
    if score >= 30:
        return "suspicious"
    return "safe"


# ------------------------------------------------------------------ #
#  CHECK 1 — Keyword scan
# ------------------------------------------------------------------ #
def check_keywords(message: str) -> tuple:
    """Return (score_added, matched_keywords)."""
    if not message:
        return 0, []

    message_lower = message.lower()
    matched = [kw for kw in SCAM_KEYWORDS if kw in message_lower]

    if not matched:
        return 0, []

    # Scale: 1 match = half weight, 2+ = full weight
    score = WEIGHTS["keyword_match"] if len(matched) >= 2 else WEIGHTS["keyword_match"] // 2
    return score, matched


# ------------------------------------------------------------------ #
#  CHECK 2 — Known scam number
# ------------------------------------------------------------------ #
def check_known_scam_number(phone: str) -> tuple:
    """Check if this phone has been reported in past ScamReports."""
    if not phone:
        return 0, []

    # Look for the phone in existing scam reports (stored in message for now)
    # A richer version would have a dedicated PhoneBlacklist model
    report_count = ScamReport.query.filter(
        ScamReport.message.contains(phone),
        ScamReport.suspicious == True
    ).count()

    if report_count > 0:
        return WEIGHTS["known_scam_number"], [f"Phone {phone} appears in {report_count} scam report(s)"]
    return 0, []


# ------------------------------------------------------------------ #
#  CHECK 3 — Suspicious amount
# ------------------------------------------------------------------ #
def check_amount(amount: float) -> tuple:
    if amount is None:
        return 0, []

    if amount in SUSPICIOUS_AMOUNTS:
        return WEIGHTS["suspicious_amount"], [f"Amount KES {amount} is a known scam bait value"]
    return 0, []


# ------------------------------------------------------------------ #
#  CHECK 4 — Off-hours transaction
# ------------------------------------------------------------------ #
def check_off_hours(timestamp: datetime = None) -> tuple:
    now = timestamp or datetime.utcnow()
    # Kenya is UTC+3
    kenya_hour = (now.hour + 3) % 24

    if kenya_hour in OFF_HOURS:
        return WEIGHTS["off_hours"], [f"Transaction initiated at {kenya_hour:02d}:00 EAT (off-hours)"]
    return 0, []


# ------------------------------------------------------------------ #
#  CHECK 5 — Repeat attempts from same phone
# ------------------------------------------------------------------ #
def check_repeat_attempts(phone: str) -> tuple:
    if not phone:
        return 0, []

    window_start = datetime.utcnow() - timedelta(minutes=REPEAT_WINDOW_MINUTES)
    count = Transaction.query.filter(
        Transaction.phone_number == phone,
        Transaction.created_at >= window_start
    ).count()

    if count >= REPEAT_THRESHOLD:
        return WEIGHTS["repeat_attempts"], [
            f"Phone {phone} has {count} transactions in the last {REPEAT_WINDOW_MINUTES} minutes"
        ]
    return 0, []


# ------------------------------------------------------------------ #
#  MAIN ENTRY POINT
# ------------------------------------------------------------------ #
def assess_transaction(tx: Transaction, message: str = None) -> tuple:
    """
    Run all fraud checks against a Transaction.

    Args:
        tx:      A Transaction model instance (already saved to DB).
        message: Optional scam message text to also keyword-scan.

    Returns:
        (score, reasons) — score is 0–100, reasons is a list of strings.
    """
    total_score = 0
    all_reasons = []

    # Run each check
    checks = [
        check_keywords(message or ""),
        check_known_scam_number(tx.phone_number),
        check_amount(tx.amount),
        check_off_hours(tx.created_at),
        check_repeat_attempts(tx.phone_number),
    ]

    for score_added, reasons in checks:
        total_score += score_added
        all_reasons.extend(reasons)

    # Cap at 100
    total_score = min(total_score, 100)
    verdict = _verdict(total_score)

    # Persist a SuspiciousEvent if anything was flagged
    if all_reasons:
        severity = "high" if verdict == "fraud" else "medium" if verdict == "suspicious" else "low"
        event = SuspiciousEvent(
            user_id=tx.user_id,
            transaction_id=tx.id,
            reason=" | ".join(all_reasons),
            severity=severity,
        )
        db.session.add(event)
        db.session.commit()

    return total_score, all_reasons


# ------------------------------------------------------------------ #
#  STANDALONE MESSAGE CHECK (no transaction needed)
#  Used by scam_bp when user just submits a suspicious message
# ------------------------------------------------------------------ #
def assess_message(message: str, user_id: int = None) -> dict:
    """
    Assess a raw message string for fraud indicators.
    Does not require a Transaction object.

    Returns a dict: { score, verdict, reasons }
    """
    score, reasons = check_keywords(message)
    score = min(score, 100)
    verdict = _verdict(score)

    # Save as a ScamReport
    report = ScamReport(
        message=message,
        suspicious=(verdict != "safe"),
        user_id=user_id,
    )
    db.session.add(report)
    db.session.commit()

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }
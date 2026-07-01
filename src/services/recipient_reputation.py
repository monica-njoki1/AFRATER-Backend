"""
src/services/recipient_reputation.py

Builds a reputation score for any phone number based on:
- How many scam reports mention it
- Whether the current user has sent to it before
- How many total users have flagged it
- Community blacklist threshold
"""

import re
from src.models.models import ScamReport, Transaction, db


# Number of unique users reporting same phone before auto-blacklist
BLACKLIST_THRESHOLD = 3


def _normalise(phone: str) -> str:
    """Strip formatting so 0712345678 == +254712345678 == 254712345678."""
    phone = re.sub(r"[\s\-()]", "", phone)
    if phone.startswith("+"):
        phone = phone[1:]
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    return phone


def get_recipient_reputation(phone: str, current_user_id: int = None) -> dict:
    """
    Return a full reputation profile for a phone number.

    Returns:
    {
        "phone":              "254712345678",
        "scam_report_count":  3,
        "unique_reporters":   2,
        "is_blacklisted":     True,
        "first_time":         True,   # current user has never sent to this number
        "risk_level":         "high", # "low" | "medium" | "high"
        "warnings":           ["This number has been reported by 2 users", ...]
    }
    """
    normalised = _normalise(phone)
    warnings = []

    # ── 1. Scam reports mentioning this number ──────────────────────
    # Match both 07xx and 254xx formats
    short = normalised[3:] if normalised.startswith("254") else normalised
    local  = "0" + short
    intl   = "254" + short

    reports = ScamReport.query.filter(
        ScamReport.suspicious == True
    ).all()

    matching_reports = [
        r for r in reports
        if local in (r.message or "") or intl in (r.message or "") or normalised in (r.message or "")
    ]

    scam_report_count = len(matching_reports)
    unique_reporters  = len(set(r.user_id for r in matching_reports if r.user_id))
    is_blacklisted    = unique_reporters >= BLACKLIST_THRESHOLD

    if is_blacklisted:
        warnings.append(f"⛔ This number is community-blacklisted — reported by {unique_reporters} different users")
    elif scam_report_count > 0:
        warnings.append(f"⚠️ This number appears in {scam_report_count} scam report(s)")

    # ── 2. First-time recipient check ───────────────────────────────
    first_time = True
    if current_user_id:
        prev = Transaction.query.filter(
            Transaction.user_id == current_user_id,
            Transaction.status.in_(["completed", "manual"]),
        ).all()

        known_numbers = set()
        for tx in prev:
            if tx.phone_number:
                known_numbers.add(_normalise(tx.phone_number))

        first_time = normalised not in known_numbers

        if first_time:
            warnings.append("👤 You have never sent money to this number before")

    # ── 3. Risk level ───────────────────────────────────────────────
    if is_blacklisted:
        risk_level = "high"
    elif scam_report_count > 0 or first_time:
        risk_level = "medium" if scam_report_count > 0 else "low"
    else:
        risk_level = "low"

    # Upgrade to high if both first-time AND reported
    if first_time and scam_report_count > 0:
        risk_level = "high"

    return {
        "phone":             phone,
        "normalised":        normalised,
        "scam_report_count": scam_report_count,
        "unique_reporters":  unique_reporters,
        "is_blacklisted":    is_blacklisted,
        "first_time":        first_time,
        "risk_level":        risk_level,
        "warnings":          warnings,
    }


def add_to_community_reports(phone: str, message: str, user_id: int = None):
    """
    Helper to quickly add a phone number to scam reports
    (called when user confirms a transaction was fraudulent).
    """
    report = ScamReport(
        message=f"Reported phone: {phone}. {message}",
        suspicious=True,
        user_id=user_id,
    )
    db.session.add(report)
    db.session.commit()
    return report
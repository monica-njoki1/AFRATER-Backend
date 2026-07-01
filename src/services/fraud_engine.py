"""
src/services/fraud_engine.py

Upgraded fraud engine:
1. English + Swahili keyword matching
2. Regex pattern detection (PIN, account numbers, phone sharing)
3. Claude API fallback for edge cases that score < 30
"""

import re
from datetime import datetime, timedelta
from src import db
from src.models.models import Transaction, SuspiciousEvent, ScamReport


# ------------------------------------------------------------------ #
#  ENGLISH SCAM KEYWORDS
# ------------------------------------------------------------------ #
ENGLISH_KEYWORDS = [
    # Reversal scams
    "reverse", "refund", "sent by mistake", "wrong number", "wrong account",
    "please send back", "kindly send back", "send it back", "return the money",
    "transfer back", "resend",

    # PIN / code fishing
    "enter pin", "enter your pin", "send pin", "share pin", "give me your pin",
    "enter code", "send code", "verification code", "confirm your pin",
    "your pin is", "secret pin", "pin number",

    # Impersonation
    "safaricom agent", "safaricom official", "mpesa agent", "mpesa support",
    "customer care", "technical team", "system upgrade", "safaricom team",
    "i am from safaricom", "calling from safaricom",

    # Urgency / pressure
    "urgent", "immediately", "account suspended", "account blocked",
    "your account will be", "failure to", "24 hours", "respond now",
    "act now", "limited time", "expires today",

    # Prize / lottery
    "you have won", "congratulations you", "claim your prize",
    "lucky winner", "promotion winner", "you are selected",

    # Credential sharing (red flag when sender volunteers these)
    "my pin is", "my password is", "my account number is",
    "secret code", "access code",

    # Mule / delivery scams
    "receive on my behalf", "pick up for me", "collect for me",
    "send me the name", "send me details", "sms me the number",
]

# ------------------------------------------------------------------ #
#  SWAHILI SCAM KEYWORDS
# ------------------------------------------------------------------ #
SWAHILI_KEYWORDS = [
    # Reversal / wrong number
    "nimekosea nambari",       # I sent to wrong number
    "nimetuma kwa makosa",     # I sent by mistake
    "nirudishie",              # send it back to me
    "rudisha pesa",            # return the money
    "nirudishie pesa",         # return my money
    "ilitumwa kwa makosa",     # it was sent by mistake
    "nambari mbaya",           # wrong number
    "tuma tena",               # send again

    # Secrets / credentials
    "siri zangu",              # my secrets
    "nambari ya siri",         # secret number
    "pin yangu",               # my PIN
    "neno la siri",            # password/secret word
    "msimbo wa siri",          # secret code

    # Delete / cover tracks
    "ufute",                   # delete it
    "futa ujumbe",             # delete the message
    "usimwambie mtu",          # don't tell anyone
    "siri yetu",               # our secret
    "usishirikishe",           # don't share

    # Urgency
    "haraka",                  # quickly/urgently
    "sasa hivi",               # right now
    "bila kuchelewa",          # without delay
    "ni muhimu sana",          # very important

    # Mule / receiving on behalf
    "pokea kwa niaba yangu",   # receive on my behalf
    "niandikie majina",        # write me the names
    "nambari utakayopokea",    # number you will receive
    "soda nayo",               # (goods) with it — mule scam
    "naelekea",                # I am heading to (creates urgency)
    "nitashukuru",             # I will be grateful (social pressure)
    "tuma jina lako",          # send your name
    "tuma nambari yako",       # send your number

    # Impersonation
    "afisa wa safaricom",      # Safaricom officer
    "timu ya safaricom",       # Safaricom team
    "kutoka safaricom",        # from Safaricom
]

# ------------------------------------------------------------------ #
#  REGEX PATTERNS — catch what keywords miss
# ------------------------------------------------------------------ #

# PIN patterns: {5529}, [5529], PIN: 5529, pin=5529
PIN_PATTERN = re.compile(
    r'(?:pin|password|passcode|siri|msimbo)\s*[=:{\[]?\s*\d{4,6}|'  # labeled PIN
    r'\{?\b\d{4,6}\b\}?(?=\s*(?:pin|clear|code|siri))',              # number near PIN word
    re.IGNORECASE
)

# Exposed PIN in braces/brackets — e.g. {5529}, [5529]
BRACKETED_NUMBER = re.compile(r'[\[{]\s*\d{4,6}\s*[\]}]')

# Bank account numbers — 8-14 digit sequences
ACCOUNT_NUMBER_PATTERN = re.compile(
    r'\b(?:acc(?:ount)?\s*(?:no|number|#)?[\s:.]?\s*|account\s*)(\d{8,14})\b',
    re.IGNORECASE
)

# Phone number shared in message (Kenyan formats)
PHONE_PATTERN = re.compile(
    r'(?:call|sms|text|whatsapp|wasiliana|piga|namba|number|nambari)[\s:/]*'
    r'(?:\+?254|0)[17]\d{8}',
    re.IGNORECASE
)

# Large amount mentioned (over 100,000 KES — bait)
LARGE_AMOUNT_PATTERN = re.compile(
    r'\b\d[\d,]*(?:\.\d+)?(?:\s*(?:million|M|bob|KES|ksh|shilling))?\b',
    re.IGNORECASE
)

# ------------------------------------------------------------------ #
#  SCORING WEIGHTS
# ------------------------------------------------------------------ #
WEIGHTS = {
    "english_keyword":      40,
    "swahili_keyword":      40,
    "pin_exposed":          45,   # highest — sharing a PIN is almost always fraud
    "account_exposed":      35,
    "phone_shared":         20,
    "large_amount_bait":    15,
    "known_scam_number":    35,
    "suspicious_amount":    10,
    "off_hours":            10,
    "repeat_attempts":      25,
}

SUSPICIOUS_AMOUNTS = {1, 10, 100, 999, 1000, 9999, 99999, 999999}
OFF_HOURS = range(0, 5)
REPEAT_THRESHOLD = 3
REPEAT_WINDOW_MINUTES = 10


def _verdict(score):
    if score >= 60:
        return "fraud"
    if score >= 30:
        return "suspicious"
    return "safe"


# ------------------------------------------------------------------ #
#  MESSAGE CHECKS
# ------------------------------------------------------------------ #

def check_english_keywords(message):
    if not message:
        return 0, []
    msg = message.lower()
    matched = [kw for kw in ENGLISH_KEYWORDS if kw in msg]
    if not matched:
        return 0, []
    score = WEIGHTS["english_keyword"] if len(matched) >= 2 else WEIGHTS["english_keyword"] // 2
    return score, [f"English scam phrase detected: '{matched[0]}'" + (f" (+{len(matched)-1} more)" if len(matched) > 1 else "")]


def check_swahili_keywords(message):
    if not message:
        return 0, []
    msg = message.lower()
    matched = [kw for kw in SWAHILI_KEYWORDS if kw in msg]
    if not matched:
        return 0, []
    score = WEIGHTS["swahili_keyword"] if len(matched) >= 2 else WEIGHTS["swahili_keyword"] // 2
    return score, [f"Swahili scam phrase detected: '{matched[0]}'" + (f" (+{len(matched)-1} more)" if len(matched) > 1 else "")]


def check_pin_exposed(message):
    if not message:
        return 0, []
    if PIN_PATTERN.search(message) or BRACKETED_NUMBER.search(message):
        return WEIGHTS["pin_exposed"], ["PIN or secret code exposed in message — no legitimate person shares their PIN"]
    return 0, []


def check_account_exposed(message):
    if not message:
        return 0, []
    if ACCOUNT_NUMBER_PATTERN.search(message):
        return WEIGHTS["account_exposed"], ["Bank account number exposed — classic social engineering tactic"]
    return 0, []


def check_phone_shared(message):
    if not message:
        return 0, []
    if PHONE_PATTERN.search(message):
        return WEIGHTS["phone_shared"], ["Phone number shared with call/SMS instruction — redirection scam pattern"]
    return 0, []


def check_large_amount(message):
    if not message:
        return 0, []
    amounts = LARGE_AMOUNT_PATTERN.findall(message)
    # Look for amounts with M/million suffix specifically
    if re.search(r'\d+\.?\d*\s*[Mm]\b', message):
        return WEIGHTS["large_amount_bait"], ["Large amount mentioned (millions) — common bait in reversal scams"]
    return 0, []


# ------------------------------------------------------------------ #
#  TRANSACTION CHECKS
# ------------------------------------------------------------------ #

def check_known_scam_number(phone):
    if not phone:
        return 0, []
    count = ScamReport.query.filter(
        ScamReport.message.contains(phone),
        ScamReport.suspicious == True
    ).count()
    if count > 0:
        return WEIGHTS["known_scam_number"], [f"Phone {phone} appears in {count} previous scam report(s)"]
    return 0, []


def check_amount(amount):
    if amount is None:
        return 0, []
    if amount in SUSPICIOUS_AMOUNTS:
        return WEIGHTS["suspicious_amount"], [f"Amount KES {amount} is a known scam bait value"]
    return 0, []


def check_off_hours(timestamp=None):
    now = timestamp or datetime.utcnow()
    kenya_hour = (now.hour + 3) % 24
    if kenya_hour in OFF_HOURS:
        return WEIGHTS["off_hours"], [f"Transaction at {kenya_hour:02d}:00 EAT (off-hours — midnight to 5AM)"]
    return 0, []


def check_repeat_attempts(phone):
    if not phone:
        return 0, []
    window_start = datetime.utcnow() - timedelta(minutes=REPEAT_WINDOW_MINUTES)
    count = Transaction.query.filter(
        Transaction.phone_number == phone,
        Transaction.created_at >= window_start
    ).count()
    if count >= REPEAT_THRESHOLD:
        return WEIGHTS["repeat_attempts"], [f"{count} transactions from {phone} in {REPEAT_WINDOW_MINUTES} minutes"]
    return 0, []


# ------------------------------------------------------------------ #
#  CLAUDE API FALLBACK
#  Only called when keyword engine scores < 30 (edge cases)
# ------------------------------------------------------------------ #

def _claude_analyse(message):
    """
    Call Claude API to analyse a message that scored low on keywords.
    Returns (score_boost, reasons).
    Only triggers on edge cases to keep costs minimal.
    """
    try:
        import anthropic
        import json
        import os

        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

        prompt = f"""You are an M-Pesa fraud detection expert in Kenya. Analyse this message for fraud indicators.

Message: "{message}"

Consider:
- Social engineering tactics (guilt, urgency, sympathy)
- Swahili or English manipulation phrases
- Requests to share credentials, delete messages, or receive goods on behalf of someone
- Impersonation of Safaricom, banks, or officials
- Reversal/refund scams
- Mule recruitment (receiving money or goods on behalf of strangers)

Respond ONLY in this exact JSON format, no extra text:
{{
  "is_scam": true/false,
  "confidence": 0-100,
  "reasons": ["reason 1", "reason 2"],
  "verdict": "fraud/suspicious/safe"
}}"""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw.strip())

        if result.get("is_scam"):
            confidence = result.get("confidence", 50)
            score_boost = min(int(confidence * 0.7), 65)
            reasons = result.get("reasons", ["AI detected suspicious patterns"])
            reasons = [f"[AI] {r}" for r in reasons]
            return score_boost, reasons

        return 0, []

    except Exception as e:
        # Never crash the engine — silently fail
        return 0, []


# ------------------------------------------------------------------ #
#  MAIN ENTRY POINTS
# ------------------------------------------------------------------ #

def assess_message(message, user_id=None):
    """
    Assess a raw message string for fraud.
    Used by scam_bp when user submits a message directly.
    """
    total_score = 0
    all_reasons = []

    # Run all message checks
    checks = [
        check_english_keywords(message),
        check_swahili_keywords(message),
        check_pin_exposed(message),
        check_account_exposed(message),
        check_phone_shared(message),
        check_large_amount(message),
    ]

    for score_added, reasons in checks:
        total_score += score_added
        all_reasons.extend(reasons)

    # Claude API fallback — only if keywords missed it
    if total_score < 30:
        boost, ai_reasons = _claude_analyse(message)
        total_score += boost
        all_reasons.extend(ai_reasons)

    total_score = min(total_score, 100)
    verdict = _verdict(total_score)

    # Save as ScamReport
    report = ScamReport(
        message=message,
        suspicious=(verdict != "safe"),
        user_id=user_id,
    )
    db.session.add(report)
    db.session.commit()

    return {
        "score":   total_score,
        "verdict": verdict,
        "reasons": all_reasons,
    }


def assess_transaction(tx, message=None):
    """
    Assess a Transaction object for fraud.
    Used by mpesa_bp (STK push) and tx_bp (manual ingest).
    """
    total_score = 0
    all_reasons = []

    checks = [
        check_english_keywords(message or ""),
        check_swahili_keywords(message or ""),
        check_pin_exposed(message or ""),
        check_account_exposed(message or ""),
        check_phone_shared(message or ""),
        check_known_scam_number(tx.phone_number),
        check_amount(tx.amount),
        check_off_hours(tx.created_at),
        check_repeat_attempts(tx.phone_number),
    ]

    for score_added, reasons in checks:
        total_score += score_added
        all_reasons.extend(reasons)

    # Claude fallback for edge cases
    if total_score < 30 and message:
        boost, ai_reasons = _claude_analyse(message)
        total_score += boost
        all_reasons.extend(ai_reasons)

    total_score = min(total_score, 100)
    verdict = _verdict(total_score)

    # Persist SuspiciousEvent if flagged
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
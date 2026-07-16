"""
src/utils/phone_validator.py

Validates Kenyan phone numbers before sending to Daraja.
Accepts: 07XXXXXXXX, 01XXXXXXXX, +2547XXXXXXXX, 2547XXXXXXXX
Rejects: fake numbers, wrong length, non-Kenyan prefixes
"""

import re

# Valid Kenyan mobile prefixes (after country code 254)
# Safaricom: 07xx, 01xx
# All valid second digits after 07: 0-9
# All valid second digits after 01: 0,1
VALID_KENYAN_PREFIXES = [
    # Safaricom
    "700", "701", "702", "703", "704", "705", "706", "707", "708", "709",
    "710", "711", "712", "713", "714", "715", "716", "717", "718", "719",
    "720", "721", "722", "723", "724", "725", "726", "727", "728", "729",
    "740", "741", "742", "743", "744", "745", "746", "747", "748", "749",
    "757", "758", "759",
    "768", "769",
    "790", "791", "792", "793", "794", "795", "796", "797", "798", "799",
    # Airtel
    "730", "731", "732", "733", "734", "735", "736", "737", "738", "739",
    "750", "751", "752", "753", "754", "755", "756",
    "762",
    # Telkom
    "770", "771", "772", "773", "774", "775", "776", "777", "778", "779",
    # Faiba / other
    "747",
    # 011x Safaricom
    "110", "111", "112", "113", "114", "115", "116", "117", "118", "119",
]


def normalise_phone(phone: str) -> str:
    """
    Normalise any Kenyan phone format to 2547XXXXXXXX.
    Returns normalised string or raises ValueError.
    """
    if not phone:
        raise ValueError("Phone number is required")

    # Strip all spaces, dashes, parentheses
    phone = re.sub(r"[\s\-().+]", "", phone.strip())

    # Remove leading zeros beyond one
    if phone.startswith("00254"):
        phone = phone[2:]   # 00254... -> 254...

    if phone.startswith("+254"):
        phone = phone[1:]   # +254... -> 254...

    if phone.startswith("254"):
        pass                # already in international format

    elif phone.startswith("0"):
        phone = "254" + phone[1:]  # 07... -> 2547...

    elif phone.startswith("7") or phone.startswith("1"):
        phone = "254" + phone      # 7... -> 2547...

    else:
        raise ValueError(f"Unrecognised phone format: {phone}")

    return phone


def validate_kenyan_phone(phone: str) -> tuple:
    """
    Validate a Kenyan phone number.

    Returns:
        (is_valid: bool, normalised: str, error: str)
    """
    try:
        normalised = normalise_phone(phone)
    except ValueError as e:
        return False, "", str(e)

    # Must be exactly 12 digits: 254 + 9 digits
    if not re.match(r"^254\d{9}$", normalised):
        return False, normalised, f"Phone number must be 12 digits (e.g. 2547XXXXXXXX), got: {normalised}"

    # Check prefix — digits 4-6 (after 254)
    prefix = normalised[3:6]  # e.g. "712" from "254712345678"

    if prefix not in VALID_KENYAN_PREFIXES:
        return False, normalised, f"'{phone}' doesn't look like a valid Kenyan mobile number. Check the prefix."

    return True, normalised, ""
import requests
import base64
from datetime import datetime
from requests.auth import HTTPBasicAuth
from config import Config
from src.utils.phone_validator import validate_kenyan_phone

OAUTH_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
STK_URL   = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
QUERY_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query"

import time
_token_cache = {"token": None, "expires_at": 0}


def get_access_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]

    resp = requests.get(
        OAUTH_URL,
        auth=HTTPBasicAuth(Config.DARAJA_CONSUMER_KEY, Config.DARAJA_CONSUMER_SECRET),
        timeout=10
    )
    resp.raise_for_status()
    data       = resp.json()
    token      = data.get("access_token")
    expires_in = int(data.get("expires_in", 3600))

    _token_cache["token"]      = token
    _token_cache["expires_at"] = now + expires_in - 60

    return token


def stk_push(phone: str, amount: float) -> dict:
    # ── Validate phone first ──────────────────────────────────────
    is_valid, normalised, error = validate_kenyan_phone(phone)
    if not is_valid:
        return {"error": f"Invalid phone number: {error}"}

    # ── Validate amount ───────────────────────────────────────────
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return {"error": "Amount must be a number"}

    if amount < 1:
        return {"error": "Minimum amount is KES 1"}

    if amount > 150000:
        return {"error": "Maximum amount per transaction is KES 150,000"}

    if not amount.is_integer() and round(amount, 2) != amount:
        return {"error": "Amount must be a valid number (e.g. 100 or 100.50)"}

    # ── Get token ─────────────────────────────────────────────────
    try:
        token = get_access_token()
    except Exception as e:
        return {"error": f"Failed to get access token: {str(e)}"}

    shortcode = Config.BUSINESS_SHORTCODE
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password  = base64.b64encode(
        f"{shortcode}{Config.LIPA_PASSKEY}{timestamp}".encode()
    ).decode()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    payload = {
        "BusinessShortCode": shortcode,
        "Password":          password,
        "Timestamp":         timestamp,
        "TransactionType":   "CustomerPayBillOnline",
        "Amount":            int(amount),
        "PartyA":            normalised,
        "PartyB":            shortcode,
        "PhoneNumber":       normalised,
        "CallBackURL":       getattr(Config, "MPESA_CALLBACK_URL", ""),
        "AccountReference":  "AFRATER",
        "TransactionDesc":   "AFRATER Payment",
    }

    print(f"STK Push → phone: {normalised}, amount: {int(amount)}")

    try:
        r = requests.post(STK_URL, json=payload, headers=headers, timeout=15)
        return r.json()
    except requests.exceptions.Timeout:
        return {"error": "Daraja request timed out. Try again."}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to Daraja API."}
    except Exception as e:
        return {"error": str(e)}


def query_stk_status(checkout_request_id: str) -> dict:
    try:
        token = get_access_token()
    except Exception as e:
        return {"error": f"Failed to get access token: {str(e)}"}

    shortcode = Config.BUSINESS_SHORTCODE
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password  = base64.b64encode(
        f"{shortcode}{Config.LIPA_PASSKEY}{timestamp}".encode()
    ).decode()

    payload = {
        "BusinessShortCode": shortcode,
        "Password":          password,
        "Timestamp":         timestamp,
        "CheckoutRequestID": checkout_request_id,
    }

    try:
        r = requests.post(
            QUERY_URL,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15,
        )
        return r.json()
    except requests.exceptions.Timeout:
        return {"error": "Daraja query timed out."}
    except Exception as e:
        return {"error": str(e)}
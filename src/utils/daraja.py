import requests
import base64
from datetime import datetime
from requests.auth import HTTPBasicAuth
from config import Config

OAUTH_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
STK_URL   = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
QUERY_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query"

# ── Token cache — reuse for ~1 hour instead of fetching every call ──
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
    data  = resp.json()
    token = data.get("access_token")
    expires_in = int(data.get("expires_in", 3600))

    _token_cache["token"]      = token
    _token_cache["expires_at"] = now + expires_in - 60   # refresh 1 min early

    return token


def _normalise_phone(phone: str) -> str:
    """
    Accepts:  0712345678 / +254712345678 / 254712345678
    Returns:  254712345678  (format Daraja requires)
    """
    phone = phone.strip().replace(" ", "").replace("-", "")
    if phone.startswith("+"):
        phone = phone[1:]
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    return phone


def stk_push(phone: str, amount: float) -> dict:
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
        "PartyA":            _normalise_phone(phone),
        "PartyB":            shortcode,
        "PhoneNumber":       _normalise_phone(phone),
        "CallBackURL":       getattr(Config, "MPESA_CALLBACK_URL", ""),
        "AccountReference":  "AFRATER",
        "TransactionDesc":   "AFRATER Payment",
    }

    try:
        r = requests.post(STK_URL, json=payload, headers=headers, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.Timeout:
        return {"error": "Daraja request timed out. Try again."}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to Daraja API."}
    except Exception as e:
        return {"error": str(e)}


def query_stk_status(checkout_request_id: str) -> dict:
    """
    Check whether an STK push completed.
    Call this when the /mpesa/callback hasn't fired yet.
    """
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
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type":  "application/json",
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.Timeout:
        return {"error": "Daraja query timed out."}
    except Exception as e:
        return {"error": str(e)}
import requests
import base64
from datetime import datetime
from requests.auth import HTTPBasicAuth
from config import Config

OAUTH_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
STK_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"

def get_access_token():
    resp = requests.get(
        OAUTH_URL,
        auth=HTTPBasicAuth(Config.DARJA_CONSUMER_KEY, Config.DARJA_CONSUMER_SECRET),
        timeout=10
    )
    resp.raise_for_status()
    return resp.json().get("access_token")

def stk_push(phone, amount):
    token = get_access_token()
    if not token:
        return {"error": "Failed to get access token"}
    shortcode = Config.BUSINESS_SHORTCODE
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(f"{shortcode}{Config.LIPA_PASSKEY}{timestamp}".encode()).decode()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(amount),
        "PartyA": phone,
        "PartyB": shortcode,
        "PhoneNumber": phone,
        "CallBackURL": getattr(Config, "MPESA_CALLBACK_URL", ""),
        "AccountReference": "AFRATER",
        "TransactionDesc": "AFRATER Payment"
    }
    r = requests.post(STK_URL, json=payload, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()

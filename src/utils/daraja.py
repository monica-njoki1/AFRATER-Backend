import requests, base64
from datetime import datetime
from requests.auth import HTTPBasicAuth
from config import Config

def get_access_token():
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    response = requests.get(url, auth=HTTPBasicAuth(Config.DARJA_CONSUMER_KEY, Config.DARJA_CONSUMER_SECRET))
    return response.json().get("access_token")

def stk_push(phone, amount):
    token = get_access_token()
    shortcode = Config.BUSINESS_SHORTCODE
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f"{shortcode}{Config.LIPA_PASSKEY}{timestamp}".encode()).decode()

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": shortcode,
        "PhoneNumber": phone,
        "CallBackURL": "https://your-ngrok-url.io/api/mpesa/callback",
        "AccountReference": "AFRATER",
        "TransactionDesc": "AFRATER Payment"
    }

    response = requests.post(
        "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        json=payload,
        headers=headers
    )
    return response.json()

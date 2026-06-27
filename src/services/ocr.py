"""
src/services/ocr.py

Uses Claude Vision (claude-sonnet-4-6) to extract text from M-Pesa
screenshots and return a structured result ready for fraud_engine.
"""

import anthropic
import base64
import os
from pathlib import Path


# Initialise once at import time — reads ANTHROPIC_API_KEY from env
_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

# Supported image types
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}


def _encode_image(filepath: str) -> tuple:
    """
    Read an image from disk and return (base64_data, mime_type).
    Raises ValueError for unsupported types.
    """
    ext = Path(filepath).suffix.lower()
    mime_map = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
        ".gif": "image/gif",
    }
    mime_type = mime_map.get(ext)
    if not mime_type:
        raise ValueError(f"Unsupported image type: {ext}")

    with open(filepath, "rb") as f:
        data = base64.standard_b64encode(f.read()).decode("utf-8")

    return data, mime_type


def extract_text_from_screenshot(filepath: str) -> dict:
    """
    Send an M-Pesa screenshot to Claude Vision and get back:
    {
        "raw_text":   str,   # everything Claude read from the image
        "phone":      str,   # phone number found, or None
        "amount":     float, # transaction amount found, or None
        "message":    str,   # the actual message/description text
        "is_mpesa":   bool,  # did this look like an M-Pesa screenshot?
        "error":      str,   # only present if something went wrong
    }
    """
    try:
        image_data, mime_type = _encode_image(filepath)
    except (ValueError, FileNotFoundError) as e:
        return {"error": str(e), "raw_text": "", "phone": None,
                "amount": None, "message": "", "is_mpesa": False}

    prompt = """You are analysing a mobile money (M-Pesa) screenshot for fraud detection.

Extract the following information and respond ONLY in this exact JSON format with no extra text:
{
  "raw_text": "<all text visible in the image>",
  "phone": "<phone number if visible, else null>",
  "amount": <numeric amount if visible, else null>,
  "message": "<the transaction description, message body, or any suspicious instruction text>",
  "is_mpesa": <true if this looks like an M-Pesa message or screenshot, else false>
}

Rules:
- phone: include country code if shown, strip spaces (e.g. "0712345678" or "+254712345678")
- amount: number only, no currency symbol (e.g. 500.0)
- message: capture the full body text of any message shown
- is_mpesa: true for M-Pesa confirmations, SMS messages, or any Safaricom-related content
"""

    try:
        response = _client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": mime_type,
                                "data": image_data,
                            },
                        },
                        {
                            "type": "text",
                            "text": prompt,
                        },
                    ],
                }
            ],
        )

        import json
        raw = response.content[0].text.strip()
        # Strip markdown fences if Claude wraps in ```json ... ```
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw.strip())
        return result

    except Exception as e:
        return {
            "error": str(e),
            "raw_text": "",
            "phone": None,
            "amount": None,
            "message": "",
            "is_mpesa": False,
        }
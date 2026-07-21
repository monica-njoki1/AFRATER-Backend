# AFRATER Backend

**Amok Fraud Terminator** — Real-time M-Pesa fraud detection API built with Flask.

## Tech Stack

- **Framework:** Flask (Python 3.8+)
- **Database:** PostgreSQL (Supabase)
- **Auth:** Flask-JWT-Extended
- **Migrations:** Flask-Migrate / Alembic
- **Storage:** Cloudinary (profile pictures)
- **Payments:** Safaricom Daraja API (M-Pesa STK Push)
- **AI:** Anthropic Claude (screenshot OCR + fraud fallback)
- **Deployment:** Render

---

## Project Structure

```
AFRATER-Backend/
├── app.py                          # Entry point
├── config.py                       # Environment config
├── requirements.txt
├── src/
│   ├── __init__.py                 # App factory + blueprint registration
│   ├── extensions.py               # db, migrate, bcrypt, jwt
│   ├── models/
│   │   └── models.py               # All database models
│   ├── routes/
│   │   ├── auth.py                 # Register, login, logout, profile
│   │   ├── mpesa.py                # STK Push + preflight fraud check
│   │   ├── scam.py                 # Message fraud check
│   │   ├── uploads.py              # Screenshot upload + OCR
│   │   ├── contacts.py             # Trusted contacts
│   │   ├── transactions.py         # Manual transaction ingest
│   │   ├── query.py                # STK push status polling
│   │   └── wallet.py               # Balance, history, receive check, summary
│   ├── services/
│   │   ├── fraud_engine.py         # Core fraud detection engine
│   │   ├── ocr.py                  # Claude Vision screenshot analysis
│   │   └── recipient_reputation.py # Phone number reputation check
│   └── utils/
│       ├── daraja.py               # Safaricom Daraja API client
│       └── phone_validator.py      # Kenyan phone number validation
```

---

## Environment Variables

Create a `.env` file in the root directory:

```env
# Flask
SECRET_KEY=your-secret-key
FLASK_DEBUG=False

# Database
DATABASE_URL=postgresql://postgres.xxx:password@aws-0-eu-west-1.pooler.supabase.com:6543/postgres

# JWT
JWT_SECRET_KEY=your-jwt-secret

# Cloudinary (profile pictures)
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Safaricom Daraja (M-Pesa)
DARAJA_CONSUMER_KEY=your-consumer-key
DARAJA_CONSUMER_SECRET=your-consumer-secret
LIPA_PASSKEY=your-passkey
BUSINESS_SHORTCODE=174379
MPESA_CALLBACK_URL=https://your-backend.onrender.com/mpesa/callback

# Anthropic (Claude AI - optional)
ANTHROPIC_API_KEY=sk-ant-your-key

# SendGrid (email alerts - optional)
SENDGRID_API_KEY=your-sendgrid-key
MAIL_DEFAULT_SENDER=afrater@example.com
```

---

## Local Setup

```bash
# Clone the repo
git clone https://github.com/monica-njoki1/AFRATER-Backend.git
cd AFRATER-Backend

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up database
flask db upgrade

# Run locally
flask run
```

---

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login + get JWT token |
| POST | `/auth/logout` | Logout + blacklist token |
| GET | `/auth/profile` | Get current user profile |
| PUT | `/auth/profile` | Update profile / photo |
| DELETE | `/auth/delete` | Delete account |

### Fraud Detection
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scam/check` | Check a message for fraud |
| GET | `/scam/reports` | Get all scam reports |
| POST | `/upload/screenshot` | Upload + analyse screenshot |

### M-Pesa
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/mpesa/preflight` | Pre-flight fraud check before payment |
| POST | `/mpesa/pay` | Initiate STK Push |
| POST | `/mpesa/callback` | Daraja webhook (public) |
| POST | `/mpesa/report` | Report a fraudulent number |

### Wallet
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/wallet/balance` | M-Pesa account balance |
| GET | `/wallet/transactions` | Transaction history with fraud scores |
| GET | `/wallet/transactions/<id>` | Single transaction detail |
| POST | `/wallet/receive/check` | Check incoming sender reputation |
| GET | `/wallet/summary` | Security score + spending summary |
| DELETE | `/wallet/transactions/clear` | Clear all history |

### Other
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/contacts/` | Add trusted contact |
| GET | `/contacts/` | List trusted contacts |
| DELETE | `/contacts/<id>` | Remove trusted contact |
| GET | `/query/stk/<id>` | Poll STK push status |
| GET | `/query/pending` | List pending payments |

---

## Fraud Engine

The fraud engine scores messages and transactions 0-100:

- **0-29** → Safe
- **30-59** → Suspicious
- **60-100** → Fraud (payments blocked automatically)

### What it detects
- English scam keywords (reversal, PIN fishing, impersonation)
- Swahili scam phrases (nimekosea nambari, ufute, siri zangu, etc.)
- Exposed PINs in messages (`{5529}`, `[1234]`)
- Exposed bank account numbers
- Phone number sharing with call/SMS instructions
- Large amount bait (millions mentioned)
- Known scam numbers (community blacklist)
- Off-hours transactions (midnight to 5AM Kenya time)
- Repeat attempts from same number

---

## Deployment (Render)

1. Push to GitHub
2. Connect repo to Render
3. Add all environment variables in Render dashboard
4. Render auto-deploys on every push to `main`

**Build command:** (none — Render detects Python automatically)
**Start command:** `gunicorn app:app`

---

## Notes

- JWT tokens expire after 30 days
- Anthropic API is optional — keyword engine catches 90%+ of scams for free
- Daraja sandbox credentials work for testing — production requires Safaricom approval
- Keep `.env` out of git (already in `.gitignore`)
# Zero Trust Security Platform

An educational Flask-based Zero Trust security platform demonstrating risk-aware access control, multi-factor authentication (TOTP), device/session monitoring, policy checks, threat-intelligence examples, protected internal applications, and IoT device management.

> **Status:** This package is prepared from the supplied `Zero_TRUST_v2_RealWorld.zip` source. Python syntax and package structure were checked, but a full live run could not be verified in this environment. Treat it as a student/demo project, not a production security product.

## Features represented in the code

- Flask web application with SQLite storage
- TOTP-based multi-factor authentication
- Risk scoring and context-aware policy examples
- Session and device tracking
- Sample threat-intelligence records
- Protected application routes
- IoT device registration and heartbeat endpoints
- SOC/admin dashboard templates
- Seed script for demo users and sample activity

## Project structure

```text
ZeroTrust-Security-Platform/
├── app.py
├── seed_data.py
├── requirements.txt
├── README.md
├── .gitignore
├── static/
│   ├── soc.css
│   └── style.css
└── templates/
    ├── admin.html
    ├── dashboard.html
    ├── device.html
    ├── error.html
    ├── index.html
    ├── internal_app.html
    ├── iot.html
    ├── login.html
    ├── mfa.html
    ├── mfa_setup.html
    ├── mfa_step_up.html
    ├── register.html
    └── soc.html
```

## Requirements

- Python 3.10 or newer
- pip

## Setup on Windows PowerShell

Extract this ZIP, open the extracted folder in VS Code, and run:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, use the venv Python directly:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Initialize demo data

The application creates its SQLite tables when `app.py` is imported. To add sample users and dashboard activity, run:

```powershell
python seed_data.py
```

**Warning:** `seed_data.py` clears several tables before inserting demo records. Run it only against a fresh demo database; it is not a safe production migration tool.

## Run locally

```powershell
python app.py
```

Then open http://127.0.0.1:5000.

The server binds to localhost by default and debug mode is disabled. To enable debug mode for local development only, set `FLASK_DEBUG=1` in your terminal before starting the app. Do not expose the debug server to a public network.

## Configuration

Optional environment variables:

- `SECRET_KEY` — Flask session signing key
- `JWT_SECRET_KEY` — JWT signing key
- `DATABASE_PATH` — SQLite database path (default: `database.db`)
- `PORT` — local port (default: `5000`)
- `FLASK_DEBUG` — set to `1` for local development only

For a persistent local secret in PowerShell, generate a random value and set it before starting the app. Never commit real secrets or a populated database to GitHub.

## Demo accounts

The seed script contains example account credentials in source code for a local classroom demonstration. Review `seed_data.py` before use and change/remove demo credentials before any shared deployment. MFA secrets are generated for demo users; this project does not provide a production-safe account recovery workflow.

## Important security notes

- This is an educational prototype and has not been independently security audited.
- Do not deploy it directly to the public internet.
- Do not commit `database.db`, real credentials, `.env` files, or production secrets.
- Use a production WSGI server, HTTPS, managed secrets, robust migrations, and a reviewed authorization model before any real deployment.
- Demo threat-intelligence entries and geolocation/risk calculations are illustrative, not authoritative feeds or reliable attribution.

## Author

Sri Aravind — [GitHub profile](https://github.com/SriAravind03)

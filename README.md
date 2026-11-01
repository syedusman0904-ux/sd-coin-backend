# SD Coin Website Starter

A starter project with a static HTML/CSS/JavaScript frontend and a Python Flask API backend.

**Important:** SD Coins in this project are internal website credits only. They are not a cryptocurrency, do not exist on a blockchain, and are not redeemable for cash. This starter is for learning/testing, not for handling real money or public financial services.

## Project layout

- `frontend/` — static pages suitable for GitHub Pages (including `privacy.html`)
- `backend/` — Flask REST API suitable for Render

## 1. Test the backend locally

Use Python 3.10+.

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Set environment variables before starting:

```bash
# macOS/Linux
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export FRONTEND_ORIGINS="http://127.0.0.1:5500,http://localhost:5500"
export ADMIN_EMAIL="your-admin-email@example.com"
export ADMIN_PASSWORD="use-a-long-unique-password-at-least-16-chars"
python app.py
```

PowerShell:

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-secret-at-least-32-characters"
$env:FRONTEND_ORIGINS = "http://127.0.0.1:5500,http://localhost:5500"
$env:ADMIN_EMAIL = "your-admin-email@example.com"
$env:ADMIN_PASSWORD = "use-a-long-unique-password-at-least-16-chars"
python app.py
```

The API runs at `http://127.0.0.1:5000`. The first admin account is created from the environment variables. New users register with zero balance; the admin can issue demo coins from the admin page.

## 2. Connect the frontend

Open `frontend/config.js` and set:

```js
window.SD_COIN_API_URL = "http://127.0.0.1:5000";
```

Serve the frontend over HTTP (do not just double-click the HTML files). For example, in a second terminal:

```bash
cd frontend
python -m http.server 5500
```

Open `http://127.0.0.1:5500`.

## 3. Deploy backend to Render

1. Push the contents of this project to GitHub. You may use one repository or two.
2. In Render, create a PostgreSQL database and a Python web service from the backend repository.
3. Set the service root directory to `backend` if the backend is in a subfolder.
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Set environment variables:
   - `SECRET_KEY`: a long random secret (32+ characters); keep private.
   - `DATABASE_URL`: Render PostgreSQL internal connection string.
   - `FRONTEND_ORIGINS`: exact deployed frontend origin, e.g. `https://YOUR-USERNAME.github.io` (no path or trailing slash).
   - `ADMIN_EMAIL`: admin email.
   - `ADMIN_PASSWORD`: unique password of at least 16 characters.
7. Deploy and test the service root URL. It should return JSON with `"status": "online"`.

Do not commit secrets, `.env` files, database files, or passwords to GitHub.

## 4. Deploy frontend to GitHub Pages

1. Create a GitHub repository and upload the contents of `frontend/` to its root (so `index.html` is at repository root).
2. In GitHub: Settings → Pages → Deploy from a branch → `main` → `/ (root)` → Save.
3. Copy the GitHub Pages origin, e.g. `https://YOUR-USERNAME.github.io`.
4. Add that exact origin to Render's `FRONTEND_ORIGINS` environment variable and redeploy if needed.
5. Set `window.SD_COIN_API_URL` in `config.js` to the deployed backend HTTPS URL, then commit the change.

If you use a project URL such as `https://YOUR-USERNAME.github.io/REPOSITORY/`, the origin for CORS is still only `https://YOUR-USERNAME.github.io`.

## Included API endpoints

- `POST /api/register` — create account with a chosen User ID (6–32 letters, numbers, _ or -)
- `POST /api/login` — login
- `GET /api/me` — authenticated account and balance
- `POST /api/transfer` — authenticated member-to-member transfer
- `GET /api/transactions` — signed-in user's transaction history
- `POST /api/admin/issue` — admin-only issue of internal demo credits
- `GET /api/mining/challenge` — get the next proof-of-work challenge
- `POST /api/mining/submit` — submit a SHA-256 proof; backend verifies it and credits 25 SD
- `GET /api/chain` — inspect recent blocks and verify the stored chain hashes
- `POST /api/change-password` — change the signed-in account password after checking the current password

The browser stores a signed bearer token in localStorage. Tokens expire after two hours. Password changes and the Log out button revoke all existing sessions for that account. HTTPS is required in production. Rate limits are enabled; for multi-instance production deployment, set RATELIMIT_STORAGE_URI to a private Redis URL.

## Security and production limitations

This is an educational starter, not a security audit or production-ready financial platform. Before public launch, obtain a professional security review. Add rate limiting, email verification, password reset, audit monitoring, account recovery, database backups, stronger abuse controls, and an operational process for disputes. Review local laws and regulatory requirements before offering transferable or purchasable value. The demo admin issuance endpoint creates internal credits and should not be used to represent cash deposits or real crypto.


## Create a specific member account and credit demo coins

The registration form now accepts a chosen User ID. For the requested example, the member can register with:
- Display name: `syedusman`
- User ID: `syedusman608`
- Email: `syedusman0904@gmail.com`

The member chooses their own private password during registration. Do not put a password in source code, GitHub, or chat.

To credit 40,000,000 internal demo SD Coins:
1. Configure the admin account using `ADMIN_EMAIL` and `ADMIN_PASSWORD` in the backend hosting environment.
2. Deploy the updated backend and frontend.
3. Sign in to the admin account, open `admin.html`, enter User ID `syedusman608`, and amount `40000000`.
4. Click **Issue SD Coins**. The backend will add the amount and record it in the ledger.

This is an internal demo-credit operation only. It does not create real cryptocurrency or money. If this member already exists, do not register a duplicate; use the admin panel to credit the existing account.


## Proof-of-work mining and blockchain demo

The dashboard includes a browser mining panel. Press **Start mining** to search for a nonce that makes the SHA-256 block hash begin with three zeroes (`000`). The backend independently recalculates and checks the proof before it accepts the block. The first valid submission for the current chain tip receives **25 SD**; the block is linked to the previous block by its hash. The chain page/API reports whether stored block hashes and previous-hash links validate.

This is a learning/demo proof-of-work chain stored in the project's database. It is not decentralized: one Render backend controls the database and consensus, so it is not equivalent to Bitcoin or another public blockchain. Mining uses the browser device's CPU and can consume battery. The chain records miner IDs and block metadata publicly; SHA-256 is a one-way hash for integrity/proof, **not encryption**. It does not hide information. Do not put passwords, email addresses, or private personal data into block contents. If private data must be stored, use authenticated encryption separately and keep encryption keys off the chain.

### Account password

Registration requires the member to choose a password (12–128 characters). The backend stores a salted password hash, never the plain password. A logged-in member can change it from the dashboard by entering the current password and a new password. For the member ID `syedusman608`, sign in to that account and use this form. Do not send the password in chat or put it in GitHub/source code. If the account already exists and its current password is unknown, use a secure password-reset flow; this starter does not include email-based password reset.


## Security, privacy and multi-device mining update

- Passwords are salted and hashed by Werkzeug; new registrations and password changes require at least 12 characters. Never share passwords in chat or commit them to GitHub.
- Signed login tokens expire after two hours. Password changes and Log out revoke tokens on all devices using an account auth-version counter.
- Login and registration have rate limits. The default limiter uses process memory for a simple demo; use a private Redis instance and set `RATELIMIT_STORAGE_URI` for a multi-worker/multi-instance deployment.
- API responses include security headers, JSON request size is limited, CORS is restricted to `FRONTEND_ORIGINS`, and API responses are not cached.
- The presence feature stores only a random browser-generated device session ID, a broad Mobile/Desktop label, and last-seen time. It does not collect GPS, contacts, camera, microphone, full user-agent strings, or device serial numbers. Stale presence records are removed after three minutes.
- Multi-device mining is cooperative competition on one central chain. Sign in on each device and press Start Mining on each device. Each device receives a separate nonce search range. The first device to submit a valid proof wins that block reward; other devices refresh and mine the next block.
- Mining is never started automatically. It pauses when the tab is hidden and stops when the user presses Stop. It uses CPU and battery while active. Do not use it on devices you do not own or without the device owner's permission.
- The chain is still centralized in the Render database. There is no peer-to-peer network, independent node consensus, wallet private-key system, or real asset value.

For a complete technical and setup guide, read `SD_COIN_TECHNICAL_GUIDE.txt` in the project root.

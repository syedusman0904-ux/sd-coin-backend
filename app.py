import os
import re
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import update, or_, inspect, text
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "")
if len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError("Set SECRET_KEY to a random value of at least 32 characters.")

database_url = os.environ.get("DATABASE_URL", "sqlite:///sd_coin.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
db = SQLAlchemy(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10000 per day", "1000 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    strategy="fixed-window",
)

allowed_origins = [x.strip() for x in os.environ.get("FRONTEND_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500").split(",") if x.strip()]
CORS(app, resources={r"/api/*": {"origins": allowed_origins}}, allow_headers=["Content-Type", "Authorization"], methods=["GET", "POST", "OPTIONS"])

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="sd-coin-auth-v1")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    name = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")
    balance = db.Column(db.BigInteger, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    auth_version = db.Column(db.Integer, nullable=False, default=0)


class MiningDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), nullable=False, index=True)
    device_key = db.Column(db.String(36), nullable=False)
    device_label = db.Column(db.String(24), nullable=False)
    last_seen = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint("user_id", "device_key", name="uq_mining_device_user_key"),)


class LedgerEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    idempotency_key = db.Column(db.String(80), unique=True, nullable=True)
    sender_user_id = db.Column(db.String(32), nullable=True, index=True)
    receiver_user_id = db.Column(db.String(32), nullable=False, index=True)
    amount = db.Column(db.BigInteger, nullable=False)
    kind = db.Column(db.String(20), nullable=False)  # transfer or admin_issue
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    block_index = db.Column(db.Integer, unique=True, nullable=False, index=True)
    previous_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.String(40), nullable=False)
    miner_user_id = db.Column(db.String(32), nullable=False, index=True)
    reward = db.Column(db.BigInteger, nullable=False)
    nonce = db.Column(db.BigInteger, nullable=False)
    block_hash = db.Column(db.String(64), unique=True, nullable=False)


def calculate_block_hash(index, previous_hash, timestamp, miner_user_id, reward, nonce):
    # Fixed field order makes the proof-of-work input deterministic.
    payload = f"{index}|{previous_hash}|{timestamp}|{miner_user_id}|{reward}|{nonce}"
    import hashlib
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def response_error(message, status=400):
    return jsonify({"error": message}), status


def make_token(user):
    return serializer.dumps({"uid": user.user_id, "ver": user.auth_version})


def current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    try:
        payload = serializer.loads(header[7:], max_age=60 * 60 * 2)
    except (BadSignature, SignatureExpired):
        return None
    user = User.query.filter_by(user_id=payload.get("uid")).first()
    if not user or payload.get("ver") != user.auth_version:
        return None
    return user


def require_user():
    user = current_user()
    if not user:
        return None, response_error("Please log in again.", 401)
    return user, None


def generate_user_id():
    # Retry on the extremely unlikely chance of a collision.
    while True:
        candidate = "sd" + uuid.uuid4().hex[:10]
        if not User.query.filter_by(user_id=candidate).first():
            return candidate


@app.get("/")
def health():
    return jsonify({"service": "SD Coin API", "status": "online"})


@app.post("/api/register")
@limiter.limit("5 per hour")
def register():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not 2 <= len(name) <= 60:
        return response_error("Name must be between 2 and 60 characters.")
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return response_error("Enter a valid email address.")
    if len(password) < 12 or len(password) > 128:
        return response_error("Password must be between 12 and 128 characters.")
    if User.query.filter(or_(User.email == email)).first():
        return response_error("An account with this email already exists.", 409)
    requested_id = str(data.get("user_id", "")).strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{6,32}", requested_id):
        return response_error("User ID must be 6–32 characters using letters, numbers, _ or -.")
    if User.query.filter_by(user_id=requested_id).first():
        return response_error("That User ID is already taken.", 409)
    user = User(user_id=requested_id, name=name, email=email,
                password_hash=generate_password_hash(password), balance=0, role="user")
    db.session.add(user)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return response_error("Could not create account. Please try again.", 500)
    return jsonify({"token": make_token(user), "user_id": user.user_id, "message": "Account created."}), 201


@app.post("/api/login")
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    identity = str(data.get("identity", "")).strip()
    password = str(data.get("password", ""))
    user = User.query.filter(or_(User.user_id == identity.lower(), User.email == identity.lower())).first()
    if not user or not check_password_hash(user.password_hash, password):
        return response_error("Incorrect user ID/email or password.", 401)
    return jsonify({"token": make_token(user), "user_id": user.user_id, "message": "Login successful."})


@app.get("/api/me")
def me():
    user, error = require_user()
    if error:
        return error
    return jsonify({"user_id": user.user_id, "name": user.name, "email": user.email,
                    "role": user.role, "balance": user.balance})


@app.post("/api/transfer")
def transfer():
    user, error = require_user()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    receiver_id = str(data.get("receiver_id", "")).strip().lower()
    idem = str(data.get("idempotency_key", "")).strip()
    amount = data.get("amount")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0 or amount > 1_000_000_000:
        return response_error("Amount must be a positive whole number of SD Coins.")
    if not re.fullmatch(r"(?:sd[a-f0-9]{10}|[a-z0-9_-]{6,32})", receiver_id):
        return response_error("Enter a valid SD User ID.")
    if not re.fullmatch(r"[A-Za-z0-9-]{16,80}", idem):
        return response_error("Invalid transaction request key.")
    if receiver_id == user.user_id:
        return response_error("You cannot transfer coins to yourself.")
    # A previously accepted request with the same key must not be processed twice.
    previous = LedgerEntry.query.filter_by(idempotency_key=idem).first()
    if previous:
        if previous.sender_user_id != user.user_id:
            return response_error("Request key already used.", 409)
        return jsonify({"message": "This transfer was already processed.", "transaction_id": previous.transaction_id})
    receiver = User.query.filter_by(user_id=receiver_id).first()
    if not receiver:
        return response_error("Receiver account was not found.", 404)
    try:
        # Conditional UPDATE prevents negative balances. The two balance changes and
        # ledger insert are committed together, so a partial transfer is not saved.
        debit = db.session.execute(
            update(User).where(User.id == user.id, User.balance >= amount)
            .values(balance=User.balance - amount)
        )
        if debit.rowcount != 1:
            db.session.rollback()
            return response_error("Insufficient balance.", 409)
        credit = db.session.execute(
            update(User).where(User.id == receiver.id)
            .values(balance=User.balance + amount)
        )
        if credit.rowcount != 1:
            db.session.rollback()
            return response_error("Receiver account was not found.", 404)
        transaction_id = str(uuid.uuid4())
        db.session.add(LedgerEntry(transaction_id=transaction_id, idempotency_key=idem,
                                   sender_user_id=user.user_id, receiver_user_id=receiver.user_id,
                                   amount=amount, kind="transfer"))
        db.session.commit()
        return jsonify({"message": "SD Coins transferred successfully.", "transaction_id": transaction_id})
    except Exception:
        db.session.rollback()
        app.logger.exception("Transfer failed")
        return response_error("Transfer could not be completed. Please retry.", 500)


@app.get("/api/transactions")
def transactions():
    user, error = require_user()
    if error:
        return error
    rows = LedgerEntry.query.filter(
        or_(LedgerEntry.sender_user_id == user.user_id, LedgerEntry.receiver_user_id == user.user_id)
    ).order_by(LedgerEntry.created_at.desc()).limit(100).all()
    result = []
    for row in rows:
        if row.kind == "admin_issue":
            kind, other = "admin_issue", "SD Coin Admin"
        elif row.kind == "mining_reward":
            kind, other = "mining_reward", "Proof-of-work mining"
        elif row.sender_user_id == user.user_id:
            kind, other = "sent", row.receiver_user_id
        else:
            kind, other = "received", row.sender_user_id
        result.append({"transaction_id": row.transaction_id, "kind": kind, "other_user": other,
                       "amount": row.amount, "created_at": row.created_at.isoformat()})
    return jsonify({"transactions": result})


@app.get("/api/mining/challenge")
def mining_challenge():
    user, error = require_user()
    if error:
        return error
    latest = Block.query.order_by(Block.block_index.desc()).first()
    if not latest:
        return response_error("Blockchain is not initialized.", 503)
    device_key = str(request.args.get("device_id", ""))
    if not re.fullmatch(r"[a-f0-9-]{36}", device_key):
        return response_error("A valid device session ID is required.")
    import hashlib
    # Give each signed-in device a separate nonce region so devices can work in parallel.
    nonce_start = int(hashlib.sha256(device_key.encode("utf-8")).hexdigest()[:8], 16) * 1_000_000
    return jsonify({
        "index": latest.block_index + 1,
        "previous_hash": latest.block_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "miner_user_id": user.user_id,
        "reward": 25,
        "difficulty": 3,
        "algorithm": "SHA-256",
        "nonce_start": nonce_start,
        "device_id": device_key,
    })


@app.post("/api/mining/submit")
def mining_submit():
    user, error = require_user()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    try:
        index = int(data.get("index"))
        nonce = int(data.get("nonce"))
        reward = int(data.get("reward"))
        timestamp = str(data.get("timestamp", ""))
        previous_hash = str(data.get("previous_hash", ""))
        supplied_hash = str(data.get("hash", "")).lower()
    except (TypeError, ValueError):
        return response_error("Invalid mining proof.")
    device_key = str(data.get("device_id", ""))
    if not re.fullmatch(r"[a-f0-9-]{36}", device_key):
        return response_error("Invalid mining device session.")
    import hashlib
    expected_nonce_start = int(hashlib.sha256(device_key.encode("utf-8")).hexdigest()[:8], 16) * 1_000_000
    if nonce < expected_nonce_start or len(timestamp) > 40 or reward != 25:
        return response_error("Invalid mining proof.")
    latest = Block.query.order_by(Block.block_index.desc()).first()
    if not latest or index != latest.block_index + 1 or previous_hash != latest.block_hash:
        return response_error("The chain changed while you were mining. Get a new challenge.", 409)
    expected = calculate_block_hash(index, previous_hash, timestamp, user.user_id, reward, nonce)
    if supplied_hash != expected or not expected.startswith("000"):
        return response_error("Proof of work is invalid. Keep mining.", 400)
    try:
        block = Block(block_index=index, previous_hash=previous_hash, timestamp=timestamp,
                      miner_user_id=user.user_id, reward=reward, nonce=nonce, block_hash=expected)
        db.session.add(block)
        db.session.execute(update(User).where(User.id == user.id).values(balance=User.balance + reward))
        txid = str(uuid.uuid4())
        db.session.add(LedgerEntry(transaction_id=txid, receiver_user_id=user.user_id,
                                   amount=reward, kind="mining_reward"))
        db.session.commit()
        return jsonify({"message": "Block mined successfully! 25 SD added to your wallet.",
                        "block_index": index, "block_hash": expected, "reward": reward,
                        "transaction_id": txid})
    except Exception:
        db.session.rollback()
        app.logger.exception("Mining block commit failed")
        return response_error("Another miner may have completed this block. Get a new challenge.", 409)


@app.post("/api/presence")
def presence_heartbeat():
    user, error = require_user()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    device_key = str(data.get("device_id", ""))
    label = str(data.get("device_label", "Desktop"))
    if not re.fullmatch(r"[a-f0-9-]{36}", device_key):
        return response_error("Invalid device session ID.")
    if label not in ("Mobile", "Desktop"):
        label = "Desktop"
    now = datetime.now(timezone.utc)
    device = MiningDevice.query.filter_by(user_id=user.user_id, device_key=device_key).first()
    if device:
        device.last_seen = now
        device.device_label = label
    else:
        device = MiningDevice(user_id=user.user_id, device_key=device_key,
                              device_label=label, last_seen=now)
        db.session.add(device)
    # Remove expired presence records for this account; no IP address or full UA is stored.
    cutoff = now.timestamp() - 180
    old = MiningDevice.query.filter_by(user_id=user.user_id).all()
    for item in old:
        if item.last_seen.timestamp() < cutoff:
            db.session.delete(item)
    db.session.commit()
    active = MiningDevice.query.filter_by(user_id=user.user_id).filter(
        MiningDevice.last_seen >= now.replace(microsecond=0) - timedelta(seconds=90)
    ).all()
    return jsonify({"online_devices": len(active), "devices": [d.device_label for d in active]})


@app.post("/api/logout-all")
def logout_all():
    user, error = require_user()
    if error:
        return error
    user.auth_version += 1
    db.session.commit()
    return jsonify({"message": "All sessions have been signed out. Please log in again."})


@app.get("/api/chain")
def chain_info():
    all_blocks = Block.query.order_by(Block.block_index.asc()).all()
    valid = bool(all_blocks)
    previous = "0" * 64
    for expected_index, block in enumerate(all_blocks):
        recalculated = calculate_block_hash(block.block_index, block.previous_hash,
            block.timestamp, block.miner_user_id, block.reward, block.nonce)
        if (block.block_index != expected_index or block.previous_hash != previous
                or block.block_hash != recalculated
                or (block.block_index > 0 and not block.block_hash.startswith("000"))):
            valid = False
            break
        previous = block.block_hash
    blocks = all_blocks[-25:]
    return jsonify({"chain_valid": valid, "total_blocks": len(all_blocks),
        "blocks": [{"index": b.block_index, "previous_hash": b.previous_hash,
        "timestamp": b.timestamp, "miner_user_id": b.miner_user_id, "reward": b.reward,
        "nonce": b.nonce, "hash": b.block_hash} for b in blocks],
        "difficulty": 3, "reward": 25, "algorithm": "SHA-256"})


@app.post("/api/change-password")
def change_password():
    user, error = require_user()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    current = str(data.get("current_password", ""))
    new = str(data.get("new_password", ""))
    if not check_password_hash(user.password_hash, current):
        return response_error("Current password is incorrect.", 401)
    if len(new) < 12 or len(new) > 128:
        return response_error("New password must be 12–128 characters.")
    user.password_hash = generate_password_hash(new)
    user.auth_version += 1  # revoke every previously issued token on every device
    db.session.commit()
    return jsonify({"message": "Password updated. All sessions were signed out; please log in again."})


@app.post("/api/admin/issue")
def admin_issue():
    admin, error = require_user()
    if error:
        return error
    if admin.role != "admin":
        return response_error("Administrator access required.", 403)
    data = request.get_json(silent=True) or {}
    target_id = str(data.get("user_id", "")).strip().lower()
    amount = data.get("amount")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0 or amount > 1_000_000_000:
        return response_error("Amount must be a positive whole number of SD Coins.")
    target = User.query.filter_by(user_id=target_id).first()
    if not target:
        return response_error("User not found.", 404)
    try:
        db.session.execute(update(User).where(User.id == target.id).values(balance=User.balance + amount))
        txid = str(uuid.uuid4())
        db.session.add(LedgerEntry(transaction_id=txid, receiver_user_id=target.user_id,
                                   amount=amount, kind="admin_issue"))
        db.session.commit()
        return jsonify({"message": f"Issued {amount} SD to {target.user_id}.", "transaction_id": txid})
    except Exception:
        db.session.rollback()
        app.logger.exception("Admin issue failed")
        return response_error("Could not issue coins.", 500)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def migrate_existing_database():
    # create_all does not add columns to existing tables. This small additive migration
    # keeps already-deployed user accounts and balances intact.
    columns = {column["name"] for column in inspect(db.engine).get_columns("users")}
    if "auth_version" not in columns:
        db.session.execute(text("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0"))
        db.session.commit()


def bootstrap_admin():
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if not admin_email and not admin_password:
        app.logger.warning("ADMIN_EMAIL/ADMIN_PASSWORD not set; no admin account created.")
        return
    if not admin_email or len(admin_password) < 16:
        raise RuntimeError("Set both ADMIN_EMAIL and ADMIN_PASSWORD (at least 16 characters).")
    existing = User.query.filter_by(email=admin_email).first()
    if existing:
        existing.role = "admin"
        db.session.commit()
        return
    admin = User(user_id="sdadmin0001", name="SD Coin Admin", email=admin_email,
                 password_hash=generate_password_hash(admin_password), role="admin", balance=0)
    db.session.add(admin)
    db.session.commit()


with app.app_context():
    db.create_all()
    migrate_existing_database()
    if not Block.query.first():
        genesis_time = "2026-11-01T00:00:00+00:00"
        genesis_hash = calculate_block_hash(0, "0" * 64, genesis_time, "GENESIS", 0, 0)
        db.session.add(Block(block_index=0, previous_hash="0" * 64, timestamp=genesis_time,
            miner_user_id="GENESIS", reward=0, nonce=0, block_hash=genesis_hash))
        db.session.commit()
    bootstrap_admin()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

"""
Email / phone one-time-code authentication: sign up and sign in, no passwords.

Flow
----
POST /auth/start   {mode: signin|signup, ...}  -> sends a 6-digit code, returns a challenge_id
POST /auth/verify  {challenge_id, code}        -> creates a session cookie
GET  /auth/me      -> who is signed in
POST /auth/logout
GET  /login        -> the login page

Security properties
-------------------
* Codes are random 6 digits, stored only as HMAC-SHA256 hashes, valid 5 minutes,
  max 5 wrong attempts, single use.
* Resend cooldown, per-destination hourly cap, and a best-effort per-IP cap.
* Sign-in does not reveal whether an account exists (same response shape either way).
* Session tokens are random, stored only as SHA-256 hashes; cookie is HttpOnly,
  SameSite=Lax, and Secure over HTTPS.
* Everything is stdlib (sqlite3, smtplib, urllib): no extra dependencies.

Delivery
--------
Email: set SMTP_HOST, SMTP_USER, SMTP_PASS (optional SMTP_PORT=587, SMTP_FROM).
SMS:   set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM.
With AUTH_DEMO_OTP=1 (the default) the code is ALSO returned to the browser so the
flow can be demonstrated without a provider. Set AUTH_DEMO_OTP=0 for real use.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter()

OTP_TTL_S = 300
OTP_MAX_ATTEMPTS = 5
RESEND_COOLDOWN_S = 30
MAX_SENDS_PER_HOUR = 5          # per destination
MAX_SENDS_PER_IP_HOUR = 20      # best effort (X-Forwarded-For can be spoofed)
SESSION_TTL_S = 7 * 24 * 3600
COOKIE = "bt_session"

_ip_hits: dict[str, list[int]] = {}
_schema_ready: set[str] = set()
_SECRET: Optional[bytes] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE,
  phone TEXT UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  phone_verified INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges(
  id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  user_id INTEGER,
  name TEXT, email TEXT, phone TEXT,
  channel TEXT NOT NULL,
  destination TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sends(
  destination TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sends_dest ON sends(destination, ts);
"""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _now() -> int:
    return int(time.time())


def _secret() -> bytes:
    global _SECRET
    if _SECRET is None:
        s = os.environ.get("AUTH_SECRET", "").strip()
        if not s:
            print("[auth] AUTH_SECRET not set: using a random per-process secret "
                  "(pending codes are invalidated on restart).", file=sys.stderr)
            s = secrets.token_hex(32)
        _SECRET = s.encode()
    return _SECRET


def _conn() -> sqlite3.Connection:
    path = os.environ.get("AUTH_DB", str(Path(__file__).parent / "auth.db"))
    c = sqlite3.connect(path, timeout=10)
    c.row_factory = sqlite3.Row
    if path not in _schema_ready:
        c.executescript(SCHEMA)
        _schema_ready.add(path)
    return c


def _code_hash(challenge_id: str, code: str) -> str:
    return hmac.new(_secret(), f"{challenge_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def _is_https(request: Request) -> bool:
    return (request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https")


_EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
_NAME_RX = re.compile(r"^[\w .'\-]{1,60}$")


def norm_email(s: str) -> Optional[str]:
    s = (s or "").strip().lower()
    return s if len(s) <= 254 and _EMAIL_RX.match(s) else None


def norm_phone(s: str) -> Optional[str]:
    """Return E.164. A bare 10-digit number starting 6-9 is treated as Indian (+91)."""
    s = re.sub(r"[\s\-().]", "", (s or "").strip())
    if re.fullmatch(r"[6-9]\d{9}", s):
        return "+91" + s
    if re.fullmatch(r"\+[1-9]\d{9,14}", s):
        return s
    return None


def norm_name(s: str) -> Optional[str]:
    s = re.sub(r"\s+", " ", (s or "").strip())
    return s if _NAME_RX.match(s) else None


def mask(channel: str, dest: str) -> str:
    if channel == "email":
        user, _, domain = dest.partition("@")
        return f"{user[:1]}***@{domain}"
    return f"{dest[:3]}{'*' * max(len(dest) - 7, 3)}{dest[-4:]}"


def _demo_on() -> bool:
    return os.environ.get("AUTH_DEMO_OTP", "1") == "1"


def _email_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER") and os.environ.get("SMTP_PASS"))


def _sms_configured() -> bool:
    return bool(os.environ.get("TWILIO_ACCOUNT_SID") and os.environ.get("TWILIO_AUTH_TOKEN")
                and os.environ.get("TWILIO_FROM"))


# --------------------------------------------------------------------------
# delivery (real providers; used only when configured)
# --------------------------------------------------------------------------
def _message(code: str) -> str:
    return (f"Your Blue-Team Firewall verification code is {code}. "
            f"It expires in {OTP_TTL_S // 60} minutes. Never share it with anyone.")


def _send_email(to: str, code: str) -> None:
    host, port = os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587"))
    user, pwd = os.environ["SMTP_USER"], os.environ["SMTP_PASS"]
    msg = EmailMessage()
    msg["Subject"] = "Your verification code"
    msg["From"] = os.environ.get("SMTP_FROM", user)
    msg["To"] = to
    msg.set_content(_message(code))
    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10, context=ctx) as s:
            s.login(user, pwd)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls(context=ctx)
            s.login(user, pwd)
            s.send_message(msg)


def _send_sms(to: str, code: str) -> None:
    sid, token = os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"]
    data = urllib.parse.urlencode(
        {"To": to, "From": os.environ["TWILIO_FROM"], "Body": _message(code)}).encode()
    req = urllib.request.Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json", data=data)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{sid}:{token}".encode()).decode())
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"Twilio HTTP {resp.status}")


# --------------------------------------------------------------------------
# core logic
# --------------------------------------------------------------------------
def _issue(c: sqlite3.Connection, request: Request, purpose: str, user_id: Optional[int],
           pending: dict, channel: str, destination: str) -> tuple[str, Optional[str]]:
    now = _now()
    ip = _client_ip(request)
    hits = [t for t in _ip_hits.get(ip, []) if t > now - 3600]
    if len(hits) >= MAX_SENDS_PER_IP_HOUR:
        raise HTTPException(429, "Too many requests. Please try again later.")
    row = c.execute("SELECT MAX(ts) AS m, COUNT(*) AS n FROM sends WHERE destination=? AND ts>?",
                    (destination, now - 3600)).fetchone()
    if row["n"] >= MAX_SENDS_PER_HOUR:
        raise HTTPException(429, "Too many codes requested. Please try again later.")
    if row["m"] and now - row["m"] < RESEND_COOLDOWN_S:
        wait = RESEND_COOLDOWN_S - (now - row["m"])
        raise HTTPException(429, f"Please wait {wait}s before requesting another code.",
                            headers={"Retry-After": str(wait)})

    configured = _email_configured() if channel == "email" else _sms_configured()
    if not configured and not _demo_on():
        raise HTTPException(503, "Code delivery is not configured on this server.")

    cid = secrets.token_hex(16)
    code = f"{secrets.randbelow(10 ** 6):06d}"
    c.execute("DELETE FROM challenges WHERE expires < ?", (now - 3600,))
    c.execute("DELETE FROM sessions WHERE expires < ?", (now,))
    c.execute("INSERT INTO challenges(id,purpose,user_id,name,email,phone,channel,destination,"
              "code_hash,expires,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (cid, purpose, user_id, pending.get("name"), pending.get("email"), pending.get("phone"),
               channel, destination, _code_hash(cid, code), now + OTP_TTL_S, now))
    c.execute("INSERT INTO sends(destination, ts) VALUES(?,?)", (destination, now))
    c.commit()
    hits.append(now)
    _ip_hits[ip] = hits

    if configured:
        try:
            (_send_email if channel == "email" else _send_sms)(destination, code)
        except Exception as e:
            print(f"[auth] delivery to {mask(channel, destination)} failed: "
                  f"{type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
            if not _demo_on():
                c.execute("DELETE FROM challenges WHERE id=?", (cid,))
                c.commit()
                raise HTTPException(502, "Could not send the code. Please try again.")
    return cid, (code if _demo_on() else None)


def _start_response(cid: str, channel: str, dest: str, code: Optional[str]) -> dict:
    return {"challenge_id": cid, "channel": channel, "sent_to": mask(channel, dest),
            "expires_in": OTP_TTL_S, "resend_after": RESEND_COOLDOWN_S, "demo_code": code}


def _create_session(c: sqlite3.Connection, user_id: int, request: Request, response: Response) -> None:
    token = secrets.token_urlsafe(32)
    c.execute("INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)",
              (_sha(token), user_id, _now() + SESSION_TTL_S))
    c.commit()
    response.set_cookie(COOKIE, token, max_age=SESSION_TTL_S, httponly=True,
                        samesite="lax", secure=_is_https(request), path="/")


def _public(u: sqlite3.Row) -> dict:
    return {"id": u["id"], "name": u["name"], "email": u["email"], "phone": u["phone"]}


def current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    c = _conn()
    try:
        row = c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
                        "WHERE s.token_hash=? AND s.expires>?", (_sha(token), _now())).fetchone()
        return _public(row) if row else None
    finally:
        c.close()


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------
class StartBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["signin", "signup"]
    identifier: Optional[str] = Field(None, max_length=254)   # signin: email or phone
    name: Optional[str] = Field(None, max_length=100)         # signup
    email: Optional[str] = Field(None, max_length=254)
    phone: Optional[str] = Field(None, max_length=40)
    channel: Optional[Literal["email", "phone"]] = None       # signup: where to send the code


class VerifyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(max_length=64)
    code: str = Field(max_length=12)


@router.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(Path(__file__).parent / "login.html")


@router.get("/auth/config")
def auth_config() -> dict:
    return {"demo_otp": _demo_on(), "email_delivery": _email_configured(),
            "sms_delivery": _sms_configured(),
            "auth_required": os.environ.get("AUTH_REQUIRED", "0") == "1"}


@router.post("/auth/start")
def auth_start(body: StartBody, request: Request) -> dict:
    c = _conn()
    try:
        if body.mode == "signin":
            ident = (body.identifier or "").strip()
            if "@" in ident:
                channel, dest = "email", norm_email(ident)
            else:
                channel, dest = "phone", norm_phone(ident)
            if not dest:
                raise HTTPException(400, "Enter a valid email address or phone number.")
            col = "email" if channel == "email" else "phone"
            user = c.execute(f"SELECT id FROM users WHERE {col}=?", (dest,)).fetchone()
            if user is None:
                # Same shape as success, nothing sent: does not reveal whether the account exists.
                return _start_response(secrets.token_hex(16), channel, dest, None)
            cid, code = _issue(c, request, "signin", user["id"], {}, channel, dest)
            return _start_response(cid, channel, dest, code)

        # signup
        name, email, phone = norm_name(body.name or ""), norm_email(body.email or ""), norm_phone(body.phone or "")
        if not name:
            raise HTTPException(400, "Enter your name (letters, spaces, . ' - only).")
        if not email:
            raise HTTPException(400, "Enter a valid email address.")
        if not phone:
            raise HTTPException(400, "Enter a valid phone number (10 digits, or +country code).")
        channel = body.channel or "email"
        if c.execute("SELECT 1 FROM users WHERE email=? OR phone=?", (email, phone)).fetchone():
            raise HTTPException(409, "An account with this email or phone already exists. Please sign in.")
        dest = email if channel == "email" else phone
        cid, code = _issue(c, request, "signup", None, {"name": name, "email": email, "phone": phone},
                           channel, dest)
        return _start_response(cid, channel, dest, code)
    finally:
        c.close()


@router.post("/auth/verify")
def auth_verify(body: VerifyBody, request: Request, response: Response) -> dict:
    bad = HTTPException(400, "Invalid or expired code.")
    c = _conn()
    try:
        ch = c.execute("SELECT * FROM challenges WHERE id=?", (body.challenge_id,)).fetchone()
        if ch is None or ch["used"] or ch["expires"] < _now() or ch["attempts"] >= OTP_MAX_ATTEMPTS:
            raise bad
        code = re.sub(r"\D", "", body.code)
        if not hmac.compare_digest(_code_hash(ch["id"], code), ch["code_hash"]):
            c.execute("UPDATE challenges SET attempts=attempts+1 WHERE id=?", (ch["id"],))
            c.commit()
            left = OTP_MAX_ATTEMPTS - ch["attempts"] - 1
            raise HTTPException(400, f"Incorrect code. {max(left, 0)} attempt(s) left.")
        c.execute("UPDATE challenges SET used=1 WHERE id=?", (ch["id"],))
        verified_col = "email_verified" if ch["channel"] == "email" else "phone_verified"

        if ch["purpose"] == "signin":
            user = c.execute("SELECT * FROM users WHERE id=?", (ch["user_id"],)).fetchone()
            if user is None:
                raise bad
            c.execute(f"UPDATE users SET {verified_col}=1 WHERE id=?", (user["id"],))
            uid = user["id"]
        else:
            try:
                cur = c.execute(
                    f"INSERT INTO users(name,email,phone,{verified_col},created) VALUES(?,?,?,1,?)",
                    (ch["name"], ch["email"], ch["phone"], _now()))
            except sqlite3.IntegrityError:
                c.commit()
                raise HTTPException(409, "An account with this email or phone already exists. Please sign in.")
            uid = cur.lastrowid
        c.commit()
        _create_session(c, uid, request, response)
        return {"authenticated": True,
                "user": _public(c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())}
    finally:
        c.close()


@router.get("/auth/me")
def auth_me(request: Request) -> dict:
    user = current_user(request)
    return {"authenticated": user is not None, "user": user}


@router.post("/auth/logout")
def auth_logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(COOKIE)
    if token:
        c = _conn()
        try:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (_sha(token),))
            c.commit()
        finally:
            c.close()
    response.delete_cookie(COOKIE, path="/")
    return {"authenticated": False}

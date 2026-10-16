"""Auth tests. Run:  python tests_auth.py   (offline; no SMS/email provider needed)."""
import os
import sqlite3
import sys
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["AUTH_DB"] = os.path.join(_tmp, "auth_test.db")
os.environ["AUTH_SECRET"] = "test-secret"
os.environ["AUTH_DEMO_OTP"] = "1"
os.environ.pop("AUTH_REQUIRED", None)

from fastapi.testclient import TestClient  # noqa: E402

import auth  # noqa: E402
from main import app  # noqa: E402

fails = 0


def check(name, cond, extra=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if (extra and not cond) else ""))
    fails += 0 if cond else 1


def fresh():
    """New client + cleared rate-limit memory + no cooldown (unless a test wants it)."""
    auth._ip_hits.clear()
    auth.RESEND_COOLDOWN_S = 0
    c = TestClient(app)
    auth._conn().close()                       # make sure the schema exists
    with sqlite3.connect(os.environ["AUTH_DB"]) as raw:
        raw.execute("DELETE FROM sends")       # reset the hourly send log between tests
    return c


def signup(c, name="Asha Rao", email="asha@example.com", phone="9876543210", channel="email"):
    return c.post("/auth/start", json={"mode": "signup", "name": name, "email": email,
                                       "phone": phone, "channel": channel})


# ---- sign up, session, sign out --------------------------------------------
c = fresh()
r = signup(c)
check("signup/start ok and returns demo code", r.status_code == 200 and len(r.json()["demo_code"] or "") == 6, r.text)
d = r.json()
check("destination is masked", d["sent_to"] == "a***@example.com", d["sent_to"])
check("not signed in before verify", c.get("/auth/me").json()["authenticated"] is False)

r = c.post("/auth/verify", json={"challenge_id": d["challenge_id"], "code": d["demo_code"]})
check("verify creates account + session", r.status_code == 200 and r.json()["user"]["name"] == "Asha Rao", r.text)
sc = r.headers.get("set-cookie", "")
check("cookie is HttpOnly + SameSite=lax", "HttpOnly" in sc and "samesite=lax" in sc.lower(), sc)
check("/auth/me shows the user", c.get("/auth/me").json()["user"]["email"] == "asha@example.com")
check("phone normalized to +91", c.get("/auth/me").json()["user"]["phone"] == "+919876543210")
check("code reuse rejected", c.post("/auth/verify", json={"challenge_id": d["challenge_id"], "code": d["demo_code"]}).status_code == 400)
c.post("/auth/logout")
check("logout clears session", c.get("/auth/me").json()["authenticated"] is False)

# ---- secrets never stored in the clear -------------------------------------
db = sqlite3.connect(os.environ["AUTH_DB"])
hashes = [row[0] for row in db.execute("SELECT code_hash FROM challenges")]
check("OTP stored only as a hash", all(d["demo_code"] not in h for h in hashes) and all(len(h) == 64 for h in hashes))
check("session tokens stored only as hashes",
      all(len(row[0]) == 64 for row in db.execute("SELECT token_hash FROM sessions")))

# ---- sign in by email and by phone -----------------------------------------
for label, ident in [("email", "ASHA@example.com "), ("phone (10 digit)", "98765 43210"), ("phone (+91)", "+919876543210")]:
    c = fresh()
    s = c.post("/auth/start", json={"mode": "signin", "identifier": ident}).json()
    v = c.post("/auth/verify", json={"challenge_id": s["challenge_id"], "code": s["demo_code"]})
    check(f"sign in with {label}", v.status_code == 200 and c.get("/auth/me").json()["authenticated"], v.text)

# ---- wrong codes, lockout --------------------------------------------------
c = fresh()
s = c.post("/auth/start", json={"mode": "signin", "identifier": "asha@example.com"}).json()
wrong = "000000" if s["demo_code"] != "000000" else "111111"
r = c.post("/auth/verify", json={"challenge_id": s["challenge_id"], "code": wrong})
check("wrong code rejected and counts attempts", r.status_code == 400 and "4 attempt" in r.json()["detail"], r.text)
for _ in range(4):
    c.post("/auth/verify", json={"challenge_id": s["challenge_id"], "code": wrong})
r = c.post("/auth/verify", json={"challenge_id": s["challenge_id"], "code": s["demo_code"]})
check("locked after 5 wrong attempts, even with the right code", r.status_code == 400)

# ---- expiry ----------------------------------------------------------------
c = fresh()
s = c.post("/auth/start", json={"mode": "signin", "identifier": "asha@example.com"}).json()
db.execute("UPDATE challenges SET expires=1 WHERE id=?", (s["challenge_id"],)); db.commit()
check("expired code rejected", c.post("/auth/verify", json={"challenge_id": s["challenge_id"], "code": s["demo_code"]}).status_code == 400)

# ---- no account enumeration on sign-in -------------------------------------
c = fresh()
known = c.post("/auth/start", json={"mode": "signin", "identifier": "asha@example.com"}).json()
unknown = c.post("/auth/start", json={"mode": "signin", "identifier": "nobody@example.com"}).json()
check("unknown sign-in: same response shape", set(known) == set(unknown))
check("unknown sign-in: no code issued", unknown["demo_code"] is None)
check("unknown sign-in: verify fails generically",
      c.post("/auth/verify", json={"challenge_id": unknown["challenge_id"], "code": "123456"}).status_code == 400)

# ---- validation ------------------------------------------------------------
c = fresh()
check("bad email rejected", signup(c, email="not-an-email", phone="9111111111").status_code == 400)
check("bad phone rejected", signup(c, email="b@example.com", phone="12345").status_code == 400)
check("bad name rejected", signup(c, name="<script>alert(1)</script>", email="c@example.com", phone="9222222222").status_code == 400)
check("duplicate signup -> 409", signup(c).status_code == 409)
check("sign-in with garbage identifier -> 400", c.post("/auth/start", json={"mode": "signin", "identifier": "hello"}).status_code == 400)
check("unknown fields rejected", c.post("/auth/start", json={"mode": "signin", "identifier": "a@b.co", "admin": True}).status_code == 422)
check("signup via phone channel masks the phone",
      signup(c, name="Ravi K", email="ravi@example.com", phone="+14155550123", channel="phone").json()["sent_to"].endswith("0123"))

# ---- rate limits -----------------------------------------------------------
c = fresh()
auth.RESEND_COOLDOWN_S = 30
signin = {"mode": "signin", "identifier": "asha@example.com"}
c.post("/auth/start", json=signin)
r = c.post("/auth/start", json=signin)
check("resend cooldown -> 429 with Retry-After", r.status_code == 429 and "Retry-After" in r.headers, r.text)
c = fresh()
codes = [c.post("/auth/start", json=signin).status_code for _ in range(7)]
check("hourly per-destination cap -> 429", codes[:1] == [200] and 429 in codes, str(codes))

# ---- delivery modes --------------------------------------------------------
c = fresh()
os.environ["AUTH_DEMO_OTP"] = "0"
r = c.post("/auth/start", json={"mode": "signin", "identifier": "asha@example.com"})
check("demo off + no provider -> 503", r.status_code == 503, r.text)

sent = {}
auth._send_email = lambda to, code: sent.update(to=to, code=code)
os.environ.update(SMTP_HOST="smtp.test", SMTP_USER="u", SMTP_PASS="p")
c = fresh()
r = c.post("/auth/start", json={"mode": "signin", "identifier": "asha@example.com"})
check("email provider called with the code", sent.get("to") == "asha@example.com" and len(sent.get("code", "")) == 6, str(sent))
check("demo off: code NOT returned to the browser", r.status_code == 200 and r.json()["demo_code"] is None, r.text)
v = c.post("/auth/verify", json={"challenge_id": r.json()["challenge_id"], "code": sent["code"]})
check("code from provider verifies", v.status_code == 200, v.text)


def boom(*a):
    raise RuntimeError("smtp down")


auth._send_email = boom
c = fresh()
r = c.post("/auth/start", json={"mode": "signin", "identifier": "asha@example.com"})
check("provider failure -> 502, nothing usable left behind", r.status_code == 502, r.text)
for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS"):
    os.environ.pop(k)
os.environ["AUTH_DEMO_OTP"] = "1"

# ---- gating the firewall behind login --------------------------------------
c = fresh()
check("firewall open by default", c.post("/analyze", json={"message": "check my balance"}).status_code == 200)
os.environ["AUTH_REQUIRED"] = "1"
check("AUTH_REQUIRED: /analyze -> 401 when signed out", c.post("/analyze", json={"message": "check my balance"}).status_code == 401)
check("AUTH_REQUIRED: /request -> 401 when signed out", c.post("/request", json={"message": "check my balance"}).status_code == 401)
check("AUTH_REQUIRED: /health and /login stay public", c.get("/health").status_code == 200 and c.get("/login").status_code == 200)
s = c.post("/auth/start", json={"mode": "signin", "identifier": "asha@example.com"}).json()
c.post("/auth/verify", json={"challenge_id": s["challenge_id"], "code": s["demo_code"]})
r = c.post("/request", json={"message": "check my balance"})
check("AUTH_REQUIRED: signed-in user gets through", r.status_code == 200 and r.json()["firewall"]["status"] == "APPROVED", r.text)
os.environ.pop("AUTH_REQUIRED")

check("/login and / pages serve", c.get("/login").status_code == 200 and "Sign in" in c.get("/login").text and c.get("/").status_code == 200)

print("\nALL AUTH CHECKS PASSED" if not fails else f"\n{fails} CHECK(S) FAILED")
sys.exit(1 if fails else 0)

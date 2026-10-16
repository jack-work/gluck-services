import hashlib
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata

from flask import Blueprint, abort, current_app, redirect, render_template, request

import mail

HOST = os.environ.get("SETTINGS_HOST", "settings.kelliher.info")
ORIGIN = f"https://{HOST}"
COOKIE = "zanni-scheme"
COOKIE_DOMAIN = os.environ.get("SETTINGS_COOKIE_DOMAIN", "kelliher.info")
COOKIE_AGE = 365 * 24 * 3600
SCHEMES = ("light", "dark")
DB_PATH = os.environ.get(
    "SETTINGS_DB", os.path.join(os.environ.get("STATE_DIRECTORY", "/var/lib/gluck-accounts"), "settings.db")
)
CONFIRM_TTL = 3600
REQUESTS_PER_DAY = 3
NAME_MAX = 64
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CSP = (
    "default-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)

REQUEST_NOTICE = """Hello {who},

Someone signed in as {who} on kelliher.info asked to change the email
address on the account from

  {old}

to

  {new}

Nothing has changed yet. The change happens only if the link sent to the
new address is opened and confirmed within an hour.

If this was not you, the account's password is known to someone else.
Tell Jack, and do not confirm anything.
"""

CONFIRM = """Hello {who},

To make this the email address for the kelliher.info account {who},
open this link while signed in and press Confirm:

  {url}

The link works once, for an hour. Password resets and sign-in codes will
come here afterwards. If you did not ask for this, ignore it and nothing
changes.
"""

CHANGED_NOTICE = """Hello {who},

The email address on the kelliher.info account {who} was changed from

  {old}

to

  {new}

Password resets and sign-in codes now go to the new address. If this was
not you, tell Jack.
"""


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.conn = None

    @property
    def db(self):
        if self.conn is None:
            self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS email_change ("
                " token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, old_email TEXT NOT NULL,"
                " new_email TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,"
                " state TEXT NOT NULL DEFAULT 'pending')"
            )
        return self.conn

    def recent(self, username, now):
        with self.lock:
            return self.db.execute(
                "SELECT count(*) FROM email_change WHERE username = ? AND created > ?",
                (username, now - 86400),
            ).fetchone()[0]

    def pending(self, username, now):
        with self.lock:
            return self.db.execute(
                "SELECT new_email, expires FROM email_change"
                " WHERE username = ? AND state = 'pending' AND expires > ? ORDER BY created DESC LIMIT 1",
                (username, now),
            ).fetchone()

    def open(self, token_hash, username, old, new, now):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute(
                "UPDATE email_change SET state = 'superseded' WHERE username = ? AND state = 'pending'",
                (username,),
            )
            self.db.execute(
                "INSERT INTO email_change (token_hash, username, old_email, new_email, created, expires)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (token_hash, username, old, new, now, now + CONFIRM_TTL),
            )
            self.db.execute("COMMIT")

    def drop(self, token_hash):
        with self.lock:
            self.db.execute("DELETE FROM email_change WHERE token_hash = ?", (token_hash,))

    def claim(self, token_hash, username, now):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT old_email, new_email FROM email_change"
                " WHERE token_hash = ? AND username = ? AND state = 'pending' AND expires > ?",
                (token_hash, username, now),
            ).fetchone()
            if row:
                self.db.execute("UPDATE email_change SET state = 'used' WHERE token_hash = ?", (token_hash,))
            self.db.execute("COMMIT")
            return row


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def clean_name(raw):
    name = unicodedata.normalize("NFC", (raw or "").strip())
    if not name or len(name) > NAME_MAX or any(unicodedata.category(c).startswith("C") for c in name):
        return None
    return name


def clean_email(raw):
    email = (raw or "").strip().lower()
    return email if len(email) <= 254 and EMAIL_RE.fullmatch(email) else None


def make_blueprint(lldap_token, gql, caller):
    bp = Blueprint("settings", __name__)
    store = Store(DB_PATH)

    def user(token, username):
        data = gql(token, "query($id: String!) { user(userId: $id) { id email displayName } }", {"id": username})
        return data["user"]

    def update(token, username, **fields):
        gql(
            token,
            "mutation($u: UpdateUserInput!) { updateUser(user: $u) { ok } }",
            {"u": dict(id=username, **fields)},
        )

    def email_taken(token, email, username):
        data = gql(
            token,
            "query($e: String!) { users(filters: {eq: {field: \"email\", value: $e}}) { id } }",
            {"e": email},
        )
        return any(u["id"] != username for u in data["users"])

    def who():
        username = caller()
        if not username:
            abort(401)
        return username

    def same_origin():
        if request.headers.get("Origin") != ORIGIN:
            abort(403)

    def page(username, status=200, notice=None, error=None):
        token = lldap_token()
        account = user(token, username)
        pending = store.pending(username, int(time.time()))
        scheme = request.cookies.get(COOKIE)
        return (
            render_template(
                "settings.html",
                username=username,
                display_name=account["displayName"],
                email=account["email"],
                pending=pending[0] if pending else None,
                current=scheme if scheme in SCHEMES else "system",
                scheme=scheme if scheme in SCHEMES else None,
                notice=notice,
                error=error,
            ),
            status,
        )

    @bp.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @bp.get("/")
    def index():
        return page(who(), notice=request.args.get("done"))

    @bp.post("/name")
    def set_name():
        username = who()
        same_origin()
        name = clean_name(request.form.get("display_name"))
        if name is None:
            return page(username, 400, error=f"A display name is 1 to {NAME_MAX} printable characters.")
        update(lldap_token(), username, displayName=name)
        current_app.logger.info("settings: %s changed display name", username)
        return redirect("/?done=name", 303)

    @bp.post("/appearance")
    def set_appearance():
        who()
        same_origin()
        choice = request.form.get("scheme")
        if choice not in SCHEMES + ("system",):
            abort(400)
        resp = redirect("/?done=appearance", 303)
        if choice == "system":
            resp.delete_cookie(COOKIE, domain=COOKIE_DOMAIN, path="/", secure=True, httponly=True, samesite="Lax")
        else:
            resp.set_cookie(
                COOKIE, choice, max_age=COOKIE_AGE, domain=COOKIE_DOMAIN, path="/",
                secure=True, httponly=True, samesite="Lax",
            )
        return resp

    @bp.post("/email")
    def request_email():
        username = who()
        same_origin()
        now = int(time.time())
        new = clean_email(request.form.get("email"))
        if new is None:
            return page(username, 400, error="That is not an email address.")
        token = lldap_token()
        old = user(token, username)["email"]
        if new == (old or "").lower():
            return page(username, 400, error="That is already the address on this account.")
        if store.recent(username, now) >= REQUESTS_PER_DAY:
            return page(username, 429, error="Too many email changes today. Try again tomorrow.")
        if email_taken(token, new, username):
            return page(username, 400, error="That address cannot be used for this account.")
        secret = secrets.token_urlsafe(32)
        hashed = digest(secret)
        store.open(hashed, username, old, new, now)
        try:
            mail.send(old, "An email change was requested on kelliher.info",
                      REQUEST_NOTICE.format(who=username, old=old, new=new))
            mail.send(new, "Confirm your new kelliher.info email address",
                      CONFIRM.format(who=username, url=f"{ORIGIN}/email/confirm?t={secret}"))
        except mail.MailFailed as e:
            store.drop(hashed)
            current_app.logger.error("settings: %s email change not opened: %s", username, e)
            return page(username, 502, error="The confirmation could not be sent. Nothing has changed.")
        current_app.logger.info("settings: %s asked to change email", username)
        return redirect("/?done=email-sent", 303)

    @bp.get("/email/confirm")
    def confirm_form():
        username = who()
        secret = request.args.get("t", "")
        return render_template("confirm.html", username=username, token=secret,
                               scheme=request.cookies.get(COOKIE) if request.cookies.get(COOKIE) in SCHEMES else None)

    @bp.post("/email/confirm")
    def confirm():
        username = who()
        same_origin()
        row = store.claim(digest(request.form.get("t", "")), username, int(time.time()))
        if row is None:
            return page(username, 400, error="That confirmation link is not valid for this account. Nothing has changed.")
        old, new = row
        token = lldap_token()
        if (user(token, username)["email"] or "") != old:
            return page(username, 409, error="The address changed in the meantime. Nothing has changed; ask again.")
        update(token, username, email=new)
        current_app.logger.info("settings: %s changed email", username)
        try:
            mail.send(old, "Your kelliher.info email address was changed",
                      CHANGED_NOTICE.format(who=username, old=old, new=new))
        except mail.MailFailed as e:
            current_app.logger.error("settings: %s changed email, notice to the old address failed: %s", username, e)
        return redirect("/?done=email", 303)

    return bp

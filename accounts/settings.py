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

HOST = os.environ.get("SETTINGS_HOST", "me.kelliher.info")
ORIGIN = f"https://{HOST}"
AUTH = os.environ.get("SETTINGS_AUTH_ORIGIN", "https://auth.kelliher.info")
METHODS = f"{AUTH}/settings/two-factor-authentication"
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
EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$")
CSP = (
    "default-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)

OLD_SIDE = """Hello {who},

Someone signed in as {who} on kelliher.info asked to move the account's
email address from this one to

  {new}

That address is where password resets and sign-in codes go, so the move
needs this address to agree. If you asked for it, open this link while
signed in and press Confirm:

  {url}

If you did not, do nothing and nothing changes, and tell Jack: someone
holds a signed-in session for your account.

The link works once, for a day. The new address has to confirm too.
"""

NEW_SIDE = """Hello {who},

To make this the email address for the kelliher.info account {who},
open this link while signed in and press Confirm:

  {url}

The link works once, for a day. The account's current address has to
confirm too. If you did not ask for this, ignore it and nothing changes.
"""

CHANGED_NOTICE = """Hello {who},

The email address on the kelliher.info account {who} was changed from

  {old}

to

  {new}

after both addresses confirmed. Password resets and sign-in codes now go
to the new address.
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
                " id INTEGER PRIMARY KEY, username TEXT NOT NULL, old_email TEXT NOT NULL,"
                " new_email TEXT NOT NULL, old_hash TEXT NOT NULL UNIQUE, new_hash TEXT NOT NULL UNIQUE,"
                " old_ok INTEGER NOT NULL DEFAULT 0, new_ok INTEGER NOT NULL DEFAULT 0,"
                " created INTEGER NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending')"
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
                "SELECT new_email, old_ok, new_ok FROM email_change"
                " WHERE username = ? AND state = 'pending' AND expires > ? ORDER BY created DESC LIMIT 1",
                (username, now),
            ).fetchone()

    def open(self, username, old, new, old_hash, new_hash, now):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute(
                "UPDATE email_change SET state = 'superseded' WHERE username = ? AND state = 'pending'",
                (username,),
            )
            cur = self.db.execute(
                "INSERT INTO email_change (username, old_email, new_email, old_hash, new_hash, created, expires)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, old, new, old_hash, new_hash, now, now + CONFIRM_TTL),
            )
            self.db.execute("COMMIT")
            return cur.lastrowid

    def drop(self, change_id):
        with self.lock:
            self.db.execute("DELETE FROM email_change WHERE id = ?", (change_id,))

    def describe(self, token_hash, now):
        with self.lock:
            return self.db.execute(
                "SELECT username, old_email, new_email FROM email_change"
                " WHERE (old_hash = ? OR new_hash = ?) AND state = 'pending' AND expires > ?"
                " AND NOT (old_hash = ? AND old_ok) AND NOT (new_hash = ? AND new_ok)",
                (token_hash, token_hash, now, token_hash, token_hash),
            ).fetchone()

    def confirm(self, token_hash, now):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT id, username, old_email, new_email, old_hash = ?, old_ok, new_ok FROM email_change"
                " WHERE (old_hash = ? OR new_hash = ?) AND state = 'pending' AND expires > ?",
                (token_hash, token_hash, token_hash, now),
            ).fetchone()
            if row is None:
                self.db.execute("COMMIT")
                return None
            change_id, username, old, new, is_old, old_ok, new_ok = row
            if (old_ok if is_old else new_ok):
                self.db.execute("COMMIT")
                return None
            old_ok, new_ok = (1, new_ok) if is_old else (old_ok, 1)
            done = old_ok and new_ok
            self.db.execute(
                "UPDATE email_change SET old_ok = ?, new_ok = ?, state = ? WHERE id = ?",
                (old_ok, new_ok, "used" if done else "pending", change_id),
            )
            self.db.execute("COMMIT")
            return username, old, new, bool(done)


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
                waiting_for=None if not pending else ("the old address" if not pending[1] and pending[2]
                                                      else "the new address" if pending[1] and not pending[2]
                                                      else "both addresses"),
                current=scheme if scheme in SCHEMES else "system",
                scheme=scheme if scheme in SCHEMES else None,
                notice=notice,
                error=error,
                methods=METHODS,
                password=f"{AUTH}/settings/security#password",
            ),
            status,
        )

    @bp.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "strict-origin"
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
        old = (user(token, username)["email"] or "").strip()
        if not old:
            return page(username, 409, error="This account has no address to confirm from. Ask Jack to set one.")
        if new == old.lower():
            return page(username, 400, error="That is already the address on this account.")
        if store.recent(username, now) >= REQUESTS_PER_DAY:
            return page(username, 429, error="Too many email changes today. Try again tomorrow.")
        if email_taken(token, new, username):
            return page(username, 400, error="That address cannot be used for this account.")
        old_secret, new_secret = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        change_id = store.open(username, old, new, digest(old_secret), digest(new_secret), now)
        try:
            mail.send(old, "Confirm moving your kelliher.info email address",
                      OLD_SIDE.format(who=username, new=new, url=f"{ORIGIN}/email/confirm?t={old_secret}"))
            mail.send(new, "Confirm your new kelliher.info email address",
                      NEW_SIDE.format(who=username, url=f"{ORIGIN}/email/confirm?t={new_secret}"))
        except mail.MailFailed as e:
            store.drop(change_id)
            current_app.logger.error("settings: %s email change not opened: %s", username, e)
            return page(username, 502, error="The confirmations could not be sent. Nothing has changed.")
        current_app.logger.info("settings: %s asked to change email", username)
        return redirect("/?done=email-sent", 303)

    def scheme():
        return request.cookies.get(COOKIE) if request.cookies.get(COOKIE) in SCHEMES else None

    def outcome(status, heading, message):
        return render_template("confirmed.html", heading=heading, message=message, scheme=scheme()), status

    @bp.get("/email/confirm")
    def confirm_form():
        secret = request.args.get("t", "")
        change = store.describe(digest(secret), int(time.time()))
        if change is None:
            return outcome(400, "Not valid", "That confirmation link is used, expired or replaced. Nothing has changed.")
        username, old, new = change
        return render_template("confirm.html", username=username, token=secret, old=old, new=new, scheme=scheme())

    @bp.post("/email/confirm")
    def confirm():
        same_origin()
        result = store.confirm(digest(request.form.get("t", "")), int(time.time()))
        if result is None:
            return outcome(400, "Not valid", "That confirmation link is used, expired or replaced. Nothing has changed.")
        username, old, new, done = result
        if not done:
            current_app.logger.info("settings: %s confirmed one side of an email change", username)
            return outcome(200, "Confirmed", "This address has confirmed. The change happens when the other address confirms too.")
        token = lldap_token()
        if (user(token, username)["email"] or "").strip() != old:
            return outcome(409, "Not changed", "The address changed in the meantime. Nothing has changed; ask again.")
        update(token, username, email=new)
        current_app.logger.info("settings: %s changed email", username)
        try:
            mail.send(old, "Your kelliher.info email address was changed",
                      CHANGED_NOTICE.format(who=username, old=old, new=new))
        except mail.MailFailed as e:
            current_app.logger.error("settings: %s changed email, notice to the old address failed: %s", username, e)
        return outcome(200, "Changed", f"{username} now uses {new}. A notice went to {old}.")

    return bp

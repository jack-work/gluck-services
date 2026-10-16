"""settings.kelliher.info: a signed-in user changes their own display name,
email address and appearance, and nothing else.

Defends, against a stand-in lldap that records every mutation:
  - the page and every write are for Remote-User's own account only
  - a write needs Origin https://settings.kelliher.info (no cross-site POST)
  - an email change reaches lldap only after the link mailed to the NEW
    address is confirmed, by the same user, once, within the hour; the OLD
    address is told when it is asked for and again when it happens
  - opening the link (GET) changes nothing, so a mail scanner cannot confirm
  - the token is never stored in the clear
  - the appearance cookie carries only light or dark, Domain=kelliher.info
"""

import http.server
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

TMP = tempfile.mkdtemp()
os.environ["LLDAP_PASSWORD_FILE"] = os.path.join(TMP, "pw")
Path(os.environ["LLDAP_PASSWORD_FILE"]).write_text("fixture")
os.environ["SETTINGS_DB"] = os.path.join(TMP, "settings.db")

USERS = {}
MUTATIONS = []


class FakeLldap(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, body):
        b = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/auth/simple/login":
            return self.reply({"token": "t"})
        q, v = req["query"], req.get("variables", {})
        if "updateUser" in q:
            u = v["u"]
            MUTATIONS.append(dict(u))
            for k, field in (("email", "email"), ("displayName", "displayName")):
                if k in u:
                    USERS[u["id"]][field] = u[k]
            return self.reply({"data": {"updateUser": {"ok": True}}})
        if "users(filters" in q:
            return self.reply({"data": {"users": [{"id": i} for i, x in USERS.items() if x["email"] == v["e"]]}})
        if "user(userId" in q:
            x = USERS.get(v["id"])
            return self.reply({"data": {"user": dict(id=v["id"], **x) if x else None}})
        self.reply({"errors": [f"unexpected query {q}"]})


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeLldap)
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["LLDAP_URL"] = f"http://127.0.0.1:{srv.server_address[1]}"

import gluck_accounts  # noqa: E402
import mail  # noqa: E402
import settings  # noqa: E402

SENT = []
FAIL_MAIL = {"to": None}


def fake_send(to, subject, body):
    if FAIL_MAIL["to"] == to:
        raise mail.MailFailed(f"to {to}: refused")
    SENT.append((to, subject, body))


mail.send = fake_send

HOST = "http://settings.kelliher.info"
ORIGIN = {"Origin": "https://settings.kelliher.info"}


def token_from(body):
    return body.split("/email/confirm?t=", 1)[1].split()[0]


class Settings(unittest.TestCase):
    def setUp(self):
        USERS.clear()
        USERS["alice"] = {"email": "alice@old.example", "displayName": "Alice"}
        USERS["bob"] = {"email": "bob@example.com", "displayName": "Bob"}
        MUTATIONS.clear()
        SENT.clear()
        FAIL_MAIL["to"] = None
        self.c = gluck_accounts.app.test_client()
        self.c.get("/", headers={"Remote-User": "alice"}, base_url=HOST)
        db = sqlite3.connect(os.environ["SETTINGS_DB"])
        db.execute("DELETE FROM email_change")
        db.commit()

    def get(self, path, user="alice", host=HOST):
        h = {"Remote-User": user} if user else {}
        return self.c.get(path, headers=h, base_url=host)

    def post(self, path, data, user="alice", origin=ORIGIN):
        h = dict(origin or {})
        if user:
            h["Remote-User"] = user
        return self.c.post(path, data=data, headers=h, base_url=HOST)

    def ask(self, email="alice@new.example", user="alice"):
        r = self.post("/email", {"email": email}, user=user)
        confirm = [b for to, _, b in SENT if "/email/confirm?t=" in b]
        return r, (token_from(confirm[-1]) if confirm else None)

    def test_page_shows_only_the_callers_account(self):
        r = self.get("/")
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("alice@old.example", body)
        self.assertNotIn("bob@example.com", body)
        self.assertNotIn("<script", body.lower())
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_identity_is_required(self):
        self.assertEqual(self.get("/", user=None).status_code, 401)
        self.assertEqual(self.post("/name", {"display_name": "X"}, user=None).status_code, 401)
        self.assertEqual(MUTATIONS, [])

    def test_each_host_serves_only_its_own_routes(self):
        self.assertEqual(self.get("/", host="http://accounts.kelliher.info").status_code, 404)
        r = self.c.post("/accounts", json={}, headers={"Remote-User": "alice", "Remote-Groups": "accounts-create"},
                        base_url=HOST)
        self.assertEqual(r.status_code, 404)

    def test_a_write_without_our_origin_is_refused(self):
        for origin in (None, {"Origin": "https://f.kelliher.info"}, {"Origin": "null"}):
            self.assertEqual(self.post("/name", {"display_name": "Mallory"}, origin=origin).status_code, 403)
            self.assertEqual(self.post("/email", {"email": "m@evil.example"}, origin=origin).status_code, 403)
            self.assertEqual(self.post("/appearance", {"scheme": "dark"}, origin=origin).status_code, 403)
            self.assertEqual(self.post("/email/confirm", {"t": "x"}, origin=origin).status_code, 403)
        self.assertEqual(MUTATIONS, [])
        self.assertEqual(SENT, [])

    def test_display_name_changes_the_callers_account(self):
        r = self.post("/name", {"display_name": "  Alice K.  "})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(MUTATIONS, [{"id": "alice", "displayName": "Alice K."}])

    def test_a_bad_display_name_changes_nothing(self):
        for bad in ("", "   ", "x" * 65, "Ali\u0000ce", "Ali\nce", "a\u202eb"):
            self.assertEqual(self.post("/name", {"display_name": bad}).status_code, 400, repr(bad))
        self.assertEqual(MUTATIONS, [])

    def test_appearance_cookie_carries_only_the_scheme(self):
        for s in ("light", "dark"):
            r = self.post("/appearance", {"scheme": s})
            cookie = r.headers["Set-Cookie"]
            self.assertTrue(cookie.startswith(f"zanni-scheme={s};"), cookie)
            for part in ("Domain=kelliher.info", "Path=/", "Secure", "HttpOnly", "SameSite=Lax"):
                self.assertIn(part, cookie)
        r = self.post("/appearance", {"scheme": "system"})
        self.assertIn("zanni-scheme=;", r.headers["Set-Cookie"])
        self.assertIn("Max-Age=0", r.headers["Set-Cookie"])
        self.assertEqual(self.post("/appearance", {"scheme": "sepia"}).status_code, 400)
        self.assertEqual(MUTATIONS, [])

    def test_asking_mails_new_and_old_and_changes_nothing(self):
        r, tok = self.ask()
        self.assertEqual(r.status_code, 303)
        self.assertEqual([to for to, _, _ in SENT], ["alice@old.example", "alice@new.example"])
        self.assertIn("alice@new.example", SENT[0][2])
        self.assertNotIn(tok, SENT[0][2])
        self.assertEqual(MUTATIONS, [])
        self.assertEqual(USERS["alice"]["email"], "alice@old.example")
        stored = sqlite3.connect(os.environ["SETTINGS_DB"]).execute("SELECT token_hash FROM email_change").fetchall()
        self.assertEqual(len(stored), 1)
        self.assertNotEqual(stored[0][0], tok)
        self.assertNotIn(tok, Path(os.environ["SETTINGS_DB"]).read_bytes().decode("latin-1"))

    def test_opening_the_link_changes_nothing(self):
        _, tok = self.ask()
        r = self.get("/email/confirm?t=" + tok)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(MUTATIONS, [])

    def test_confirming_changes_the_address_once_and_tells_the_old_one(self):
        _, tok = self.ask()
        SENT.clear()
        r = self.post("/email/confirm", {"t": tok})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(MUTATIONS, [{"id": "alice", "email": "alice@new.example"}])
        self.assertEqual([to for to, _, _ in SENT], ["alice@old.example"])
        self.assertIn("was changed", SENT[0][1])
        self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 400)
        self.assertEqual(len(MUTATIONS), 1)

    def test_another_user_cannot_confirm_and_does_not_burn_the_link(self):
        _, tok = self.ask()
        self.assertEqual(self.post("/email/confirm", {"t": tok}, user="bob").status_code, 400)
        self.assertEqual(MUTATIONS, [])
        self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 303)

    def test_a_wrong_or_expired_token_is_refused(self):
        _, tok = self.ask()
        self.assertEqual(self.post("/email/confirm", {"t": tok + "x"}).status_code, 400)
        self.assertEqual(self.post("/email/confirm", {"t": ""}).status_code, 400)
        db = sqlite3.connect(os.environ["SETTINGS_DB"])
        db.execute("UPDATE email_change SET expires = 0")
        db.commit()
        self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 400)
        self.assertEqual(MUTATIONS, [])

    def test_a_newer_request_supersedes_the_older_link(self):
        _, first = self.ask("alice@one.example")
        _, second = self.ask("alice@two.example")
        self.assertEqual(self.post("/email/confirm", {"t": first}).status_code, 400)
        self.assertEqual(self.post("/email/confirm", {"t": second}).status_code, 303)
        self.assertEqual(MUTATIONS, [{"id": "alice", "email": "alice@two.example"}])

    def test_a_change_in_the_meantime_voids_the_link(self):
        _, tok = self.ask()
        USERS["alice"]["email"] = "alice@elsewhere.example"
        self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 409)
        self.assertEqual(MUTATIONS, [])

    def test_bad_same_or_taken_addresses_mail_nobody(self):
        for email in ("not-an-address", "alice@old.example", "ALICE@OLD.EXAMPLE", "bob@example.com"):
            r, _ = self.ask(email)
            self.assertEqual(r.status_code, 400, email)
        self.assertEqual(SENT, [])

    def test_three_requests_a_day(self):
        for i in range(3):
            self.assertEqual(self.ask(f"alice@n{i}.example")[0].status_code, 303)
        SENT.clear()
        self.assertEqual(self.ask("alice@n4.example")[0].status_code, 429)
        self.assertEqual(SENT, [])

    def test_if_the_old_address_cannot_be_told_nothing_is_opened(self):
        FAIL_MAIL["to"] = "alice@old.example"
        r, tok = self.ask()
        self.assertEqual(r.status_code, 502)
        self.assertIsNone(tok)
        self.assertEqual(sqlite3.connect(os.environ["SETTINGS_DB"]).execute(
            "SELECT count(*) FROM email_change WHERE state = 'pending'").fetchone()[0], 0)

    def test_the_page_renders_the_pinned_scheme(self):
        self.c.set_cookie("zanni-scheme", "dark", domain="settings.kelliher.info")
        self.assertIn('<html lang="en" data-scheme="dark">', self.get("/").get_data(as_text=True))
        self.c.set_cookie("zanni-scheme", '"><b>', domain="settings.kelliher.info")
        self.assertNotIn("data-scheme", self.get("/").get_data(as_text=True).split("<head>")[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

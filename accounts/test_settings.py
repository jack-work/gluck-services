"""me.kelliher.info: a signed-in user changes their own display name,
email address and appearance, and nothing else.

Defends, against a stand-in lldap that records every mutation:
  - the page and every write are for Remote-User's own account only, except
    the email confirmation, which the two mailed tokens alone authorize
  - a write needs Origin https://me.kelliher.info (no cross-site POST)
  - an email change reaches lldap only after BOTH the current address and the
    new one confirm their own link, by the same signed-in user, once each,
    within a day; a stolen session alone, which controls only the new
    address, cannot complete it
  - opening the link (GET) changes nothing, so a mail scanner cannot confirm
  - the token is never stored in the clear
  - the appearance cookie carries only light or dark, Domain=kelliher.info
"""

import http.server
import json
import os
import re
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


REAL_SEND = mail.send
mail.send = fake_send

HOST = "http://me.kelliher.info"
ORIGIN = {"Origin": "https://me.kelliher.info"}


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
        before = len(SENT)
        r = self.post("/email", {"email": email}, user=user)
        links = {to: token_from(b) for to, _, b in SENT[before:] if "/email/confirm?t=" in b}
        return r, links

    def test_page_shows_only_the_callers_account(self):
        r = self.get("/")
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("alice@old.example", body)
        self.assertNotIn("bob@example.com", body)
        self.assertNotIn("<script", body.lower())
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_the_page_lets_the_browser_send_its_origin(self):
        r = self.get("/")
        self.assertEqual(r.headers["Referrer-Policy"], "strict-origin")
        body = r.get_data(as_text=True)
        self.assertIn('<meta name="referrer" content="strict-origin">', body)
        self.assertNotIn("no-referrer", body)

    def test_password_managers_are_told_these_are_profile_fields(self):
        body = self.get("/").get_data(as_text=True)
        fields = re.findall(r"<input [^>]*>", body)
        typed = [f for f in fields if 'type="radio"' not in f and 'type="hidden"' not in f]
        self.assertEqual(len(typed), 2, typed)
        for field, hint in zip(typed, ("name", "email")):
            self.assertIn(f'autocomplete="{hint}"', field)
            self.assertIn("data-1p-ignore", field)
        self.assertNotIn('type="password"', body)
        self.assertNotIn("username", " ".join(fields))

    def test_sign_in_methods_and_password_open_on_the_sign_in_site(self):
        body = self.get("/").get_data(as_text=True)
        links = re.findall(r'href="(https://[^"]+)"', body)
        self.assertEqual(links, [
            "https://auth.kelliher.info/settings/two-factor-authentication#passkey",
            "https://auth.kelliher.info/settings/two-factor-authentication#otp",
            "https://auth.kelliher.info/settings/two-factor-authentication#manage",
            "https://auth.kelliher.info/settings/security#password",
        ])

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

    def test_asking_mails_both_sides_and_changes_nothing(self):
        r, links = self.ask()
        self.assertEqual(r.status_code, 303)
        self.assertEqual([to for to, _, _ in SENT], ["alice@old.example", "alice@new.example"])
        old_tok, new_tok = links["alice@old.example"], links["alice@new.example"]
        self.assertNotEqual(old_tok, new_tok)
        self.assertNotIn(new_tok, SENT[0][2])
        self.assertNotIn(old_tok, SENT[1][2])
        self.assertIn("alice@new.example", SENT[0][2])
        self.assertEqual(MUTATIONS, [])
        raw = Path(os.environ["SETTINGS_DB"]).read_bytes().decode("latin-1")
        self.assertNotIn(old_tok, raw)
        self.assertNotIn(new_tok, raw)

    def test_opening_a_link_changes_nothing(self):
        _, links = self.ask()
        for tok in links.values():
            self.assertEqual(self.get("/email/confirm?t=" + tok).status_code, 200)
        self.assertEqual(MUTATIONS, [])

    def test_the_confirm_page_shows_where_the_address_would_move(self):
        _, links = self.ask("thief@evil.example")
        for tok in links.values():
            body = self.get("/email/confirm?t=" + tok).get_data(as_text=True)
            self.assertIn("thief@evil.example", body)
            self.assertIn("alice@old.example", body)
        self.assertEqual(self.get("/email/confirm?t=nonsense").status_code, 400)
        self.assertEqual(self.get("/email/confirm?t=nonsense", user=None).status_code, 400)

    def test_a_stolen_session_confirming_the_new_side_changes_nothing(self):
        _, links = self.ask("thief@evil.example")
        r = self.post("/email/confirm", {"t": links["thief@evil.example"]})
        self.assertEqual(r.status_code, 200)
        self.assertIn("has confirmed", r.get_data(as_text=True))
        self.assertEqual(MUTATIONS, [])
        self.assertEqual(USERS["alice"]["email"], "alice@old.example")
        self.assertEqual(self.post("/email/confirm", {"t": links["thief@evil.example"]}).status_code, 400)
        self.assertEqual(MUTATIONS, [])

    def test_both_sides_in_either_order_change_it_once_and_tell_the_old_one(self):
        for order in (("alice@new.example", "alice@old.example"), ("alice@old.example", "alice@new.example")):
            self.setUp()
            _, links = self.ask()
            SENT.clear()
            self.assertIn("has confirmed", self.post("/email/confirm", {"t": links[order[0]]}).get_data(as_text=True))
            self.assertEqual(MUTATIONS, [])
            r = self.post("/email/confirm", {"t": links[order[1]]})
            self.assertEqual(r.status_code, 200, order)
            self.assertIn("now uses alice@new.example", r.get_data(as_text=True))
            self.assertEqual(MUTATIONS, [{"id": "alice", "email": "alice@new.example"}])
            self.assertEqual([to for to, _, _ in SENT], ["alice@old.example"])
            self.assertIn("was changed", SENT[0][1])
            for tok in links.values():
                self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 400)
            self.assertEqual(len(MUTATIONS), 1)

    # The confirm route sits outside forward_auth, so Remote-User there is
    # whatever a client sends. Only the two tokens may decide the account.
    def test_the_tokens_alone_decide_the_account(self):
        _, links = self.ask()
        for tok in links.values():
            self.assertEqual(self.post("/email/confirm", {"t": tok}, user="bob").status_code, 200)
        self.assertEqual(MUTATIONS, [{"id": "alice", "email": "alice@new.example"}])
        self.assertEqual(USERS["bob"]["email"], "bob@example.com")

    def test_a_reader_with_no_session_confirms_both_sides(self):
        _, links = self.ask()
        for tok in links.values():
            body = self.get("/email/confirm?t=" + tok, user=None).get_data(as_text=True)
            self.assertIn("alice@new.example", body)
        self.assertEqual(MUTATIONS, [])
        for tok in links.values():
            self.assertEqual(self.post("/email/confirm", {"t": tok}, user=None).status_code, 200)
        self.assertEqual(MUTATIONS, [{"id": "alice", "email": "alice@new.example"}])

    def test_one_side_alone_never_changes_it_and_cannot_be_reused(self):
        _, links = self.ask("thief@evil.example")
        tok = links["thief@evil.example"]
        self.assertEqual(self.post("/email/confirm", {"t": tok}, user=None).status_code, 200)
        self.assertEqual(self.get("/email/confirm?t=" + tok, user=None).status_code, 400)
        self.assertEqual(self.post("/email/confirm", {"t": tok}, user=None).status_code, 400)
        self.assertEqual(MUTATIONS, [])

    def test_a_head_prefetch_reads_the_link_without_using_it(self):
        _, links = self.ask()
        tok = links["alice@old.example"]
        r = self.c.head("/email/confirm?t=" + tok, base_url=HOST)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Referrer-Policy"], "strict-origin")
        self.assertEqual(self.get("/email/confirm?t=" + tok, user=None).status_code, 200)
        self.assertEqual(MUTATIONS, [])

    def test_links_live_one_hour(self):
        self.ask()
        db = sqlite3.connect(os.environ["SETTINGS_DB"])
        self.assertEqual(db.execute("SELECT expires - created FROM email_change").fetchall(), [(3600,)])

    def test_the_confirm_pages_keep_the_token_on_this_origin(self):
        _, links = self.ask()
        tok = links["alice@old.example"]
        for r in (self.get("/email/confirm?t=" + tok, user=None), self.post("/email/confirm", {"t": tok}, user=None),
                  self.get("/email/confirm?t=nonsense", user=None)):
            self.assertEqual(r.headers["Referrer-Policy"], "strict-origin")
            self.assertTrue(r.headers["Content-Security-Policy"].startswith("default-src 'none'"))
            self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_a_wrong_or_expired_token_is_refused(self):
        _, links = self.ask()
        tok = links["alice@old.example"]
        self.assertEqual(self.post("/email/confirm", {"t": tok + "x"}).status_code, 400)
        self.assertEqual(self.post("/email/confirm", {"t": ""}).status_code, 400)
        db = sqlite3.connect(os.environ["SETTINGS_DB"])
        db.execute("UPDATE email_change SET expires = 0")
        db.commit()
        for tok in links.values():
            self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 400)
        self.assertEqual(MUTATIONS, [])

    def test_a_newer_request_supersedes_the_older_links(self):
        _, first = self.ask("alice@one.example")
        _, second = self.ask("alice@two.example")
        for tok in first.values():
            self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 400)
        for tok in second.values():
            self.assertEqual(self.post("/email/confirm", {"t": tok}).status_code, 200)
        self.assertEqual(MUTATIONS, [{"id": "alice", "email": "alice@two.example"}])

    def test_a_change_in_the_meantime_voids_the_links(self):
        _, links = self.ask()
        self.post("/email/confirm", {"t": links["alice@new.example"]})
        USERS["alice"]["email"] = "alice@elsewhere.example"
        self.assertEqual(self.post("/email/confirm", {"t": links["alice@old.example"]}).status_code, 409)
        self.assertEqual(MUTATIONS, [])

    def test_bad_same_or_taken_addresses_mail_nobody(self):
        for email in ("not-an-address", "a,b@c.example", '"a"@c.example', "a b@c.example", "a@c",
                      "alice@old.example", "ALICE@OLD.EXAMPLE", "bob@example.com"):
            r, _ = self.ask(email)
            self.assertEqual(r.status_code, 400, email)
        self.assertEqual(SENT, [])

    def test_an_account_without_an_address_cannot_self_serve(self):
        USERS["alice"]["email"] = ""
        r, _ = self.ask()
        self.assertEqual(r.status_code, 409)
        self.assertEqual(SENT, [])

    def test_three_requests_a_day(self):
        for i in range(3):
            self.assertEqual(self.ask(f"alice@n{i}.example")[0].status_code, 303)
        SENT.clear()
        self.assertEqual(self.ask("alice@n4.example")[0].status_code, 429)
        self.assertEqual(SENT, [])

    def test_if_the_old_address_cannot_be_mailed_nothing_is_opened(self):
        FAIL_MAIL["to"] = "alice@old.example"
        r, links = self.ask()
        self.assertEqual(r.status_code, 502)
        self.assertEqual(links, {})
        self.assertEqual(sqlite3.connect(os.environ["SETTINGS_DB"]).execute(
            "SELECT count(*) FROM email_change WHERE state = 'pending'").fetchone()[0], 0)

    def test_the_page_renders_the_pinned_scheme(self):
        self.c.set_cookie("zanni-scheme", "dark", domain="me.kelliher.info")
        self.assertIn('<html lang="en" data-scheme="dark">', self.get("/").get_data(as_text=True))
        self.c.set_cookie("zanni-scheme", '"><b>', domain="me.kelliher.info")
        self.assertNotIn("data-scheme", self.get("/").get_data(as_text=True).split("<head>")[0])


class Envelope(unittest.TestCase):
    def test_the_recipient_is_given_as_the_envelope_not_parsed_from_a_header(self):
        seen = {}

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self, **k):
                pass

            def login(self, *a):
                pass

            def send_message(self, msg, from_addr=None, to_addrs=None):
                seen.update(from_addr=from_addr, to_addrs=to_addrs)

        creds = tempfile.mkdtemp()
        Path(creds, "smtp_password").write_text("x")
        os.environ["CREDENTIALS_DIRECTORY"] = creds
        real_smtp = mail.smtplib.SMTP
        mail.smtplib.SMTP = FakeSMTP
        try:
            REAL_SEND("a@b.example", "s", "body")
        finally:
            mail.smtplib.SMTP = real_smtp
            del os.environ["CREDENTIALS_DIRECTORY"]
        self.assertEqual(seen["to_addrs"], ["a@b.example"])
        self.assertEqual(seen["from_addr"], "auth@kelliher.info")


if __name__ == "__main__":
    unittest.main(verbosity=2)

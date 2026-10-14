#!/usr/bin/env python3
"""Each shipped entrypoint over an inherited unix socket.

  belief     a hyphen Remote-User is believed: the positive control
  underscore Remote_User and remote_user are not believed
  no tcp     PORT is set but nothing listens on it
  refuse     KWEB_LISTEN=socket with no inherited socket exits nonzero
"""
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ACTIVATE = os.environ["SOCKET_ACTIVATE"]
TMP = tempfile.mkdtemp()
PASSWORD = os.path.join(TMP, "lldap_password")
with open(PASSWORD, "w") as fh:
    fh.write("fixture")

APPS = {
    "accounts": {
        "entry": os.environ["ACCOUNTS_ENTRY"],
        "port": 29092,
        "env": {"LLDAP_PASSWORD_FILE": PASSWORD, "LLDAP_URL": "http://127.0.0.1:1"},
        "request": ("POST", "/accounts", b"{}"),
        "anonymous": 401,
        "believed": 403,
    },
    "todo": {
        "entry": os.environ["TODO_ENTRY"],
        "port": 29093,
        "env": {"GLUCK_TODO_DB": os.path.join(TMP, "todo.duckdb")},
        "request": ("GET", "/todos", None),
        "anonymous": 401,
        "believed": 200,
    },
}


def env(app):
    return {**os.environ, **app["env"], "KWEB_LISTEN": "socket", "PORT": str(app["port"])}


def call(sock, app, headers):
    method, path, body = app["request"]
    c = http.client.HTTPConnection("x")
    c.sock = socket.socket(socket.AF_UNIX)
    c.sock.settimeout(5)
    c.sock.connect(sock)
    hdrs = dict(headers)
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=hdrs)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def tcp_refused(port):
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect(("127.0.0.1", port))
        return False
    except ConnectionRefusedError:
        return True
    finally:
        s.close()


class Socket(unittest.TestCase):
    procs = []

    @classmethod
    def setUpClass(cls):
        for name, app in APPS.items():
            sock = os.path.join(TMP, f"{name}.sock")
            e = env(app)
            forward = [f"--setenv={k}" for k in (*app["env"], "KWEB_LISTEN", "PORT")]
            cls.procs.append(subprocess.Popen(
                [ACTIVATE, "-l", sock, *forward, sys.executable, app["entry"]],
                env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            app["sock"] = sock
        for name, app in APPS.items():
            for _ in range(150):
                try:
                    call(app["sock"], app, {})
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError(f"{name} never answered on its socket")

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.terminate()
            p.wait(timeout=10)

    def test_anonymous_is_refused(self):
        for name, app in APPS.items():
            self.assertEqual(call(app["sock"], app, {}), app["anonymous"], name)

    def test_positive_control_hyphen_is_believed(self):
        for name, app in APPS.items():
            self.assertEqual(call(app["sock"], app, {"Remote-User": "forged-probe"}), app["believed"], name)

    def test_underscore_forms_are_not_believed(self):
        for name, app in APPS.items():
            for header in ("Remote_User", "remote_user"):
                self.assertEqual(call(app["sock"], app, {header: "forged-probe"}), app["anonymous"], f"{name} {header}")

    def test_no_tcp_listener(self):
        for name, app in APPS.items():
            self.assertTrue(tcp_refused(app["port"]), name)


class Refuse(unittest.TestCase):
    def test_no_inherited_socket_means_no_start(self):
        for name, app in APPS.items():
            r = subprocess.run([sys.executable, app["entry"]], env=env(app),
                               capture_output=True, text=True, timeout=60)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn("refusing to fall back to TCP", r.stderr + r.stdout, name)
            self.assertTrue(tcp_refused(app["port"]), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)

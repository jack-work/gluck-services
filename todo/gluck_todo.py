"""gluck-todo — CRUD over a DuckDB-backed todo table with per-item ACLs.

Trust model: binds to loopback; identity comes from the Remote-User /
Remote-Groups headers set by Caddy from Authelia's forward-auth response
(client-supplied values are stripped upstream).

Bearer bypass: when a request carries an ``Authorization: Bearer <jwt>``
header, Caddy skips forward-auth and delivers the request straight to us.
A middleware here validates the JWT against Authelia's JWKS and synthesises
Remote-User / Remote-Groups from the ``preferred_username`` / ``groups``
claims before the rest of the app sees the request. The rest of the code
doesn't need to know which path a request came in on.

Authorization: creating todos requires the todo-create group.
Per-item permissions (Read/Write/Delete/Share) live in the acl table;
the creator gets all four. Items the caller cannot Read return 404 to
avoid existence leaks; Read-but-not-X returns 403.

DuckDB is single-writer: one connection guarded by a lock, single instance.
"""

import os
import threading
import time

import duckdb
import jwt
import requests
from flask import Flask, jsonify, request
from jwt import PyJWKClient

DB_PATH = os.environ.get("GLUCK_TODO_DB", "/var/lib/gluck-todo/todo.duckdb")
PORT = int(os.environ.get("PORT", "9093"))

# OIDC config for bearer validation. Left as env so the same code runs
# against a staging Authelia. ISSUER must exactly match the ``iss`` claim
# Authelia produces (its external URL, no trailing slash).
OIDC_ISSUER = os.environ.get("GLUCK_TODO_OIDC_ISSUER", "https://auth.kelliher.info")
# JWKS is fetched over loopback by default — Authelia runs on the same box.
# Going through the public URL would take a Cloudflare round-trip and, more
# annoyingly, CF blocks urllib's default UA with 403.
OIDC_JWKS_URL = os.environ.get(
    "GLUCK_TODO_OIDC_JWKS_URL", "http://127.0.0.1:9091/jwks.json"
)
# Authelia's access tokens include ``client_id`` (not ``aud``) identifying
# the requesting client. We validate the ``client_id`` claim explicitly.
OIDC_CLIENT_ID = os.environ.get("GLUCK_TODO_OIDC_CLIENT_ID", "gluck-todo-cli")
# Userinfo lives at /api/oidc/userinfo. Loopback again — same reason.
OIDC_USERINFO_URL = os.environ.get(
    "GLUCK_TODO_OIDC_USERINFO_URL", "http://127.0.0.1:9091/api/oidc/userinfo"
)
# Userinfo cache: keyed by access-token sha, small TTL. Handles the common
# case where a client bursts several requests back-to-back with the same
# token; avoids re-hitting Authelia every hit.
_userinfo_cache: dict = {}
_userinfo_cache_lock = threading.Lock()
USERINFO_TTL = 60  # seconds


def fetch_userinfo(access_token: str, sub: str) -> dict:
    now = time.time()
    with _userinfo_cache_lock:
        hit = _userinfo_cache.get(sub)
        if hit and hit[0] > now:
            return hit[1]
    r = requests.get(
        OIDC_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    if r.status_code != 200:
        raise RuntimeError(f"userinfo {r.status_code}: {r.text}")
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else _decode_jwt_payload(r.text)
    with _userinfo_cache_lock:
        _userinfo_cache[sub] = (now + USERINFO_TTL, data)
    return data


def _decode_jwt_payload(compact: str) -> dict:
    """Authelia signs userinfo as a JWS when the client's ``userinfo_signed
    _response_alg`` is set. Since we haven't set it, we get JSON. This
    fallback exists so a config flip doesn't crash the API."""
    import base64
    import json as _json

    parts = compact.split(".")
    if len(parts) < 2:
        return {}
    pad = "=" * (-len(parts[1]) % 4)
    return _json.loads(base64.urlsafe_b64decode(parts[1] + pad))


CREATE_GROUP = "todo-create"
PERMISSIONS = ("Read", "Write", "Delete", "Share")

app = Flask(__name__)
db_lock = threading.Lock()
db = duckdb.connect(DB_PATH)

# JWKS client caches keys and refetches when a new kid appears; safe to
# construct lazily so the app boots even if Authelia is briefly down.
_jwks_client = None
_jwks_lock = threading.Lock()


def jwks_client():
    global _jwks_client
    with _jwks_lock:
        if _jwks_client is None:
            _jwks_client = PyJWKClient(OIDC_JWKS_URL, cache_keys=True, lifespan=3600)
        return _jwks_client


@app.before_request
def bearer_to_remote_headers():
    """If the caller sent Authorization: Bearer <jwt>, verify it and stamp
    Remote-User / Remote-Groups from the claims. Downstream handlers then
    behave identically to the forward-auth path.

    On any verification failure we fail closed with 401. We never fall
    through to trusting caller-supplied Remote-* headers when a bearer is
    present — that would let a bogus token bypass auth by presenting both.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(None, 1)[1].strip()
    try:
        signing_key = jwks_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=OIDC_ISSUER,
            # Authelia access tokens have an empty ``aud`` and identify the
            # requesting client via ``client_id`` instead. Disable audience
            # verification and enforce client_id below.
            options={
                "require": ["exp", "iat", "iss", "sub", "client_id"],
                "verify_aud": False,
            },
        )
    except Exception as e:  # noqa: BLE001 — any failure = reject
        return jsonify(error=f"invalid bearer token: {e}"), 401

    if claims.get("client_id") != OIDC_CLIENT_ID:
        return jsonify(error="token not issued for this client"), 401

    # Identity claims live on the *id_token*, not the access token. Authelia
    # exposes them at /api/oidc/userinfo when the client presents a valid
    # access token; we fetch there and cache per-token via the ``sub`` claim.
    userinfo = fetch_userinfo(token, claims["sub"])
    username = (
        userinfo.get("preferred_username")
        or userinfo.get("sub")
        or claims.get("sub")
        or ""
    )
    groups = userinfo.get("groups") or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]

    # request.headers is immutable; stash on the environ so the caller-
    # facing helpers below pick it up. environ is per-request.
    request.environ["HTTP_REMOTE_USER"] = username
    request.environ["HTTP_REMOTE_GROUPS"] = ",".join(groups)
    return None

db.execute("CREATE SEQUENCE IF NOT EXISTS todo_id_seq")
db.execute(
    """CREATE TABLE IF NOT EXISTS todo (
        id BIGINT PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT now(),
        updated_at TIMESTAMP NOT NULL DEFAULT now()
    )"""
)
db.execute(
    """CREATE TABLE IF NOT EXISTS acl (
        todo_id BIGINT NOT NULL,
        username TEXT NOT NULL,
        permission TEXT NOT NULL,
        UNIQUE (todo_id, username, permission)
    )"""
)


def caller():
    return request.headers.get("Remote-User", "").strip()


def caller_groups():
    raw = request.headers.get("Remote-Groups", "")
    return [g.strip() for g in raw.split(",") if g.strip()]


def has_perm(todo_id, username, permission):
    row = db.execute(
        "SELECT 1 FROM acl WHERE todo_id = ? AND username = ? AND permission = ?",
        [todo_id, username, permission],
    ).fetchone()
    return row is not None


def todo_row(todo_id):
    return db.execute(
        "SELECT id, title, body, created_by, created_at, updated_at FROM todo WHERE id = ?",
        [todo_id],
    ).fetchone()


def as_dict(row):
    return {
        "id": row[0],
        "title": row[1],
        "body": row[2],
        "created_by": row[3],
        "created_at": str(row[4]),
        "updated_at": str(row[5]),
    }


def gate(todo_id, permission):
    """Returns (error_response, status) or None when access is allowed."""
    user = caller()
    if not user:
        return jsonify(error="unauthenticated"), 401
    if todo_row(todo_id) is None or not has_perm(todo_id, user, "Read"):
        return jsonify(error="not found"), 404
    if permission != "Read" and not has_perm(todo_id, user, permission):
        return jsonify(error=f"requires {permission} permission"), 403
    return None


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/todos")
def create_todo():
    user = caller()
    if not user:
        return jsonify(error="unauthenticated"), 401
    if CREATE_GROUP not in caller_groups():
        return jsonify(error=f"requires group {CREATE_GROUP}"), 403
    body = request.get_json(silent=True) or {}
    title = body.get("title", "").strip()
    if not title:
        return jsonify(error="title is required"), 400
    with db_lock:
        todo_id = db.execute("SELECT nextval('todo_id_seq')").fetchone()[0]
        db.execute(
            "INSERT INTO todo (id, title, body, created_by) VALUES (?, ?, ?, ?)",
            [todo_id, title, body.get("body", ""), user],
        )
        for perm in PERMISSIONS:
            db.execute(
                "INSERT INTO acl (todo_id, username, permission) VALUES (?, ?, ?)",
                [todo_id, user, perm],
            )
        return jsonify(as_dict(todo_row(todo_id))), 201


@app.get("/todos")
def list_todos():
    user = caller()
    if not user:
        return jsonify(error="unauthenticated"), 401
    with db_lock:
        rows = db.execute(
            """SELECT t.id, t.title, t.body, t.created_by, t.created_at, t.updated_at
               FROM todo t JOIN acl a ON a.todo_id = t.id
               WHERE a.username = ? AND a.permission = 'Read'
               ORDER BY t.id""",
            [user],
        ).fetchall()
        return jsonify([as_dict(r) for r in rows])


@app.get("/todos/<int:todo_id>")
def get_todo(todo_id):
    with db_lock:
        denied = gate(todo_id, "Read")
        if denied:
            return denied
        return jsonify(as_dict(todo_row(todo_id)))


@app.put("/todos/<int:todo_id>")
def update_todo(todo_id):
    with db_lock:
        denied = gate(todo_id, "Write")
        if denied:
            return denied
        body = request.get_json(silent=True) or {}
        current = todo_row(todo_id)
        title = body.get("title", current[1])
        text = body.get("body", current[2])
        if not str(title).strip():
            return jsonify(error="title must not be empty"), 400
        db.execute(
            "UPDATE todo SET title = ?, body = ?, updated_at = now() WHERE id = ?",
            [title, text, todo_id],
        )
        return jsonify(as_dict(todo_row(todo_id)))


@app.delete("/todos/<int:todo_id>")
def delete_todo(todo_id):
    with db_lock:
        denied = gate(todo_id, "Delete")
        if denied:
            return denied
        db.execute("DELETE FROM acl WHERE todo_id = ?", [todo_id])
        db.execute("DELETE FROM todo WHERE id = ?", [todo_id])
        return jsonify(deleted=todo_id)


@app.post("/todos/<int:todo_id>/share")
def share_todo(todo_id):
    with db_lock:
        denied = gate(todo_id, "Share")
        if denied:
            return denied
        body = request.get_json(silent=True) or {}
        grantee = str(body.get("username", "")).strip()
        permissions = body.get("permissions", [])
        if not grantee:
            return jsonify(error="username is required"), 400
        if (
            not isinstance(permissions, list)
            or not permissions
            or any(p not in PERMISSIONS for p in permissions)
        ):
            return jsonify(error=f"permissions must be a non-empty subset of {PERMISSIONS}"), 400
        for perm in permissions:
            db.execute(
                """INSERT INTO acl (todo_id, username, permission)
                   SELECT ?, ?, ?
                   WHERE NOT EXISTS (
                     SELECT 1 FROM acl WHERE todo_id = ? AND username = ? AND permission = ?
                   )""",
                [todo_id, grantee, perm, todo_id, grantee, perm],
            )
        return jsonify(todo_id=todo_id, username=grantee, permissions=permissions)


if __name__ == "__main__":
    from waitress import serve

    serve(app, host="127.0.0.1", port=PORT, threads=4)

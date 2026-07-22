"""gluck-accounts — mint lldap user accounts over an authenticated API.

Trust model: this service binds to loopback and trusts the Remote-User /
Remote-Groups headers because the only route to it is Caddy, which strips
client-supplied Remote-* headers and sets them from Authelia's forward-auth
response. Callers must hold the accounts-create group.
"""

import os
import re
import secrets
import subprocess

import requests
from flask import Flask, jsonify, request

LLDAP_URL = os.environ.get("LLDAP_URL", "http://127.0.0.1:17170")
PASSWORD_FILE = os.environ["LLDAP_PASSWORD_FILE"]
SERVICE_USER = os.environ.get("LLDAP_SERVICE_USER", "gluck-accounts")
PORT = int(os.environ.get("PORT", "9092"))

REQUIRED_GROUP = "accounts-create"
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Only application capability groups may be granted here — never lldap_admin
# or other lldap built-ins.
GRANTABLE_GROUP_RE = re.compile(r"^gluck-[a-z0-9-]+$")

app = Flask(__name__)


class GraphQLError(Exception):
    pass


def caller():
    return request.headers.get("Remote-User", "").strip()


def caller_groups():
    raw = request.headers.get("Remote-Groups", "")
    return [g.strip() for g in raw.split(",") if g.strip()]


def lldap_token():
    with open(PASSWORD_FILE) as f:
        password = f.read().strip()
    r = requests.post(
        f"{LLDAP_URL}/auth/simple/login",
        json={"username": SERVICE_USER, "password": password},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["token"]


def gql(token, query, variables=None):
    r = requests.post(
        f"{LLDAP_URL}/api/graphql",
        json={"query": query, "variables": variables or {}},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("errors"):
        raise GraphQLError(str(body["errors"]))
    return body["data"]


def user_exists(token, username):
    try:
        data = gql(
            token,
            "query($id: String!) { user(userId: $id) { id } }",
            {"id": username},
        )
        return data.get("user") is not None
    except GraphQLError:
        return False


def group_id(token, name):
    data = gql(token, "{ groups { id displayName } }")
    for g in data["groups"]:
        if g["displayName"] == name:
            return g["id"]
    return None


@app.get("/accounts/health")
def health():
    return jsonify(status="ok")


@app.post("/accounts")
def create_account():
    if not caller():
        return jsonify(error="unauthenticated"), 401
    if REQUIRED_GROUP not in caller_groups():
        return jsonify(error=f"requires group {REQUIRED_GROUP}"), 403

    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    email = body.get("email", "")
    display_name = body.get("display_name", "")
    groups = body.get("groups", [])

    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="invalid username (want ^[a-z][a-z0-9_-]{2,31}$)"), 400
    if not EMAIL_RE.fullmatch(email):
        return jsonify(error="invalid email"), 400
    if not isinstance(groups, list) or not all(
        isinstance(g, str) and GRANTABLE_GROUP_RE.fullmatch(g) for g in groups
    ):
        return jsonify(error="groups must match ^gluck-[a-z0-9-]+$"), 400

    token = lldap_token()

    if user_exists(token, username):
        return jsonify(error="user already exists"), 409

    group_ids = {}
    for g in groups:
        gid = group_id(token, g)
        if gid is None:
            return jsonify(error=f"group does not exist: {g}"), 400
        group_ids[g] = gid

    gql(
        token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        {"u": {"id": username, "email": email, "displayName": display_name or username}},
    )

    temp_password = secrets.token_urlsafe(16)
    subprocess.run(
        [
            "lldap_set_password",
            "--base-url", LLDAP_URL,
            "--token", token,
            "--username", username,
            "--password", temp_password,
        ],
        check=True,
        capture_output=True,
    )

    for g, gid in group_ids.items():
        gql(
            token,
            "mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }",
            {"u": username, "g": gid},
        )

    app.logger.info("account %s created by %s (groups: %s)", username, caller(), groups)
    return (
        jsonify(
            username=username,
            email=email,
            groups=groups,
            temporary_password=temp_password,
            note="temporary password is shown exactly once; user must log in and register 2FA",
        ),
        201,
    )


if __name__ == "__main__":
    from waitress import serve

    serve(app, host="127.0.0.1", port=PORT, threads=4)

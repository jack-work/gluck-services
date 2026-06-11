"""gluck-todo — CRUD over a DuckDB-backed todo table with per-item ACLs.

Trust model: binds to loopback; identity comes from the Remote-User /
Remote-Groups headers set by Caddy from Authelia's forward-auth response
(client-supplied values are stripped upstream).

Authorization: creating todos requires the gluck-todo-create group.
Per-item permissions (Read/Write/Delete/Share) live in the acl table;
the creator gets all four. Items the caller cannot Read return 404 to
avoid existence leaks; Read-but-not-X returns 403.

DuckDB is single-writer: one connection guarded by a lock, single instance.
"""

import os
import threading

import duckdb
from flask import Flask, jsonify, request

DB_PATH = os.environ.get("GLUCK_TODO_DB", "/var/lib/gluck-todo/todo.duckdb")
PORT = int(os.environ.get("PORT", "9093"))

CREATE_GROUP = "gluck-todo-create"
PERMISSIONS = ("Read", "Write", "Delete", "Share")

app = Flask(__name__)
db_lock = threading.Lock()
db = duckdb.connect(DB_PATH)

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

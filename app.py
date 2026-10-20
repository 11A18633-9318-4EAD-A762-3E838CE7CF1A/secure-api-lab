"""Secure REST API - Laboratory Work No. 1.

Three endpoints: registration, login (JWT) and a protected data endpoint.
SQLite for storage, bcrypt for password hashing, PyJWT for tokens,
markupsafe for output encoding and parameterised statements for every query.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-32-bytes-minimum-secret-key")
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME = timedelta(hours=1)

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " login TEXT NOT NULL UNIQUE,"
            " password_hash TEXT NOT NULL)"
        )


def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "token missing"}), 401
        try:
            payload = jwt.decode(header[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401
        g.user_id = payload["user_id"]
        return f(*args, **kwargs)

    return wrapper


@app.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    login = str(data.get("login", "")).strip()
    password = str(data.get("password", ""))
    if not login or not password:
        return jsonify({"error": "login and password are required"}), 400

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (login, password_hash) VALUES (?, ?)",
            (login, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "login already taken"}), 409
    finally:
        conn.close()

    return jsonify({"message": "registered"}), 201


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    login = str(data.get("login", ""))
    password = str(data.get("password", ""))

    conn = get_db()
    row = conn.execute(
        "SELECT id, login, password_hash FROM users WHERE login = ?", (login,)
    ).fetchone()
    conn.close()

    if row is None or not bcrypt.checkpw(
        password.encode("utf-8"), row["password_hash"].encode("utf-8")
    ):
        return jsonify({"error": "invalid credentials"}), 401

    token = jwt.encode(
        {"user_id": row["id"], "exp": datetime.now(timezone.utc) + TOKEN_LIFETIME},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    return jsonify({"token": token})


@app.get("/api/data")
@token_required
def api_data():
    conn = get_db()
    rows = conn.execute("SELECT id, login FROM users ORDER BY id").fetchall()
    conn.close()
    data = [{"id": r["id"], "login": str(escape(r["login"]))} for r in rows]
    return jsonify({"data": data})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)

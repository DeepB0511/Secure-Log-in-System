from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from hashlib import sha256
from pathlib import Path
from typing import Any

import bcrypt
from flask import (
    Flask,
    Response,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue
from werkzeug.wrappers import Response

SESSION_COOKIE = "secure_login_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,32}\Z")
MIN_PASSWORD_LENGTH = 12
MAX_BCRYPT_BYTES = 72
LOGIN_LIMIT = 5
LOGIN_WINDOW_SECONDS = 15 * 60
REGISTER_LIMIT = 5
REGISTER_WINDOW_SECONDS = 60 * 60


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    default_database = Path(app.instance_path) / "auth.sqlite3"
    app.config.from_mapping(
        DATABASE_PATH=os.environ.get("DATABASE_PATH", str(default_database)),
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower()
        in {"1", "true", "yes"},
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    app.config["DUMMY_PASSWORD_HASH"] = bcrypt.hashpw(
        secrets.token_bytes(32), bcrypt.gensalt(rounds=12)
    )
    initialize_database(app)
    app.teardown_appcontext(close_db)

    @app.context_processor
    def inject_csrf_token() -> dict[str, str]:
        return {"csrf_token": getattr(g, "csrf_token", "")}

    @app.before_request
    def load_session() -> None:
        if request.endpoint == "static":
            return

        db = get_db()
        now = int(time.time())
        raw_token = request.cookies.get(SESSION_COOKIE, "")
        token_hash = _digest_token(raw_token) if len(raw_token) <= 128 else ""
        row = None
        if token_hash:
            row = db.execute(
                """
                SELECT sessions.user_id, sessions.csrf_token, users.username
                FROM sessions
                LEFT JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()

        if row is None:
            raw_token = secrets.token_urlsafe(32)
            token_hash = _digest_token(raw_token)
            csrf_token = secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) "
                "VALUES (?, NULL, ?, ?)",
                (token_hash, csrf_token, now + SESSION_TTL_SECONDS),
            )
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            db.commit()
            g.new_session_token = raw_token
            g.session_token_hash = token_hash
            g.csrf_token = csrf_token
            g.user = None
            return

        g.session_token_hash = token_hash
        g.csrf_token = row["csrf_token"]
        g.user = (
            {"id": row["user_id"], "username": row["username"]}
            if row["user_id"] is not None
            else None
        )

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000"
            )

        new_token = getattr(g, "new_session_token", None)
        if new_token:
            response.set_cookie(
                SESSION_COOKIE,
                new_token,
                max_age=SESSION_TTL_SECONDS,
                httponly=True,
                secure=app.config["SESSION_COOKIE_SECURE"],
                samesite="Lax",
                path="/",
            )
        if getattr(g, "clear_session_cookie", False):
            response.delete_cookie(
                SESSION_COOKIE,
                httponly=True,
                secure=app.config["SESSION_COOKIE_SECURE"],
                samesite="Lax",
                path="/",
            )
        return response

    @app.get("/")
    def index() -> str:
        if g.user:
            return render_template("home.html", username=g.user["username"])
        return render_template("login.html", error=None, username="")

    @app.get("/register")
    def register_page() -> ResponseReturnValue:
        if g.user:
            return redirect(url_for("index"))
        return render_template("register.html", error=None, username="")

    @app.post("/register")
    def register() -> ResponseReturnValue:
        if g.user:
            return redirect(url_for("index"))
        _require_csrf()
        if not _allow_attempt(
            "register", REGISTER_LIMIT, REGISTER_WINDOW_SECONDS
        ):
            return (
                render_template(
                    "register.html",
                    error="Too many registration attempts. Please try again later.",
                    username=request.form.get("username", "")[:32],
                ),
                429,
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_PATTERN.fullmatch(username):
            return (
                render_template(
                    "register.html",
                    error="Username must be 3–32 characters: letters, numbers, dots, "
                    "underscores, or hyphens.",
                    username=username[:32],
                ),
                400,
            )
        password_bytes = password.encode("utf-8")
        if (
            len(password) < MIN_PASSWORD_LENGTH
            or len(password_bytes) > MAX_BCRYPT_BYTES
        ):
            return (
                render_template(
                    "register.html",
                    error="Password must be at least 12 characters and no more than "
                    "72 UTF-8 bytes.",
                    username=username,
                ),
                400,
            )

        password_hash = bcrypt.hashpw(
            password_bytes, bcrypt.gensalt(rounds=12)
        ).decode("ascii")
        db = get_db()
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, created_at) "
            "VALUES (?, ?, ?) ON CONFLICT(username) DO NOTHING",
            (username.lower(), password_hash, int(time.time())),
        )
        if cursor.rowcount == 0:
            return (
                render_template(
                    "register.html",
                    error="That username is already taken.",
                    username=username,
                ),
                409,
            )

        user_id = cursor.lastrowid
        if user_id is None:
            raise RuntimeError("The database did not return the new user ID.")
        _rotate_session(user_id, username.lower())
        return redirect(url_for("index"))

    @app.post("/login")
    def login() -> ResponseReturnValue:
        if g.user:
            return redirect(url_for("index"))
        _require_csrf()
        if not _allow_attempt("login", LOGIN_LIMIT, LOGIN_WINDOW_SECONDS):
            return (
                render_template(
                    "login.html",
                    error="Too many sign-in attempts. Please try again in 15 minutes.",
                    username=request.form.get("username", "")[:32],
                ),
                429,
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = None
        if USERNAME_PATTERN.fullmatch(username):
            user = get_db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username.lower(),),
            ).fetchone()

        password_bytes = password.encode("utf-8")
        can_check_password = len(password_bytes) <= MAX_BCRYPT_BYTES
        candidate = password_bytes if can_check_password else secrets.token_bytes(32)
        password_hash = (
            user["password_hash"].encode("ascii")
            if user is not None and can_check_password
            else app.config["DUMMY_PASSWORD_HASH"]
        )
        password_valid = bcrypt.checkpw(candidate, password_hash)

        if user is None or not can_check_password or not password_valid:
            return (
                render_template(
                    "login.html",
                    error="Invalid username or password.",
                    username=username[:32],
                ),
                401,
            )

        _rotate_session(user["id"], user["username"])
        return redirect(url_for("index"))

    @app.post("/logout")
    def logout() -> ResponseReturnValue:
        _require_csrf()
        get_db().execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (g.session_token_hash,),
        )
        get_db().commit()
        g.user = None
        g.clear_session_cookie = True
        return redirect(url_for("index"))

    return app


def initialize_database(app: Flask) -> None:
    database_path = Path(app.config["DATABASE_PATH"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database_path)) as db, db:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry_idx
                ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY,
                bucket TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                attempted_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS auth_attempts_lookup_idx
                ON auth_attempts(bucket, ip_address, attempted_at);
            """
        )


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db = sqlite3.connect(current_app.config["DATABASE_PATH"], timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        g.db = db
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    del _error
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _digest_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _require_csrf() -> None:
    submitted = request.form.get("csrf_token", "")
    if not secrets.compare_digest(submitted, g.csrf_token):
        abort(400, description="Invalid or missing CSRF token.")


def _allow_attempt(bucket: str, limit: int, window_seconds: int) -> bool:
    now = int(time.time())
    cutoff = now - window_seconds
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO auth_attempts (bucket, ip_address, attempted_at)
        SELECT ?, ?, ?
        WHERE (
            SELECT COUNT(*) FROM auth_attempts
            WHERE bucket = ? AND ip_address = ? AND attempted_at > ?
        ) < ?
        RETURNING id
        """,
        (
            bucket,
            request.remote_addr or "unknown",
            now,
            bucket,
            request.remote_addr or "unknown",
            cutoff,
            limit,
        ),
    )
    allowed = cursor.fetchone() is not None
    if allowed:
        db.execute("DELETE FROM auth_attempts WHERE attempted_at < ?", (now - 86400,))
        db.commit()
    return allowed


def _rotate_session(user_id: int, username: str) -> None:
    db = get_db()
    db.execute(
        "DELETE FROM sessions WHERE token_hash = ?",
        (g.session_token_hash,),
    )
    raw_token = secrets.token_urlsafe(32)
    token_hash = _digest_token(raw_token)
    csrf_token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (token_hash, user_id, csrf_token, int(time.time()) + SESSION_TTL_SECONDS),
    )
    db.commit()
    g.new_session_token = raw_token
    g.session_token_hash = token_hash
    g.csrf_token = csrf_token
    g.user = {"id": user_id, "username": username}


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )

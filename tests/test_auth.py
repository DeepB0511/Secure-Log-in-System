import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from hashlib import sha256
from pathlib import Path

from app import SESSION_COOKIE, create_app


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.database_path = Path(cls.temp_dir.name) / "test.sqlite3"
        cls.app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(cls.database_path),
                "SESSION_COOKIE_SECURE": False,
            }
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def setUp(self) -> None:
        with closing(sqlite3.connect(self.database_path)) as db, db:
            db.execute("DELETE FROM auth_attempts")
            db.execute("DELETE FROM sessions")
            db.execute("DELETE FROM users")
        self.client = self.app.test_client()

    def csrf_token(self, path: str = "/") -> str:
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(
            rb'name="csrf_token" value="([^"]+)"', response.data
        )
        assert match is not None, "The page did not contain a CSRF token."
        return match.group(1).decode("ascii")

    def session_cookie(self) -> str:
        cookie = self.client.get_cookie(SESSION_COOKIE)
        assert cookie is not None, "The response did not set a session cookie."
        return cookie.value

    def register(self, username: str = "mira", password: str = "correct horse battery") -> None:
        token = self.csrf_token("/register")
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": username,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_registration_hashes_password_and_rotates_session(self) -> None:
        initial_token = self.csrf_token("/register")
        before = self.session_cookie()
        response = self.client.post(
            "/register",
            data={
                "csrf_token": initial_token,
                "username": "Mira",
                "password": "correct horse battery",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(before, self.session_cookie())
        self.assertIn(b"You\xe2\x80\x99re all set, mira.", self.client.get("/").data)
        with closing(sqlite3.connect(self.database_path)) as db:
            stored_hash = db.execute(
                "SELECT password_hash FROM users WHERE username = 'mira'"
            ).fetchone()[0]
            session_hash = db.execute(
                "SELECT token_hash FROM sessions WHERE user_id = "
                "(SELECT id FROM users WHERE username = 'mira')"
            ).fetchone()[0]
            self.assertTrue(stored_hash.startswith("$2"))
            self.assertNotEqual(stored_hash, "correct horse battery")
            self.assertEqual(len(session_hash), 64)
            self.assertEqual(
                session_hash,
                sha256(self.session_cookie().encode()).hexdigest(),
            )

        cookie_header = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("SameSite=Lax", cookie_header)

    def test_login_and_csrf_protected_logout(self) -> None:
        self.register()
        self.client.post("/logout", data={"csrf_token": self.csrf_token()})
        token = self.csrf_token()
        before = self.session_cookie()
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "MIRA",
                "password": "correct horse battery",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(before, self.session_cookie())
        self.assertIn(b"mira", self.client.get("/").data)

        authenticated_cookie = self.session_cookie()
        logout = self.client.post(
            "/logout", data={"csrf_token": self.csrf_token()}
        )
        self.assertEqual(logout.status_code, 302)
        self.assertIsNone(self.client.get_cookie(SESSION_COOKIE))
        self.client.set_cookie(SESSION_COOKIE, authenticated_cookie)
        self.assertIn(b"Welcome back", self.client.get("/").data)

    def test_registration_validates_username_and_password(self) -> None:
        token = self.csrf_token("/register")
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "' OR 1=1 --",
                "password": "correct horse battery",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Username must be", response.data)

        token = self.csrf_token("/register")
        response = self.client.post(
            "/register",
            data={"csrf_token": token, "username": "mira", "password": "short"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"at least 12 characters", response.data)

    def test_forms_reject_invalid_csrf_tokens(self) -> None:
        response = self.client.post(
            "/login",
            data={
                "csrf_token": "not-the-session-token",
                "username": "mira",
                "password": "correct horse battery",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_login_attempts_are_rate_limited(self) -> None:
        token = self.csrf_token()
        for _ in range(5):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "username": "missing",
                    "password": "wrong password",
                },
            )
            self.assertEqual(response.status_code, 401)

        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "missing",
                "password": "wrong password",
            },
        )
        self.assertEqual(response.status_code, 429)

    def test_security_headers_are_present(self) -> None:
        response = self.client.get("/")
        self.assertEqual(
            response.headers["X-Content-Type-Options"], "nosniff"
        )
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_secure_cookie_flag_is_enabled_in_https_configuration(self) -> None:
        self.app.config["SESSION_COOKIE_SECURE"] = True
        response = self.client.get("/", base_url="https://localhost")
        self.app.config["SESSION_COOKIE_SECURE"] = False
        self.assertIn("Secure", response.headers["Set-Cookie"])
        self.assertIn("Max-Age=43200", response.headers["Set-Cookie"])


if __name__ == "__main__":
    unittest.main()

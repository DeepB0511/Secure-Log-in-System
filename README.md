# Secure Login System

A small, server-rendered login app built with Flask and SQLite. It supports account registration, bcrypt password hashing, server-side sessions, CSRF protection, login-attempt throttling, and logout.

## Requirements

- Python 3.10 or later
- pip

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

The SQLite database is created at `instance\auth.sqlite3` on first run. Set `DATABASE_PATH` to choose another location and `PORT` to change the listening port.

## Production notes

- Set `SESSION_COOKIE_SECURE=1` and serve the app only over HTTPS.
- Use a production WSGI server (for example, Waitress on Windows) behind a correctly configured HTTPS reverse proxy. Do not expose Flask's development server to the internet.
- Back up the SQLite database securely and restrict access to the database and `instance` directory.
- Login and registration requests are throttled per client IP and stored in SQLite. The app deliberately uses the direct peer IP (`REMOTE_ADDR`); only add trusted-proxy IP handling when the proxy is configured to prevent clients from spoofing forwarded headers.
- Passwords must be at least 12 characters and no more than 72 UTF-8 bytes (the bcrypt input limit). Use a unique passphrase.

## Security behavior

- Passwords are hashed with bcrypt; plaintext passwords are never stored.
- Session identifiers are random, opaque cookies. Only their SHA-256 digests are stored in SQLite, and the identifier is rotated after registration or login.
- Session cookies are `HttpOnly`, `SameSite=Lax`, and become `Secure` when `SESSION_COOKIE_SECURE=1`.
- Every form has a synchronizer CSRF token. Logout is a CSRF-protected POST.
- Login and registration use parameterized SQLite queries; usernames are restricted to a small allow-list.
- Login attempts are limited to five per IP per 15 minutes; registration attempts to five per IP per hour.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

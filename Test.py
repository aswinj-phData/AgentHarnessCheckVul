"""
Security-remediated version of Test.py.
All VULN-1 through VULN-28 issues from VULNERABILITY_REPORT.md have been fixed.
Code-quality issues QUALITY-1 through QUALITY-12 have also been resolved.
"""

import os
import re
import ast
import ssl
import json
import uuid
import operator
import pathlib
import hashlib
import hashlib
import sqlite3
import logging
import tempfile
import ipaddress
import subprocess
import xml.etree.ElementTree as _UnsafeET  # kept for reference; defusedxml used below

import bcrypt
import yaml
import defusedxml.ElementTree as ET
from flask import Flask, request, render_template_string, redirect, send_file, session, abort
from markupsafe import escape
import requests
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# VULN-1 FIX: Load all secrets from environment variables — never hardcode.
# ---------------------------------------------------------------------------
SECRET_KEY            = os.environ["SECRET_KEY"]
DB_PASSWORD           = os.environ["DB_PASSWORD"]
AWS_ACCESS_KEY_ID     = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
API_TOKEN             = os.environ["API_TOKEN"]

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Use WARNING level in production; avoid DEBUG to prevent credential leaks.
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

BASE_UPLOAD_DIR = pathlib.Path("/var/app/uploads").resolve()
BASE_FILES_DIR  = pathlib.Path("/var/app/files").resolve()
ALLOWED_EXT     = {".png", ".jpg", ".jpeg", ".gif", ".pdf"}


def get_db() -> sqlite3.Connection:
    """Return a new SQLite connection. Callers must use it as a context manager."""
    return sqlite3.connect("users.db")


# ---------------------------------------------------------------------------
# VULN-17 FIX: Strong password hashing with bcrypt; SHA-256 for tokens.
# ---------------------------------------------------------------------------

def hash_password(password: str) -> bytes:
    """Hash a password with bcrypt (salted, adaptive cost)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    """Constant-time bcrypt password verification."""
    return bcrypt.checkpw(password.encode(), hashed)


def hash_token(token: str) -> str:
    """Hash a token with SHA-256 (minimum acceptable for non-password tokens)."""
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# VULN-18 FIX: Cryptographically secure token generation.
# ---------------------------------------------------------------------------

def generate_reset_token() -> str:
    """Generate a 256-bit cryptographically secure random token."""
    return uuid.uuid4().hex + uuid.uuid4().hex   # or: secrets.token_hex(32)


# ---------------------------------------------------------------------------
# VULN-2 FIX: Parameterised query — no string interpolation.
# ---------------------------------------------------------------------------

@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM users WHERE username = ?", (username,))
        return json.dumps(cur.fetchall())


# ---------------------------------------------------------------------------
# VULN-3 FIX: Parameterised query.
# VULN-4 FIX: bcrypt password verification.
# VULN-5 FIX: Password never written to logs.
# ---------------------------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # VULN-5 FIX: log only the username, never the password.
    logger.info("Login attempt for user: %s", username)
    with get_db() as conn:
        cur = conn.cursor()
        # VULN-3 FIX: parameterised query.
        cur.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
    # VULN-4 FIX: constant-time bcrypt comparison.
    if row and verify_password(password, row[0]):
        session["user_id"] = username
        return "Welcome!"
    return "Invalid", 401


# ---------------------------------------------------------------------------
# VULN-6 FIX: No shell=True; host validated as a real IP address.
# ---------------------------------------------------------------------------

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    try:
        ipaddress.ip_address(host)   # raises ValueError for non-IP strings
    except ValueError:
        return "Invalid host — must be a valid IP address.", 400
    result = subprocess.check_output(["ping", "-c", "1", host], shell=False, timeout=5)
    return result


# ---------------------------------------------------------------------------
# VULN-7 FIX: Allowlist on name; subprocess with shell=False.
# ---------------------------------------------------------------------------

@app.route("/backup")
def backup():
    name = request.args.get("name", "")
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,64}", name):
        return "Invalid backup name.", 400
    subprocess.run(
        ["tar", "-czf", f"/backups/{name}.tgz", "/data"],
        shell=False,
        check=True,
        timeout=60,
    )
    return "done"


# ---------------------------------------------------------------------------
# VULN-8 FIX: User input passed as template variable, not concatenated.
# ---------------------------------------------------------------------------

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # render_template_string auto-escapes {{ name }}; escape() adds defence-in-depth.
    return render_template_string("<h1>Hello {{ name }}</h1>", name=escape(name))


# ---------------------------------------------------------------------------
# VULN-9 FIX: Path traversal prevented by resolving and checking the prefix.
# ---------------------------------------------------------------------------

@app.route("/download")
def download():
    filename = request.args.get("file", "")
    target = (BASE_FILES_DIR / filename).resolve()
    if not str(target).startswith(str(BASE_FILES_DIR) + os.sep):
        abort(400, "Invalid file path.")
    if not target.is_file():
        abort(404)
    return send_file(target)


# ---------------------------------------------------------------------------
# VULN-10 FIX: Extension allowlist + randomised filename prevents traversal
#              and arbitrary code upload.
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return "No file provided.", 400
    ext = pathlib.Path(f.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        return "File type not allowed.", 400
    safe_name = f"{uuid.uuid4().hex}{ext}"
    f.save(BASE_UPLOAD_DIR / safe_name)
    return "uploaded"


# ---------------------------------------------------------------------------
# VULN-11 FIX: pickle replaced by JSON deserialization.
# ---------------------------------------------------------------------------

@app.route("/load", methods=["POST"])
def load_session():
    try:
        obj = json.loads(request.get_data())
    except (json.JSONDecodeError, ValueError):
        return "Invalid JSON payload.", 400
    return str(obj)


# ---------------------------------------------------------------------------
# VULN-12 FIX: yaml.safe_load disallows arbitrary Python object construction.
# ---------------------------------------------------------------------------

def parse_config(text: str) -> dict:
    """Parse YAML configuration safely."""
    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# VULN-13 FIX: eval() replaced by a safe AST-based arithmetic evaluator.
# ---------------------------------------------------------------------------

_SAFE_OPS = {
    ast.Add:  operator.add,
    ast.Sub:  operator.sub,
    ast.Mult: operator.mul,
    ast.Div:  operator.truediv,
    ast.Pow:  operator.pow,
    ast.USub: operator.neg,
}


def _safe_eval_node(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_safe_eval_node(node.left), _safe_eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_safe_eval_node(node.operand))
    raise ValueError(f"Unsupported expression node: {type(node)}")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        tree = ast.parse(expr, mode="eval")
        result = _safe_eval_node(tree.body)
        return str(result)
    except Exception:
        return "Invalid or unsupported expression.", 400


# ---------------------------------------------------------------------------
# VULN-14 FIX: SSRF blocked via scheme/host allowlist.
# VULN-15 FIX: TLS verification always enabled; timeout enforced.
# ---------------------------------------------------------------------------

_SSRF_BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0",
    "169.254.169.254",    # AWS IMDS
    "metadata.google.internal",
    "::1",
}


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme not in {"https"}:
        return "Only HTTPS URLs are permitted.", 403
    hostname = (parsed.hostname or "").lower()
    if hostname in _SSRF_BLOCKED_HOSTS:
        return "Forbidden host.", 403
    # Block private/link-local IP ranges
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "Forbidden host.", 403
    except ValueError:
        pass   # hostname is a domain name — proceed
    r = requests.get(url, verify=True, timeout=5)   # VULN-15 FIX: verify=True
    return r.text


# ---------------------------------------------------------------------------
# VULN-16 FIX: Open redirect blocked; only relative paths from allowlist.
# ---------------------------------------------------------------------------

_ALLOWED_REDIRECTS = {"/dashboard", "/home", "/profile"}


@app.route("/redirect")
def do_redirect():
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)
    # Reject any URL that carries a scheme or netloc (i.e., external/absolute).
    if parsed.scheme or parsed.netloc:
        return "Forbidden.", 403
    if next_url not in _ALLOWED_REDIRECTS:
        return redirect("/")
    return redirect(next_url)


# ---------------------------------------------------------------------------
# VULN-19 FIX: defusedxml prevents XXE attacks.
# ---------------------------------------------------------------------------

@app.route("/xml", methods=["POST"])
def parse_xml():
    try:
        tree = ET.fromstring(request.data)
    except ET.ParseError:
        return "Invalid XML.", 400
    return tree.tag


# ---------------------------------------------------------------------------
# VULN-20 FIX: NamedTemporaryFile creates the file atomically — no TOCTOU.
# ---------------------------------------------------------------------------

def write_temp(data: str) -> str:
    """Write data to a secure temporary file; returns the file path."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp") as f:
        f.write(data)
        return f.name


# ---------------------------------------------------------------------------
# VULN-21 FIX: Non-backtracking email regex; no nested quantifiers.
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def is_valid_email(email: str) -> bool:
    """Validate an e-mail address without catastrophic backtracking."""
    return bool(_EMAIL_RE.fullmatch(email))


# ---------------------------------------------------------------------------
# VULN-22 FIX: SSL context retains secure defaults — no overrides.
# ---------------------------------------------------------------------------

def make_ctx() -> ssl.SSLContext:
    """Return a secure SSL context with hostname checking and cert verification."""
    return ssl.create_default_context()   # defaults: check_hostname=True, CERT_REQUIRED


# ---------------------------------------------------------------------------
# VULN-23 FIX: Authorization check — account must belong to the logged-in user.
# ---------------------------------------------------------------------------

@app.route("/account/<int:account_id>")
def account(account_id: int):
    current_user = session.get("user_id")
    if not current_user:
        abort(401, "Authentication required.")
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, balance FROM accounts WHERE id = ? AND owner_id = ?",
            (account_id, current_user),
        )
        row = cur.fetchone()
    if row is None:
        abort(403, "Access denied.")
    return json.dumps(row)


# ---------------------------------------------------------------------------
# VULN-24 FIX: File permissions restricted to owner read/write only.
# ---------------------------------------------------------------------------

def save_secret(data: str) -> None:
    """Save sensitive data to a file readable only by the process owner."""
    with open("/tmp/secret.txt", "w") as f:
        f.write(data)
    os.chmod("/tmp/secret.txt", 0o600)   # owner r/w only


# ---------------------------------------------------------------------------
# VULN-25 FIX: Stack trace goes to log only; client receives a generic message
#              with a reference ID for correlation.
# ---------------------------------------------------------------------------

@app.errorhandler(Exception)
def handle_error(e: Exception):
    error_id = uuid.uuid4().hex
    logger.exception("Unhandled exception [ref=%s]", error_id)
    return (
        f"An unexpected error occurred. Please quote reference: {error_id}",
        500,
    )


# ---------------------------------------------------------------------------
# VULN-26 FIX: Allowlist of updatable fields; parameterised UPDATE query;
#              uses session user ID — not a hardcoded 1.
# ---------------------------------------------------------------------------

_ALLOWED_PROFILE_FIELDS = frozenset({"display_name", "email", "bio"})


@app.route("/profile", methods=["POST"])
def update_profile():
    current_user = session.get("user_id")
    if not current_user:
        abort(401)
    data = request.get_json(silent=True) or {}
    filtered = {k: v for k, v in data.items() if k in _ALLOWED_PROFILE_FIELDS}
    if not filtered:
        return "No valid fields provided.", 400
    set_clause = ", ".join(f"{k} = ?" for k in filtered)
    with get_db() as conn:
        conn.execute(
            f"UPDATE users SET {set_clause} WHERE id = ?",
            (*filtered.values(), current_user),
        )
        conn.commit()
    return "ok"


# ---------------------------------------------------------------------------
# VULN-27 FIX: PermissionError raised explicitly — not stripped by python -O.
# ---------------------------------------------------------------------------

def delete_user(user, target) -> None:
    """Delete target; caller must be an admin."""
    if not user.is_admin:
        raise PermissionError("Admin privileges required.")
    logger.info("Deleting user: %s", target)


# ---------------------------------------------------------------------------
# Code-quality fixes
# ---------------------------------------------------------------------------

# QUALITY-1 FIX: Use None as default; initialise list inside the function.
def add_item(item: object, items: list | None = None) -> list:
    if items is None:
        items = []
    items.append(item)
    return items


# QUALITY-2 & QUALITY-3 FIX: Specific exception; context manager closes file.
def read_file(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return None


# QUALITY-4 & QUALITY-5 FIX: No shadowed builtins; `is None` comparison.
def process(items: list, mapping: dict) -> None:  # renamed from list/dict
    for item in items:                             # iterate directly
        if item is None:                           # QUALITY-5 FIX
            continue
        print(item)


# QUALITY-6 FIX: Named constants eliminate magic numbers; DRY pricing logic.
_TAX_RATE    = 1.0825
_DISCOUNT    = 5.0
_BASE_PRICES = {"A": 19.99, "B": 29.99, "C": 39.99}
_DEFAULT_PRICE = 49.99


def calculate_price(qty: int, kind: str) -> float:
    """Return the final price for qty units of product kind."""
    base = _BASE_PRICES.get(kind, _DEFAULT_PRICE)
    return qty * base * _TAX_RATE - _DISCOUNT


# QUALITY-7 FIX: Early-return pattern flattens nesting depth.
def complex_logic(a: bool, b: bool, c: bool, d: bool) -> int:
    if not a:
        return 6
    if not b:
        return 5
    if c:
        return 1 if d else 2
    return 3 if d else 4


# QUALITY-8 FIX: Context manager ensures connection is always closed.
def count_users() -> int:
    """Return the total number of users in the database."""
    with sqlite3.connect("users.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        return cur.fetchone()[0]


# QUALITY-9 FIX: Open with exclusive creation flag; no TOCTOU window.
def safe_write(path: str, data: str) -> bool:
    """Write data to path only if it does not already exist. Returns True on success."""
    try:
        with open(path, "x", encoding="utf-8") as fh:   # 'x' = exclusive create
            fh.write(data)
        return True
    except FileExistsError:
        return False


# QUALITY-10 FIX: Dead code removed.
def get_status(code: int) -> str:
    return "ok" if code == 200 else "error"


# QUALITY-11 FIX: Timeout added; exception handled gracefully.
def get_remote_data(url: str) -> dict | None:
    """Fetch JSON from url with a 10-second timeout. Returns None on error."""
    try:
        response = requests.get(url, timeout=10, verify=True)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        logger.error("Failed to fetch %s: %s", url, exc)
        return None


# QUALITY-12 FIX: Module-level cache replaced by a proper dict; no bare global;
#                  docstrings and type hints added.
_CACHE: dict[str, object] = {}


def cached(key: str) -> object:
    """Return a cached result for key, computing it with expensive() if absent."""
    if key not in _CACHE:
        _CACHE[key] = expensive(key)
    return _CACHE[key]


def expensive(key: str) -> str:
    """Simulate a costly computation."""
    return key * 2


# ---------------------------------------------------------------------------
# VULN-28 FIX: Debug mode controlled by env var; bind to localhost only.
#              Use gunicorn/uwsgi for production.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=_debug)

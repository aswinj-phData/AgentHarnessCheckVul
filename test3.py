"""
Security-remediated version of test3.py — Round 3.

VULN-T3-1 FIX: SQL Injection eliminated — parameterized query replaces f-string interpolation.
VULN-T3-2 FIX: Insecure Deserialization eliminated — pickle replaced with JSON + schema validation.
VULN-T3-3 FIX: Path Traversal eliminated — canonical path validation with pathlib.resolve().
VULN-T3-4 FIX: Flask dev server bound to loopback only; debug mode controlled by env var.

See VULNERABILITY_REPORT.md for full details of each fix.
"""

import os
import json
import base64
import pathlib
import sqlite3

from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULN-T3-3 FIX: Resolve the allowed log directory once at startup.
# All incoming filenames will be resolved against this base path and
# rejected if they escape it (prevents ../../../etc/passwd traversal).
# ---------------------------------------------------------------------------
BASE_LOG_DIR = pathlib.Path('/var/logs/app/').resolve()


# ---------------------------------------------------------------------------
# VULN-T3-1 FIX: SQL Injection — parameterized query (OWASP A03:2021 / CWE-89)
#
# Previously: f"SELECT * FROM users WHERE username = '{username}'"
#   Allowed payloads like  ' OR '1'='1  or  '; DROP TABLE users;--
#
# Fix: Use sqlite3's parameterized query interface (the ? placeholder).
#   The driver handles all escaping internally; the query structure is
#   never altered by user-supplied data.
# ---------------------------------------------------------------------------
@app.route('/user_search', methods=['GET'])
def search_user():
    username = request.args.get('username', '')
    if not username:
        return jsonify({"error": "username parameter required"}), 400

    with sqlite3.connect('app.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Parameterized query: sqlite3 driver handles escaping — injection impossible
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        results = [dict(row) for row in cursor.fetchall()]

    return jsonify(results)


# ---------------------------------------------------------------------------
# VULN-T3-3 FIX: Path Traversal (OWASP A01:2021 / CWE-22)
#
# Previously: os.path.join('/var/logs/app/', filename)  — no bounds check.
#   Allowed: filename='../../../etc/passwd' → reads /etc/passwd
#
# Fix:
#   1. Resolve the requested path to its canonical absolute form.
#   2. Verify it starts with BASE_LOG_DIR (i.e., is still inside it).
#   3. Restrict to known-safe file extensions (.log / .txt).
# ---------------------------------------------------------------------------
@app.route('/read_log', methods=['GET'])
def read_log():
    filename = request.args.get('filename', '')
    if not filename:
        return "filename parameter required", 400

    # Resolve symlinks and .. components to a canonical absolute path
    requested_path = (BASE_LOG_DIR / filename).resolve()

    # Ensure the resolved path is still inside the allowed directory
    if not str(requested_path).startswith(str(BASE_LOG_DIR)):
        return "Access denied — path traversal attempt detected", 403

    # Allowlist: only serve .log and .txt files
    if requested_path.suffix not in {'.log', '.txt'}:
        return "Access denied — file type not permitted", 403

    if not requested_path.is_file():
        return "File not found", 404

    try:
        content = requested_path.read_text(encoding='utf-8')
    except OSError:
        return "Cannot read file", 500

    return content


# ---------------------------------------------------------------------------
# VULN-T3-2 FIX: Insecure Deserialization (OWASP A08:2021 / CWE-502)
#
# Previously: pickle.loads(base64.b64decode(raw_data))
#   Unpickling attacker-controlled bytes ≡ arbitrary code execution.
#
# Fix:
#   1. Remove the pickle import entirely (not merely unused — presence invites misuse).
#   2. Decode base64, then parse as JSON — no code can be embedded.
#   3. Validate the schema: only allow an explicit whitelist of keys.
# ---------------------------------------------------------------------------
@app.route('/load_session', methods=['POST'])
def load_session():
    payload = request.get_json(silent=True)
    if not payload or 'session_data' not in payload:
        abort(400, description="Missing session_data field")

    raw_data = payload['session_data']
    try:
        # base64-decode, then parse as JSON — never unpickle untrusted data
        decoded_str = base64.b64decode(raw_data).decode('utf-8')
        session_obj = json.loads(decoded_str)
    except (ValueError, UnicodeDecodeError) as exc:
        abort(400, description=f"Invalid session data: {exc}")

    # Whitelist: reject any payload that contains unexpected keys
    allowed_keys = {'user_id', 'username', 'role'}
    if not isinstance(session_obj, dict) or not session_obj.keys() <= allowed_keys:
        abort(400, description="Malformed session payload")

    return jsonify({"status": "Session loaded", "user": session_obj.get("username", "")})


# ---------------------------------------------------------------------------
# VULN-T3-4 FIX: Flask dev server bound to loopback (OWASP A05:2021 / CWE-200)
#
# Previously: app.run(host='0.0.0.0', port=5001)
#   Exposed the un-hardened Flask dev server on all network interfaces.
#
# Fix: Bind to 127.0.0.1 only; gate debug mode behind FLASK_DEBUG env var.
#   In production, run under gunicorn / uwsgi behind a TLS-terminating
#   reverse proxy (nginx / ALB) — never expose the dev server directly.
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    _debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=5001, debug=_debug)

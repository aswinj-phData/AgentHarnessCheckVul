"""
Intentionally vulnerable sample code for testing a code-scanning agent.
DO NOT use in production. Every issue is labeled with a [VULN-n] or [QUALITY-n] tag
so you can check the agent's findings against this answer key.
"""
import os
import re
import ssl
import json
import yaml
import pickle
import random
import hashlib
import sqlite3
import logging
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string, redirect, send_file
import requests

app = Flask(__name__)

# [VULN-1] Hardcoded secrets (CWE-798)
SECRET_KEY = "super-secret-key-123"
DB_PASSWORD = "admin123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

app.secret_key = SECRET_KEY

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def get_db():
    return sqlite3.connect("users.db")


# [VULN-2] SQL injection via string formatting (CWE-89)
@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return json.dumps(cur.fetchall())


# [VULN-3] SQL injection via f-string + authentication bypass (CWE-89, CWE-287)
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    cur = conn.cursor()
    # [VULN-4] Plaintext password comparison / weak storage (CWE-256)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # [VULN-5] Sensitive data written to logs (CWE-532)
    logger.debug("Login attempt: %s / %s", username, password)
    cur.execute(query)
    if cur.fetchone():
        return "Welcome!"
    return "Invalid", 401


# [VULN-6] OS command injection (CWE-78)
@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


# [VULN-7] Command injection via os.system (CWE-78)
@app.route("/backup")
def backup():
    name = request.args.get("name")
    os.system("tar -czf /backups/%s.tgz /data" % name)
    return "done"


# [VULN-8] Reflected XSS / Server-side template injection (CWE-79, CWE-1336)
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")


# [VULN-9] Path traversal (CWE-22)
@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("/var/app/files", filename))


# [VULN-10] Arbitrary file write with unsanitized filename (CWE-434, CWE-22)
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save("/var/app/uploads/" + f.filename)
    return "uploaded"


# [VULN-11] Insecure deserialization with pickle (CWE-502)
@app.route("/load", methods=["POST"])
def load_session():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)


# [VULN-12] Unsafe YAML load (CWE-502)
def parse_config(text):
    return yaml.load(text, Loader=yaml.Loader)


# [VULN-13] eval / exec on user input (CWE-95)
@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


# [VULN-14] Server-side request forgery (CWE-918)
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # [VULN-15] TLS verification disabled (CWE-295)
    r = requests.get(url, verify=False)
    return r.text


# [VULN-16] Open redirect (CWE-601)
@app.route("/redirect")
def do_redirect():
    return redirect(request.args.get("next"))


# [VULN-17] Weak hashing for passwords (CWE-327, CWE-328)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()


# [VULN-18] Insecure randomness for security tokens (CWE-330)
def generate_reset_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(8))


# [VULN-19] XXE-prone XML parsing of untrusted input (CWE-611)
@app.route("/xml", methods=["POST"])
def parse_xml():
    tree = ET.fromstring(request.data)
    return tree.tag


# [VULN-20] Insecure temp file usage (CWE-377)
def write_temp(data):
    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write(data)
    return path


# [VULN-21] ReDoS - catastrophic backtracking regex (CWE-1333)
def is_valid_email(email):
    return re.match(r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-z]+$", email)


# [VULN-22] Insecure SSL context (CWE-295)
def make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# [VULN-23] Missing authorization / IDOR (CWE-639, CWE-862)
@app.route("/account/<int:account_id>")
def account(account_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
    return json.dumps(cur.fetchall())  # no check that the caller owns this account


# [VULN-24] Overly permissive file permissions (CWE-732)
def save_secret(data):
    with open("/tmp/secret.txt", "w") as f:
        f.write(data)
    os.chmod("/tmp/secret.txt", 0o777)


# [VULN-25] Verbose error leaking stack traces / internals (CWE-209)
@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return "<pre>" + traceback.format_exc() + "</pre>", 500


# [VULN-26] Mass assignment (CWE-915)
@app.route("/profile", methods=["POST"])
def update_profile():
    data = request.get_json()
    conn = get_db()
    sets = ", ".join(f"{k} = '{v}'" for k, v in data.items())  # also SQLi, user can set is_admin
    conn.execute("UPDATE users SET " + sets + " WHERE id = 1")
    conn.commit()
    return "ok"


# [VULN-27] Use of assert for security checks (CWE-617) - stripped with python -O
def delete_user(user, target):
    assert user.is_admin, "Admin only"
    print("deleting", target)


# ---------------------------------------------------------------------------
# Code quality issues (not security-critical)
# ---------------------------------------------------------------------------

# [QUALITY-1] Mutable default argument
def add_item(item, items=[]):
    items.append(item)
    return items


# [QUALITY-2] Bare except swallowing all errors
def read_file(path):
    try:
        return open(path).read()  # [QUALITY-3] file handle never closed
    except:
        pass


# [QUALITY-4] Unused imports/variables, shadowed builtins, poor naming
def process(list, dict):
    x = 1
    unused_var = 42
    id = 5
    for i in range(len(list)):
        if list[i] == None:  # [QUALITY-5] should use `is None`
            continue
        print(list[i])


# [QUALITY-6] Duplicate logic and magic numbers
def calculate_price(qty, kind):
    if kind == "A":
        return qty * 19.99 * 1.0825 - 5
    elif kind == "B":
        return qty * 29.99 * 1.0825 - 5
    elif kind == "C":
        return qty * 39.99 * 1.0825 - 5
    else:
        return qty * 49.99 * 1.0825 - 5


# [QUALITY-7] Deep nesting / high cyclomatic complexity
def complex_logic(a, b, c, d):
    if a:
        if b:
            if c:
                if d:
                    return 1
                else:
                    return 2
            else:
                if d:
                    return 3
                else:
                    return 4
        else:
            return 5
    else:
        return 6


# [QUALITY-8] Resource leak: DB connection never closed; no context manager
def count_users():
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    return cur.fetchone()[0]


# [QUALITY-9] Race condition / TOCTOU
def safe_write(path, data):
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(data)


# [QUALITY-10] Dead code / unreachable statements
def get_status(code):
    return "ok" if code == 200 else "error"
    print("never runs")


# [QUALITY-11] No timeout on network call, no error handling
def get_remote_data(url):
    return requests.get(url).json()


# [QUALITY-12] Missing docstrings, type hints, and a global mutable state
CACHE = {}


def cached(key):
    global CACHE
    if key not in CACHE:
        CACHE[key] = expensive(key)
    return CACHE[key]


def expensive(key):
    return key * 2


if __name__ == "__main__":
    # [VULN-28] Debug mode on and binding to all interfaces (CWE-489, CWE-668)
    app.run(host="0.0.0.0", port=5000, debug=True)

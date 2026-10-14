"""
Security-remediated version of test2.py.

VULN-T2-1 FIX: Hardcoded AWS credentials replaced with environment variables.
VULN-T2-2 FIX: Command injection eliminated — shell=False + IP validation + timeout.
VULN-T2-3 FIX: Flask bound to loopback only; debug controlled by env var.

See VULNERABILITY_REPORT.md for full details of each fix.
"""

import os
import ipaddress
import subprocess

from flask import Flask, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULN-T2-1 FIX: Load credentials from environment variables.
# Never hardcode secrets in source code — they become permanently visible in
# git history and are trivially discoverable by anyone with repo access.
# In production, prefer IAM instance roles or AWS Secrets Manager.
# ---------------------------------------------------------------------------
AWS_ACCESS_KEY_ID     = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]


# ---------------------------------------------------------------------------
# VULN-T2-2 FIX: Command injection via subprocess + shell=True eliminated.
# - Validate host is a well-formed IP address before use (rejects shell metacharacters).
# - Pass arguments as a list (shell=False) so no shell interprets the input.
# - Enforce a timeout to prevent resource exhaustion / hung processes.
# ---------------------------------------------------------------------------
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    try:
        # Raises ValueError for anything that is not a valid IPv4 or IPv6 address,
        # which blocks all shell-injection payloads (e.g. "127.0.0.1; rm -rf /").
        ipaddress.ip_address(host)
    except ValueError:
        return "Invalid host — must be a valid IP address.", 400

    output = subprocess.check_output(
        ["ping", "-c", "1", host],   # list form: shell never invoked
        shell=False,                  # explicit for clarity
        timeout=5                     # prevent hung processes
    )
    return output


# ---------------------------------------------------------------------------
# VULN-T2-3 FIX: Bind to loopback only; debug controlled by environment.
# host="0.0.0.0" exposes the Flask dev server on all network interfaces,
# including public-facing NICs. The dev server is not production-hardened.
# Use gunicorn / uwsgi behind a reverse proxy for production deployments.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=_debug)

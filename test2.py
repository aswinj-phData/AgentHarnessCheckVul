import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Vulnerability 2: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Unsanitized input passed directly to shell execution
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

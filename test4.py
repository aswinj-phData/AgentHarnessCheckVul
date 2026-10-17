import os
import sqlite3
import yaml
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerability 1: Hardcoded Sensitive Secrets (OWASP A07:2021 - Identification and Authentication Failures)
DATABASE_PASSWORD = "SuperSecretAdminPassword123!"
API_KEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"


# Vulnerability 2: Command Injection (OWASP A03:2021 - Injection)
@app.route('/api/v1/network/ping', methods=['GET'])
def ping_host():
    host = request.args.get('host', '127.0.0.1')
    # Vulnerable: Unsanitized user input concatenated directly into a shell command
    command = f"ping -c 1 {host}"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return jsonify({"status": "success", "output": output.decode('utf-8')})


# Vulnerability 3: SQL Injection (OWASP A03:2021 - Injection)
@app.route('/api/v1/users/find', methods=['GET'])
def find_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Vulnerable: Direct string interpolation into raw SQL query without parameterized queries
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    users = cursor.fetchall()
    conn.close()
    return jsonify({"users": users})


# Vulnerability 4: Insecure Deserialization / Arbitrary Code Execution (OWASP A08:2021 - Software and Data Integrity Failures)
@app.route('/api/v1/config/load', methods=['POST'])
def load_config():
    yaml_data = request.data.decode('utf-8')
    # Vulnerable: yaml.unsafe_load allows execution of arbitrary Python objects during deserialization
    parsed_config = yaml.unsafe_load(yaml_data)
    return jsonify({"status": "configuration loaded", "config": str(parsed_config)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

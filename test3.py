import os
import sqlite3
import pickle
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerability 1: SQL Injection (OWASP A03:2021 - Injection)
@app.route('/user_search', methods=['GET'])
def search_user():
    username = request.args.get('username')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Unsafe direct string formatting permits SQL injection payloads
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)

# Vulnerability 2: Path Traversal (OWASP A01:2021 - Broken Access Control)
@app.route('/read_log', methods=['GET'])
def read_log():
    filename = request.args.get('filename')
    # Unsanitized path parameter allows directory traversal (e.g., ../../../etc/passwd)
    file_path = os.path.join('/var/logs/app/', filename)
    with open(file_path, 'r') as f:
        content = f.read()
    return content

# Vulnerability 3: Insecure Deserialization (OWASP A08:2021 - Software/Data Integrity)
@app.route('/load_session', methods=['POST'])
def load_session():
    raw_data = request.json.get('session_data')
    # Unpickling untrusted input allows arbitrary code execution
    decoded_data = base64.b64decode(raw_data)
    session_obj = pickle.loads(decoded_data)
    return jsonify({"status": "Session loaded", "user": str(session_obj)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)

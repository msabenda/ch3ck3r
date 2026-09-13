# Ch3ck3r SAST — Vulnerable Test Application
# Python Flask API with deliberate security flaws
# Run: python app.py  (DO NOT DEPLOY — intentionally vulnerable)

from flask import Flask, request, jsonify, session
import sqlite3
import os
import subprocess
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # 🔴 CWE-798 Hardcoded secret

API_KEY = 'sk-live-abcdefghijklmnopqrstuvwxyz'  # 🔴 CWE-798 API key
SECRET_KEY = 'super-secret-123'  # 🔴 hardcoded JWT secret


@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # 🔴 CWE-89 SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    user = cursor.fetchone()
    return jsonify(user)


@app.route('/api/users', methods=['POST'])
def create_user():
    # 🔴 CWE-915 Mass Assignment
    data = request.json
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users VALUES (%s)" % data)
    conn.commit()
    return jsonify(data), 201


@app.route('/api/proxy', methods=['POST'])
def proxy_request():
    # 🔴 CWE-918 SSRF — user-controlled URL
    url = request.json.get('url')
    result = subprocess.check_output(['curl', url])
    return result


@app.route('/api/search', methods=['GET'])
def search():
    # 🔴 CWE-78 Command Injection
    query = request.args.get('q')
    result = subprocess.check_output('grep -r "%s" /data' % query, shell=True)
    return result


@app.route('/api/admin/users')
def admin_users():
    # 🔴 CWE-285 No authorization check
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return jsonify([{
        'id': u[0],
        'password': u[2],  # 🔴 CWE-200 password in response
        'ssn': u[3],  # 🔴 CWE-200 sensitive data
    } for u in users])


@app.route('/api/export')
def export_data():
    # 🔴 CWE-770 Bulk export without pagination or quota
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return jsonify(cursor.fetchall())


@app.route('/api/webhook', methods=['POST'])
def webhook():
    # 🔴 CWE-918 SSRF via webhook callback
    callback = request.json.get('callback')
    os.system('curl -s -o /dev/null ' + callback)  # 🔴 CWE-78
    return '', 204


if __name__ == '__main__':
    # 🔴 CWE-215 Debug mode enabled
    app.run(debug=True)

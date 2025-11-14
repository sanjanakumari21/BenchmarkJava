# app.py
# Run: pip install -r requirements.txt && python app.py
from flask import Flask, request, send_file
import sqlite3
import os
import hashlib
import subprocess
import pickle   # insecure
import json

app = Flask(__name__)

# -----------------------------
# Hardcoded secret (vulnerability)
# -----------------------------
app.config['SECRET_KEY'] = "my-hardcoded-secret-key-1234"

# -----------------------------
# Insecure DB (in-memory)
# -----------------------------
conn = sqlite3.connect(":memory:", check_same_thread=False)
cur = conn.cursor()
cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
cur.execute("INSERT INTO users (username, password) VALUES ('admin','admin123')")
conn.commit()

# ----------------------------------------------------------
# 1) SQL Injection (string concatenation)
# ----------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # MD5 (weak hashing)
    hashed = hashlib.md5(password.encode()).hexdigest()

    # SQL Injection vulnerability:
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    row = cur.execute(query).fetchone()

    if row:
        return f"Welcome {username}"
    return "Invalid credentials"


# ----------------------------------------------------------
# 2) Command Injection
# ----------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Vulnerable: directly injecting into shell command
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output


# ----------------------------------------------------------
# 3) Path Traversal
# ----------------------------------------------------------
@app.route("/read")
def read_file():
    filename = request.args.get("file", "")
    # Vulnerable: user-controlled path
    return send_file(filename)


# ----------------------------------------------------------
# 4) XSS (Reflected)
# ----------------------------------------------------------
@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    return f"<h1>Hello {name}</h1>"     # no sanitization


# ----------------------------------------------------------
# 5) Insecure Deserialization
# ----------------------------------------------------------
@app.route("/load", methods=["POST"])
def load_data():
    data = request.data
    # Vulnerable: directly loading pickle data
    obj = pickle.loads(data)
    return json.dumps({"loaded": str(obj)})


# ----------------------------------------------------------
# Run server
# ----------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

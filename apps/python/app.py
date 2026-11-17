"""Deliberately vulnerable Flask API for the DevSecOps PoC.

WARNING: this app contains intentional security flaws so that scanners have
something to find. Never expose it to a network you don't control.
Each planted flaw is tagged with `VULN:` so it's easy to find and explain.
"""

import hashlib
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    """In-memory database seeded with a few users."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users (id, name, role) VALUES (?, ?, ?)",
        [(1, "alice", "admin"), (2, "bob", "user"), (3, "carol", "user")],
    )
    return conn


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/users")
def users():
    user_id = request.args.get("id", "1")
    conn = get_db()
    # VULN: SQL injection (string formatting into SQL). Try ?id=1 OR 1=1
    rows = conn.execute(f"SELECT id, name, role FROM users WHERE id = {user_id}").fetchall()
    return jsonify([{"id": r[0], "name": r[1], "role": r[2]} for r in rows])


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: OS command injection (shell=True with user input). Try ?host=127.0.0.1;id
    output = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5
    )
    return jsonify(stdout=output.stdout, stderr=output.stderr)


@app.get("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    # VULN: SSRF (server fetches any user-supplied URL), and TLS verification is disabled
    resp = requests.get(url, timeout=5, verify=False)
    return jsonify(status=resp.status_code, length=len(resp.content))


@app.post("/config")
def config():
    # VULN: unsafe YAML deserialization (yaml.load without SafeLoader)
    data = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    return jsonify(parsed=str(data))


@app.get("/hash")
def hash_value():
    value = request.args.get("value", "")
    # VULN: weak hash algorithm (MD5)
    return jsonify(md5=hashlib.md5(value.encode()).hexdigest())


if __name__ == "__main__":
    # VULN: debug mode enables the interactive Werkzeug debugger
    app.run(host="0.0.0.0", port=8080, debug=True)

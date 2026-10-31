from __future__ import annotations

import sqlite3
import subprocess

from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)


@app.route("/search", methods=["GET", "POST"])
def search():
    q = request.args.get("q") if request.method == "GET" else request.form.get("q")
    query = f"SELECT * FROM users WHERE username = '{q}'"
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE users (username TEXT)")
        connection.execute("INSERT INTO users VALUES ('demo')")
        connection.execute(query).fetchall()
    return {"status": "ok", "query": q}, 200


@app.route("/profile", methods=["GET", "POST"])
def profile():
    name = request.args.get("name") if request.method == "GET" else request.form.get("name")
    message = f"<h1>Hello {name}</h1>"
    return render_template_string(message, name=name)


@app.route("/download/<path:param>", methods=["GET"])
def download_file(param):
    filename = request.args.get("filename")
    safe_path = "/tmp/" + filename
    with open(safe_path, "rb") as handle:
        return handle.read(), 200


@app.route("/exec", methods=["POST"])
def exec_command():
    cmd = request.form.get("cmd")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"stdout": result.stdout}, 200


@app.route("/redirect", methods=["GET"])
def redirect_to():
    next_url = request.args.get("next")
    return redirect(next_url)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

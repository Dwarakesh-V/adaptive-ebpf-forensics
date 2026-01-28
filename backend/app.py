from flask import Flask, render_template, request, redirect, session, url_for
from auth.login import login_user, verify_mfa
from auth.password_hash import create_user
import sqlite3

app = Flask(__name__)
app.secret_key = "super_secret_demo_key"

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        result = login_user(username, password)
        if result["status"] == "MFA_REQUIRED":
            session["temp_user"] = username
            return redirect(url_for("mfa"))

        return "Invalid credentials"

    return render_template("login.html")

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "temp_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = request.form["otp"]
        if verify_mfa(session["temp_user"], otp):
            session["user"] = session["temp_user"]
            session.pop("temp_user")
            return redirect(url_for("dashboard"))
        return "Invalid OTP"

    return render_template("mfa.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)

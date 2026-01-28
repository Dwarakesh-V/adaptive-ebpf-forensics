from flask import Flask, render_template, request, redirect, session, url_for
from auth.login import login_user, verify_mfa
from auth.password_hash import create_user
import sqlite3
import json

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
            session["temp_role"] = result["role"]
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
            session["role"] = session["temp_role"]
            session.pop("temp_user")
            session.pop("temp_role")
            return redirect(url_for("dashboard"))
        return "Invalid OTP"

    return render_template("mfa.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    role = session.get("role")

    if role == "ADMIN":
        return render_template("dashboard_admin.html")
    elif role == "INVESTIGATOR":
        return render_template("dashboard_investigator.html")
    elif role == "AUDITOR":
        return render_template("dashboard_auditor.html")

    return "Unauthorized"

@app.route("/memory-events")
def memory_events():
    if session.get("role") != "INVESTIGATOR":
        return "Access denied"

    with open("ebpf/probe_output.json") as f:
        event = json.load(f)

    response = {
        "status": "Live memory anomaly detected",
        "event": event
    }

    return response

@app.route("/deploy-probes", methods=["POST"])
def deploy_probes():
    if session.get("role") != "ADMIN":
        return "Access denied"

    # Synthetic deployment logic
    return render_template(
        "dashboard_admin.html",
        message="eBPF probes successfully deployed with adaptive configuration."
    )


@app.route("/view-dumps")
def view_dumps():
    if session.get("role") != "ADMIN":
        return "Access denied"

    dumps = [
        "memdump_ssh_4123.enc",
        "memdump_nginx_2211.enc"
    ]

    return {
        "available_dumps": dumps
    }

@app.route("/generate-report", methods=["POST"])
def generate_report():
    if session.get("role") != "INVESTIGATOR":
        return "Access denied"

    report = {
        "report_id": "FR-2026-001",
        "generated_by": session["user"],
        "summary": "Suspicious heap access detected in ssh process",
        "integrity": "SHA256 hash generated",
        "signature": "Digitally signed by investigator"
    }

    return render_template(
        "dashboard_investigator.html",
        message="Forensic report generated and signed successfully."
    )

@app.route("/view-reports")
def view_reports():
    if session.get("role") != "AUDITOR":
        return "Access denied"

    reports = [
        "FR-2026-001",
        "FR-2026-002"
    ]

    return {
        "signed_reports": reports
    }


@app.route("/verify-report", methods=["POST"])
def verify_report():
    if session.get("role") != "AUDITOR":
        return "Access denied"

    return render_template(
        "dashboard_auditor.html",
        message="Report integrity verified. Hash and signature valid."
    )

if __name__ == "__main__":
    app.run(debug=True)

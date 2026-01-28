from flask import Flask, render_template, request, redirect, session, url_for
from auth.login import login_user, verify_mfa
from auth.password_hash import create_user
import sqlite3
import json
from flask import Response
from ebpf.live_generator import event_stream
from crypto.aes_crypto import encrypt_data
from crypto.signature import sign_data, verify_signature
from crypto.aes_crypto import decrypt_data
import os

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

    # Synthetic memory dump
    dump_data = b"Live memory snapshot: suspicious heap activity detected"

    encrypted_dump, aes_key, iv = encrypt_data(dump_data)

    signature = sign_data(encrypted_dump)

    with open("storage/encrypted_dumps/dump.enc", "wb") as f:
        f.write(encrypted_dump)

    with open("storage/encrypted_dumps/aes.key", "wb") as f:
        f.write(aes_key)

    with open("storage/encrypted_dumps/aes.iv", "wb") as f:
        f.write(iv)

    with open("storage/signatures/dump.sig", "wb") as f:
        f.write(signature)

    return render_template(
        "dashboard_investigator.html",
        message="Memory dump encrypted with AES and digitally signed successfully."
    )

@app.route("/view-reports")
def view_reports():
    if session.get("role") != "AUDITOR":
        return "Access denied"

    output = (
        "Signed Forensic Reports:\n"
        "- dump.enc (AES-encrypted)\n"
        "- dump.sig (Digital Signature)\n"
    )

    return render_template(
        "dashboard_auditor.html",
        output=output
    )

@app.route("/verify-report", methods=["POST"])
def verify_report():
    if session.get("role") != "AUDITOR":
        return "Access denied"

    with open("storage/encrypted_dumps/dump.enc", "rb") as f:
        encrypted_dump = f.read()

    with open("storage/signatures/dump.sig", "rb") as f:
        signature = f.read()

    valid = verify_signature(encrypted_dump, signature)

    msg = "Integrity verified. Signature valid." if valid else "Integrity check failed."

    return render_template(
        "dashboard_auditor.html",
        message=msg
    )

@app.route("/live-stream")
def live_stream():
    if session.get("role") != "INVESTIGATOR":
        return "Access denied"

    return Response(
        event_stream(),
        mimetype="text/event-stream"
    )

@app.route("/decrypt-dump", methods=["POST"])
def decrypt_dump():
    if session.get("role") != "ADMIN":
        return "Access denied"

    with open("storage/encrypted_dumps/dump.enc", "rb") as f:
        encrypted_dump = f.read()

    with open("storage/encrypted_dumps/aes.key", "rb") as f:
        key = f.read()

    with open("storage/encrypted_dumps/aes.iv", "rb") as f:
        iv = f.read()

    plaintext = decrypt_data(encrypted_dump, key, iv)

    output = (
        "Decrypted Memory Dump:\n\n"
        + plaintext.decode()
    )

    return render_template(
        "dashboard_admin.html",
        output=output
    )

if __name__ == "__main__":
    app.run(debug=True)

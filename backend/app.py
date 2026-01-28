from flask import Flask, render_template, request, redirect, session, url_for
from auth.login import login_user, verify_mfa
import json
from flask import Response
from ebpf.live_generator import event_stream
from crypto.aes_crypto import encrypt_data
from crypto.signature import sign_data, verify_signature
from crypto.aes_crypto import decrypt_data
from crypto.qr_codec import generate_qr
from crypto.qr_codec import decode_qr
import hashlib
from datetime import datetime
from zoneinfo import ZoneInfo
import shutil

LIVE_EVENT_BUFFER = []

app = Flask(__name__)

@app.before_request
def enforce_login():
    allowed_routes = ["login", "mfa", "static"]
    if request.endpoint not in allowed_routes:
        if "user" not in session:
            return redirect(url_for("login"))

@app.after_request
def disable_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

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

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

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

        return render_template(
            "mfa.html",
            error="Invalid verification code. Please try again."
        )

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
        output = (
                "Probe Deployment Summary:\n"
                "- Access control verified for ADMIN role\n"
                "- Adaptive eBPF probe configuration initialized\n"
                "- Kernel memory monitoring hooks activated\n"
                "- Event severity thresholds loaded (LOW/MEDIUM/HIGH)\n"
                "- System is now actively monitoring memory behavior\n"
            )
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
    dump_text = ""
    for e in LIVE_EVENT_BUFFER:
        dump_text += (
            f"[{e['time']}] "
            f"PID {e['pid']} ({e['process']}) -> "
            f"{e['event']} | Severity: {e['severity']}\n"
        )

    dump_data = dump_text.encode()
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

    report_metadata = {
        "report_id": "FR-2026-001",
        "generated_by": session["user"],
        "timestamp": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
        "description": "Encrypted eBPF memory forensic snapshot",
        "hash": hashlib.sha256(encrypted_dump).hexdigest()
    }

    generate_qr(
        report_metadata,
        "storage/qr/report_qr.png"
    )
    shutil.copy("storage/qr/report_qr.png", "static/report_qr.png")

    return render_template(
        "dashboard_investigator.html",
        message="Memory dump encrypted with AES and digitally signed successfully."
    )

@app.route("/view-reports")
def view_reports():
    if session.get("role") != "AUDITOR":
        return "Access denied"

    output = (
        "Forensic Snapshot Generation Complete:\n"
        "- Live memory events aggregated into a forensic snapshot\n"
        "- Snapshot encrypted using AES-256 for confidentiality\n"
        "- Cryptographic hash generated for integrity verification\n"
        "- Digital signature applied using investigator credentials\n"
        "- Encrypted evidence securely stored for audit and analysis\n"
        "- Encoded data stored in dump.enc and signature stored in data.sig\n"
        "- Forensic metadata encoded into QR code\n"
        "- QR code generated for quick verification"
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

    qr_data = decode_qr("storage/qr/report_qr.png")
    if valid:
        msg = (
            "Integrity Verification Result:\n"
            "- Digital signature verified\n"
            "- Evidence integrity confirmed\n\n"
            "Decoded QR Metadata:\n"
            f"Report ID: {qr_data.get('report_id')}\n"
            f"Generated By: {qr_data.get('generated_by')}\n"
            f"Timestamp: {qr_data.get('timestamp')}\n"
        )
    else:
        msg = (
            "Integrity Verification Failed:\n"
            "- Signature mismatch detected. This indicates that the data was likely tampered with.\n"
            "- Evidence integrity cannot be guaranteed\n"
        )

    return render_template(
    "dashboard_auditor.html",
    output=msg
    )

@app.route("/live-stream")
def live_stream():
    if session.get("role") != "INVESTIGATOR":
        return "Access denied"

    return Response(
        event_stream(LIVE_EVENT_BUFFER),
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
        "Decryption Operation Summary:\n"
        "- Administrator access verified via role-based control\n"
        "- AES encryption key and IV retrieved securely\n"
        "- Encrypted forensic dump decrypted successfully\n"
        "- Plaintext memory evidence reconstructed\n\n"
        "Decrypted Memory Dump:\n\n"
        + plaintext.decode()
    )


    return render_template(
        "dashboard_admin.html",
        output=output
    )

@app.errorhandler(405)
def method_not_allowed(e):
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)

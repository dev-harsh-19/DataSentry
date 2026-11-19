import csv
import io
import json
import os
import re
import sqlite3
from datetime import datetime

import mysql.connector
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "datasentry-secret")

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
APP_DB_PATH = os.path.join(APP_ROOT, "datasentry.db")

SENSITIVE_KEYWORDS = {
    "email": ["email", "mail"],
    "phone": ["phone", "mobile", "telephone", "contact"],
    "card": ["card", "credit", "debit", "payment", "account"],
    "aadhaar": ["aadhaar", "uid", "gov", "government", "national_id", "identity"],
    "password": ["password", "passwd", "pwd", "secret"],
    "name": ["name", "first_name", "last_name", "full_name"],
    "address": ["address", "street", "city", "state", "postal_code", "zip", "pincode", "location"],
}

RECOMMENDATIONS = {
    "Email Address": "Apply email masking and restrict access to the column.",
    "Phone Number": "Mask the last digits and limit reading privileges.",
    "Card Number": "Encrypt the values and mask all but the last four digits.",
    "Aadhaar-like Identifier": "Restrict access, encrypt the column and audit usage.",
    "Password": "Store using a strong password hashing algorithm and avoid plaintext storage.",
    "Personal Name": "Keep minimum visibility and avoid exposing names in plain logs.",
    "Address Information": "Apply access restrictions and separate sensitive address data from general records.",
    "Non-Sensitive": "No immediate action required for this column.",
}


def get_data_connection_config():
    return {
        "host": os.getenv("MYSQL_HOST", "localhost"),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", "datasentry"),
    }


def normalize_name(name):
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")


def looks_like_email(value):
    if value is None:
        return False
    value = str(value).strip()
    return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value))


def looks_like_phone(value):
    if value is None:
        return False
    digits = re.sub(r"\D", "", str(value))
    return 10 <= len(digits) <= 15 and bool(digits)


def luhn_check(number):
    digits = [int(ch) for ch in number if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit
    return checksum % 10 == 0


def looks_like_card(value):
    if value is None:
        return False
    digits = re.sub(r"\D", "", str(value))
    return 13 <= len(digits) <= 19 and luhn_check(digits)


def looks_like_aadhaar(value):
    if value is None:
        return False
    digits = re.sub(r"\D", "", str(value))
    return len(digits) == 12 and digits.isdigit()


def mask_email(value):
    value = str(value)
    local, domain = value.split("@", 1)
    if len(local) <= 2:
        masked_local = "*" * max(len(local), 1)
    else:
        masked_local = local[0] + ("*" * (len(local) - 1))
    return f"{masked_local}@{domain}"


def mask_phone(value):
    digits = re.sub(r"\D", "", str(value))
    if len(digits) <= 4:
        return "*" * len(digits)
    return ("*" * (len(digits) - 4)) + digits[-4:]


def mask_card(value):
    digits = re.sub(r"\D", "", str(value))
    if len(digits) <= 4:
        return "*" * len(digits)
    return ("*" * (len(digits) - 4)) + digits[-4:]


def mask_generic(value):
    text = str(value)
    if len(text) <= 4:
        return "*" * len(text)
    return ("*" * (len(text) - 4)) + text[-4:]


def mask_value(value, detected_type):
    if value is None:
        return ""
    val = str(value)
    if detected_type == "Email Address":
        return mask_email(val)
    if detected_type == "Phone Number":
        return mask_phone(val)
    if detected_type == "Card Number":
        return mask_card(val)
    if detected_type in {"Password", "Aadhaar-like Identifier"}:
        return mask_generic(val)
    return val


def analyze_sample_values(column_name, sample_values):
    normalized = normalize_name(column_name)
    positive_hits = []
    negatives = []

    for key in SENSITIVE_KEYWORDS:
        for keyword in SENSITIVE_KEYWORDS[key]:
            if keyword in normalized:
                positive_hits.append(key)
                break

    if any(looks_like_email(str(v)) for v in sample_values if v is not None):
        positive_hits.append("email")
    if any(looks_like_phone(str(v)) for v in sample_values if v is not None):
        positive_hits.append("phone")
    if any(looks_like_card(str(v)) for v in sample_values if v is not None):
        positive_hits.append("card")
    if any(looks_like_aadhaar(str(v)) for v in sample_values if v is not None):
        positive_hits.append("aadhaar")
    if any("password" in normalize_name(str(v)) for v in sample_values if v is not None):
        positive_hits.append("password")

    if any(v is not None and isinstance(v, str) and len(v.split()) >= 2 and v.replace(" ", "").isalpha() for v in sample_values):
        positive_hits.append("name")

    if any("address" in normalized or "city" in normalized or "zip" in normalized or "postal" in normalized for _ in [0]):
        positive_hits.append("address")

    if "password" in normalized or "pwd" in normalized or "passwd" in normalized:
        positive_hits.append("password")
    if "name" in normalized or "first_name" in normalized or "last_name" in normalized or "full_name" in normalized:
        positive_hits.append("name")
    if "email" in normalized or "e_mail" in normalized:
        positive_hits.append("email")
    if "phone" in normalized or "mobile" in normalized or "contact" in normalized:
        positive_hits.append("phone")
    if "card" in normalized or "credit" in normalized or "debit" in normalized or "payment" in normalized:
        positive_hits.append("card")
    if "aadhaar" in normalized or "government" in normalized or "uid" in normalized:
        positive_hits.append("aadhaar")
    if "address" in normalized or "street" in normalized or "city" in normalized or "postal" in normalized or "zip" in normalized:
        positive_hits.append("address")

    if "email" in positive_hits:
        detected_type = "Email Address"
        risk_level = "MEDIUM"
    elif "phone" in positive_hits:
        detected_type = "Phone Number"
        risk_level = "MEDIUM"
    elif "card" in positive_hits:
        detected_type = "Card Number"
        risk_level = "HIGH"
    elif "aadhaar" in positive_hits:
        detected_type = "Aadhaar-like Identifier"
        risk_level = "HIGH"
    elif "password" in positive_hits:
        detected_type = "Password"
        risk_level = "HIGH"
    elif "address" in positive_hits:
        detected_type = "Address Information"
        risk_level = "MEDIUM"
    elif "name" in positive_hits:
        detected_type = "Personal Name"
        risk_level = "LOW"
    else:
        detected_type = "Non-Sensitive"
        risk_level = "NON-SENSITIVE"

    reasons = []
    if any(item in positive_hits for item in ["email", "phone", "card", "aadhaar", "password", "address", "name"]):
        reasons.append(f"Matched column name or sample values: {normalized}")
    if not reasons:
        reasons.append("No strong pattern match found.")
    return {
        "detected_type": detected_type,
        "risk_level": risk_level,
        "recommendation": RECOMMENDATIONS.get(detected_type, RECOMMENDATIONS["Non-Sensitive"]),
        "classification_reason": "; ".join(reasons),
    }


def get_sqlite_connection():
    conn = sqlite3.connect(APP_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_datasentry_db():
    conn = get_sqlite_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS database_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connection_name TEXT NOT NULL,
            host TEXT NOT NULL,
            database_name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            database_name TEXT NOT NULL,
            total_tables INTEGER NOT NULL,
            total_columns INTEGER NOT NULL,
            sensitive_columns INTEGER NOT NULL,
            scan_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            detected_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            classification_reason TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            data_type TEXT NOT NULL,
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()

    admin_user = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
    existing = conn.execute("SELECT id FROM admin_users WHERE username = ?", (admin_user,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            (admin_user, generate_password_hash(admin_password)),
        )
        conn.commit()
    conn.close()


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = get_sqlite_connection()
    row = conn.execute(
        "SELECT username, password_hash FROM admin_users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if row and check_password_hash(row["password_hash"], password):
        return jsonify({"success": True, "message": "Login successful", "username": row["username"]})
    return jsonify({"success": False, "message": "Invalid username or password"}), 401


@app.route("/api/test-connection", methods=["POST"])
def test_connection():
    data = request.get_json() or {}
    config = {
        "host": data.get("host", "localhost"),
        "user": data.get("username", "root"),
        "password": data.get("password", ""),
        "database": data.get("database_name", ""),
    }

    conn = None
    cursor = None
    try:
        if config["database"]:
            conn = mysql.connector.connect(**config, connect_timeout=5)
        else:
            conn = mysql.connector.connect(host=config["host"], user=config["user"], password=config["password"], connect_timeout=5)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        return jsonify({"success": True, "message": "Connection successful"})
    except mysql.connector.Error as exc:
        return jsonify({"success": False, "message": f"MySQL connection failed: {exc}"}), 400
    except Exception as exc:
        return jsonify({"success": False, "message": f"Unable to connect: {exc}"}), 400
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


@app.route("/api/connections", methods=["GET", "POST"])
def database_connections():
    if request.method == "GET":
        conn = get_sqlite_connection()
        rows = conn.execute(
            "SELECT id, connection_name, host, database_name, created_at FROM database_connections ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return jsonify({"connections": [dict(row) for row in rows]})

    data = request.get_json() or {}
    connection_name = (data.get("connection_name") or "Default Connection").strip() or "Default Connection"
    host = (data.get("host") or "localhost").strip()
    database_name = (data.get("database_name") or "").strip()

    if not database_name:
        return jsonify({"success": False, "message": "Database name is required"}), 400

    conn = get_sqlite_connection()
    conn.execute(
        "INSERT INTO database_connections (connection_name, host, database_name) VALUES (?, ?, ?)",
        (connection_name, host, database_name),
    )
    conn.commit()
    connection_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    conn.close()
    return jsonify({"success": True, "message": "Connection saved", "id": connection_id})


@app.route("/api/scan", methods=["POST"])
def scan_database():
    data = request.get_json() or {}
    host = data.get("host") or os.getenv("MYSQL_HOST", "localhost")
    username = data.get("username") or os.getenv("MYSQL_USER", "root")
    password = data.get("password") or os.getenv("MYSQL_PASSWORD", "")
    database_name = data.get("database_name") or os.getenv("TARGET_DB_NAME") or ""

    if not database_name:
        return jsonify({"success": False, "message": "Target database name is required"}), 400

    try:
        target_conn = mysql.connector.connect(host=host, user=username, password=password, database=database_name, connect_timeout=5)
    except mysql.connector.Error as exc:
        return jsonify({"success": False, "message": f"Unable to connect to target database: {exc}"}), 400

    cursor = target_conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s ORDER BY TABLE_NAME",
        (database_name,),
    )
    tables = [row["TABLE_NAME"] for row in cursor.fetchall()]

    all_results = []
    total_columns = 0
    sensitive_columns = 0
    new_columns = []
    schema_conn = get_sqlite_connection()
    previous_map = {}
    for row in schema_conn.execute("SELECT table_name, column_name, data_type FROM schema_history").fetchall():
        previous_map.setdefault(row["table_name"], set()).add(row["column_name"])
    schema_conn.close()

    for table_name in tables:
        cursor.execute(
            "SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
            (database_name, table_name),
        )
        columns = cursor.fetchall()
        total_columns += len(columns)

        try:
            quoted_table = "`" + table_name.replace("`", "``") + "`"
            cursor.execute(f"SELECT * FROM {quoted_table} LIMIT 10")
            rows = cursor.fetchall()
        except Exception:
            rows = []

        for column in columns:
            column_name = column["COLUMN_NAME"]
            data_type = column["DATA_TYPE"]
            sample_values = []
            for row in rows:
                sample_values.append(row.get(column_name))

            classification = analyze_sample_values(column_name, sample_values)
            if classification["risk_level"] != "NON-SENSITIVE":
                sensitive_columns += 1
            if column_name not in (previous_map.get(table_name, set())):
                new_columns.append({
                    "table_name": table_name,
                    "column_name": column_name,
                    "data_type": data_type,
                    "detected_type": classification["detected_type"],
                    "risk_level": classification["risk_level"],
                })

            all_results.append({
                "table_name": table_name,
                "column_name": column_name,
                "data_type": data_type,
                "detected_type": classification["detected_type"],
                "risk_level": classification["risk_level"],
                "recommendation": classification["recommendation"],
                "classification_reason": classification["classification_reason"],
            })

    scan_conn = get_sqlite_connection()
    scan_conn.execute(
        "INSERT INTO scan_history (database_name, total_tables, total_columns, sensitive_columns, scan_date) VALUES (?, ?, ?, ?, ?)",
        (database_name, len(tables), total_columns, sensitive_columns, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
    )
    scan_id = scan_conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    for result in all_results:
        scan_conn.execute(
            "INSERT INTO scan_results (scan_id, table_name, column_name, detected_type, risk_level, recommendation, classification_reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                result["table_name"],
                result["column_name"],
                result["detected_type"],
                result["risk_level"],
                result["recommendation"],
                result["classification_reason"],
            ),
        )

    for table_name in tables:
        cursor.execute(
            "SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
            (database_name, table_name),
        )
        for column in cursor.fetchall():
            column_name = column["COLUMN_NAME"]
            data_type = column["DATA_TYPE"]
            row = scan_conn.execute(
                "SELECT id FROM schema_history WHERE table_name = ? AND column_name = ?",
                (table_name, column_name),
            ).fetchone()
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            if row:
                scan_conn.execute(
                    "UPDATE schema_history SET data_type = ?, last_seen = ? WHERE id = ?",
                    (data_type, timestamp, row["id"]),
                )
            else:
                scan_conn.execute(
                    "INSERT INTO schema_history (table_name, column_name, data_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                    (table_name, column_name, data_type, timestamp, timestamp),
                )

    scan_conn.commit()
    scan_conn.close()
    target_conn.close()

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "summary": {
            "total_tables": len(tables),
            "total_columns": total_columns,
            "sensitive_columns": sensitive_columns,
            "high_risk": sum(1 for item in all_results if item["risk_level"] == "HIGH"),
            "medium_risk": sum(1 for item in all_results if item["risk_level"] == "MEDIUM"),
            "low_risk": sum(1 for item in all_results if item["risk_level"] == "LOW"),
        },
        "results": all_results,
        "new_columns": new_columns,
        "message": "Database scan completed successfully",
    })


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    scan_conn = get_sqlite_connection()
    latest_scan = scan_conn.execute(
        "SELECT * FROM scan_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not latest_scan:
        scan_conn.close()
        return jsonify({"summary": {"total_tables": 0, "total_columns": 0, "sensitive_columns": 0, "high_risk": 0, "medium_risk": 0, "low_risk": 0}, "results": []})

    results = scan_conn.execute(
        "SELECT table_name, column_name, detected_type, risk_level, recommendation, classification_reason FROM scan_results WHERE scan_id = ? ORDER BY table_name, column_name",
        (latest_scan["id"],),
    ).fetchall()
    scan_conn.close()
    result_list = [dict(row) for row in results]
    summary = {
        "total_tables": latest_scan["total_tables"],
        "total_columns": latest_scan["total_columns"],
        "sensitive_columns": latest_scan["sensitive_columns"],
        "high_risk": sum(1 for r in result_list if r["risk_level"] == "HIGH"),
        "medium_risk": sum(1 for r in result_list if r["risk_level"] == "MEDIUM"),
        "low_risk": sum(1 for r in result_list if r["risk_level"] == "LOW"),
    }
    return jsonify({"summary": summary, "results": result_list})


@app.route("/api/history", methods=["GET"])
def history():
    conn = get_sqlite_connection()
    scans = conn.execute(
        "SELECT id, database_name, total_tables, total_columns, sensitive_columns, scan_date FROM scan_history ORDER BY id DESC"
    ).fetchall()
    history_list = []
    for scan in scans:
        results = conn.execute(
            "SELECT table_name, column_name, detected_type, risk_level, recommendation, classification_reason FROM scan_results WHERE scan_id = ? ORDER BY table_name, column_name",
            (scan["id"],),
        ).fetchall()
        history_list.append({
            "id": scan["id"],
            "database_name": scan["database_name"],
            "total_tables": scan["total_tables"],
            "total_columns": scan["total_columns"],
            "sensitive_columns": scan["sensitive_columns"],
            "scan_date": scan["scan_date"],
            "results": [dict(item) for item in results],
        })
    conn.close()
    return jsonify({"history": history_list})


@app.route("/api/reports/export", methods=["GET"])
def export_csv():
    scan_id = request.args.get("scan_id")
    conn = get_sqlite_connection()
    if scan_id:
        rows = conn.execute(
            "SELECT table_name, column_name, detected_type, risk_level, recommendation, classification_reason FROM scan_results WHERE scan_id = ? ORDER BY table_name, column_name",
            (int(scan_id),),
        ).fetchall()
    else:
        latest = conn.execute("SELECT id FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
        if not latest:
            conn.close()
            return jsonify({"message": "No scan available to export"}), 404
        rows = conn.execute(
            "SELECT table_name, column_name, detected_type, risk_level, recommendation, classification_reason FROM scan_results WHERE scan_id = ? ORDER BY table_name, column_name",
            (latest["id"],),
        ).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["table_name", "column_name", "detected_type", "risk_level", "recommendation", "classification_reason"])
    for row in rows:
        writer.writerow([
            row["table_name"],
            row["column_name"],
            row["detected_type"],
            row["risk_level"],
            row["recommendation"],
            row["classification_reason"],
        ])
    csv_content = output.getvalue().encode("utf-8")
    return Response(csv_content, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=datasentry_report.csv"})


@app.route("/api/mask-demo", methods=["POST"])
def mask_demo():
    data = request.get_json() or {}
    samples = data.get("samples", [])
    detected_type = data.get("detected_type", "Email Address")
    masked = [mask_value(item, detected_type) for item in samples]
    return jsonify({"masked": masked})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "datasentry-backend"})


if __name__ == "__main__":
    init_datasentry_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

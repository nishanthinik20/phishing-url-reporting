from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
from functools import wraps

app = Flask(__name__)

# Flask secret key
app.secret_key = "phishing_reporting_secret_key_2026"


# =========================
# DATABASE CONNECTION
# =========================
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="phishing_reporting_db"
    )


# =========================
# LOGIN REQUIRED DECORATOR
# =========================
def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "warning")
            return redirect(url_for("login"))

        return route_function(*args, **kwargs)

    return wrapper


# =========================
# URL VALIDATION
# =========================
def is_valid_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False

        if not parsed.netloc:
            return False

        return True

    except Exception:
        return False


# =========================
# HOME
# =========================
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# =========================
# REGISTER
# =========================
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        try:
            db = get_db_connection()
            cursor = db.cursor()

            query = """
                INSERT INTO users (username, email, password)
                VALUES (%s, %s, %s)
            """

            cursor.execute(query, (username, email, password_hash))
            db.commit()

            cursor.close()
            db.close()

            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))

        except mysql.connector.IntegrityError:
            flash("Username or email already exists.", "danger")

        except Exception as e:
            flash("Database error occurred.", "danger")

    return render_template("register.html")


# =========================
# LOGIN
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("login"))

        try:
            db = get_db_connection()
            cursor = db.cursor(dictionary=True)

            query = """
                SELECT id, username, email, password
                FROM users
                WHERE email = %s
            """

            cursor.execute(query, (email,))
            user = cursor.fetchone()

            cursor.close()
            db.close()

            if user and check_password_hash(user["password"], password):

                session["user_id"] = user["id"]
                session["username"] = user["username"]

                return redirect(url_for("dashboard"))

            flash("Invalid email or password.", "danger")

        except Exception:
            flash("Database connection error.", "danger")

    return render_template("login.html")


# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# =========================
# DASHBOARD
# =========================
@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total FROM phishing_reports")
    total_reports = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM phishing_reports
        WHERE threat_type = 'Phishing'
    """)
    phishing_count = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM phishing_reports
        WHERE threat_type = 'Safe'
    """)
    safe_count = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM phishing_reports
        WHERE status = 'Pending'
    """)
    pending_count = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT p.*, u.username
        FROM phishing_reports p
        JOIN users u ON p.reported_by = u.id
        ORDER BY p.created_at DESC
        LIMIT 10
    """)

    reports = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "dashboard.html",
        total_reports=total_reports,
        phishing_count=phishing_count,
        safe_count=safe_count,
        pending_count=pending_count,
        reports=reports
    )


# =========================
# CREATE REPORT
# =========================
@app.route("/report", methods=["GET", "POST"])
@login_required
def report():

    if request.method == "POST":

        url = request.form.get("url", "").strip()
        threat_type = request.form.get("threat_type", "").strip()
        description = request.form.get("description", "").strip()

        if not url or not threat_type:
            flash("URL and threat type are required.", "danger")
            return redirect(url_for("report"))

        if not is_valid_url(url):
            flash("Please enter a valid HTTP/HTTPS URL.", "danger")
            return redirect(url_for("report"))

        db = get_db_connection()
        cursor = db.cursor()

        query = """
            INSERT INTO phishing_reports
            (url, threat_type, description, status, reported_by)
            VALUES (%s, %s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (
                url,
                threat_type,
                description,
                "Pending",
                session["user_id"]
            )
        )

        db.commit()

        cursor.close()
        db.close()

        flash("Phishing report submitted successfully.", "success")

        return redirect(url_for("dashboard"))

    return render_template("report.html")


# =========================
# VIEW ALL REPORTS
# =========================
@app.route("/reports")
@login_required
def reports():

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    query = """
        SELECT p.*, u.username
        FROM phishing_reports p
        JOIN users u ON p.reported_by = u.id
        ORDER BY p.created_at DESC
    """

    cursor.execute(query)
    all_reports = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "reports.html",
        reports=all_reports
    )


# =========================
# EDIT REPORT
# =========================
@app.route("/edit/<int:report_id>", methods=["GET", "POST"])
@login_required
def edit_report(report_id):

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":

        threat_type = request.form.get("threat_type", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "").strip()

        query = """
            UPDATE phishing_reports
            SET threat_type = %s,
                description = %s,
                status = %s
            WHERE id = %s
        """

        cursor.execute(
            query,
            (threat_type, description, status, report_id)
        )

        db.commit()

        cursor.close()
        db.close()

        flash("Report updated successfully.", "success")

        return redirect(url_for("reports"))

    cursor.execute(
        "SELECT * FROM phishing_reports WHERE id = %s",
        (report_id,)
    )

    report_data = cursor.fetchone()

    cursor.close()
    db.close()

    if not report_data:
        flash("Report not found.", "danger")
        return redirect(url_for("reports"))

    return render_template(
        "edit_report.html",
        report=report_data
    )


# =========================
# DELETE REPORT
# =========================
@app.route("/delete/<int:report_id>", methods=["POST"])
@login_required
def delete_report(report_id):

    db = get_db_connection()
    cursor = db.cursor()

    query = """
        DELETE FROM phishing_reports
        WHERE id = %s
    """

    cursor.execute(query, (report_id,))

    db.commit()

    cursor.close()
    db.close()

    flash("Report deleted successfully.", "success")

    return redirect(url_for("reports"))


# =========================
# RUN APPLICATION
# =========================
if __name__ == "__main__":
    app.run(debug=True)
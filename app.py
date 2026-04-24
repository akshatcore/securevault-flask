"""
app.py — Secure File Downloader (Production)
============================================
Run:
    python app.py                       # development
    gunicorn -w 4 -b 0.0.0.0:8000 app:app  # production

Environment variables (set before running):
    SECRET_KEY      — long random string (required in prod)
    FLASK_ENV       — "production" | "development"
"""

import os
import uuid
import mimetypes
import logging
from datetime import datetime, timezone
from functools import wraps
from logging.handlers import RotatingFileHandler

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import database as db
from config import get_config

# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    cfg = get_config()
    app.config.from_object(cfg)

    # Ensure directories exist
    os.makedirs(cfg.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(os.path.dirname(cfg.DATABASE), exist_ok=True)

    # Logging
    if not app.debug:
        handler = RotatingFileHandler(
            "instance/app.log", maxBytes=5_000_000, backupCount=3
        )
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s — %(message)s"
        ))
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # Initialise DB
    db.init_db(cfg.DATABASE)

    _register_blueprints(app)
    _register_error_handlers(app)

    return app


def _register_blueprints(app: Flask) -> None:
    # All routes inline (single-file keeps submission simple)
    # ── Security helpers ─────────────────────────────────────────────────────
    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("login"))
            user = db.get_user_by_id(session["user_id"])
            if not user:
                session.clear()
                flash("Session expired. Please log in again.", "warning")
                return redirect(url_for("login"))
            g.current_user = user
            return f(*args, **kwargs)
        return decorated

    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                flash("Authentication required.", "warning")
                return redirect(url_for("login"))
            user = db.get_user_by_id(session["user_id"])
            if not user or user["role"] != "admin":
                abort(403)
            g.current_user = user
            return f(*args, **kwargs)
        return decorated

    def allowed_file(filename: str) -> bool:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return ext in app.config["ALLOWED_EXTENSIONS"]

    def human_size(n: int) -> str:
        size = float(n)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    app.jinja_env.globals["human_size"] = human_size
    app.jinja_env.globals["now_year"] = datetime.now().year

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        cfg = app.config
        ip = request.remote_addr or "unknown"

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            # Rate-limit check
            if db.check_rate_limit(ip, cfg["LOGIN_MAX_ATTEMPTS"], cfg["LOGIN_WINDOW_SECONDS"]):
                db.log_login(username, ip, False)
                flash("Too many failed attempts. Please wait 5 minutes.", "danger")
                return render_template("login.html"), 429

            user = db.get_user_by_username(username)
            if user and check_password_hash(user["password_hash"], password):
                db.clear_rate_limit(ip)
                db.log_login(username, ip, True)
                db.update_last_login(user["id"])
                session.clear()
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                session["role"]     = user["role"]
                session.permanent   = True
                app.logger.info("LOGIN OK user=%s ip=%s", username, ip)
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for("dashboard"))
            else:
                db.record_failed_login(ip)
                db.log_login(username, ip, False)
                app.logger.warning("LOGIN FAIL user=%s ip=%s", username, ip)
                flash("Invalid credentials. Please try again.", "danger")

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        username = session.get("username", "unknown")
        session.clear()
        app.logger.info("LOGOUT user=%s", username)
        flash("You have been logged out securely.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        files = db.list_files()
        return render_template("dashboard.html", files=files, user=g.current_user)

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if request.method == "POST":
            if "file" not in request.files:
                flash("No file selected.", "danger")
                return redirect(request.url)

            f = request.files["file"]
            description = request.form.get("description", "").strip()

            # Coerce to a strict string to satisfy Pylance
            filename = f.filename or ""

            if not filename:
                flash("No file selected.", "danger")
                return redirect(request.url)

            if not allowed_file(filename):
                ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "none"
                flash(f"File type '.{ext}' is not allowed.", "danger")
                return redirect(request.url)

            original_name = secure_filename(filename)
            ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else "bin"
            safe_name = f"{uuid.uuid4().hex}.{ext}"
            dest = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
            f.save(dest)

            size = os.path.getsize(dest)
            mime = mimetypes.guess_type(original_name)[0] or "application/octet-stream"

            db.register_file(
                filename=safe_name,
                original_name=original_name,
                mime_type=mime,
                size_bytes=size,
                uploaded_by=session["user_id"],
                description=description,
            )
            app.logger.info("UPLOAD file=%s user=%s", original_name, session["username"])
            flash(f"'{original_name}' uploaded successfully!", "success")
            return redirect(url_for("dashboard"))

        return render_template("upload.html", user=g.current_user)

    @app.route("/download/<int:file_id>")
    @login_required
    def download(file_id: int):
        record = db.get_file_by_id(file_id)
        if not record:
            abort(404)
        path = os.path.join(app.config["UPLOAD_FOLDER"], record["filename"])
        if not os.path.exists(path):
            abort(404)
        app.logger.info("DOWNLOAD file_id=%d user=%s", file_id, session["username"])
        return send_from_directory(
            app.config["UPLOAD_FOLDER"],
            record["filename"],
            as_attachment=True,
            download_name=record["original_name"],
            mimetype=record["mime_type"],
        )

    @app.route("/delete/<int:file_id>", methods=["POST"])
    @login_required
    def delete_file(file_id: int):
        record = db.get_file_by_id(file_id)
        if not record:
            abort(404)
        # Only uploader or admin can delete
        if record["uploaded_by"] != session["user_id"] and session["role"] != "admin":
            abort(403)
        # Remove from disk
        path = os.path.join(app.config["UPLOAD_FOLDER"], record["filename"])
        if os.path.exists(path):
            os.remove(path)
        db.delete_file_record(file_id)
        app.logger.info("DELETE file_id=%d user=%s", file_id, session["username"])
        flash(f"'{record['original_name']}' deleted.", "info")
        return redirect(url_for("dashboard"))

    # ── Admin panel ───────────────────────────────────────────────────────────

    @app.route("/admin")
    @admin_required
    def admin_panel():
        users   = db.list_users()
        logs    = db.recent_login_log(50)
        files   = db.list_files()
        return render_template("admin.html", users=users, logs=logs,
                               files=files, user=g.current_user)

    @app.route("/admin/user/create", methods=["POST"])
    @admin_required
    def admin_create_user():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role     = request.form.get("role", "user")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("admin_panel"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("admin_panel"))
        if db.get_user_by_username(username):
            flash(f"Username '{username}' already exists.", "danger")
            return redirect(url_for("admin_panel"))

        db.create_user(username, generate_password_hash(password), role)
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("admin_panel"))

    @app.route("/admin/user/<int:uid>/toggle", methods=["POST"])
    @admin_required
    def admin_toggle_user(uid: int):
        if uid == session["user_id"]:
            flash("Cannot deactivate yourself.", "danger")
            return redirect(url_for("admin_panel"))
        user = db.get_user_by_id(uid)
        new_state = not bool(user["is_active"]) if user else True
        db.toggle_user_active(uid, new_state)
        flash("User status updated.", "success")
        return redirect(url_for("admin_panel"))

    @app.route("/admin/user/<int:uid>/reset-password", methods=["POST"])
    @admin_required
    def admin_reset_password(uid: int):
        new_pw = request.form.get("new_password", "")
        if len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("admin_panel"))
        db.change_password(uid, generate_password_hash(new_pw))
        flash("Password reset successfully.", "success")
        return redirect(url_for("admin_panel"))
    
    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password_self():
        if request.method == "POST":
            current  = request.form.get("current_password", "")
            new_pw   = request.form.get("new_password", "")
            confirm  = request.form.get("confirm_password", "")
            
            user = db.get_user_by_id(session["user_id"])

            # Use user["password_hash"] since it's a Row object, not .get()
            if user is None or not check_password_hash(str(user["password_hash"]), str(current)):
                flash("Current password is incorrect.", "danger")
            elif new_pw != confirm:
                flash("New passwords do not match.", "danger")
            elif len(str(new_pw)) < 8:
                flash("Password must be at least 8 characters.", "danger")
            else:
                db.change_password(session["user_id"], generate_password_hash(str(new_pw)))
                flash("Password changed successfully.", "success")
                return redirect(url_for("dashboard"))

        return render_template("change_password.html", user=g.current_user)

    # ── API endpoints (JSON) ───────────────────────────────────────────────────

    @app.route("/api/files")
    @login_required
    def api_files():
        files = db.list_files()
        return jsonify([dict(f) for f in files])

    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok", "version": app.config["APP_VERSION"]})


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(401)
    def unauthorized(e):
        return render_template("error.html", code=401,
                               message="Authentication required."), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                               message="You don't have permission to access this resource."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="The resource you requested could not be found."), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", code=413,
                               message="File exceeds the 100 MB size limit."), 413

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500,
                               message="An internal server error occurred."), 500


# ── Entry point ───────────────────────────────────────────────────────────────
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=app.config["DEBUG"])

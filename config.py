"""
config.py — Production configuration for Secure File Downloader
================================================================
All sensitive values are read from environment variables.
Provide a .env file (never commit it) or set them in your deployment
environment (Docker, systemd, Heroku, etc.).

Usage:
    export SECRET_KEY="your-very-long-random-string"
    export FLASK_ENV="production"
    python app.py
"""

import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # ── Security ────────────────────────────────────────────────────────────
    # ALWAYS override via environment variable in production!
    SECRET_KEY: str = os.environ.get("SECRET_KEY") or secrets.token_hex(48)

    SESSION_COOKIE_HTTPONLY: bool = True   # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE: str  = "Lax"  # CSRF mitigation
    SESSION_COOKIE_SECURE: bool   = False  # Set True when behind HTTPS in prod
    PERMANENT_SESSION_LIFETIME: int = 3600  # 1 hour idle timeout (seconds)

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE: str = os.path.join(BASE_DIR, "instance", "filestore.db")

    # ── File upload ───────────────────────────────────────────────────────────
    UPLOAD_FOLDER: str        = os.path.join(BASE_DIR, "uploads")
    #MAX_CONTENT_LENGTH: int   = 100 * 1024 * 1024   # 100 MB hard limit
    

    # Allowed MIME types — extend as needed
    ALLOWED_EXTENSIONS: set = {
        "pdf", "txt", "csv", "xlsx", "xls", "docx", "doc",
        "png", "jpg", "jpeg", "gif", "zip", "tar", "gz",
        "pptx", "mp4", "mp3", "json", "xml", "md"
    }

    # ── Rate limiting (manual token-bucket; no Flask-Limiter needed) ──────────
    LOGIN_MAX_ATTEMPTS: int = 5      # per IP per window
    LOGIN_WINDOW_SECONDS: int = 300  # 5 minutes

    # ── Application ───────────────────────────────────────────────────────────
    APP_NAME: str    = "SecureVault"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool      = os.environ.get("FLASK_ENV") == "development"


class ProductionConfig(Config):
    DEBUG           = False
    SESSION_COOKIE_SECURE = True   # Requires HTTPS


class DevelopmentConfig(Config):
    DEBUG = True


config_map = {
    "production":  ProductionConfig,
    "development": DevelopmentConfig,
    "default":     Config,
}

def get_config() -> Config:
    env = os.environ.get("FLASK_ENV", "default")
    return config_map.get(env, Config)()

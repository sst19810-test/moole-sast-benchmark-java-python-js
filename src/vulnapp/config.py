"""Application configuration.

WARNING: This module intentionally embeds secrets in source for SAST testing.
"""
import os


class Config:
    # CWE-798: Hardcoded credentials / secrets committed to source.
    SECRET_KEY = "s3cr3t-flask-signing-key-do-not-use-in-prod"  # noqa
    JWT_SECRET = "hardcoded-jwt-signing-secret-1234567890"      # noqa
    DB_USER = "admin"
    DB_PASSWORD = "P@ssw0rd123!"                                # noqa
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"                  # noqa
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa

    # A legitimate, environment-driven value (control sample; not a finding).
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///vulnapp.db")

    # CWE-489 / debug enabled: encourages running with the reloader/debugger.
    DEBUG = True


def get_db_dsn() -> str:
    """Returns a DSN string built from the hardcoded credentials above."""
    return f"postgresql://{Config.DB_USER}:{Config.DB_PASSWORD}@10.10.60.12:5432/app"

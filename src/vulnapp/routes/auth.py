"""Authentication routes (weak crypto, predictable tokens, reflected XSS)."""
import jwt
from flask import Blueprint, jsonify, render_template_string, request

from ..config import Config
from ..services.crypto_utils import generate_reset_token, hash_password

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.post("/login")
def login():
    body = request.get_json(force=True) or {}
    # Weak MD5 hashing of the supplied password (CWE-327).
    digest = hash_password(body.get("password", ""))
    # CWE-798 (secret) + 'none'/HS256 confusion surface using a hardcoded key.
    token = jwt.encode({"user": body.get("username", ""), "pw": digest},
                       Config.JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@bp.post("/reset")
def reset():
    # CWE-330: password reset token generated from predictable PRNG.
    return jsonify({"reset_token": generate_reset_token()})


# Inline template re-used by the reflected-XSS endpoint below.
PROFILE_TMPL = "<html><body><h1>Hello {{ name | safe }}</h1></body></html>"


@bp.get("/welcome")
def welcome():
    # CWE-79: reflected XSS — 'name' rendered with `| safe` (autoescape off).
    name = request.args.get("name", "guest")
    return render_template_string(PROFILE_TMPL, name=name)

"""User routes — request data here is the SOURCE of several taint flows."""
from flask import Blueprint, jsonify, request

from ..services import user_service

bp = Blueprint("users", __name__, url_prefix="/users")


@bp.get("/lookup")
def lookup():
    # SOURCE (CWE-89): request.args -> user_service.find_user_by_id -> db.raw_query
    user_id = request.args.get("id", "")
    rows = user_service.find_user_by_id(user_id)
    return jsonify(rows)


@bp.get("/search")
def search():
    # SOURCE (CWE-89): tainted 'q' flows cross-file into the LIKE sink.
    term = request.args.get("q", "")
    return jsonify(user_service.search_users(term))


@bp.post("/register")
def register():
    body = request.get_json(force=True) or {}
    # SOURCE (CWE-89): three tainted fields flow into the INSERT sink.
    user_service.create_user(
        body.get("username", ""),
        body.get("password", ""),
        body.get("email", ""),
    )
    return jsonify({"status": "created"}), 201

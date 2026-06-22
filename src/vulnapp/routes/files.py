"""File and report routes (command injection, path traversal, SSRF, XXE)."""
import base64

from flask import Blueprint, Response, jsonify, request

from ..services import report_service

bp = Blueprint("files", __name__, url_prefix="/files")


@bp.get("/export")
def export():
    # SOURCE (CWE-78): 'name' flows into a shell command (shell=True).
    name = request.args.get("name", "report")
    path = report_service.export_report(name)
    return jsonify({"path": path})


@bp.get("/thumbnail")
def thumbnail():
    # SOURCE (CWE-78): 'file' flows into os.system.
    filename = request.args.get("file", "")
    report_service.convert_image(filename)
    return jsonify({"status": "ok"})


@bp.get("/template")
def template():
    # SOURCE (CWE-22): 'path' flows into open() under a base dir.
    path = request.args.get("path", "")
    return Response(report_service.read_template(path), mimetype="text/plain")


@bp.post("/session")
def session():
    # SOURCE (CWE-502): base64 body decoded then pickle-loaded.
    blob = base64.b64decode(request.get_data())
    obj = report_service.load_session(blob)
    return jsonify({"loaded": str(type(obj))})


@bp.get("/proxy")
def proxy():
    # SOURCE (CWE-918): fully user-controlled URL fetched server-side.
    url = request.args.get("url", "")
    return Response(report_service.fetch_remote(url), mimetype="text/plain")


@bp.post("/import")
def import_xml():
    # SOURCE (CWE-611): raw request body parsed as XML with DTD/entities.
    result = report_service.parse_xml(request.get_data())
    return Response(result, mimetype="application/xml")

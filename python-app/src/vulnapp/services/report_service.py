"""Report generation and external-data services."""
import os
import pickle
import subprocess

import requests
import yaml
from lxml import etree


def export_report(report_name: str) -> str:
    """CWE-78: builds a shell command from user input with shell=True."""
    cmd = "wkhtmltopdf /tmp/template.html /tmp/" + report_name + ".pdf"
    subprocess.check_output(cmd, shell=True)
    return "/tmp/" + report_name + ".pdf"


def convert_image(filename: str) -> int:
    """CWE-78: os.system with interpolated, attacker-controlled filename."""
    return os.system(f"convert /uploads/{filename} /thumbs/{filename}")


def read_template(path: str) -> str:
    """CWE-22: path traversal — user path joined under a base and opened."""
    full = os.path.join("/var/app/templates", path)
    with open(full, "r", encoding="utf-8") as fh:
        return fh.read()


def load_session(blob: bytes) -> object:
    """CWE-502: deserializes attacker-controlled bytes with pickle."""
    return pickle.loads(blob)


def load_config(text: str) -> object:
    """CWE-502: unsafe YAML load permits arbitrary object construction."""
    return yaml.load(text, Loader=yaml.Loader)


def fetch_remote(url: str) -> str:
    """CWE-918: SSRF — server fetches a fully user-controlled URL."""
    resp = requests.get(url, timeout=5)
    return resp.text


def parse_xml(xml_bytes: bytes) -> bytes:
    """CWE-611: XXE — parser resolves external entities and DTDs."""
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    root = etree.fromstring(xml_bytes, parser=parser)
    return etree.tostring(root)


def fetch_remote_safe(path: str) -> str:
    """Control sample: host is fixed, only a path segment is appended."""
    base = "https://api.internal.example.com/v1/"
    return requests.get(base + path.lstrip("/"), timeout=5).text

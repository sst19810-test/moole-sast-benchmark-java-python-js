# python-app (Flask) — SAST test corpus

Intentionally vulnerable Flask service. Layout follows the `src/` packaging
convention with a Blueprint-per-domain structure.

```
python-app/
├── pyproject.toml          # PEP 621 metadata + deps
├── requirements.txt
├── src/vulnapp/
│   ├── app.py              # application factory
│   ├── config.py           # hardcoded secrets (CWE-798)
│   ├── db.py               # SQL sinks (CWE-89)
│   ├── routes/             # taint SOURCES (request.args / json)
│   └── services/           # business logic + sinks
└── tests/                  # smoke test only
```

## Cross-file taint example
`routes/users.py` (source) → `services/user_service.py` → `db.raw_query`
(sink) is a three-hop SQL-injection flow spanning three modules.

See the top-level `VULNERABILITIES.md` for the full source→sink ground-truth map.

## Run
```
pip install -e .
python -m vulnapp.app
```

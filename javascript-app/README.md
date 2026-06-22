# javascript-app (Node.js / Express) — SAST test corpus

Intentionally vulnerable Express service. Standard `src/` layout with
routes / services / middleware separation.

```
javascript-app/
├── package.json
├── src/
│   ├── server.js          # app bootstrap + ReDoS endpoint
│   ├── config.js           # hardcoded secrets (CWE-798)
│   ├── db.js               # SQL sink (CWE-89)
│   ├── routes/             # taint SOURCES (req.query / req.body)
│   ├── services/           # business logic + sinks
│   └── middleware/         # JWT auth (alg confusion, CWE-347)
└── test/                   # smoke test only
```

## Cross-file taint example
`routes/users.js` (source) → `services/userService.js` → `db.runQuery`
(sink) is a three-hop SQL-injection flow across three modules.

See the top-level `VULNERABILITIES.md` for the full source→sink ground-truth map.

## Run
```
npm install
npm start
```

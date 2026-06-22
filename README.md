# vuln-sast-testbed

A multi-language, intentionally vulnerable application corpus for benchmarking
a Static Application Security Testing (SAST) engine. It contains three
self-contained apps — Python (Flask), Java (Spring Boot), and Node.js
(Express) — each laid out using its ecosystem's conventional project
structure.

> **Safety note.** Every file in this repository is *deliberately* insecure and
> exists solely to produce findings in a scanner. Do not deploy any of it, do
> not point it at real data, and run it only in a disposable, isolated
> environment.

## Layout

```
vuln-sast-testbed/
├── README.md
├── VULNERABILITIES.md      # ground-truth source→sink map (expected findings)
├── python-app/             # Flask, src/ packaging, Blueprint-per-domain
├── java-app/               # Spring Boot, Maven, controller/service/repo layers
└── javascript-app/         # Express, routes/services/middleware
```

## What it exercises

Each app covers a spread of CWEs with both **single-file** and **cross-file**
taint flows, plus a set of **control samples** (parameterized queries, CSPRNGs,
hardened parsers, fixed-host requests) that a precise engine should *not* flag.
Use the controls to measure false-positive rate alongside recall.

Cross-file flows follow the same three-tier shape in every language:

| Language   | Source (route)            | Propagator (service)            | Sink (data layer)         |
|------------|---------------------------|---------------------------------|---------------------------|
| Python     | `routes/users.py`         | `services/user_service.py`      | `db.raw_query`            |
| Java       | `controller/UserController` | `service/UserService`         | `repository/UserRepository` |
| JavaScript | `routes/users.js`         | `services/userService.js`       | `db.runQuery`             |

## Coverage summary

| CWE      | Category                         | Python | Java | JavaScript |
|----------|----------------------------------|:------:|:----:|:----------:|
| CWE-89   | SQL Injection                    |   ✔    |  ✔   |     ✔      |
| CWE-78   | OS Command Injection             |   ✔    |  ✔   |     ✔      |
| CWE-22   | Path Traversal                   |   ✔    |  ✔   |     ✔      |
| CWE-79   | Reflected XSS                    |   ✔    |  ✔   |     ✔      |
| CWE-502  | Insecure Deserialization         |   ✔    |  ✔   |     ✔      |
| CWE-918  | SSRF                             |   ✔    |  ✔   |     ✔      |
| CWE-611  | XXE                              |   ✔    |  ✔   |            |
| CWE-327  | Weak Cryptography                |   ✔    |  ✔   |     ✔      |
| CWE-330  | Insecure Randomness              |   ✔    |  ✔   |     ✔      |
| CWE-798  | Hardcoded Credentials            |   ✔    |  ✔   |     ✔      |
| CWE-90   | LDAP Injection                   |        |  ✔   |            |
| CWE-95   | Eval Injection                   |        |      |     ✔      |
| CWE-601  | Open Redirect                    |        |      |     ✔      |
| CWE-943  | NoSQL Injection                  |        |      |     ✔      |
| CWE-1321 | Prototype Pollution              |        |      |     ✔      |
| CWE-1333 | ReDoS                            |        |      |     ✔      |
| CWE-347  | Improper JWT Verification        |        |      |     ✔      |
| CWE-209  | Stack-trace Information Exposure  |        |  ✔   |            |

See `VULNERABILITIES.md` for the per-finding breakdown (file, line, flow).

## Running each app

Per-language instructions live in each app's own `README.md`. All three run
locally with their standard toolchains (pip / Maven / npm).

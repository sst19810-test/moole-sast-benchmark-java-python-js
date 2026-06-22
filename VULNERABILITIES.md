# Ground-truth findings map

Expected findings for the `vuln-sast-testbed` corpus, to diff against scanner
output (recall) and to confirm the control samples stay clean (precision).

Line numbers point at the annotation comment that sits on the source or sink.
"Flow" is **cross-file** when source, propagator, and sink are in different
modules, otherwise **local**.

---

## python-app (Flask)

| #  | CWE      | Type                     | Source (entry)                         | Sink                                          | Flow       |
|----|----------|--------------------------|----------------------------------------|-----------------------------------------------|------------|
| P1 | CWE-89   | SQL Injection (id)       | `routes/users.py:11` `request.args`    | `db.py:21` `raw_query` ← `user_service.py:14` | cross-file |
| P2 | CWE-89   | SQL Injection (search)   | `routes/users.py:19`                   | `db.py:21` ← `user_service.py:20`             | cross-file |
| P3 | CWE-89   | SQL Injection (register) | `routes/users.py:27`                   | `db.py:21` ← `user_service.py:27`             | cross-file |
| P4 | CWE-78   | Command Injection        | `routes/files.py:13`                   | `report_service.py:12` `subprocess shell=True`| cross-file |
| P5 | CWE-78   | Command Injection        | `routes/files.py:21`                   | `report_service.py:19` `os.system`            | cross-file |
| P6 | CWE-22   | Path Traversal           | `routes/files.py:29`                   | `report_service.py:24` `open`                 | cross-file |
| P7 | CWE-502  | Deserialization (pickle) | `routes/files.py:36`                   | `report_service.py:31` `pickle.loads`         | cross-file |
| P8 | CWE-502  | Deserialization (YAML)   | `services/report_service.py:36`        | `yaml.load(Loader=yaml.Loader)`               | local      |
| P9 | CWE-918  | SSRF                     | `routes/files.py:44`                   | `report_service.py:41` `requests.get`         | cross-file |
| P10| CWE-611  | XXE                      | `routes/files.py:51`                   | `report_service.py:47` `etree` w/ entities    | cross-file |
| P11| CWE-79   | Reflected XSS            | `routes/auth.py:34` `request.args`     | `render_template_string` (`| safe`)           | local      |
| P12| CWE-327  | Weak Hash (MD5)          | `services/crypto_utils.py:8`           | `hashlib.md5`                                 | local      |
| P13| CWE-327  | Weak Hash (SHA-1)        | `services/crypto_utils.py:13`          | `hashlib.sha1`                                | local      |
| P14| CWE-330  | Insecure Randomness      | `services/crypto_utils.py:18`          | `random.choice` for token                     | local      |
| P15| CWE-798  | Hardcoded Secrets        | `config.py:9`                          | several constants                             | local      |
| P16| CWE-489  | Debug Mode Enabled       | `app.py:24`                            | `run(debug=True, host=0.0.0.0)`               | local      |

Controls (must NOT be flagged): `user_service.get_user_safe`,
`db.query_one`, `report_service.fetch_remote_safe`, `crypto_utils.secure_hash`.

---

## java-app (Spring Boot)

| #  | CWE      | Type                     | Source (entry)                              | Sink                                              | Flow       |
|----|----------|--------------------------|---------------------------------------------|---------------------------------------------------|------------|
| J1 | CWE-89   | SQL Injection (search)   | `controller/UserController.java:28`         | `UserRepository.java:31` `Statement` ← `UserService` | cross-file |
| J2 | CWE-89   | SQL Injection (email)    | `controller/UserController.java:34`         | `UserRepository.java:47` ← `UserService`          | cross-file |
| J3 | CWE-78   | Command Injection        | `controller/FileController.java:33`         | `CommandService.java:19` `Runtime.exec`           | cross-file |
| J4 | CWE-22   | Path Traversal           | `controller/FileController.java:39`         | `CommandService.java:35` `FileInputStream`        | cross-file |
| J5 | CWE-611  | XXE                      | `controller/FileController.java:45`         | `XmlUtil.java:20` `DocumentBuilderFactory`        | cross-file |
| J6 | CWE-502  | Deserialization          | `controller/FileController.java:51`         | `SerializationUtil.java:15` `ObjectInputStream`   | cross-file |
| J7 | CWE-918  | SSRF                     | `controller/FileController.java:59`         | `URL.openConnection`                              | local      |
| J8 | CWE-90   | LDAP Injection           | `controller/AdminController.java:32`        | `DirContext.search` filter                        | local      |
| J9 | CWE-79   | Reflected XSS            | `controller/SearchController.java:14`       | HTML response unescaped                           | local      |
| J10| CWE-327  | Weak Hash (MD5)          | `service/CryptoService.java:21`             | `MessageDigest "MD5"`                             | local      |
| J11| CWE-327  | Weak Cipher (DES/ECB)    | `service/CryptoService.java:32`             | `Cipher "DES/ECB/PKCS5Padding"`                  | local      |
| J12| CWE-330  | Insecure Randomness      | `service/CryptoService.java:41`             | `java.util.Random` for token                      | local      |
| J13| CWE-798  | Hardcoded Secrets        | `config/AppConfig.java:15`                  | credential constants                              | local      |
| J14| CWE-798  | Hardcoded Secrets (cfg)  | `resources/application.properties:4`        | password / api-key in properties                  | local      |
| J15| CWE-209  | Stack-trace Exposure     | `resources/application.properties:10`       | `include-stacktrace=always`                       | local      |

Controls (must NOT be flagged): `UserRepository.searchByNameSafe`,
`XmlUtil.parseSafe`, `CryptoService.secureToken`.

---

## javascript-app (Express)

| #   | CWE      | Type                     | Source (entry)                        | Sink                                          | Flow       |
|-----|----------|--------------------------|---------------------------------------|-----------------------------------------------|------------|
| N1  | CWE-89   | SQL Injection (lookup)   | `routes/users.js:8` `req.query.id`    | `db.js:15` `runQuery` ← `userService.js:11`   | cross-file |
| N2  | CWE-89   | SQL Injection (search)   | `routes/users.js:16`                  | `db.js:15` ← `userService.js:17`              | cross-file |
| N3  | CWE-78   | Command Injection        | `routes/files.js:9`                   | `commandService.js:12` `child_process.exec`   | cross-file |
| N4  | CWE-22   | Path Traversal           | `routes/files.js:17`                  | `commandService.js:17` `fs.readFile`          | cross-file |
| N5  | CWE-918  | SSRF                     | `routes/files.js:25`                  | `commandService.js:23` `axios.get`            | cross-file |
| N6  | CWE-502  | Deserialization          | `routes/files.js:35`                  | `node-serialize.unserialize`                  | local      |
| N7  | CWE-79   | Reflected XSS            | `routes/search.js:9` `req.query.q`    | HTML response unescaped                        | local      |
| N8  | CWE-95   | Eval Injection           | `routes/search.js:15`                 | `eval(expr)`                                   | local      |
| N9  | CWE-601  | Open Redirect            | `routes/search.js:23`                 | `res.redirect(req.query.next)`                | local      |
| N10 | CWE-943  | NoSQL Injection          | `routes/search.js:28` `req.body`      | `collection.find(filter)`                      | local      |
| N11 | CWE-1321 | Prototype Pollution      | `routes/auth.js:38` `req.body`        | recursive `merge` (`__proto__`)               | local      |
| N12 | CWE-327  | Weak Hash (MD5)          | `services/cryptoUtils.js:9`           | `crypto.createHash('md5')`                    | local      |
| N13 | CWE-327  | Weak Hash (SHA-1)        | `services/cryptoUtils.js:14`          | `crypto.createHash('sha1')`                   | local      |
| N14 | CWE-330  | Insecure Randomness      | `services/cryptoUtils.js:19`          | `Math.random` for token                        | local      |
| N15 | CWE-347  | Improper JWT Verify      | `middleware/auth.js:14`               | `jwt.verify` w/o `algorithms` allowlist        | local      |
| N16 | CWE-798  | Hardcoded Secrets        | `config.js:5`                         | secret constants                              | local      |
| N17 | CWE-1333 | ReDoS                    | `server.js:21` `req.query.value`      | `/^(a+)+$/.test`                              | local      |

Controls (must NOT be flagged): `userService.getUserSafe`,
`db.runQuerySafe`, `commandService.fetchInternal`, `cryptoUtils.secureToken`.

---

## Totals

| Language   | Expected findings | Cross-file flows | Control samples |
|------------|:-----------------:|:----------------:|:---------------:|
| Python     | 16                | 8                | 4               |
| Java       | 15                | 6                | 3               |
| JavaScript | 17                | 5                | 4               |
| **Total**  | **48**            | **19**           | **11**          |

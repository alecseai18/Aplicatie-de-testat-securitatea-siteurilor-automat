# CTF Aggressive Scanner Report

Target: `http://127.0.0.1:5000`

Findings: **21**

## CRITICAL

### SQL Injection - login bypass
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/login`
- Evidence: Login accepted SQLi payload in password: ' OR 1=1 --
- Request/Test: `POST /login`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - login bypass
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/login`
- Evidence: Login accepted SQLi payload in password: ' OR '1'='1' --
- Request/Test: `POST /login`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - login bypass
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/login`
- Evidence: Login accepted SQLi payload in password: '/**/OR/**/1=1--
- Request/Test: `POST /login`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - login bypass
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/login`
- Evidence: Login accepted SQLi payload in password: ' OR 'a'='a
- Request/Test: `POST /login`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### Insecure Deserialization
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/deserialize`
- Evidence: Application accepted/deserialized attacker-controlled serialized blob field=blob
- Request/Test: `POST serialized blob`
- Recommendation: Do not deserialize untrusted data, especially with pickle/native object serializers. Use safe formats such as JSON with schema validation, sign and authenticate serialized data if it must be accepted, and remove gadget-capable deserialization paths.

## HIGH

### SQL Injection - form probing
- Status: `likely`
- URL: `http://127.0.0.1:5000/documents?id=2`
- Evidence: SQL-related response after payload ' OR '1'='1' --
- Request/Test: `GET http://127.0.0.1:5000/documents?id=2`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - form probing
- Status: `likely`
- URL: `http://127.0.0.1:5000/documents?id=1`
- Evidence: SQL-related response after payload ' OR '1'='1' --
- Request/Test: `GET http://127.0.0.1:5000/documents?id=1`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - form probing
- Status: `likely`
- URL: `http://127.0.0.1:5000/ssrf`
- Evidence: SQL-related response after payload ' UNION SELECT NULL--
- Request/Test: `POST http://127.0.0.1:5000/ssrf`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - form probing
- Status: `likely`
- URL: `http://127.0.0.1:5000/command`
- Evidence: SQL-related response after payload ' UNION SELECT NULL--
- Request/Test: `POST http://127.0.0.1:5000/command`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - form probing
- Status: `likely`
- URL: `http://127.0.0.1:5000/xss`
- Evidence: SQL-related response after payload ' OR '1'='1' --
- Request/Test: `GET http://127.0.0.1:5000/xss`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### SQL Injection - form probing
- Status: `likely`
- URL: `http://127.0.0.1:5000/documents`
- Evidence: SQL-related response after payload ' OR '1'='1' --
- Request/Test: `GET http://127.0.0.1:5000/documents`
- Recommendation: Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, use least-privilege DB accounts, and add regression tests with SQLi payloads.

### Cross-Site Scripting (XSS)
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/xss`
- Evidence: Payload token reflected/stored; unescaped=True
- Request/Test: `payload=<script>alert('CTF_XSS_5cc27f11')</script>`
- Recommendation: Encode output contextually (HTML, attribute, JavaScript, URL), sanitize rich text with a trusted allowlist sanitizer, avoid rendering raw user input, use HttpOnly/SameSite cookies, and deploy a strict Content-Security-Policy.

### IDOR / Broken Access Control
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/documents?id=2`
- Evidence: Changing id returned different accessible resources: ['1', '2', '3']
- Request/Test: `GET parameter tampering`
- Recommendation: Enforce object-level authorization on the server for every resource access. Do not trust IDs from the client; check that the authenticated user owns or is allowed to access the requested object, and add negative authorization tests.

### Insecure File Upload
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/upload`
- Evidence: Potentially dangerous file accepted: ctf.php
- Request/Test: `multipart upload`
- Recommendation: Validate file type by content and extension allowlist, rename files to random names, store uploads outside the web root, disable execution in upload directories, enforce size limits, and scan files before serving them.

### SSRF
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/ssrf`
- Evidence: Server fetched local/internal resource via url=http://127.0.0.1:5000/
- Request/Test: `GET SSRF payload`
- Recommendation: Use a strict allowlist of permitted destination hosts/schemes, block loopback/private/link-local/cloud metadata IPs after DNS resolution, disable redirects or revalidate every redirect hop, and separate internal networks from user-controlled fetchers.

### Race Condition
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/race`
- Evidence: Concurrent withdrawals sent (80 x 50); final page indicates inconsistent state/negative value candidates=[-8, 1, 2, 2, -2850, 700]
- Request/Test: `parallel POST /race`
- Recommendation: Make the operation atomic using database transactions, row-level locks, optimistic locking/version checks, or atomic UPDATE conditions. Avoid check-then-update flows and add concurrent-request tests for financial/state-changing operations.

## MEDIUM

### Debug/Misconfiguration Exposure
- Status: `likely`
- URL: `http://127.0.0.1:5000/`
- Evidence: Debug/framework artifacts visible
- Recommendation: Add security headers: Content-Security-Policy, X-Frame-Options or CSP frame-ancestors, X-Content-Type-Options, Strict-Transport-Security in HTTPS deployments, secure cookie flags, and disable debug/default configurations.

### Clickjacking
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/`
- Evidence: No X-Frame-Options or CSP frame-ancestors protection
- Request/Test: `GET /`
- Recommendation: Set X-Frame-Options=DENY/SAMEORIGIN or CSP frame-ancestors to trusted origins only. Test that sensitive pages cannot be embedded in iframes.

### Cross-Site Request Forgery (CSRF)
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/xss`
- Evidence: State changed via cross-origin POST without CSRF token; token CSRF_52c2c76e visible after request
- Request/Test: `POST without CSRF token`
- Recommendation: Require unpredictable per-session CSRF tokens on all state-changing requests, validate Origin/Referer, set cookies to SameSite=Lax or Strict where possible, and reject POST/PUT/DELETE requests without a valid token.

### Open Redirect
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/redirect?next=https%3A%2F%2Fexample.com&url=https%3A%2F%2Fexample.com`
- Evidence: Redirected to external Location: https://example.com
- Request/Test: `GET redirect parameter`
- Recommendation: Do not redirect to arbitrary user-supplied URLs. Use relative paths or a server-side allowlist of trusted destinations; normalize URLs before validation and reject protocol-relative URLs such as //example.com.

## LOW

### Security Misconfiguration - Missing Headers
- Status: `confirmed`
- URL: `http://127.0.0.1:5000/`
- Evidence: Missing headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
- Request/Test: `GET /`
- Recommendation: Add security headers: Content-Security-Policy, X-Frame-Options or CSP frame-ancestors, X-Content-Type-Options, Strict-Transport-Security in HTTPS deployments, secure cookie flags, and disable debug/default configurations.

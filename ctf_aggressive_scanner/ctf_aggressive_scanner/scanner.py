"""
CTF Aggressive Web Pentest Scanner
Local/authorized competition scanner. Scope guard allows localhost/private ranges by default.
"""
from __future__ import annotations
import concurrent.futures, dataclasses, html, ipaddress, json, os, pickle, re, socket, threading, time, uuid
from collections import defaultdict, deque
from typing import Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
from requests import Response, Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import Finding, Form
from .env import get_gemini_api_key
from .payloads import (
    DANGEROUS_NOTE,
    REDIRECT_PAYLOADS,
    SQL_PAYLOADS,
    SSRF_PAYLOADS,
    TRAVERSAL_PAYLOADS,
    UPLOADS,
    XSS_PAYLOADS,
)

class Scanner:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        workers: int,
        depth: int,
        aggressive: bool,
        confirm_only: bool,
        timeout: float,
        ai: bool=False,
        ai_model: str='gemini-3-flash-preview',
        ai_api_key: str='',
        ai_concurrency: int=4,
        ai_max_findings: int=0,
        ai_max_output_tokens: int=2048,
        ai_skip_overviews: bool=False,
        log_callback: Optional[Callable[[str], None]]=None,
        progress_callback: Optional[Callable[[str, int, int], None]]=None,
        finding_callback: Optional[Callable[[Finding], None]]=None,
        stop_event: Optional[threading.Event]=None,
        report_dir: str='reports',
    ):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.workers = max(1, workers)
        self.depth = max(0, depth)
        self.aggressive = aggressive
        self.confirm_only = confirm_only
        self.timeout = timeout
        self.ai = ai
        self.ai_model = ai_model
        self.ai_api_key = ai_api_key.strip()
        self.ai_concurrency = max(1, min(8, int(ai_concurrency or 1)))
        self.ai_max_findings = max(0, int(ai_max_findings or 0))
        self.ai_max_output_tokens = max(512, min(8192, int(ai_max_output_tokens or 2048)))
        self.ai_skip_overviews = ai_skip_overviews
        self.session = self._new_session()
        self.owner_thread_id = threading.get_ident()
        self.thread_local = threading.local()
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.finding_callback = finding_callback
        self.stop_event = stop_event or threading.Event()
        self.findings: List[Finding] = []
        self.visited: Set[str] = set()
        self.forms: List[Form] = []
        self.lock = threading.Lock()
        self.report_dir = os.path.abspath(report_dir)
        os.makedirs(self.report_dir, exist_ok=True)

    def _new_session(self) -> Session:
        s = requests.Session()
        retry = Retry(total=1, backoff_factor=0.05, status_forcelist=[500,502,503,504], allowed_methods=False)
        adapter = HTTPAdapter(pool_connections=200, pool_maxsize=200, max_retries=retry)
        s.mount('http://', adapter); s.mount('https://', adapter)
        s.headers.update({'User-Agent':'CTF-Aggressive-Scanner/1.0','X-CTF-Scanner':'authorized-local'})
        return s

    def log(self, message: str):
        print(message)
        if self.log_callback:
            self.log_callback(message)

    def progress(self, label: str, done: int, total: int):
        if self.progress_callback:
            self.progress_callback(label, done, total)

    def should_stop(self) -> bool:
        return self.stop_event.is_set()

    def _request_session(self) -> Session:
        if threading.get_ident() == self.owner_thread_id:
            return self.session
        session = getattr(self.thread_local, 'session', None)
        if session is None:
            session = self._new_session()
            session.cookies.update(self.session.cookies)
            self.thread_local.session = session
        return session

    def _pool_size(self, cap: int=120, item_count: Optional[int]=None) -> int:
        size = max(1, min(self.workers, cap))
        if item_count is not None:
            size = min(size, max(1, item_count))
        return size

    def _run_parallel(self, worker, items: Iterable, cap: int=120):
        items = list(items)
        if not items or self.should_stop():
            return
        max_workers = self._pool_size(cap, len(items))
        item_iter = iter(items)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = set()

            def submit_available():
                while len(futures) < max_workers and not self.should_stop():
                    try:
                        item = next(item_iter)
                    except StopIteration:
                        return
                    futures.add(ex.submit(worker, item))

            submit_available()
            while futures:
                done, futures = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                for fut in done:
                    if self.should_stop():
                        for pending in futures:
                            pending.cancel()
                        futures.clear()
                        break
                    yield fut.result()
                submit_available()

    def in_scope_or_die(self):
        p = urlparse(self.base_url)
        host = p.hostname or ''
        if host in ('localhost','127.0.0.1','::1','0.0.0.0'):
            return
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                ip = ipaddress.ip_address(socket.gethostbyname(host))
            except Exception:
                raise SystemExit(f"Refusing target outside default local/private scope: {host}. {DANGEROUS_NOTE}")
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise SystemExit(f"Refusing public target {ip}. {DANGEROUS_NOTE}")

    def req(self, method: str, url: str, **kwargs) -> Optional[Response]:
        if self.should_stop():
            return None
        try:
            return self._request_session().request(method, url, timeout=self.timeout, allow_redirects=False, **kwargs)
        except requests.RequestException:
            return None

    def remediation_for(self, name: str) -> str:
        """Return practical developer remediation guidance for each finding type."""
        n = name.lower()
        if 'sql injection' in n:
            return (
                'Use parameterized queries/prepared statements everywhere; never concatenate user input into SQL. '
                'Add server-side allowlist validation for input types, keep DB errors out of HTTP responses, '
                'use least-privilege DB accounts, and add regression tests with SQLi payloads.'
            )
        if 'xss' in n or 'cross-site scripting' in n:
            return (
                'Encode output contextually (HTML, attribute, JavaScript, URL), sanitize rich text with a trusted allowlist sanitizer, '
                'avoid rendering raw user input, use HttpOnly/SameSite cookies, and deploy a strict Content-Security-Policy.'
            )
        if 'csrf' in n:
            return (
                'Require unpredictable per-session CSRF tokens on all state-changing requests, validate Origin/Referer, '
                'set cookies to SameSite=Lax or Strict where possible, and reject POST/PUT/DELETE requests without a valid token.'
            )
        if 'idor' in n or 'broken access control' in n:
            return (
                'Enforce object-level authorization on the server for every resource access. Do not trust IDs from the client; '
                'check that the authenticated user owns or is allowed to access the requested object, and add negative authorization tests.'
            )
        if 'race condition' in n:
            return (
                'Make the operation atomic using database transactions, row-level locks, optimistic locking/version checks, or atomic UPDATE conditions. '
                'Avoid check-then-update flows and add concurrent-request tests for financial/state-changing operations.'
            )
        if 'ssrf' in n:
            return (
                'Use a strict allowlist of permitted destination hosts/schemes, block loopback/private/link-local/cloud metadata IPs after DNS resolution, '
                'disable redirects or revalidate every redirect hop, and separate internal networks from user-controlled fetchers.'
            )
        if 'file upload' in n:
            return (
                'Validate file type by content and extension allowlist, rename files to random names, store uploads outside the web root, '
                'disable execution in upload directories, enforce size limits, and scan files before serving them.'
            )
        if 'open redirect' in n:
            return (
                'Do not redirect to arbitrary user-supplied URLs. Use relative paths or a server-side allowlist of trusted destinations; '
                'normalize URLs before validation and reject protocol-relative URLs such as //example.com.'
            )
        if 'deserialization' in n:
            return (
                'Do not deserialize untrusted data, especially with pickle/native object serializers. Use safe formats such as JSON with schema validation, '
                'sign and authenticate serialized data if it must be accepted, and remove gadget-capable deserialization paths.'
            )
        if 'missing headers' in n or 'misconfiguration' in n:
            return (
                'Add security headers: Content-Security-Policy, X-Frame-Options or CSP frame-ancestors, X-Content-Type-Options, '
                'Strict-Transport-Security in HTTPS deployments, secure cookie flags, and disable debug/default configurations.'
            )
        if 'sensitive data' in n:
            return (
                'Remove secrets from public routes, logs, backups, and repositories. Store secrets in a vault/environment manager, rotate exposed credentials, '
                'block access to config/backup paths, and add automated secret scanning.'
            )
        if 'clickjacking' in n:
            return (
                'Set X-Frame-Options=DENY/SAMEORIGIN or CSP frame-ancestors to trusted origins only. Test that sensitive pages cannot be embedded in iframes.'
            )
        if 'fuzzing crash' in n or 'internal error' in n:
            return (
                'Review server logs for stack traces and unhandled exceptions, add input validation, return generic error messages, '
                'and create regression tests for the payload that triggered the error.'
            )
        return (
            'Reproduce the request manually, identify the affected code path, add server-side validation and authorization checks, '
            'then create a regression test proving the issue is fixed.'
        )

    def add(self, name, status, severity, evidence, url, request='', recommendation=''):
        if self.confirm_only and status not in ('confirmed',):
            return
        if not recommendation:
            recommendation = self.remediation_for(name)
        finding = None
        with self.lock:
            if not any(f.name == name and f.url == url and f.evidence == evidence for f in self.findings):
                finding = Finding(name,status,severity,evidence,url,request,recommendation)
                self.findings.append(finding)
        if finding and self.finding_callback:
            self.finding_callback(finding)

    def login(self):
        login_url = urljoin(self.base_url+'/', 'login')
        candidates = [
            {'username': self.username, 'password': self.password},
            {'user': self.username, 'pass': self.password},
            {'email': self.username, 'password': self.password},
        ]
        self.req('GET', login_url)
        for data in candidates:
            if self.should_stop():
                return False
            r = self.req('POST', login_url, data=data)
            if r and (r.status_code in (200,302,303) or 'session' in self.session.cookies.get_dict()):
                return True
        return False

    def crawl(self):
        q = deque([(self.base_url+'/',0)])
        while q:
            if self.should_stop():
                return
            url, d = q.popleft()
            if url in self.visited or d > self.depth: continue
            if not url.startswith(self.base_url): continue
            self.visited.add(url)
            r = self.req('GET', url)
            if not r or 'text/html' not in r.headers.get('content-type','text/html'): continue
            soup = BeautifulSoup(r.text, 'lxml')
            for form in soup.find_all('form'):
                action = urljoin(url, form.get('action') or url)
                method = (form.get('method') or 'get').lower()
                inputs=[]
                for inp in form.find_all(['input','textarea','select']):
                    name = inp.get('name')
                    if name: inputs.append((name, inp.get('type') or 'text'))
                self.forms.append(Form(action, method, inputs, url))
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href']).split('#')[0]
                if link.startswith(self.base_url) and link not in self.visited:
                    q.append((link,d+1))
        # Seed known lab endpoints too
        for ep in ['search','comments','csrf','documents','redirect','upload','deserialize','ssrf','race','profile','admin','debug','config','backup','.git/config']:
            self.visited.add(urljoin(self.base_url+'/', ep))

    def submit_form(self, form: Form, payload: str, override: Optional[Dict[str,str]]=None) -> Optional[Response]:
        data={}
        for name, typ in form.inputs:
            if typ in ('submit','button','image','file'): continue
            lname=name.lower()
            if lname in ('username','user','email'): data[name]=self.username
            elif lname in ('password','pass','passwd','pswd'): data[name]=self.password
            elif 'amount' in lname or 'sum' in lname: data[name]='50'
            else: data[name]=payload
        if override: data.update(override)
        return self.req(form.method.upper(), form.action, data=data)

    def test_sqli(self):
        targets = list(self.forms)
        # login bypass with fresh sessions
        def login_bypass(payload):
            s = self._new_session()
            url=urljoin(self.base_url+'/','login')
            try:
                r=s.post(url,data={'username':'admin','password':payload},timeout=self.timeout,allow_redirects=False)
                if r.status_code in (302,303) or s.cookies.get_dict():
                    return payload
            except requests.RequestException:
                return None
            return None
        for payload in self._run_parallel(login_bypass, SQL_PAYLOADS, cap=80):
            if payload:
                self.add('SQL Injection - login bypass','confirmed','critical',f'Login accepted SQLi payload in password: {payload}',urljoin(self.base_url+'/','login'),'POST /login')

        payloads = SQL_PAYLOADS[:4 if not self.aggressive else len(SQL_PAYLOADS)]
        def probe_form(form):
            for p in payloads:
                if self.should_stop():
                    return None
                r=self.submit_form(form,p)
                if r and (re.search(r'(sqlite|syntax error|sql|OperationalError|UNION)', r.text, re.I) or len(r.text)>20000):
                    return form, p
            return None
        for result in self._run_parallel(probe_form, targets, cap=80):
            if result:
                form, p = result
                self.add('SQL Injection - form probing','likely','high',f'SQL-related response after payload {p[:30]}',form.action,f'{form.method.upper()} {form.action}')

    def test_xss(self):
        for form in self.forms:
            if self.should_stop():
                return
            for p in XSS_PAYLOADS:
                token='CTF_XSS_'+uuid.uuid4().hex[:8]
                payload=p.replace('CTF_XSS',token)
                self.submit_form(form,payload)
                # reload source page and action URL
                for u in {form.source, form.action}:
                    r=self.req('GET',u)
                    if r and token in r.text:
                        unescaped = payload in r.text or html.escape(payload) not in r.text
                        status='confirmed' if unescaped else 'likely'
                        self.add('Cross-Site Scripting (XSS)',status,'high',f'Payload token reflected/stored; unescaped={unescaped}',u,f'payload={payload}')
                        return

    def test_csrf(self):
        # New unauth-style/session request with no referer/origin/csrf token but same cookie jar copied.
        for form in self.forms:
            if self.should_stop():
                return
            if form.method != 'post': continue
            if any('csrf' in n.lower() or 'token' in n.lower() for n,_ in form.inputs):
                # token present, try omit it
                pass
            before = self.req('GET', form.source)
            token='CSRF_'+uuid.uuid4().hex[:8]
            data={}
            for n,t in form.inputs:
                if t in ('submit','button','file'): continue
                if 'csrf' in n.lower() or 'token' in n.lower(): continue
                if 'amount' in n.lower(): data[n]='1'
                elif 'password' in n.lower(): data[n]='newpass'
                else: data[n]=token
            headers={'Origin':'http://attacker.invalid','Referer':'http://attacker.invalid/poc'}
            r=self.req('POST', form.action, data=data, headers=headers)
            after=self.req('GET', form.source)
            if r and r.status_code in (200,302,303) and after and token in after.text:
                self.add('Cross-Site Request Forgery (CSRF)','confirmed','medium',f'State changed via cross-origin POST without CSRF token; token {token} visible after request',form.action,'POST without CSRF token')

    def test_idor(self):
        candidates=[]
        for u in self.visited:
            p=urlparse(u)
            qs=parse_qs(p.query)
            if qs: candidates.append(u)
        # known doc pattern
        candidates += [urljoin(self.base_url+'/','documents?id=1'), urljoin(self.base_url+'/','documents?id=2'), urljoin(self.base_url+'/','documents?id=3')]
        seen=set()
        jobs=[]
        for u in candidates:
            if u in seen: continue
            seen.add(u)
            parsed=urlparse(u); qs=parse_qs(parsed.query)
            keys=list(qs.keys()) or ['id']
            for k in keys:
                jobs.append((u, parsed, qs, k))

        def check_param(job):
            u, parsed, qs, k = job
            bodies=[]
            for val in ['1','2','3','4','5']:
                if self.should_stop():
                    return None
                qsdict={kk:vv[-1] for kk,vv in qs.items()}
                qsdict[k]=val
                new=urlunparse(parsed._replace(query=urlencode(qsdict))) if parsed.query else urljoin(self.base_url+'/', f'documents?id={val}')
                r=self.req('GET', new)
                if r and r.status_code==200:
                    bodies.append((val, re.sub(r'\s+',' ',r.text[:1000])))
            if len({b for _,b in bodies})>1 and len(bodies)>=2:
                return u, k, bodies
            return None

        for result in self._run_parallel(check_param, jobs, cap=80):
            if result:
                u, k, bodies = result
                self.add('IDOR / Broken Access Control','confirmed','high',f'Changing {k} returned different accessible resources: {[v for v,_ in bodies[:3]]}',u,'GET parameter tampering')
                return

    def test_open_redirect(self):
        params=['url','next','redirect','redirect_url','return','to']
        endpoints=list(dict.fromkeys(list(self.visited)+[urljoin(self.base_url+'/','redirect')]))

        def check_endpoint(base):
            parsed=urlparse(base)
            for param in params:
                for payload in REDIRECT_PAYLOADS:
                    if self.should_stop():
                        return None
                    q=parse_qs(parsed.query); q[param]=payload
                    u=urlunparse(parsed._replace(query=urlencode({k:v[-1] if isinstance(v,list) else v for k,v in q.items()})))
                    r=self.req('GET',u)
                    loc=r.headers.get('location','') if r else ''
                    if r and r.status_code in (301,302,303,307,308) and ('example.com' in loc or 'evil.invalid' in loc):
                        return u, loc
            return None

        for result in self._run_parallel(check_endpoint, endpoints, cap=80):
            if result:
                u, loc = result
                self.add('Open Redirect','confirmed','medium',f'Redirected to external Location: {loc}',u,'GET redirect parameter')
                return

    def test_upload(self):
        upload_forms=[f for f in self.forms if any(t=='file' or 'file' in n.lower() or 'upload' in f.action.lower() for n,t in f.inputs)]
        if not upload_forms: upload_forms=[Form(urljoin(self.base_url+'/','upload'),'post',[('file','file')],urljoin(self.base_url+'/','upload'))]
        for form in upload_forms:
            if self.should_stop():
                return
            for fname,content,mime in UPLOADS:
                files={'file':(fname,content,mime),'upload':(fname,content,mime)}
                r=self.req('POST',form.action,files=files)
                if r and r.status_code in (200,302,303):
                    self.add('Insecure File Upload','confirmed','high',f'Potentially dangerous file accepted: {fname}',form.action,'multipart upload')
                    return

    def test_ssrf(self):
        endpoints=list(dict.fromkeys([u for u in self.visited if any(x in u.lower() for x in ['ssrf','fetch','url','proxy'])]+[urljoin(self.base_url+'/','ssrf')]))

        def check_endpoint(ep):
            for p in SSRF_PAYLOADS:
                for param in ['url','target','u','uri','link']:
                    if self.should_stop():
                        return None
                    r=self.req('GET', ep, params={param:p})
                    body=r.text[:2000] if r else ''
                    if r and (r.status_code==200 and ('VulnWeb' in body or 'root:' in body or '<html' in body.lower())):
                        return ep, f'Server fetched local/internal resource via {param}={p}', 'GET SSRF payload'
                r=self.req('POST', ep, data={'url':p})
                if r and ('VulnWeb' in r.text or 'root:' in r.text):
                    return ep, f'Server fetched local/internal resource via POST url={p}', 'POST SSRF payload'
            return None

        for result in self._run_parallel(check_endpoint, endpoints, cap=80):
            if result:
                ep, evidence, request = result
                self.add('SSRF','confirmed','high',evidence,ep,request)
                return

    def test_deserialization(self):
        ep=urljoin(self.base_url+'/','deserialize')
        # harmless pickle object used only to test unsafe load behavior, no code execution payload.
        blob=pickle.dumps({'ctf':'DESERIALIZE_TEST','n':1337})
        for field in ['blob','data','payload','object']:
            if self.should_stop():
                return
            r=self.req('POST', ep, data={field:blob.hex()})
            if r and ('DESERIALIZE_TEST' in r.text or '1337' in r.text or 'pickle' in r.text.lower()):
                self.add('Insecure Deserialization','confirmed','critical',f'Application accepted/deserialized attacker-controlled serialized blob field={field}',ep,'POST serialized blob')
                return

    def test_headers_misconfig(self):
        r=self.req('GET', self.base_url+'/')
        if not r: return
        missing=[]
        for h in ['Content-Security-Policy','X-Frame-Options','X-Content-Type-Options']:
            if h not in r.headers: missing.append(h)
        if missing:
            self.add('Security Misconfiguration - Missing Headers','confirmed','low',f'Missing headers: {", ".join(missing)}',self.base_url+'/','GET /')
        if 'debug' in r.text.lower() or 'werkzeug' in r.text.lower():
            self.add('Debug/Misconfiguration Exposure','likely','medium','Debug/framework artifacts visible',self.base_url+'/')

    def test_sensitive_exposure(self):
        paths=['/config','/debug','/backup','/backup.zip','/.env','/.git/config','/users','/admin','/secrets']
        patterns=[r'password\s*[:=]', r'secret\s*[:=]', r'api[_-]?key', r'BEGIN RSA PRIVATE KEY', r'admin123']

        def check_path(path):
            u=urljoin(self.base_url+'/',path.lstrip('/'))
            r=self.req('GET',u)
            if r and r.status_code==200:
                for pat in patterns:
                    if re.search(pat,r.text,re.I):
                        return path, u, pat
            return None

        for result in self._run_parallel(check_path, paths, cap=40):
            if result:
                path, u, pat = result
                self.add('Sensitive Data Exposure','confirmed','high',f'Sensitive pattern {pat} exposed at {path}',u,'GET sensitive path')
                return

    def test_race(self):
        ep=urljoin(self.base_url+'/','race')
        # warmup and attempt to parse balance
        self.req('GET',ep)
        amount='50'
        n=max(20,self.workers)
        def post_one():
            if self.should_stop():
                return None
            return self.req('POST',ep,data={'amount':amount})
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._pool_size(120, n)) as ex:
            list(ex.map(lambda _: post_one(), range(n)))
        r=self.req('GET',ep)
        if r:
            nums=[int(x) for x in re.findall(r'-?\d+', r.text)]
            # lab starts often 1000; many 50 withdrawals below zero/inconsistent confirms
            if any(x < 0 for x in nums) or ('insufficient' not in r.text.lower() and n*int(amount) >= 1000):
                self.add('Race Condition','confirmed','high',f'Concurrent withdrawals sent ({n} x {amount}); final page indicates inconsistent state/negative value candidates={nums[:10]}',ep,'parallel POST /race')

    def test_clickjacking(self):
        r=self.req('GET',self.base_url+'/')
        if r:
            xfo=r.headers.get('X-Frame-Options','')
            csp=r.headers.get('Content-Security-Policy','')
            if not xfo and 'frame-ancestors' not in csp.lower():
                self.add('Clickjacking','confirmed','medium','No X-Frame-Options or CSP frame-ancestors protection',self.base_url+'/','GET /')

    def aggressive_fuzz_forms(self):
        payloads=SQL_PAYLOADS+XSS_PAYLOADS+TRAVERSAL_PAYLOADS
        if not self.aggressive: payloads=payloads[:8]
        def job(args):
            if self.should_stop():
                return
            form,p=args
            r=self.submit_form(form,p)
            if r and r.status_code>=500:
                self.add('Input Fuzzing Crash/Error','likely','medium',f'Payload triggered server error: {p[:60]}',form.action,f'{form.method.upper()} fuzz')
        tasks=[(f,p) for f in self.forms for p in payloads]
        for _ in self._run_parallel(job, tasks, cap=80):
            pass

    def run(self):
        self.in_scope_or_die()
        self.log(f'[+] Target: {self.base_url}')
        self.log(f'[+] Fast engine: {self.workers} workers, depth={self.depth}, aggressive={self.aggressive}')
        self.log('[+] Logging in...')
        ok=self.login()
        self.log(f'[+] Login attempted: {ok}')
        if self.should_stop():
            self.log('[!] Scan stopped before crawling.')
            return
        self.log('[+] Crawling and discovering forms...')
        self.crawl()
        self.log(f'[+] Discovered URLs={len(self.visited)} forms={len(self.forms)}')
        tests=[self.test_headers_misconfig,self.test_clickjacking,self.test_sensitive_exposure,self.test_sqli,self.test_xss,self.test_csrf,self.test_idor,self.test_open_redirect,self.test_upload,self.test_ssrf,self.test_deserialization,self.test_race,self.aggressive_fuzz_forms]
        total=len(tests)
        for index, t in enumerate(tests, 1):
            if self.should_stop():
                self.log('[!] Scan stopped by user.')
                break
            self.progress(t.__name__, index-1, total)
            self.log(f'[+] Running {t.__name__}...')
            try: t()
            except Exception as e: self.add('Scanner Internal Error','inconclusive','info',f'{t.__name__}: {type(e).__name__}: {e}',self.base_url)
            self.progress(t.__name__, index, total)
        self.write_reports()
        self.write_ai_reports()
        self.log(f'[+] Done. Findings: {len(self.findings)}')
        self.log(f'[+] Report: {os.path.join(self.report_dir, "report.md")}')

    def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini generateContent REST API using GEMINI_API_KEY or GOOGLE_API_KEY."""
        api_key = get_gemini_api_key(self.ai_api_key)
        if not api_key:
            return 'AI analysis was requested, but GEMINI_API_KEY or GOOGLE_API_KEY is not set in the environment.'

        # Try the requested model first, then common Flash fallbacks.
        models = []
        if self.ai_model:
            models.append(self.ai_model)
        for m in ['gemini-3-flash-preview', 'gemini-2.5-flash', 'gemini-2.0-flash']:
            if m not in models:
                models.append(m)

        last_error = None
        for model in models:
            try:
                url = f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'
                payload = {
                    'contents': [
                        {
                            'role': 'user',
                            'parts': [{'text': prompt}]
                        }
                    ],
                    'generationConfig': {
                        'temperature': 0.2,
                        'topP': 0.9,
                        'maxOutputTokens': self.ai_max_output_tokens
                    }
                }
                r = requests.post(
                    url,
                    params={'key': api_key},
                    json=payload,
                    timeout=max(30, self.timeout * 10),
                )
                if r.status_code >= 400:
                    last_error = f'{r.status_code}: {r.text[:1000]}'
                    continue
                data = r.json()
                parts = []
                for cand in data.get('candidates', []) or []:
                    content = cand.get('content', {}) or {}
                    for part in content.get('parts', []) or []:
                        text = part.get('text')
                        if text:
                            parts.append(text)
                if parts:
                    return '\n'.join(parts).strip()
                last_error = json.dumps(data, ensure_ascii=False)[:1000]
            except Exception as e:
                last_error = f'{type(e).__name__}: {e}'
        return f'AI analysis failed via Gemini API. Last error: {last_error}'

    def _call_ai(self, prompt: str) -> str:
        return self._call_gemini(prompt)

    def _findings_for_ai(self) -> List[Finding]:
        if self.ai_max_findings <= 0 or len(self.findings) <= self.ai_max_findings:
            return list(self.findings)

        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        indexed = list(enumerate(self.findings))
        selected = sorted(
            indexed,
            key=lambda item: (severity_rank.get(item[1].severity, 5), item[0]),
        )[:self.ai_max_findings]
        selected_indexes = {index for index, _ in selected}
        return [finding for index, finding in indexed if index in selected_indexes]

    def ai_prompt_for_finding(self, finding: Finding) -> str:
        return f"""
You are a senior web application security consultant.

Context:
- This is a local CTF/lab scanner report for an authorized target.
- Focus on defensive analysis and remediation.
- Do not provide destructive exploitation steps, persistence, stealth, or data exfiltration guidance.
- The scanner has already captured the request/evidence. Analyze the finding and help developers fix it.

Return the answer in Romanian, in Markdown, with these exact sections:
1. Rezumat tehnic
2. De ce este periculos
3. Impact posibil
4. Cauza probabilă în cod
5. Pași concreți de remediere
6. Exemplu de implementare sigură, dacă este relevant
7. Checklist pentru dezvoltatori
8. Test de regresie recomandat

Finding JSON:
{json.dumps(dataclasses.asdict(finding), ensure_ascii=False, indent=2)}
""".strip()

    def ai_prompt_for_finding(self, finding: Finding) -> str:
        return f"""
You are a senior web application security consultant.

Context:
- This is a local CTF/lab scanner report for an authorized target.
- Focus on defensive analysis and remediation.
- Do not provide destructive exploitation steps, persistence, stealth, or data exfiltration guidance.
- The scanner has already captured the request/evidence. Analyze the finding and help developers fix it.
- Your output must help a developer fix the bug effectively, not just describe it.
- Infer likely backend code areas from the URL/request, but clearly say when source code inspection is required.
- Prefer concrete secure implementation patterns for Python web apps, especially Django/Flask-style apps when relevant.
- Include safe code snippets only for remediation, such as parameterized queries, CSRF protection, authorization checks, safe upload handling, transaction locks, or validation.

Return the answer in Romanian, in Markdown, with these exact sections:
1. Rezumat tehnic
2. De ce este periculos
3. Impact posibil
4. Cauza probabila in cod
5. Pasi concreti de remediere
6. Exemplu de implementare sigura, daca este relevant
7. Checklist pentru dezvoltatori
8. Test de regresie recomandat

Finding JSON:
{json.dumps(dataclasses.asdict(finding), ensure_ascii=False, indent=2)}
""".strip()

    def write_ai_reports(self):
        if not self.ai:
            return
        os.makedirs(self.report_dir, exist_ok=True)
        if not get_gemini_api_key(self.ai_api_key):
            msg = '# AI Report\n\nAI was enabled, but no Gemini API key was found.\n\nSet `GEMINI_API_KEY` in `.env.local`, `.env`, or your shell environment.\n'
            with open(os.path.join(self.report_dir, 'ai_report.md'),'w',encoding='utf-8') as f: f.write(msg)
            with open(os.path.join(self.report_dir, 'executive_summary.md'),'w',encoding='utf-8') as f: f.write(msg)
            with open(os.path.join(self.report_dir, 'developer_checklist.md'),'w',encoding='utf-8') as f: f.write(msg)
            self.log('[!] AI report skipped: no Gemini API key was found in .env.local, .env, the shell, or the GUI field.')
            self.log(f'[!] Placeholder AI report written to {os.path.join(self.report_dir, "ai_report.md")}')
            return

        if not self.findings:
            msg = '# AI-Enhanced Security Report\n\nNo findings were detected by the scanner, so there is no vulnerability-specific remediation to generate.\n'
            with open(os.path.join(self.report_dir, 'ai_report.md'),'w',encoding='utf-8') as f: f.write(msg)
            with open(os.path.join(self.report_dir, 'report_ai_enriched.json'),'w',encoding='utf-8') as f: json.dump([], f, indent=2)
            with open(os.path.join(self.report_dir, 'executive_summary.md'),'w',encoding='utf-8') as f: f.write('# Executive Summary\n\nNo findings were detected by the scanner.\n')
            with open(os.path.join(self.report_dir, 'developer_checklist.md'),'w',encoding='utf-8') as f: f.write('# Developer Remediation Checklist\n\nNo findings were detected by the scanner.\n')
            self.log(f'[+] AI report: no findings to analyze. Wrote {os.path.join(self.report_dir, "ai_report.md")}')
            return

        ai_findings = self._findings_for_ai()
        skipped_count = len(self.findings) - len(ai_findings)
        if skipped_count:
            self.log(f'[+] AI will analyze top {len(ai_findings)} findings and skip {skipped_count} lower-priority finding(s).')
        self.log(f'[+] Generating AI-enhanced remediation report with {self.ai_concurrency} parallel call(s)...')

        sections_by_index = [None] * len(ai_findings)
        enriched_by_index = [None] * len(ai_findings)

        def analyze_finding(item):
            index, finding = item
            if self.should_stop():
                return index, finding, 'AI analysis stopped before this finding was processed.'
            self.log(f'[+] AI analysis {index + 1}/{len(ai_findings)}: {finding.name}')
            try:
                analysis = self._call_ai(self.ai_prompt_for_finding(finding))
            except Exception as exc:
                analysis = f'AI analysis failed locally: {type(exc).__name__}: {exc}'
            return index, finding, analysis

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.ai_concurrency, len(ai_findings))) as executor:
            futures = [executor.submit(analyze_finding, item) for item in enumerate(ai_findings)]
            for future in concurrent.futures.as_completed(futures):
                if self.should_stop():
                    for pending in futures:
                        pending.cancel()
                    self.log('[!] AI report generation stopped by user.')
                    return
                index, finding, analysis = future.result()
                data = dataclasses.asdict(finding)
                data['ai_analysis'] = analysis
                enriched_by_index[index] = data
                sections_by_index[index] = (
                    f"# {finding.name}\n\n"
                    f"- Status: `{finding.status}`\n"
                    f"- Severity: `{finding.severity}`\n"
                    f"- URL: `{finding.url}`\n"
                    f"- Evidence: {finding.evidence}\n\n"
                    f"{analysis}\n"
                )

        sections = [section for section in sections_by_index if section is not None]
        enriched = [item for item in enriched_by_index if item is not None]
        if skipped_count:
            sections.append(
                '# Findings Not Sent To AI\n\n'
                f'{skipped_count} lower-priority finding(s) were omitted because `ai_max_findings={self.ai_max_findings}`.\n'
            )

        with open(os.path.join(self.report_dir, 'ai_report.md'),'w',encoding='utf-8') as f:
            f.write('# AI-Enhanced Security Report\n\n' + '\n---\n\n'.join(sections))
        with open(os.path.join(self.report_dir, 'report_ai_enriched.json'),'w',encoding='utf-8') as f:
            json.dump(enriched, f, indent=2, ensure_ascii=False)

        if self.ai_skip_overviews:
            skipped = '# Skipped\n\nSkipped because fast AI mode was enabled with `--ai-skip-overviews`.\n'
            with open(os.path.join(self.report_dir, 'executive_summary.md'),'w',encoding='utf-8') as f:
                f.write('# Executive Summary\n\n' + skipped)
            with open(os.path.join(self.report_dir, 'developer_checklist.md'),'w',encoding='utf-8') as f:
                f.write('# Developer Remediation Checklist\n\n' + skipped)
            self.log('[+] Skipped executive/checklist AI calls for faster run.')
            return

        summary_prompt = f"""
You are preparing an executive cybersecurity summary in Romanian for a CTF/lab web security scanner.
Use the findings below. Do not include exploit instructions.
Return a concise management-ready report with:
- overall risk level
- top 5 priorities
- business impact
- remediation roadmap by priority, focused on actual engineering fixes
- suggested next steps

Findings:
{json.dumps([dataclasses.asdict(f) for f in ai_findings], ensure_ascii=False, indent=2)}
""".strip()
        executive = self._call_ai(summary_prompt)
        with open(os.path.join(self.report_dir, 'executive_summary.md'),'w',encoding='utf-8') as f:
            f.write('# Executive Summary\n\n' + executive + '\n')

        checklist_prompt = f"""
Create a Romanian developer remediation checklist from these web security findings.
Group by vulnerability type. Make it practical and actionable. Include concrete fix tasks and regression tests. Do not include exploit steps.

Findings:
{json.dumps([dataclasses.asdict(f) for f in ai_findings], ensure_ascii=False, indent=2)}
""".strip()
        checklist = self._call_ai(checklist_prompt)
        with open(os.path.join(self.report_dir, 'developer_checklist.md'),'w',encoding='utf-8') as f:
            f.write('# Developer Remediation Checklist\n\n' + checklist + '\n')

    def write_reports(self):
        data=[dataclasses.asdict(f) for f in self.findings]
        os.makedirs(self.report_dir, exist_ok=True)
        with open(os.path.join(self.report_dir, 'report.json'),'w',encoding='utf-8') as f: json.dump(data,f,indent=2)
        lines=['# CTF Aggressive Scanner Report','',f'Target: `{self.base_url}`','',f'Findings: **{len(self.findings)}**','']
        bysev=defaultdict(list)
        for f in self.findings: bysev[f.severity].append(f)
        for sev in ['critical','high','medium','low','info']:
            if sev not in bysev: continue
            lines += [f'## {sev.upper()}','']
            for f in bysev[sev]:
                lines += [f'### {f.name}',f'- Status: `{f.status}`',f'- URL: `{f.url}`',f'- Evidence: {f.evidence}']
                if f.request: lines.append(f'- Request/Test: `{f.request}`')
                if f.recommendation: lines.append(f'- Recommendation: {f.recommendation}')
                lines.append('')
        with open(os.path.join(self.report_dir, 'report.md'),'w',encoding='utf-8') as f: f.write('\n'.join(lines))


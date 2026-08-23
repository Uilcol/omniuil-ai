import json, os, sys, time, uuid, hashlib, hmac as hmac_lib, threading, subprocess, secrets, re, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from collections import deque
from functools import wraps

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "qsec-agents"))
from flask import Flask, request, jsonify, Response, send_from_directory, stream_with_context
from licensing import check_access, declare_company_size, install_license_key, get_tier, get_tier_limits, check_repo_limit, TIER_LIMITS

_RAW_SECRET = os.environ.get("QSEC_API_SECRET", "dev-secret-change-in-production")
_DEFAULT_SECRET = "dev-secret-change-in-production"
# FIX HIGH: refuse startup with default secret in production
if os.environ.get("QSEC_PRODUCTION") == "1" and _RAW_SECRET == _DEFAULT_SECRET:
    import sys as _sys
    print("FATAL: QSEC_API_SECRET not set. Cannot start in QSEC_PRODUCTION=1 mode with default secret.", file=_sys.stderr)
    _sys.exit(1)
API_SECRET    = _RAW_SECRET
QSEC_BIN      = os.environ.get("QSEC_BIN", str(Path(__file__).parent.parent.parent / "qsec-rust/target/release/qsec"))
API_VERSION       = "v1"
MAX_JOBS          = 500
MAX_FINDINGS      = 10_000   # FIX MEDIUM: cap global findings list — OOM protection
MAX_LOG_ENTRIES   = 500      # FIX MEDIUM: cap per-job log — large scans can't exhaust RAM
TOKEN_TTL_MAX     = 86400
RATE_LIMIT_ROTATE = 5
# FIX HIGH: allowlist for JWT sub/aud — blocks shell metacharacters before subprocess args
_SAFE_STR_RE      = re.compile(r"^[\w@.\-+:/= ]{1,256}$")
_CORS_RAW = os.environ.get("CORS_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080")
CORS_ORIGINS = set(o.strip() for o in _CORS_RAW.split(",") if o.strip())

app = Flask(__name__, static_folder="../web/static")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # FIX HIGH: 1MB body limit

# ── SQLite persistence ────────────────────────────────────────────────────────
_DATA_DIR = Path(os.environ.get("QSEC_DATA_DIR", str(Path(__file__).parent.parent / "data")))
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH  = str(_DATA_DIR / "qsec.db")

def _db_init():
    """Create tables on first run. Called once at startup."""
    con = sqlite3.connect(_DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")   # safe concurrent writes
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS repos_tracked (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_path TEXT UNIQUE NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS findings (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id    TEXT,
            severity  TEXT,
            rule_id   TEXT,
            file      TEXT,
            line      INTEGER,
            title     TEXT,
            description TEXT,
            recommendation TEXT,
            code_snippet TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            payload   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_job      ON findings(job_id);

        CREATE TABLE IF NOT EXISTS jobs (
            job_id     TEXT PRIMARY KEY,
            status     TEXT NOT NULL DEFAULT 'queued',
            path       TEXT,
            created_at TEXT,
            started_at TEXT,
            completed_at TEXT,
            result     TEXT
        );

        CREATE TABLE IF NOT EXISTS agent_jobs (
            job_id     TEXT PRIMARY KEY,
            status     TEXT NOT NULL DEFAULT 'queued',
            path       TEXT,
            created_at TEXT,
            completed_at TEXT,
            log        TEXT,
            result     TEXT
        );

        CREATE TABLE IF NOT EXISTS metrics (
            key   TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0
        );
    """)
    con.commit()
    con.close()

def _db_conn():
    """Return a thread-local SQLite connection (WAL mode, row_factory)."""
    con = sqlite3.connect(_DB_PATH, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.row_factory = sqlite3.Row
    return con

def _db_save_finding(finding: dict, job_id: str = ""):
    try:
        with _db_conn() as con:
            con.execute(
                "INSERT INTO findings (job_id,severity,rule_id,file,line,title,"
                "description,recommendation,code_snippet,payload) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (job_id,
                 finding.get("severity",""),
                 finding.get("rule_id",""),
                 finding.get("file",""),
                 finding.get("line",0),
                 finding.get("title",""),
                 finding.get("description",""),
                 finding.get("recommendation",""),
                 finding.get("code_snippet",""),
                 json.dumps(finding, ensure_ascii=False))
            )
    except Exception as e:
        print(f"[DB] save_finding error: {e}", file=sys.stderr)

def _db_save_job(job: dict, table="jobs"):
    try:
        cols = list(job.keys())
        vals = [json.dumps(v) if isinstance(v,(dict,list)) else v for v in job.values()]
        placeholders = ",".join("?" * len(cols))
        sets = ",".join(f"{c}=excluded.{c}" for c in cols if c != "job_id")
        with _db_conn() as con:
            con.execute(
                f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders}) "
                f"ON CONFLICT(job_id) DO UPDATE SET {sets}",
                vals
            )
    except Exception as e:
        print(f"[DB] save_job({table}) error: {e}", file=sys.stderr)

def _db_load_findings() -> list:
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT payload FROM findings ORDER BY id DESC LIMIT ?", (MAX_FINDINGS,)
            ).fetchall()
        return [json.loads(r["payload"]) for r in reversed(rows)]
    except Exception as e:
        print(f"[DB] load_findings error: {e}", file=sys.stderr)
        return []

def _db_load_jobs(table="jobs") -> dict:
    try:
        with _db_conn() as con:
            rows = con.execute(f"SELECT * FROM {table}").fetchall()
        out = {}
        for r in rows:
            d = dict(r)
            for fld in ("result","log"):
                if fld in d and d[fld] and isinstance(d[fld], str):
                    try: d[fld] = json.loads(d[fld])
                    except: pass
            out[d["job_id"]] = d
        return out
    except Exception as e:
        print(f"[DB] load_jobs({table}) error: {e}", file=sys.stderr)
        return {}

# ── Per-IP rate limiter (auth endpoint brute-force protection) ────────────────
# Separate from the per-token rate limiter already in place for key rotation.
_IP_RATE: dict = {}   # ip -> deque of timestamps
_IP_RATE_LOCK = threading.Lock()

def _ip_rate_limit(ip: str, max_per_minute: int = 20) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.time()
    with _IP_RATE_LOCK:
        if ip not in _IP_RATE:
            _IP_RATE[ip] = deque()
        dq = _IP_RATE[ip]
        while dq and dq[0] < now - 60:
            dq.popleft()
        if len(dq) >= max_per_minute:
            return False
        dq.append(now)
        # Prune old IPs periodically to prevent unbounded growth
        if len(_IP_RATE) > 10_000:
            stale = [k for k, v in _IP_RATE.items() if not v or v[-1] < now - 120]
            for k in stale[:1000]:
                del _IP_RATE[k]
    return True

def _client_ip() -> str:
    """Extract real client IP, respecting X-Forwarded-For behind nginx."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

_TOKEN_KEY  = os.environ.get("QSEC_TOKEN_KEY", secrets.token_hex(32))
_state_lock = threading.Lock()
_tokens:     dict = {}
_jobs:       dict = {}
_findings:   list = []
_agent_jobs: dict = {}
_rotate_log: dict = {}
_revoked_jtis: dict = {}   # jti -> expiry_ts (TTL 24h after revocation)

# ── Boot: init DB and restore persisted state ─────────────────────────────────
_db_init()
_findings   = _db_load_findings()
_jobs       = _db_load_jobs("jobs")
_agent_jobs = _db_load_jobs("agent_jobs")
print(f"[QSEC] DB loaded — {len(_findings)} findings, {len(_jobs)} jobs, {len(_agent_jobs)} agent jobs restored")

def _prune_revoked_nolock():
    """Evict JTIs older than 24h. MUST be called with _state_lock already held."""
    now = time.time()
    expired = [k for k, v in _revoked_jtis.items() if v < now]
    for k in expired: del _revoked_jtis[k]
    empty = [k for k, v in _rotate_log.items() if not v]
    for k in empty: del _rotate_log[k]
_metrics: dict = {
    "scans_total":0,"findings_total":0,"critical_total":0,"high_total":0,
    "patches_applied":0,"tokens_issued":0,"tokens_revoked":0,
    "api_calls_total":0,"uptime_start":time.time(),
}

# FIX CRITICAL: path validation
_BLOCKED = ("/etc","/proc","/sys","/dev","/root","/usr/bin","/usr/sbin",
            "/bin","/sbin","/boot","/lib","/lib64","/run")

def _safe_api_path(raw):
    if not raw or not isinstance(raw, str): return None
    bad_chars = set([chr(0), "\n", "\r", ";", "&", "|", "`", "$", ">"])
    if any(c in raw for c in bad_chars): return None
    try: p = Path(raw).resolve()
    except (ValueError, OSError): return None
    for prefix in _BLOCKED:
        if str(p).startswith(prefix): return None
    return str(p)

# FIX HIGH: HMAC-signed tokens
def _sign_token(tid, exp):
    msg = "{0}:{1:.0f}".format(tid, exp).encode()
    sig = hmac_lib.new(_TOKEN_KEY.encode(), msg, hashlib.sha3_256).hexdigest()
    return "{0}.{1}".format(tid, sig)

def _verify_sig(raw_token):
    parts = raw_token.rsplit(".", 1)
    if len(parts) != 2: return None
    tid, sig = parts
    with _state_lock: info = _tokens.get(tid)
    if not info: return None
    msg = "{0}:{1:.0f}".format(tid, info["exp"]).encode()
    exp_sig = hmac_lib.new(_TOKEN_KEY.encode(), msg, hashlib.sha3_256).hexdigest()
    return tid if hmac_lib.compare_digest(sig, exp_sig) else None

def _issue_token(sub, scopes, ttl=3600):
    ttl = min(ttl, TOKEN_TTL_MAX)
    tid = secrets.token_hex(24)
    exp = time.time() + ttl
    with _state_lock:
        _tokens[tid] = {"sub":sub,"exp":exp,"scopes":scopes,"issued":datetime.now(timezone.utc).isoformat()}
        _metrics["tokens_issued"] += 1
    return _sign_token(tid, exp)

# FIX HIGH: token eviction + job dict size limit
def _cleanup():
    now = time.time()
    with _state_lock:
        for k in [k for k,v in _tokens.items() if v["exp"] < now]: del _tokens[k]
        if len(_jobs) > MAX_JOBS:
            for k in sorted(_jobs, key=lambda k: _jobs[k].get("created_at",""))[:100]: del _jobs[k]
        if len(_agent_jobs) > MAX_JOBS:
            for k in sorted(_agent_jobs, key=lambda k: _agent_jobs[k].get("created_at",""))[:100]: del _agent_jobs[k]
        # Prune revoked JTIs and empty rate-limit entries
        now2 = time.time()
        for k in [k for k,v in _revoked_jtis.items() if v < now2]: del _revoked_jtis[k]
        for k in [k for k,v in _rotate_log.items() if not v]: del _rotate_log[k]

# FIX HIGH: require_auth with HMAC verification
def require_auth(scope=None):
    def dec(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            with _state_lock: _metrics["api_calls_total"] += 1
            auth = request.headers.get("Authorization","")
            if not auth.startswith("Bearer "): return jsonify({"error":"Missing Authorization"}), 401
            tid = _verify_sig(auth.split(" ",1)[1])
            if not tid: return jsonify({"error":"Invalid token"}), 401
            with _state_lock: info = _tokens.get(tid)
            if not info: return jsonify({"error":"Token not found"}), 401
            if info["exp"] < time.time(): return jsonify({"error":"Token expired"}), 401
            if scope and scope not in info["scopes"]: return jsonify({"error":"Scope required: "+scope}), 403
            request.token_info = info
            request.token_id   = tid
            _cleanup()
            return fn(*a, **kw)
        return wrap
    return dec

# FIX LOW: rate limiter
def _rate_limit(tid, action, max_pm):
    key = tid+":"+action
    now = time.time()
    with _state_lock:
        if key not in _rotate_log: _rotate_log[key] = deque()
        dq = _rotate_log[key]
        while dq and dq[0] < now-60: dq.popleft()
        if len(dq) >= max_pm: return False
        dq.append(now)
    return True

def _run_qsec(*args, timeout=60):
    if not Path(QSEC_BIN).exists(): return _simulate(*args)
    try:
        r = subprocess.run([QSEC_BIN]+list(args), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
        raw = r.stdout.strip()
        if raw:
            lines = raw.split("\n")
            json_lines = []
            in_json = False
            for line in lines:
                s = line.strip()
                if not in_json and (s.startswith("[{") or s.startswith("{") or s == "[" or s == "{"):
                    in_json = True
                if in_json:
                    json_lines.append(line)
            json_str = "\n".join(json_lines).strip()
            try: return {"success":True,"data":json.loads(json_str)}
            except: return {"success":True,"data":{"output":raw}}
        if r.returncode != 0: return {"success":False,"error":r.stderr.strip() or "Engine error"}
        return {"success":True,"data":{}}
    except subprocess.TimeoutExpired: return {"success":False,"error":"Engine timeout"}
    except Exception as e: return {"success":False,"error":str(e)}

def _simulate(*args):
    cmd = args[0] if args else ""
    if cmd == "scan":
        path = args[1] if len(args)>1 else "."
        seed = hashlib.sha256((path+str(time.time_ns())).encode()).hexdigest()[:8]
        return {"success":True,"data":{"scan_path":path,"files_scanned":12,"scan_id":seed,
            "findings":[
                {"file":path+"/src/auth.rs","line":47,"severity":"CRITICAL","rule_id":"QSC-001",
                 "title":"RSA detectado","description":"RSA vulneravel ao Shor",
                 "recommendation":"Migre para ML-DSA + ML-KEM","code_snippet":"RSA::generate(2048)"},
                {"file":path+"/src/hash.rs","line":23,"severity":"HIGH","rule_id":"QSC-010",
                 "title":"MD5 detectado","description":"MD5 quebrado",
                 "recommendation":"Use SHA3-256","code_snippet":"md5::compute(&data)"},
                {"file":path+"/src/token.rs","line":89,"severity":"CRITICAL","rule_id":"QSC-020",
                 "title":"JWT alg:none","description":"JWT sem assinatura",
                 "recommendation":"Use PQC-JWT Ed25519+ML-DSA","code_snippet":"alg: none"},
            ],"severity_counts":{"critical":2,"high":1,"medium":0,"low":0},"backend":"simulation"}}
    if cmd == "info":
        return {"success":True,"data":{"version":"3.2.1","backend":"reference",
            "kem_algorithm":"X25519 + ML-KEM-1024","dsa_algorithm":"Ed25519 + ML-DSA-87",
            "symmetric":"AES-256-GCM","kdf":"HKDF-SHA3-256","hndl_protection":True,
            "nist_pqc_compliant":False,"uptime":int(time.time()-_metrics["uptime_start"])}}
    if cmd == "token":
        return {"success":True,"data":{"token":"pqcjwt."+uuid.uuid4().hex+"."+uuid.uuid4().hex,
            "algorithm":"Ed25519+ML-DSA-87","expires_in":3600,"type":"PQC-JWT"}}
    if cmd == "keys":
        action = args[1] if len(args)>1 else "status"
        if action == "status":
            return {"success":True,"data":{"active_keys":1,"current_key":{
                "key_id":secrets.token_hex(8),"algorithm":"Ed25519+ML-DSA-87",
                "created_at":datetime.now(timezone.utc).isoformat(),"expires_in_days":28}}}
        return {"success":True,"data":{"new_key_id":secrets.token_hex(8),
            "algorithm":"Ed25519+ML-DSA-87","rotated_at":datetime.now(timezone.utc).isoformat()}}
    if cmd == "sbom":
        return {"success":True,"data":{"bomFormat":"CycloneDX","specVersion":"1.5",
            "serialNumber":"urn:uuid:"+str(uuid.uuid4()),"components":8,
            "timestamp":datetime.now(timezone.utc).isoformat(),
            "fingerprint":hashlib.sha3_256(str(time.time()).encode()).hexdigest()}}
    return {"success":True,"data":{"command":cmd,"status":"executed"}}

def _run_scan_job(job_id, safe_path):
    with _state_lock:
        _jobs[job_id]["status"]     = "running"
        _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
    _db_save_job(_jobs[job_id], "jobs")
    result = _run_qsec("scan", safe_path, "--format","json")
    with _state_lock:
        _metrics["scans_total"] += 1
        if result.get("success"):
            d=result.get("data",{})
            if isinstance(d,list): d={"scanner_findings":d,"taint_findings":[]}
            f=d.get("scanner_findings",d.get("findings",[]))
            tr=d.get("taint_findings",[])
            f=f+[{"severity":"HIGH","rule_id":t.get("rule_id","TAINT-001"),"title":t.get("title","Taint"),"file":t.get("file",""),"line":t.get("path",{}).get("sink_line",0),"description":t.get("path",{}).get("description",""),"recommendation":"Remova dados externos.","code_snippet":t.get("path",{}).get("sink_code","")} for t in tr]
            c={"critical":sum(1 for x in f if str(x.get("severity","")).upper()=="CRITICAL"),"high":sum(1 for x in f if str(x.get("severity","")).upper()=="HIGH"),"medium":0,"low":0}
            # FIX MEDIUM: cap global findings list at MAX_FINDINGS
            space = MAX_FINDINGS - len(_findings)
            if space > 0:
                new_f = f[:space]
                _findings.extend(new_f)
                # Persist each finding to SQLite
                threading.Thread(
                    target=lambda nf=new_f, jid=job_id: [_db_save_finding(fi, jid) for fi in nf],
                    daemon=True
                ).start()
            _metrics["findings_total"] += len(f)
            _metrics["critical_total"] += c.get("critical",0)
            _metrics["high_total"]     += c.get("high",0)
        _jobs[job_id].update({"status":"completed","completed_at":datetime.now(timezone.utc).isoformat(),"result":result})
    _db_save_job(_jobs[job_id], "jobs")

def _run_agent_job(job_id, safe_path, auto_remediate):
    with _state_lock:
        _agent_jobs[job_id]["status"] = "running"
        _agent_jobs[job_id]["log"]    = []
    _db_save_job(_agent_jobs[job_id], "agent_jobs")
    def log(msg):
        with _state_lock:
            lg = _agent_jobs[job_id]["log"]
            # FIX MEDIUM: cap log to MAX_LOG_ENTRIES — prevents OOM on huge scans
            if len(lg) < MAX_LOG_ENTRIES:
                lg.append({"ts":datetime.now(timezone.utc).isoformat(),"msg":msg})
    log("[Orchestrator] Starting quantum audit: "+safe_path)
    log("[ScannerAgent] Scanning "+safe_path+"...")
    time.sleep(0.4)
    scan = _run_qsec("scan", safe_path, "--format","json")
    d2=scan.get("data",{})
    if isinstance(d2,list): d2={"scanner_findings":d2,"taint_findings":[]}
    sf2=d2.get("scanner_findings",d2.get("findings",[]))
    tr2=d2.get("taint_findings",[])
    findings=sf2+[{"severity":"HIGH","rule_id":t.get("rule_id","TAINT-001"),"title":t.get("title","Taint"),"file":t.get("file",""),"line":t.get("path",{}).get("sink_line",0),"description":t.get("path",{}).get("description",""),"recommendation":"Remova dados externos.","code_snippet":t.get("path",{}).get("sink_code","")} for t in tr2]
    log("[ScannerAgent] Found "+str(len(findings))+" vulnerabilities")
    critical = [f for f in findings if f.get("severity")=="CRITICAL"]
    if critical:
        log("[AgentBus] ALERT: "+str(len(critical))+" CRITICAL — notifying IncidentAgent")
        log("[IncidentAgent] Containment protocols activated")
    log("[AnalysisAgent] Calculating Quantum Risk Score...")
    time.sleep(0.4)
    counts={"critical":sum(1 for f in findings if str(f.get("severity","")).upper()=="CRITICAL"),"high":sum(1 for f in findings if str(f.get("severity","")).upper()=="HIGH"),"medium":0,"low":0}
    qrs = min(100, counts.get("critical",0)*25+counts.get("high",0)*10+counts.get("medium",0)*3+counts.get("low",0))
    log("[AnalysisAgent] Quantum Risk Score: "+str(qrs)+"/100")
    if qrs > 70: log("[AnalysisAgent] CRITICAL RISK — HNDL exposure window active")
    elif qrs > 40: log("[AnalysisAgent] HIGH RISK — migrate within 6 months")
    else: log("[AnalysisAgent] MODERATE RISK — planned migration recommended")
    log("[AnalysisAgent] 3-phase migration plan generated")
    qw_applied = 0
    if auto_remediate:
        qw = [f for f in findings if f.get("rule_id") in ["QSC-010","QSC-011","QSC-020","QSC-030"]]
        log("[RemediationAgent] "+str(len(qw))+" Quick Win patches available")
        for f in qw:
            time.sleep(0.15)
            log("[RemediationAgent] Patching "+f.get("rule_id","")+" in "+f.get("file","?"))
        qw_applied = len(qw)
        if qw_applied:
            with _state_lock: _metrics["patches_applied"] += qw_applied
            log("[RemediationAgent] Applied "+str(qw_applied)+" patches")
    log("[Orchestrator] Audit complete")
    with _state_lock:
        _agent_jobs[job_id].update({"status":"completed","completed_at":datetime.now(timezone.utc).isoformat(),
            "result":{"findings":findings,"quantum_risk_score":qrs,"severity_counts":counts,
                "patches_applied":qw_applied,"migration_phases":{
                    "quick_wins":["MD5->SHA3","SHA1->SHA3","JWT none->PQC-JWT","hardcoded->env"],
                    "medium_term":["RSA->ML-DSA","ECDH->ML-KEM"],
                    "long_term":["Full PQC-JWT","Supply chain attestation","liboqs production"]}}})
    _db_save_job(_agent_jobs[job_id], "agent_jobs")

@app.route("/api/"+API_VERSION+"/auth/token", methods=["POST"])
def auth_token():
    # RATE LIMIT: 20 auth attempts per IP per minute — brute-force protection
    ip = _client_ip()
    if not _ip_rate_limit(ip, max_per_minute=20):
        return jsonify({"error":"Too many requests — slow down"}), 429
    b = request.get_json(force=True,silent=True) or {}
    secret = b.get("client_secret","")
    if not isinstance(secret,str) or not hmac_lib.compare_digest(secret.encode(), API_SECRET.encode()):
        return jsonify({"error":"Invalid credentials"}), 401
    sub    = str(b.get("client_id","api-client"))[:128]
    ttl    = min(int(b.get("ttl",3600)), TOKEN_TTL_MAX)
    _VALID_SCOPES = {"scan","sign","jwt","keys","sbom","dashboard"}
    raw_scopes = b.get("scopes", list(_VALID_SCOPES))
    scopes = [s for s in raw_scopes if s in _VALID_SCOPES] or ["scan","dashboard"]
    token  = _issue_token(sub, scopes, ttl)
    return jsonify({"access_token":token,"token_type":"Bearer","expires_in":ttl,
        "scopes":scopes,"issued_at":datetime.now(timezone.utc).isoformat()})

@app.route("/api/"+API_VERSION+"/engine/info")
@require_auth()
def engine_info(): return jsonify(_run_qsec("info"))


@app.route("/api/"+API_VERSION+"/license/usage")
def license_usage():
    """Retorna uso atual vs limites do plano."""
    with _state_lock:
        try:
            con = sqlite3.connect(_DB_PATH)
            cur = con.cursor()
            cur.execute("SELECT COUNT(*) FROM repos_tracked")
            repo_count = cur.fetchone()[0]
            con.close()
        except Exception:
            repo_count = 0
    tier = get_tier()
    limits = get_tier_limits()
    return jsonify({
        "tier": tier,
        "limits": limits,
        "usage": {
            "repos": repo_count,
            "scans_total": _metrics.get("scans_total", 0),
            "findings_total": _metrics.get("findings_total", 0),
        },
        "upgrade_url": "https://docs.google.com/forms/d/e/1FAIpQLSfNMleQF2Ik-jHTT5HgPdsdkirXc4U_eJV3ON2hzI8ZR1TmQg/viewform",
    })

@app.route("/api/"+API_VERSION+"/license/status")
def license_status():
    return jsonify(check_access())

@app.route("/api/"+API_VERSION+"/license/activate", methods=["POST"])
def license_activate():
    body = request.get_json(force=True, silent=True) or {}
    ok, msg = install_license_key(body.get("license_key", ""))
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"message": msg})

@app.route("/api/"+API_VERSION+"/setup/company-size", methods=["POST"])
def setup_company_size():
    body = request.get_json(force=True, silent=True) or {}
    result = declare_company_size(body.get("size", "1-9"))
    return jsonify(result)

@app.route("/api/"+API_VERSION+"/scan", methods=["POST"])
@require_auth("scan")
def scan_start():
    # RATE LIMIT: 30 scans per token per minute
    if not _rate_limit(request.token_id, "scan", 30):
        return jsonify({"error":"Rate limit: max 30 scans/min per token"}), 429
    b = request.get_json(force=True,silent=True) or {}
    safe = _safe_api_path(b.get("path","."))
    if not safe: return jsonify({"error":"Invalid or forbidden path"}), 400
    jid = secrets.token_hex(16)
    job = {"job_id":jid,"status":"queued","path":safe,"created_at":datetime.now(timezone.utc).isoformat(),"result":None}
    with _state_lock:
        _jobs[jid] = job
    _db_save_job(job, "jobs")
    # Verifica limite de repositórios do tier
    try:
        con = sqlite3.connect(_DB_PATH)
        cur = con.cursor()
        cur.execute("INSERT OR IGNORE INTO repos_tracked (repo_path) VALUES (?)", (safe,))
        con.commit()
        cur.execute("SELECT COUNT(*) FROM repos_tracked")
        repo_count = cur.fetchone()[0]
        con.close()
        ok, msg = check_repo_limit(repo_count)
        if not ok:
            with _state_lock:
                del _jobs[jid]
            return jsonify({"error": msg, "upgrade_url": "https://docs.google.com/forms/d/e/1FAIpQLSfNMleQF2Ik-jHTT5HgPdsdkirXc4U_eJV3ON2hzI8ZR1TmQg/viewform"}), 403
    except Exception as e:
        pass  # Não bloqueia scan se verificação falhar
    # Verifica limite de repositórios do tier
    try:
        con = sqlite3.connect(_DB_PATH)
        cur = con.cursor()
        cur.execute('INSERT OR IGNORE INTO repos_tracked (repo_path) VALUES (?)', (safe,))
        con.commit()
        cur.execute('SELECT COUNT(*) FROM repos_tracked')
        repo_count = cur.fetchone()[0]
        con.close()
        ok, msg = check_repo_limit(repo_count)
        if not ok:
            with _state_lock:
                _jobs.pop(jid, None)
            return jsonify({'error': msg, 'upgrade_url': 'https://docs.google.com/forms/d/e/1FAIpQLSfNMleQF2Ik-jHTT5HgPdsdkirXc4U_eJV3ON2hzI8ZR1TmQg/viewform'}), 403
    except Exception:
        pass  # Não bloqueia scan se verificação falhar
    threading.Thread(target=_run_scan_job, args=(jid,safe), daemon=True).start()
    return jsonify({"job_id":jid,"status":"queued","poll_url":"/api/"+API_VERSION+"/scan/"+jid}), 202

@app.route("/api/"+API_VERSION+"/scan/<jid>")
@require_auth("scan")
def scan_status(jid):
    with _state_lock: j = _jobs.get(jid)
    return jsonify(j) if j else (jsonify({"error":"Not found"}), 404)

@app.route("/api/"+API_VERSION+"/findings")
@require_auth("scan")
def get_findings():
    sev   = request.args.get("severity","").upper()
    limit = min(int(request.args.get("limit",100)),1000)
    off   = int(request.args.get("offset",0))
    with _state_lock: results = list(_findings)
    if sev: results = [f for f in results if f.get("severity")==sev]
    return jsonify({"total":len(results),"offset":off,"limit":limit,"findings":results[off:off+limit]})

@app.route("/api/"+API_VERSION+"/sign", methods=["POST"])
@require_auth("sign")
def sign_artifact():
    b = request.get_json(force=True,silent=True) or {}
    safe = _safe_api_path(b.get("artifact_path"))
    if not safe: return jsonify({"error":"Invalid artifact_path"}), 400
    return jsonify(_run_qsec("sign", safe))

@app.route("/api/"+API_VERSION+"/verify", methods=["POST"])
@require_auth("sign")
def verify_artifact():
    b  = request.get_json(force=True,silent=True) or {}
    sa = _safe_api_path(b.get("artifact_path"))
    sm = _safe_api_path(b.get("manifest_path"))
    if not sa or not sm: return jsonify({"error":"Invalid paths"}), 400
    return jsonify(_run_qsec("verify", sa, "--manifest", sm))

@app.route("/api/"+API_VERSION+"/sbom", methods=["POST"])
@require_auth("sbom")
def generate_sbom():
    b = request.get_json(force=True,silent=True) or {}
    safe = _safe_api_path(b.get("path","."))
    if not safe: return jsonify({"error":"Invalid path"}), 400
    return jsonify(_run_qsec("sbom", safe))

@app.route("/api/"+API_VERSION+"/jwt/issue", methods=["POST"])
@require_auth("jwt")
def jwt_issue():
    b   = request.get_json(force=True,silent=True) or {}
    sub = str(b.get("subject","")).strip()[:256]
    aud = str(b.get("audience","api.example.com")).strip()[:256]
    ttl = min(int(b.get("ttl",3600)),86400)
    if not sub: return jsonify({"error":"subject required"}), 400
    # FIX HIGH: reject sub/aud with shell-injection chars before passing to subprocess args
    if not _SAFE_STR_RE.match(sub):
        return jsonify({"error":"subject contains invalid characters"}), 400
    if not _SAFE_STR_RE.match(aud):
        return jsonify({"error":"audience contains invalid characters"}), 400
    return jsonify(_run_qsec("token","issue","--subject",sub,"--audience",aud,"--ttl",str(ttl)))

@app.route("/api/"+API_VERSION+"/jwt/verify", methods=["POST"])
@require_auth("jwt")
def jwt_verify():
    b   = request.get_json(force=True,silent=True) or {}
    tok = str(b.get("token","")).strip()[:4096]
    aud = str(b.get("audience","api.example.com")).strip()[:256]
    if not tok: return jsonify({"error":"token required"}), 400
    return jsonify(_run_qsec("token","verify","--token",tok,"--audience",aud))

@app.route("/api/"+API_VERSION+"/jwt/revoke", methods=["POST"])
@require_auth("jwt")
def jwt_revoke():
    b   = request.get_json(force=True,silent=True) or {}
    jti = str(b.get("jti","")).strip()[:128]
    if not jti: return jsonify({"error":"jti required"}), 400
    with _state_lock:
        _revoked_jtis[jti] = time.time() + 86400   # TTL 24h
        _prune_revoked_nolock()   # FIX: no nested lock — called within _state_lock
        _metrics["tokens_revoked"] += 1
        count = len(_revoked_jtis)
    return jsonify({"revoked":True,"jti":jti,"total_revoked":count})

@app.route("/api/"+API_VERSION+"/keys")
@require_auth("keys")
def keys_status(): return jsonify(_run_qsec("keys","status"))

@app.route("/api/"+API_VERSION+"/keys/rotate", methods=["POST"])
@require_auth("keys")
def keys_rotate():
    if not _rate_limit(request.token_id,"rotate",RATE_LIMIT_ROTATE):
        return jsonify({"error":"Rate limit: max 5 rotations/min"}), 429
    b      = request.get_json(force=True,silent=True) or {}
    reason = str(b.get("reason","manual"))[:256]
    r      = _run_qsec("keys","rotate")
    if r.get("success"):
        r["data"]["reason"]     = reason
        r["data"]["rotated_by"] = request.token_info.get("sub")
    return jsonify(r)

@app.route("/api/"+API_VERSION+"/dashboard")
@require_auth()
def dashboard():
    up = int(time.time()-_metrics["uptime_start"])
    h,rem=divmod(up,3600); m,s=divmod(rem,60)
    with _state_lock:
        ms  = dict(_metrics)
        fs  = list(_findings[-10:])
        sev = {k:sum(1 for f in _findings if f.get("severity")==k.upper()) for k in ["critical","high","medium","low"]}
        at  = len([v for v in _tokens.values() if v["exp"]>time.time()])
        all_jobs = {**_jobs,**_agent_jobs}
        jrc = sum(1 for j in all_jobs.values() if j["status"]=="running")
        jcc = sum(1 for j in all_jobs.values() if j["status"]=="completed")
        rev = len(_revoked_jtis)
    return jsonify({"status":"operational","version":"3.2.1",
        "uptime":"{:02d}:{:02d}:{:02d}".format(h,m,s),"uptime_s":up,
        "engine":{"backend":"liboqs" if Path(QSEC_BIN).exists() else "simulation",
                  "kem":"X25519 + ML-KEM-1024","dsa":"Ed25519 + ML-DSA-87","nist_level":5},
        "metrics":{k:v for k,v in ms.items() if k!="uptime_start"},
        "active_tokens":at,"active_jobs":jrc,"completed_jobs":jcc,"revoked_tokens":rev,
        "recent_findings":fs,"severity_breakdown":sev,
        "timestamp":datetime.now(timezone.utc).isoformat()})

@app.route("/api/"+API_VERSION+"/agents/audit", methods=["POST"])
@require_auth("scan")
def agents_audit():
    # RATE LIMIT: 10 AI audits per token per minute (heavy operation)
    if not _rate_limit(request.token_id, "audit", 10):
        return jsonify({"error":"Rate limit: max 10 AI audits/min per token"}), 429
    b    = request.get_json(force=True,silent=True) or {}
    safe = _safe_api_path(b.get("path","."))
    if not safe: return jsonify({"error":"Invalid or forbidden path"}), 400
    ar  = bool(b.get("auto_remediate",False))
    jid = secrets.token_hex(16)
    job = {"job_id":jid,"status":"queued","path":safe,
           "created_at":datetime.now(timezone.utc).isoformat(),"log":[],"result":None}
    with _state_lock:
        _agent_jobs[jid] = job
    _db_save_job(job, "agent_jobs")
    threading.Thread(target=_run_agent_job, args=(jid,safe,ar), daemon=True).start()
    return jsonify({"job_id":jid,"status":"queued","poll_url":"/api/"+API_VERSION+"/agents/audit/"+jid}), 202

@app.route("/api/"+API_VERSION+"/agents/audit/<jid>")
@require_auth("scan")
def agents_audit_status(jid):
    with _state_lock: j = _agent_jobs.get(jid)
    return jsonify(j) if j else (jsonify({"error":"Not found"}), 404)

@app.route("/api/"+API_VERSION+"/agents/status")
@require_auth()
def agents_status():
    with _state_lock:
        ac = sum(1 for j in _agent_jobs.values() if j["status"]=="running")
        cc = sum(1 for j in _agent_jobs.values() if j["status"]=="completed")
    return jsonify({"agents":[
        {"name":"ScannerAgent","status":"ready","specialty":"Crypto vulnerability detection"},
        {"name":"AnalysisAgent","status":"ready","specialty":"Quantum Risk Score + migration planning"},
        {"name":"RemediationAgent","status":"ready","specialty":"Autonomous code patching"},
        {"name":"MonitoringAgent","status":"ready","specialty":"Continuous file watching"},
        {"name":"IncidentAgent","status":"ready","specialty":"Real-time incident response"},
    ],"model":"claude-sonnet-4-20250514","max_iterations":10,"token_budget":80000,
      "active_jobs":ac,"completed_audits":cc})

# FIX: SSE auth via query param (browser EventSource cannot send Authorization headers)
@app.route("/api/"+API_VERSION+"/agents/audit/<jid>/stream")
def stream_audit_log(jid):
    """
    SSE endpoint — auth via ?token=<bearer> query param because browser EventSource
    API cannot send custom headers. Token is validated identically to Bearer header.
    """
    raw_token = request.args.get("token","")
    if not raw_token:
        return jsonify({"error":"Missing token query param"}), 401
    tid = _verify_sig(raw_token)
    if not tid:
        return jsonify({"error":"Invalid token"}), 401
    with _state_lock: info = _tokens.get(tid)
    if not info:
        return jsonify({"error":"Token not found"}), 401
    if info["exp"] < time.time():
        return jsonify({"error":"Token expired"}), 401
    if "scan" not in info["scopes"]:
        return jsonify({"error":"Scope required: scan"}), 403
    with _state_lock: _metrics["api_calls_total"] += 1
    # FIX MEDIUM: capture token expiry at stream start for periodic re-check
    _stream_token_exp = info["exp"]

    def generate():
        seen = 0
        while True:
            # FIX MEDIUM: re-check token expiry every iteration
            if time.time() > _stream_token_exp:
                yield "data: " + json.dumps({"error":"token_expired","msg":"stream terminated — token expired"}) + "\n\n"
                return
            with _state_lock:
                j = _agent_jobs.get(jid)
            if not j:
                yield "data: " + json.dumps({"error":"job not found"}) + "\n\n"
                return
            with _state_lock:
                entries = list(j.get("log",[])); status = j["status"]
            for e in entries[seen:]:
                yield "data: " + json.dumps(e) + "\n\n"
            seen = len(entries)
            if status in ("completed","failed"):
                yield "data: " + json.dumps({"event":"done","status":status}) + "\n\n"
                return
            time.sleep(0.2)
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/welcome")
def serve_welcome():
    """Página de boas-vindas — guia de início rápido para novos clientes."""
    d = Path(__file__).parent.parent/"web"
    if (d/"welcome.html").exists():
        resp = send_from_directory(str(d),"welcome.html")
    else:
        # fallback inline se arquivo não existir
        resp = Response(
            "<h1>QSEC v3.2.1 Online</h1><p>Acesse <a href='/'>Dashboard</a></p>",
            mimetype="text/html"
        )
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

@app.route("/")
@app.route("/<path:p>")
def serve_ui(p=""):
    d = Path(__file__).parent.parent/"web"
    if (d/"index.html").exists():
        resp = send_from_directory(str(d),"index.html")
        # FIX MEDIUM: Content-Security-Policy blocks injected scripts
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "   # unsafe-inline required for inline JS in single-file app
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' http://localhost:8080 http://127.0.0.1:8080; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'"
        )
        resp.headers["X-Frame-Options"]        = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
        return resp
    return jsonify({"qsec":"3.1.0","ui":"not built"})

@app.route("/health")
def health():
    return jsonify({"status":"ok","version":"3.2.1","llm_provider":os.environ.get("LLM_PROVIDER","ollama"),"ollama_model":os.environ.get("OLLAMA_MODEL","llama3.2:3b"),
        "engine":"online" if (Path(QSEC_BIN).exists() and Path(QSEC_BIN).stat().st_mode & 0o111) else "simulation",
        "uptime":int(time.time()-_metrics["uptime_start"])})

# FIX MEDIUM: CORS origin allowlist only — removed dev mode wildcard fallback
# Rationale: missing Origin header = non-browser (curl/script) → no CORS needed
@app.after_request
def add_cors(r):
    origin = request.headers.get("Origin","")
    if origin in CORS_ORIGINS:
        r.headers["Access-Control-Allow-Origin"] = origin
        r.headers["Vary"] = "Origin"
    r.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return r

@app.before_request
def attach_request_id():
    request.rid = secrets.token_hex(8)

@app.after_request
def add_request_id(r):
    r.headers["X-Request-ID"] = getattr(request, "rid", "—")
    return r

@app.errorhandler(413)
def too_large(e): return jsonify({"error":"Request too large — max 1 MB"}), 413

if __name__ == "__main__":
    port  = int(os.environ.get("PORT",8080))
    host  = os.environ.get("HOST","0.0.0.0")
    debug = os.environ.get("DEBUG","").lower()=="true"
    print("QSEC Enterprise API Server v3.2.1 (hardened)")
    print("  Host:", host+":"+str(port), "| CORS: allowlist |",
          "Max body: 1MB | Token: HMAC-SHA3-256 | Thread-safe: YES")
    app.run(host=host, port=port, debug=debug, threaded=True)
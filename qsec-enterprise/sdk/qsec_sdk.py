"""
QSEC Enterprise Python SDK
============================
Cliente tipado para a QSEC Enterprise API.

Instalação:
    pip install qsec-sdk   (ou: pip install .)

Uso rápido:
    from qsec_sdk import QsecClient

    client = QsecClient(
        base_url="https://qsec.yourcompany.com",
        client_secret="your-secret",
    )

    # Scan a project
    job    = client.scan.start("./src")
    result = client.scan.wait(job.job_id)
    print(f"QRS: {result.quantum_risk_score}/100")

    # Issue PQC-JWT
    token = client.jwt.issue("user@example.com", audience="api.example.com")
    claims = client.jwt.verify(token, audience="api.example.com")

    # Rotate keys
    client.keys.rotate(reason="Quarterly rotation")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
import urllib.request
import urllib.error
import json

__version__ = "3.0.0"
__all__      = ["QsecClient", "QsecError", "ScanResult", "Finding", "JwtToken"]


# ── Exceptions ────────────────────────────────────────────────────────────────

class QsecError(Exception):
    """Base exception for QSEC SDK errors."""
    def __init__(self, message: str, status_code: int = 0, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response    = response or {}


class QsecAuthError(QsecError):
    """Authentication or authorization failure."""

class QsecScanError(QsecError):
    """Scan job failure."""

class QsecTimeoutError(QsecError):
    """Polling timeout exceeded."""


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class Finding:
    file:           str
    line:           int
    severity:       str       # CRITICAL | HIGH | MEDIUM | LOW
    rule_id:        str       # QSC-001 ... QSC-040
    title:          str
    description:    str
    recommendation: str
    code_snippet:   str = ""
    column:         int = 0

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            file           = d.get("file", ""),
            line           = d.get("line", 0),
            severity       = d.get("severity", ""),
            rule_id        = d.get("rule_id", ""),
            title          = d.get("title", ""),
            description    = d.get("description", ""),
            recommendation = d.get("recommendation", ""),
            code_snippet   = d.get("code_snippet", ""),
            column         = d.get("column", 0),
        )

    @property
    def is_critical(self) -> bool:
        return self.severity == "CRITICAL"

    @property
    def is_high(self) -> bool:
        return self.severity == "HIGH"


@dataclass
class ScanResult:
    job_id:               str
    status:               str
    path:                 str
    findings:             list[Finding]
    severity_counts:      dict[str, int]
    quantum_risk_score:   int
    patches_applied:      int
    migration_phases:     dict[str, list[str]] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return self.severity_counts.get("critical", 0)

    @property
    def high_count(self) -> int:
        return self.severity_counts.get("high", 0)

    @property
    def is_clean(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    @property
    def risk_label(self) -> str:
        qrs = self.quantum_risk_score
        if qrs >= 70: return "CRITICAL"
        if qrs >= 40: return "HIGH"
        if qrs >= 20: return "MODERATE"
        return "LOW"

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        result = d.get("result") or {}
        return cls(
            job_id             = d.get("job_id", ""),
            status             = d.get("status", ""),
            path               = d.get("path", ""),
            findings           = [Finding.from_dict(f) for f in result.get("findings", [])],
            severity_counts    = result.get("severity_counts", {}),
            quantum_risk_score = int(result.get("quantum_risk_score", 0) or 0),
            patches_applied    = int(result.get("patches_applied", 0) or 0),
            migration_phases   = result.get("migration_phases", {}),
        )


@dataclass
class JwtToken:
    raw:       str
    algorithm: str = "Ed25519+ML-DSA-87"
    token_type: str = "PQC-JWT"
    expires_in: int = 3600

    def __str__(self) -> str:
        return self.raw


@dataclass
class KeyStatus:
    active_keys:     int
    key_id:          str
    algorithm:       str
    created_at:      str
    expires_in_days: int

    @property
    def is_expiring_soon(self) -> bool:
        return self.expires_in_days < 7


@dataclass
class EngineInfo:
    version:            str
    backend:            str
    kem_algorithm:      str
    dsa_algorithm:      str
    symmetric:          str
    kdf:                str
    hndl_protection:    bool
    nist_pqc_compliant: bool

    @property
    def is_production(self) -> bool:
        return self.nist_pqc_compliant and "liboqs" in self.backend


# ── HTTP Transport ────────────────────────────────────────────────────────────

class _Transport:
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self._token: str | None = None
        # FIX MEDIUM: warn when base_url is http:// — TLS strongly recommended
        if self.base_url.startswith("http://") and "localhost" not in self.base_url and "127.0.0.1" not in self.base_url:
            import warnings
            warnings.warn(
                "QsecClient: base_url uses http:// — TLS (https://) is required in production to prevent MITM attacks.",
                stacklevel=3,
            )

    def __del__(self):
        # FIX MEDIUM: overwrite token in memory before GC (best-effort in CPython)
        if self._token:
            self._token = "0" * len(self._token)
            self._token = None

    def _request(self, method: str, path: str, body: dict = None) -> dict:
        url  = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body else None
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   f"qsec-sdk-python/{__version__}",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body_err = {}
            try:
                body_err = json.loads(e.read())
            except Exception:
                pass
            if e.code == 401:
                raise QsecAuthError("Authentication failed", e.code, body_err)
            if e.code == 403:
                raise QsecAuthError("Insufficient scope", e.code, body_err)
            raise QsecError(body_err.get("error", str(e)), e.code, body_err)
        except urllib.error.URLError as e:
            raise QsecError(f"Cannot reach QSEC API at {self.base_url}: {e.reason}")

    def authenticate(self, client_id: str, client_secret: str,
                     scopes: list[str] = None) -> None:
        resp = self._request("POST", "/api/v1/auth/token", {
            "client_id":     client_id,
            "client_secret": client_secret,
            "scopes":        scopes or ["scan", "sign", "jwt", "keys", "sbom", "dashboard"],
        })
        token = resp.get("access_token")
        if not token:
            raise QsecAuthError("No token in response", response=resp)
        self._token = token


# ── Sub-clients ───────────────────────────────────────────────────────────────

class ScanClient:
    def __init__(self, transport: _Transport):
        self._t = transport

    def start(self, path: str, auto_remediate: bool = False) -> dict:
        """Start a background audit. Returns job info dict."""
        return self._t._request("POST", "/api/v1/agents/audit", {
            "path": path, "auto_remediate": auto_remediate
        })

    def status(self, job_id: str) -> dict:
        """Get current job status dict."""
        return self._t._request("GET", f"/api/v1/agents/audit/{job_id}")

    def wait(self, job_id: str, timeout: int = 120, poll_interval: float = 1.0) -> ScanResult:
        """
        Block until job completes, then return ScanResult.

        Raises QsecTimeoutError if timeout exceeded.
        Raises QsecScanError if job failed.
        """
        # FIX LOW: exponential backoff (1s → 2s → 4s → capped at 8s)
        deadline = time.time() + timeout
        interval = poll_interval
        while time.time() < deadline:
            job = self.status(job_id)
            if job["status"] == "completed":
                return ScanResult.from_dict(job)
            if job["status"] == "failed":
                raise QsecScanError(f"Scan job {job_id} failed")
            time.sleep(min(interval, 8.0))
            interval = min(interval * 1.5, 8.0)
        raise QsecTimeoutError(f"Scan job {job_id} timed out after {timeout}s")

    def run(self, path: str, auto_remediate: bool = False,
            timeout: int = 120) -> ScanResult:
        """
        Convenience: start + wait in one call.

        Example:
            result = client.scan.run("./src")
            if result.critical_count > 0:
                sys.exit(1)   # fail CI/CD
        """
        job = self.start(path, auto_remediate)
        return self.wait(job["job_id"], timeout=timeout)

    def findings(self, severity: str = None, limit: int = 100) -> list[Finding]:
        """Get accumulated findings (all scans)."""
        path = f"/api/v1/findings?limit={limit}"
        if severity:
            path += f"&severity={severity.upper()}"
        resp = self._t._request("GET", path)
        return [Finding.from_dict(f) for f in resp.get("findings", [])]


class JwtClient:
    def __init__(self, transport: _Transport):
        self._t = transport

    def issue(self, subject: str, audience: str = "api.example.com",
              ttl: int = 3600, extra_claims: dict = None) -> str:
        """Issue a PQC-JWT. Returns raw token string."""
        body = {"subject": subject, "audience": audience, "ttl": ttl}
        if extra_claims:
            body["extra_claims"] = extra_claims
        resp = self._t._request("POST", "/api/v1/jwt/issue", body)
        data = resp.get("data") or resp
        return data.get("token", "")

    def verify(self, token: str, audience: str = "api.example.com") -> dict:
        """Verify a PQC-JWT. Returns claims dict."""
        resp = self._t._request("POST", "/api/v1/jwt/verify",
                                {"token": token, "audience": audience})
        if not resp.get("success", True) and resp.get("error"):
            raise QsecError(f"Token invalid: {resp['error']}")
        return resp.get("data", resp)

    def revoke(self, jti: str) -> dict:
        """Revoke a token by JTI."""
        return self._t._request("POST", "/api/v1/jwt/revoke", {"jti": jti})


class KeysClient:
    def __init__(self, transport: _Transport):
        self._t = transport

    def status(self) -> KeyStatus:
        resp = self._t._request("GET", "/api/v1/keys")
        d = resp.get("data", {})
        k = d.get("current_key", {})
        return KeyStatus(
            active_keys     = d.get("active_keys", 1),
            key_id          = k.get("key_id", ""),
            algorithm       = k.get("algorithm", "Ed25519+ML-DSA-87"),
            created_at      = k.get("created_at", ""),
            expires_in_days = k.get("expires_in_days", 30),
        )

    def rotate(self, reason: str = "manual") -> dict:
        return self._t._request("POST", "/api/v1/keys/rotate", {"reason": reason})


class EngineClient:
    def __init__(self, transport: _Transport):
        self._t = transport

    def info(self) -> EngineInfo:
        resp = self._t._request("GET", "/api/v1/engine/info")
        d = resp.get("data", {})
        return EngineInfo(
            version            = d.get("version", "3.0.0"),
            backend            = d.get("backend", ""),
            kem_algorithm      = d.get("kem_algorithm", "X25519 + ML-KEM-1024"),
            dsa_algorithm      = d.get("dsa_algorithm", "Ed25519 + ML-DSA-87"),
            symmetric          = d.get("symmetric", "AES-256-GCM"),
            kdf                = d.get("kdf", "HKDF-SHA3-256"),
            hndl_protection    = d.get("hndl_protection", True),
            nist_pqc_compliant = d.get("nist_pqc_compliant", False),
        )


class SbomClient:
    def __init__(self, transport: _Transport):
        self._t = transport

    def generate(self, path: str = ".") -> dict:
        """Generate CycloneDX 1.5 SBOM."""
        resp = self._t._request("POST", "/api/v1/sbom", {"path": path})
        return resp.get("data", resp)


# ── Main client ───────────────────────────────────────────────────────────────

class QsecClient:
    """
    QSEC Enterprise API Client.

    Example:
        from qsec_sdk import QsecClient

        client = QsecClient(
            base_url="https://qsec.yourcompany.com",
            client_secret="prod-secret",
        )

        # Full audit
        result = client.scan.run("./src", auto_remediate=True)
        print(f"Quantum Risk Score: {result.quantum_risk_score}/100 ({result.risk_label})")
        print(f"Critical: {result.critical_count}, High: {result.high_count}")
        print(f"Patches applied: {result.patches_applied}")

        if not result.is_clean:
            for f in result.findings:
                if f.is_critical:
                    print(f"  {f.rule_id}: {f.title} at {f.file}:{f.line}")
    """

    def __init__(
        self,
        base_url:      str,
        client_secret: str,
        client_id:     str  = "sdk-client",
        scopes:        list = None,
        timeout:       int  = 30,
        auto_auth:     bool = True,
    ):
        self._transport = _Transport(base_url, timeout)

        if auto_auth:
            self._transport.authenticate(client_id, client_secret, scopes)

        self.scan   = ScanClient(self._transport)
        self.jwt    = JwtClient(self._transport)
        self.keys   = KeysClient(self._transport)
        self.engine = EngineClient(self._transport)
        self.sbom   = SbomClient(self._transport)

    def health(self) -> dict:
        """Check API health — no auth required."""
        return self._transport._request("GET", "/health")

    def dashboard(self) -> dict:
        """Get full dashboard metrics."""
        return self._transport._request("GET", "/api/v1/dashboard")

    @property
    def is_authenticated(self) -> bool:
        return self._transport._token is not None


# ── CLI helper — scan and exit ─────────────────────────────────────────────────

def cli_scan_and_exit():
    """
    Minimal CLI: python -m qsec_sdk scan ./src

    Returns exit code 0 if clean, 1 if CRITICAL/HIGH found.
    """
    import sys, argparse

    parser = argparse.ArgumentParser(description="QSEC SDK — CI/CD scan helper")
    parser.add_argument("command", choices=["scan", "info"])
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--url",    default="http://localhost:8080")
    # FIX HIGH: secret no longer accepted as CLI arg (visible in ps aux)
    # Use env var QSEC_API_SECRET instead
    parser.add_argument("--auto-remediate", action="store_true")
    parser.add_argument("--fail-on", choices=["critical", "high", "any"],
                        default="critical")
    args = parser.parse_args()
    # Validate url
    if not args.url.startswith(("http://","https://")):
        print("[QSEC] ERROR: --url must start with http:// or https://", file=sys.stderr)
        sys.exit(1)

    # FIX HIGH: read secret from env var — never from argv
    import os as _os
    _secret = _os.environ.get("QSEC_API_SECRET", "")
    if not _secret:
        print("[QSEC] ERROR: QSEC_API_SECRET env var not set", file=sys.stderr)
        sys.exit(1)
    client = QsecClient(args.url, _secret)

    if args.command == "info":
        info = client.engine.info()
        print(f"QSEC Engine {info.version}")
        print(f"  KEM:     {info.kem_algorithm}")
        print(f"  DSA:     {info.dsa_algorithm}")
        print(f"  Backend: {info.backend}")
        print(f"  NIST:    {'✓ Compliant' if info.nist_pqc_compliant else '◎ Reference'}")
        sys.exit(0)

    print(f"[QSEC] Scanning {args.path}...")
    result = client.scan.run(args.path, auto_remediate=args.auto_remediate)

    print(f"[QSEC] Quantum Risk Score: {result.quantum_risk_score}/100 ({result.risk_label})")
    print(f"[QSEC] Findings: {len(result.findings)} total")
    print(f"[QSEC]   CRITICAL: {result.critical_count}")
    print(f"[QSEC]   HIGH:     {result.high_count}")

    for f in result.findings:
        if f.severity in ("CRITICAL", "HIGH"):
            print(f"  [{f.severity}] {f.rule_id}: {f.title}")
            print(f"    File: {f.file}:{f.line}")
            print(f"    Fix:  {f.recommendation}")

    if result.patches_applied > 0:
        print(f"[QSEC] Auto-patched: {result.patches_applied} Quick Wins applied")

    should_fail = (
        (args.fail_on == "critical" and result.critical_count > 0) or
        (args.fail_on == "high"     and (result.critical_count + result.high_count) > 0) or
        (args.fail_on == "any"      and len(result.findings) > 0)
    )

    if should_fail:
        print(f"[QSEC] ✗ Scan FAILED — {result.critical_count} critical, {result.high_count} high")
        sys.exit(1)
    else:
        print("[QSEC] ✓ Scan passed")
        sys.exit(0)


if __name__ == "__main__":
    cli_scan_and_exit()

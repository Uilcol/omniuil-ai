"""
QSEC Enterprise Notifier

Integrações com plataformas enterprise:
  - Slack (Incoming Webhooks)
  - Microsoft Teams (Adaptive Cards)
  - PagerDuty (Events API v2)
  - JIRA (REST API v3 — auto-cria issues)
  - Generic Webhook (qualquer endpoint HTTP)

Uso:
    config = {
        "slack":     {"webhook_url": "...", "channel": "#security", "min_severity": "HIGH"},
        "pagerduty": {"routing_key": "...", "min_severity": "CRITICAL"},
        "jira":      {"url": "...", "project": "SEC", "token": "...", "email": "..."},
    }
    notifier = EnterpriseNotifier(config)
    await notifier.notify_findings(findings, quantum_risk_score=85)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False
    print("[QSEC Notifier] httpx not installed — install with: pip install httpx")


# Severity ordering
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _meets_severity(finding_sev: str, min_sev: str) -> bool:
    return _SEV_ORDER.get(finding_sev.upper(), 0) >= _SEV_ORDER.get(min_sev.upper(), 0)


# ─── Slack ────────────────────────────────────────────────────────────────────

class SlackNotifier:
    """Slack via Incoming Webhooks — Block Kit formatting."""

    def __init__(self, webhook_url: str, channel: str = "#security-alerts",
                 min_severity: str = "HIGH"):
        self.webhook_url   = webhook_url
        self.channel       = channel
        self.min_severity  = min_severity

    async def send_findings_report(
        self,
        findings: list[dict],
        score: int,
        project: str = ".",
    ) -> bool:
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in findings if f.get("severity") == "HIGH"]

        if not any(_meets_severity(f.get("severity","LOW"), self.min_severity) for f in findings):
            return True  # Nothing to notify

        color  = "#F85149" if critical else "#D29922" if high else "#3FB950"
        emoji  = "🔴" if score >= 75 else "🟡" if score >= 40 else "🟢"
        status = "CRITICAL" if score >= 75 else "AT RISK" if score >= 40 else "SECURE"

        # Build Block Kit message
        blocks: list[dict] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} QSEC Security Alert — {status}", "emoji": True}
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Quantum Risk Score*\n{score}/100"},
                    {"type": "mrkdwn", "text": f"*Project*\n`{project}`"},
                    {"type": "mrkdwn", "text": f"*🔴 Critical*\n{len(critical)}"},
                    {"type": "mrkdwn", "text": f"*🟠 High*\n{len(high)}"},
                ]
            },
        ]

        # Top findings (max 5)
        top = sorted(findings, key=lambda f: -_SEV_ORDER.get(f.get("severity","LOW"), 0))[:5]
        if top:
            finding_text = "\n".join(
                f"• `{f.get('rule_id','')}` {f.get('title','')} — "
                f"`{f.get('file','').split('/')[-1]}:{f.get('line',0)}`"
                for f in top
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{finding_text}"}
            })

        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn",
                 "text": f"QSEC v3.0.0 · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} · "
                         f"<https://docs.qsec.io|Documentation>"}
            ]
        })

        payload = {
            "channel":     self.channel,
            "attachments": [{"color": color, "blocks": blocks}]
        }

        return await self._post(payload)

    async def send_incident(self, incident_type: str, description: str, severity: str = "CRITICAL") -> bool:
        color = "#F85149" if severity == "CRITICAL" else "#D29922"
        emoji = "🚨" if severity == "CRITICAL" else "⚠️"
        payload = {
            "channel": self.channel,
            "attachments": [{
                "color": color,
                "blocks": [
                    {"type": "header",
                     "text": {"type": "plain_text", "text": f"{emoji} QSEC Security Incident", "emoji": True}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Type*\n{incident_type}"},
                        {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
                    ]},
                    {"type": "section",
                     "text": {"type": "mrkdwn", "text": f"*Description*\n{description}"}},
                    {"type": "context", "elements": [
                        {"type": "mrkdwn",
                         "text": f"QSEC Incident Response · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}"}
                    ]}
                ]
            }]
        }
        return await self._post(payload)

    async def _post(self, payload: dict) -> bool:
        if not _HAS_HTTPX:
            print(f"[Slack] Would send: {json.dumps(payload)[:200]}")
            return True
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.webhook_url, json=payload)
                return resp.status_code == 200
        except Exception as e:
            print(f"[Slack] Error: {e}")
            return False


# ─── Microsoft Teams ──────────────────────────────────────────────────────────

class TeamsNotifier:
    """Microsoft Teams via Incoming Webhooks — Adaptive Cards."""

    def __init__(self, webhook_url: str, min_severity: str = "CRITICAL"):
        self.webhook_url  = webhook_url
        self.min_severity = min_severity

    async def send_findings_report(self, findings: list[dict], score: int, project: str = ".") -> bool:
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in findings if f.get("severity") == "HIGH")

        if not any(_meets_severity(f.get("severity","LOW"), self.min_severity) for f in findings):
            return True

        color   = "attention" if score >= 75 else "warning" if score >= 40 else "good"
        status  = "CRITICAL" if score >= 75 else "AT RISK" if score >= 40 else "SECURE"
        icon    = "🔴" if score >= 75 else "🟡" if score >= 40 else "🟢"

        top5 = sorted(findings, key=lambda f: -_SEV_ORDER.get(f.get("severity","LOW"), 0))[:5]

        payload = {
            "type":        "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type":    "AdaptiveCard",
                    "version": "1.4",
                    "body":    [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": f"{icon} QSEC Security Report — {status}",
                            "color": color,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Quantum Risk Score", "value": f"{score}/100"},
                                {"title": "Project",           "value": project},
                                {"title": "Critical",          "value": str(critical)},
                                {"title": "High",              "value": str(high)},
                                {"title": "Total Findings",    "value": str(len(findings))},
                            ]
                        },
                        *([{
                            "type": "TextBlock",
                            "text": "Top Findings:",
                            "weight": "Bolder",
                            "separator": True,
                        }] if top5 else []),
                        *[{
                            "type": "TextBlock",
                            "text": f"• [{f.get('rule_id','')}] {f.get('title','')} "
                                    f"({f.get('file','').split('/')[-1]}:{f.get('line',0)})",
                            "wrap": True,
                            "color": "attention" if f.get("severity") == "CRITICAL" else "warning",
                        } for f in top5],
                    ]
                }
            }]
        }
        return await self._post(payload)

    async def _post(self, payload: dict) -> bool:
        if not _HAS_HTTPX:
            print(f"[Teams] Would send: {json.dumps(payload)[:200]}")
            return True
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.webhook_url, json=payload)
                return resp.status_code in (200, 202)
        except Exception as e:
            print(f"[Teams] Error: {e}")
            return False


# ─── PagerDuty ────────────────────────────────────────────────────────────────

class PagerDutyNotifier:
    """PagerDuty Events API v2 — cria/resolve incidents automaticamente."""

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str, min_severity: str = "CRITICAL",
                 service_name: str = "QSEC Security"):
        self.routing_key  = routing_key
        self.min_severity = min_severity
        self.service_name = service_name

    async def trigger(self, summary: str, severity: str = "critical",
                      details: dict | None = None, dedup_key: str | None = None) -> bool:
        pd_severity = {
            "CRITICAL": "critical",
            "HIGH":     "error",
            "MEDIUM":   "warning",
            "LOW":      "info",
        }.get(severity.upper(), "error")

        payload = {
            "routing_key":  self.routing_key,
            "event_action": "trigger",
            "dedup_key":    dedup_key or f"qsec-{int(time.time())}",
            "payload": {
                "summary":   summary,
                "severity":  pd_severity,
                "source":    self.service_name,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "custom_details": details or {},
            },
            "client":     "QSEC v3",
            "client_url": "https://github.com/yourorg/qsec",
        }
        return await self._post(payload)

    async def resolve(self, dedup_key: str) -> bool:
        payload = {
            "routing_key":  self.routing_key,
            "event_action": "resolve",
            "dedup_key":    dedup_key,
        }
        return await self._post(payload)

    async def send_findings_report(self, findings: list[dict], score: int, project: str = ".") -> bool:
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        if not critical:
            return True  # PagerDuty só para CRITICAL por padrão

        if not any(_meets_severity(f.get("severity","LOW"), self.min_severity) for f in findings):
            return True

        return await self.trigger(
            summary   = f"QSEC: {len(critical)} CRITICAL crypto findings in {project} (score={score}/100)",
            severity  = "CRITICAL",
            details   = {
                "quantum_risk_score": score,
                "project":            project,
                "critical_count":     len(critical),
                "top_findings": [
                    {"rule": f.get("rule_id"), "title": f.get("title"),
                     "file": f.get("file"), "line": f.get("line")}
                    for f in critical[:5]
                ],
            },
            dedup_key = f"qsec-scan-{project.replace('/', '-')}",
        )

    async def _post(self, payload: dict) -> bool:
        if not _HAS_HTTPX:
            print(f"[PagerDuty] Would send: {json.dumps(payload)[:200]}")
            return True
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.EVENTS_URL, json=payload)
                return resp.status_code == 202
        except Exception as e:
            print(f"[PagerDuty] Error: {e}")
            return False


# ─── JIRA ─────────────────────────────────────────────────────────────────────

class JiraNotifier:
    """JIRA REST API v3 — cria issues automaticamente para cada CRITICAL/HIGH."""

    def __init__(self, url: str, project: str, token: str,
                 email: str = "", issue_type: str = "Bug",
                 auto_create: bool = True, min_severity: str = "HIGH"):
        self.base_url    = url.rstrip("/")
        self.project     = project
        self.token       = token
        self.email       = email
        self.issue_type  = issue_type
        self.auto_create = auto_create
        self.min_sev     = min_severity

    def _auth_header(self) -> dict:
        import base64
        creds = base64.b64encode(f"{self.email}:{self.token}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    async def create_issue(self, finding: dict, score: int) -> str | None:
        """Cria uma issue JIRA para o finding. Retorna o issue key ou None."""
        sev  = finding.get("severity", "MEDIUM")
        priority = {
            "CRITICAL": "Critical",
            "HIGH":     "High",
            "MEDIUM":   "Medium",
            "LOW":      "Low",
        }.get(sev, "Medium")

        description = {
            "version": 1,
            "type":    "doc",
            "content": [{
                "type": "paragraph",
                "content": [{"type": "text", "text": (
                    f"QSEC detected {sev} cryptographic vulnerability.\n\n"
                    f"Rule: {finding.get('rule_id', '')}\n"
                    f"File: {finding.get('file', '')}:{finding.get('line', 0)}\n"
                    f"Description: {finding.get('description', '')}\n\n"
                    f"Recommendation: {finding.get('recommendation', '')}\n\n"
                    f"Code: {finding.get('code_snippet', '')}\n\n"
                    f"Quantum Risk Score: {score}/100"
                )}]
            }]
        }

        payload = {
            "fields": {
                "project":     {"key": self.project},
                "summary":     f"[QSEC-{finding.get('rule_id','')}] {finding.get('title','')} "
                               f"in {finding.get('file','').split('/')[-1]}:{finding.get('line',0)}",
                "description": description,
                "issuetype":   {"name": self.issue_type},
                "priority":    {"name": priority},
                "labels":      ["qsec", "security", "post-quantum", sev.lower()],
            }
        }

        if not _HAS_HTTPX:
            print(f"[JIRA] Would create: {payload['fields']['summary']}")
            return "DEMO-001"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self.base_url}/rest/api/3/issue",
                    headers=self._auth_header(),
                    json=payload,
                )
                if resp.status_code == 201:
                    data = resp.json()
                    return data.get("key")
                else:
                    print(f"[JIRA] Create issue failed: {resp.status_code} {resp.text[:200]}")
                    return None
        except Exception as e:
            print(f"[JIRA] Error: {e}")
            return None

    async def send_findings_report(self, findings: list[dict], score: int, project: str = ".") -> bool:
        if not self.auto_create:
            return True

        qualifying = [
            f for f in findings
            if _meets_severity(f.get("severity","LOW"), self.min_sev)
        ]

        created = []
        tasks   = [self.create_issue(f, score) for f in qualifying[:10]]  # max 10
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for key in results:
            if isinstance(key, str):
                created.append(key)

        if created:
            print(f"[JIRA] Created {len(created)} issues: {', '.join(created)}")
        return True


# ─── Generic Webhook ──────────────────────────────────────────────────────────

class WebhookNotifier:
    """Generic HTTP webhook — envia payload JSON para qualquer endpoint."""

    def __init__(self, url: str, method: str = "POST",
                 headers: dict | None = None, min_severity: str = "HIGH"):
        self.url          = url
        self.method       = method.upper()
        self.headers      = headers or {}
        self.min_severity = min_severity

    async def send_findings_report(self, findings: list[dict], score: int, project: str = ".") -> bool:
        qualifying = [
            f for f in findings
            if _meets_severity(f.get("severity","LOW"), self.min_severity)
        ]
        if not qualifying:
            return True

        payload = {
            "source":             "qsec",
            "version":            "3.0.0",
            "timestamp":          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "project":            project,
            "quantum_risk_score": score,
            "total_findings":     len(findings),
            "by_severity": {
                "CRITICAL": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "HIGH":     sum(1 for f in findings if f.get("severity") == "HIGH"),
                "MEDIUM":   sum(1 for f in findings if f.get("severity") == "MEDIUM"),
                "LOW":      sum(1 for f in findings if f.get("severity") == "LOW"),
            },
            "findings": qualifying[:20],
        }
        return await self._send(payload)

    async def _send(self, payload: dict) -> bool:
        if not _HAS_HTTPX:
            print(f"[Webhook] Would POST to {self.url}: {json.dumps(payload)[:200]}")
            return True
        try:
            headers = {"Content-Type": "application/json", **self.headers}
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.request(self.method, self.url, headers=headers, json=payload)
                return resp.status_code < 400
        except Exception as e:
            print(f"[Webhook] Error: {e}")
            return False


# ─── EnterpriseNotifier ───────────────────────────────────────────────────────

class EnterpriseNotifier:
    """
    Fachada que orquestra todas as integrações enterprise.

    Inicializado com dict de config (normalmente de .qsec.toml via JSON).
    Suporta Slack, Teams, PagerDuty, JIRA e Generic Webhook.
    """

    def __init__(self, config: dict):
        self.notifiers: list[Any] = []

        if "slack" in config:
            c = config["slack"]
            self.notifiers.append(SlackNotifier(
                webhook_url  = c.get("webhook_url", ""),
                channel      = c.get("channel", "#security-alerts"),
                min_severity = c.get("min_severity", "HIGH"),
            ))

        if "teams" in config:
            c = config["teams"]
            self.notifiers.append(TeamsNotifier(
                webhook_url  = c.get("webhook_url", ""),
                min_severity = c.get("min_severity", "CRITICAL"),
            ))

        if "pagerduty" in config:
            c = config["pagerduty"]
            self.notifiers.append(PagerDutyNotifier(
                routing_key  = c.get("routing_key", ""),
                min_severity = c.get("min_severity", "CRITICAL"),
                service_name = c.get("service_name", "QSEC Security"),
            ))

        if "jira" in config:
            c = config["jira"]
            self.notifiers.append(JiraNotifier(
                url          = c.get("url", ""),
                project      = c.get("project", ""),
                token        = c.get("token", ""),
                email        = c.get("email", ""),
                issue_type   = c.get("issue_type", "Bug"),
                auto_create  = c.get("auto_create", True),
                min_severity = c.get("min_severity", "HIGH"),
            ))

        if "webhook" in config:
            c = config["webhook"]
            self.notifiers.append(WebhookNotifier(
                url          = c.get("url", ""),
                method       = c.get("method", "POST"),
                headers      = c.get("headers", {}),
                min_severity = c.get("min_severity", "HIGH"),
            ))

    async def notify_findings(
        self,
        findings: list[dict],
        quantum_risk_score: int = 0,
        project: str = ".",
    ) -> dict[str, bool]:
        """Envia para todas as integrações configuradas em paralelo."""
        if not self.notifiers:
            return {}

        tasks = [
            n.send_findings_report(findings, quantum_risk_score, project)
            for n in self.notifiers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            type(n).__name__: (r is True)
            for n, r in zip(self.notifiers, results)
        }

    async def notify_incident(self, incident_type: str, description: str,
                               severity: str = "CRITICAL") -> dict[str, bool]:
        """Notifica incidente via todos os canais suportados."""
        results = {}
        for notifier in self.notifiers:
            name = type(notifier).__name__
            try:
                if hasattr(notifier, "send_incident"):
                    ok = await notifier.send_incident(incident_type, description, severity)
                elif hasattr(notifier, "trigger"):
                    ok = await notifier.trigger(
                        summary  = f"[{severity}] {incident_type}: {description}",
                        severity = severity,
                    )
                else:
                    ok = await notifier._send({
                        "type": "incident", "severity": severity,
                        "incident_type": incident_type, "description": description,
                    })
                results[name] = ok
            except Exception as e:
                print(f"[{name}] notify_incident error: {e}")
                results[name] = False

        return results


# ─── CLI demo ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    async def demo():
        # Demonstra sem webhooks reais
        cfg = {
            "slack":     {"webhook_url": "https://demo.invalid/webhook", "channel": "#sec"},
            "pagerduty": {"routing_key": "demo-key"},
        }
        notifier = EnterpriseNotifier(cfg)
        findings = [
            {"severity": "CRITICAL", "rule_id": "QSC-001", "title": "RSA detected",
             "file": "src/auth.rs", "line": 42, "description": "...", "recommendation": "..."},
            {"severity": "HIGH", "rule_id": "QSC-010", "title": "MD5 hash",
             "file": "src/crypto.rs", "line": 17, "description": "...", "recommendation": "..."},
        ]
        results = await notifier.notify_findings(findings, quantum_risk_score=85, project="demo")
        print(f"Notification results: {results}")

    asyncio.run(demo())

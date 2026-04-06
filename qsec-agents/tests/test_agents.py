"""
Testes do sistema multi-agente QSEC.

Testa sem necessidade de API key real:
  - SharedMemory: estado compartilhado
  - Tools: execute_tool com modo simulação
  - AgentBus: roteamento de mensagens
  - Orchestrator: workflows completos (mock de agentes)
"""

import asyncio
import json
import sys
import os
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from memory.shared_memory import SharedMemory, IncidentStatus, TaskStatus
from tools.qsec_tools import execute_tool, _simulate_scan


# ════════════════════════════════════════════════════════════════════════════
# SHARED MEMORY
# ════════════════════════════════════════════════════════════════════════════

class TestSharedMemory(unittest.IsolatedAsyncioTestCase):

    async def test_initial_state(self):
        mem = SharedMemory()
        snap = await mem.snapshot()
        self.assertEqual(snap["total_findings"], 0)
        self.assertEqual(snap["active_incidents"], 0)
        self.assertEqual(snap["pending_tasks"], 0)

    async def test_add_findings(self):
        mem = SharedMemory()
        findings = [
            {"severity": "CRITICAL", "rule_id": "QSC-001", "title": "RSA"},
            {"severity": "HIGH",     "rule_id": "QSC-010", "title": "MD5"},
        ]
        await mem.add_findings(findings, "./src", "ScannerAgent")

        self.assertEqual(len(mem.findings), 2)
        self.assertEqual(mem.system_status["total_findings"], 2)
        self.assertIsNotNone(mem.system_status["last_scan_at"])

    async def test_findings_by_severity(self):
        mem = SharedMemory()
        findings = [
            {"severity": "CRITICAL", "rule_id": "QSC-001"},
            {"severity": "CRITICAL", "rule_id": "QSC-002"},
            {"severity": "HIGH",     "rule_id": "QSC-010"},
        ]
        await mem.add_findings(findings, ".", "test")
        crits = await mem.get_findings_by_severity("CRITICAL")
        self.assertEqual(len(crits), 2)

    async def test_open_and_resolve_incident(self):
        mem = SharedMemory()
        inc = await mem.open_incident(
            title="Test Incident",
            description="RSA key compromised",
            severity="CRITICAL",
            agent="IncidentAgent",
        )
        self.assertTrue(inc.id.startswith("INC-"))
        self.assertEqual(inc.status, IncidentStatus.OPEN)
        snap = await mem.snapshot()
        self.assertEqual(snap["active_incidents"], 1)

        resolved = await mem.resolve_incident(inc.id, "Key rotated, tokens revoked")
        self.assertTrue(resolved)
        snap2 = await mem.snapshot()
        self.assertEqual(snap2["active_incidents"], 0)

    async def test_incident_not_found(self):
        mem = SharedMemory()
        result = await mem.resolve_incident("INC-NOTEXIST", "resolution")
        self.assertFalse(result)

    async def test_task_enqueue_and_complete(self):
        mem = SharedMemory()
        task = await mem.enqueue_task("scan", {"path": "./src"}, "Orchestrator")

        self.assertTrue(task.id.startswith("TASK-"))
        self.assertEqual(task.status, TaskStatus.PENDING)

        snap = await mem.snapshot()
        self.assertEqual(snap["pending_tasks"], 1)

        next_task = await mem.next_task(timeout=0.1)
        self.assertIsNotNone(next_task)
        self.assertEqual(next_task.id, task.id)

        await mem.complete_task(task.id, {"findings": 5})
        self.assertEqual(mem.tasks[task.id].status, TaskStatus.DONE)

    async def test_task_failure(self):
        mem = SharedMemory()
        task = await mem.enqueue_task("scan", {}, "test")
        await mem.next_task(timeout=0.1)
        await mem.fail_task(task.id, "Connection refused")
        self.assertEqual(mem.tasks[task.id].status, TaskStatus.FAILED)
        self.assertEqual(mem.tasks[task.id].error, "Connection refused")

    async def test_agent_log(self):
        mem = SharedMemory()
        await mem.log_action("ScannerAgent", "scan_started", {"path": "./src"})
        await mem.log_action("AnalysisAgent", "analysis_complete", {})
        self.assertEqual(len(mem.agent_log), 2)
        self.assertEqual(mem.agent_log[0]["agent"], "ScannerAgent")

    async def test_token_revocation(self):
        mem = SharedMemory()
        await mem.revoke_token("jti-12345")
        await mem.revoke_token("jti-67890")
        snap = await mem.snapshot()
        self.assertEqual(snap["revoked_tokens"], 2)
        self.assertIn("jti-12345", mem.revoked_tokens)

    async def test_patch_lifecycle(self):
        mem = SharedMemory()
        await mem.add_patch({
            "file_path": "src/crypto.rs",
            "rule_id":   "QSC-010",
            "finding":   {"severity": "HIGH"},
        })
        snap = await mem.snapshot()
        self.assertEqual(snap["pending_patches"], 1)

        await mem.mark_patch_applied("src/crypto.rs", "QSC-010")
        self.assertEqual(mem.system_status["patches_applied"], 1)

    async def test_unpatched_findings(self):
        mem = SharedMemory()
        await mem.add_findings([
            {"severity": "HIGH", "rule_id": "QSC-010"},
            {"severity": "CRITICAL", "rule_id": "QSC-001"},
        ], ".", "test")
        await mem.add_patch({"file_path": "f.rs", "rule_id": "QSC-010", "status": "applied"})
        await mem.mark_patch_applied("f.rs", "QSC-010")
        unpatched = await mem.get_unpatched_findings()
        self.assertTrue(len(unpatched) >= 1)

    async def test_monitored_paths(self):
        mem = SharedMemory()
        mem.monitored_paths.add("./src")
        mem.monitored_paths.add("./lib")
        snap = await mem.snapshot()
        self.assertIn("./src", snap["monitored_paths"])

    async def test_save_to_disk(self):
        import tempfile
        mem = SharedMemory()
        await mem.add_findings([{"severity": "HIGH", "rule_id": "QSC-001"}], ".", "test")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        mem.save_to_disk(path)
        data = json.loads(path.read_text())
        self.assertIn("findings", data)
        self.assertIn("system_status", data)
        path.unlink()

    async def test_concurrent_access(self):
        """Testa que operações concorrentes não corrompem o estado."""
        mem = SharedMemory()
        tasks = [
            mem.add_findings([{"severity": "HIGH", "rule_id": f"QSC-{i:03d}"}], ".", "test")
            for i in range(10)
        ]
        await asyncio.gather(*tasks)
        self.assertEqual(mem.system_status["total_findings"], 10)


# ════════════════════════════════════════════════════════════════════════════
# TOOLS
# ════════════════════════════════════════════════════════════════════════════

class TestQsecTools(unittest.TestCase):

    def test_simulate_scan_returns_findings(self):
        findings = _simulate_scan("./src")
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn("severity",  f)
            self.assertIn("rule_id",   f)
            self.assertIn("file",      f)
            self.assertIn("title",     f)

    def test_simulate_scan_has_critical_findings(self):
        findings = _simulate_scan("./src")
        severities = {f["severity"] for f in findings}
        self.assertIn("CRITICAL", severities)

    def test_tool_scan_codebase(self):
        result = execute_tool("scan_codebase", {"path": "./src"})
        self.assertIn("findings",       result)
        self.assertIn("total_findings", result)
        self.assertIn("by_severity",    result)
        self.assertIn("has_critical",   result)

    def test_tool_scan_counts_by_severity(self):
        result = execute_tool("scan_codebase", {"path": "./src"})
        by_sev = result["by_severity"]
        self.assertIn("CRITICAL", by_sev)
        self.assertIn("HIGH",     by_sev)
        self.assertIn("MEDIUM",   by_sev)
        self.assertIn("LOW",      by_sev)

    def test_tool_engine_info(self):
        result = execute_tool("get_engine_info", {})
        self.assertIn("pqc_engine", result)
        pqc = result["pqc_engine"]
        self.assertIn("kem_algorithm", pqc)
        self.assertIn("dsa_algorithm", pqc)
        self.assertTrue(pqc.get("harvest_now_decrypt_later_protection"))

    def test_tool_generate_sbom(self):
        result = execute_tool("generate_sbom", {"project_path": "."})
        self.assertIn("components", result)
        self.assertIsInstance(result["components"], list)

    def test_tool_remediation_patch_md5(self):
        result = execute_tool("generate_remediation_patch", {
            "file_path":    "src/hash.rs",
            "rule_id":      "QSC-010",
            "code_snippet": "let h = Md5::new();",
            "line_number":  10,
        })
        self.assertIn("patch",         result)
        self.assertIn("ready_to_apply", result)
        self.assertTrue(result["ready_to_apply"])
        self.assertIn("Sha3_256", result["patch"]["after"])

    def test_tool_remediation_patch_sha1(self):
        result = execute_tool("generate_remediation_patch", {
            "file_path":    "src/hash.rs",
            "rule_id":      "QSC-011",
            "code_snippet": "let h = Sha1::new();",
        })
        self.assertTrue(result["ready_to_apply"])
        self.assertIn("SHA3", result["patch"]["explanation"])

    def test_tool_remediation_patch_rsa(self):
        result = execute_tool("generate_remediation_patch", {
            "file_path":    "src/crypto.rs",
            "rule_id":      "QSC-001",
            "code_snippet": "let k = RSA::generate(2048);",
        })
        self.assertTrue(result["ready_to_apply"])
        self.assertIn("ML-KEM", result["patch"]["explanation"])

    def test_tool_remediation_patch_jwt_none(self):
        result = execute_tool("generate_remediation_patch", {
            "file_path":    "src/auth.rs",
            "rule_id":      "QSC-020",
            'code_snippet': 'algorithm: "none"',
        })
        self.assertTrue(result["ready_to_apply"])
        self.assertIn("ML-DSA", result["patch"]["after"])

    def test_tool_remediation_patch_hardcoded(self):
        result = execute_tool("generate_remediation_patch", {
            "file_path":    "src/secrets.rs",
            "rule_id":      "QSC-030",
            "code_snippet": 'let key = "supersecret";',
        })
        self.assertTrue(result["ready_to_apply"])
        self.assertIn("env", result["patch"]["after"].lower())

    def test_tool_remediation_unknown_rule(self):
        result = execute_tool("generate_remediation_patch", {
            "file_path": "f.rs", "rule_id": "QSC-999", "code_snippet": "x"
        })
        self.assertFalse(result["ready_to_apply"])

    def test_tool_send_alert_info(self):
        result = execute_tool("send_alert", {
            "severity": "INFO",
            "title":    "Test",
            "message":  "Test alert",
        })
        self.assertTrue(result["sent"])
        self.assertIn("timestamp", result)

    def test_tool_send_alert_critical(self):
        result = execute_tool("send_alert", {
            "severity": "CRITICAL",
            "title":    "Key Compromised",
            "message":  "Rotate immediately",
            "details":  {"key_id": "abc123"},
        })
        self.assertTrue(result["sent"])

    def test_tool_read_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False) as f:
            f.write("fn main() { println!(\"hello\"); }\n" * 5)
            path = f.name
        result = execute_tool("read_file_content", {"file_path": path, "max_lines": 3})
        self.assertIn("content",     result)
        self.assertIn("total_lines", result)
        self.assertEqual(result["total_lines"], 5)
        self.assertTrue(result["truncated"])
        Path(path).unlink()

    def test_tool_read_nonexistent_file(self):
        result = execute_tool("read_file_content", {"file_path": "/nonexistent/file.rs"})
        self.assertIn("error", result)

    def test_tool_write_file_with_backup(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False) as f:
            f.write("original content")
            path = f.name
        result = execute_tool("write_file", {
            "file_path": path,
            "content":   "new content",
            "create_backup": True,
        })
        self.assertTrue(result["written"])
        self.assertEqual(Path(path).read_text(), "new content")
        backup = Path(path + ".bak")
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_text(), "original content")
        Path(path).unlink(); backup.unlink()

    def test_tool_unknown(self):
        result = execute_tool("nonexistent_tool", {})
        self.assertIn("error", result)

    def test_all_tools_have_required_fields(self):
        from tools.qsec_tools import QSEC_TOOLS
        for tool in QSEC_TOOLS:
            self.assertIn("name",          tool, f"{tool.get('name')} missing 'name'")
            self.assertIn("description",   tool, f"{tool.get('name')} missing 'description'")
            self.assertIn("input_schema",  tool, f"{tool.get('name')} missing 'input_schema'")
            schema = tool["input_schema"]
            self.assertIn("type",          schema)
            self.assertIn("properties",    schema)


# ════════════════════════════════════════════════════════════════════════════
# AGENT BUS
# ════════════════════════════════════════════════════════════════════════════

class TestAgentBus(unittest.IsolatedAsyncioTestCase):

    async def test_publish_and_dispatch(self):
        from orchestrator import AgentBus
        bus = AgentBus()
        received = []

        async def handler(msg):
            received.append(msg)

        bus.subscribe("test_topic", handler)
        await bus.publish("test_topic", {"key": "value"})
        dispatched = await bus.dispatch_pending()

        self.assertEqual(dispatched, 1)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["key"], "value")

    async def test_no_subscribers(self):
        from orchestrator import AgentBus
        bus = AgentBus()
        await bus.publish("orphan_topic", {"data": 1})
        dispatched = await bus.dispatch_pending()
        self.assertEqual(dispatched, 1)  # dispatched mas sem handler

    async def test_multiple_subscribers(self):
        from orchestrator import AgentBus
        bus = AgentBus()
        received_a, received_b = [], []

        async def handler_a(msg): received_a.append(msg)
        async def handler_b(msg): received_b.append(msg)

        bus.subscribe("topic", handler_a)
        bus.subscribe("topic", handler_b)
        await bus.publish("topic", {"x": 1})
        await bus.dispatch_pending()

        self.assertEqual(len(received_a), 1)
        self.assertEqual(len(received_b), 1)

    async def test_empty_queue(self):
        from orchestrator import AgentBus
        bus = AgentBus()
        count = await bus.dispatch_pending()
        self.assertEqual(count, 0)


# ════════════════════════════════════════════════════════════════════════════
# MONITORING AGENT (sem API)
# ════════════════════════════════════════════════════════════════════════════

class TestMonitoringAgent(unittest.IsolatedAsyncioTestCase):

    async def test_snapshot_directory(self):
        import tempfile
        mem   = SharedMemory()
        from agents.monitoring_agent import MonitoringAgent
        agent = MonitoringAgent(mem)

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.rs").write_text("fn main() {}")
            agent._snapshot_directory(tmpdir)
            self.assertTrue(len(agent._file_hashes) > 0)

    async def test_detect_no_changes(self):
        import tempfile
        mem   = SharedMemory()
        from agents.monitoring_agent import MonitoringAgent
        agent = MonitoringAgent(mem)

        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.rs"
            f.write_text("fn main() {}")
            agent._snapshot_directory(tmpdir)
            changed = agent._detect_changes(tmpdir)
            self.assertEqual(len(changed), 0)

    async def test_detect_changes(self):
        import tempfile
        mem   = SharedMemory()
        from agents.monitoring_agent import MonitoringAgent
        agent = MonitoringAgent(mem)

        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.rs"
            f.write_text("fn main() {}")
            agent._snapshot_directory(tmpdir)

            # Modifica o arquivo
            f.write_text("fn main() { /* CHANGED */ }")
            changed = agent._detect_changes(tmpdir)
            self.assertIn(str(f), changed)

    async def test_add_watch_path(self):
        import tempfile
        mem   = SharedMemory()
        from agents.monitoring_agent import MonitoringAgent
        agent = MonitoringAgent(mem)

        with tempfile.TemporaryDirectory() as tmpdir:
            agent.add_watch_path(tmpdir)
            self.assertIn(tmpdir, agent._watch_paths)
            self.assertIn(tmpdir, mem.monitored_paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)

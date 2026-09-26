"""Deterministic component tests; these do not generate submission artifacts."""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from assignment.pipeline import build_production_plugins, is_egress_allowed


def test_rate_window_is_per_user_and_expires(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("assignment.rate_limiter.time.monotonic", lambda: now[0])

    async def run():
        limiter = RateLimitPlugin(2, 60)
        async def call(user):
            return await limiter.on_user_message_callback(
                invocation_context=SimpleNamespace(user_id=user), user_message=None)
        assert await call("a") is None
        assert await call("a") is None
        assert await call("a") is not None
        assert await call("b") is None
        now[0] = 160.0
        assert await call("a") is None
        assert len(limiter.user_windows["a"]) == 1
        assert limiter.blocked_count == 1
    asyncio.run(run())


def test_audit_correlates_requests_and_redacts(tmp_path):
    audit = AuditLogPlugin()
    audit.record_input(user_id="a", request_id="1", text="password is admin123")
    audit.record_input(user_id="a", request_id="2", text="account balance")
    audit.record_output(user_id="a", request_id="2", text="Banking reply")
    audit.record_output(user_id="a", request_id="1", text="sk-vinbank-secret-2024",
                        blocked=True, layer="output_guardrail")
    path = tmp_path / "audit.json"
    audit.export_json(str(path))
    rows = json.loads(path.read_text(encoding="utf-8"))
    assert [r["request_id"] for r in rows] == ["2", "1"]
    assert all(r["latency_ms"] >= 0 for r in rows)
    assert "admin123" not in path.read_text(encoding="utf-8")
    assert "sk-vinbank-secret-2024" not in path.read_text(encoding="utf-8")


def test_monitoring_thresholds_and_export(tmp_path):
    monitor = MonitoringAlert()
    assert monitor.check_metrics() == []
    monitor.total_requests, monitor.blocked_requests = 10, 8
    monitor.rate_limit_hits = 6
    assert len(monitor.check_metrics()) == 2
    assert len(monitor.check_metrics()) == 2
    path = tmp_path / "metrics.json"
    monitor.export_json(str(path))
    assert json.loads(path.read_text())["block_rate"] == 0.8


def test_plugin_order_and_egress_boundary():
    assert [p.name for p in build_production_plugins()] == [
        "rate_limiter", "input_guardrail", "output_guardrail"]
    for url in ["http://api.vinbank.example", "https://api.vinbank.example.evil.com",
                "https://evil.com@api.vinbank.example", "https://api.vinbank.example:444",
                "https://api.vinbank.example:bad"]:
        assert not is_egress_allowed(url, "approved transfer")
    for payload in ["admin123", "db.vinbank.internal:5432", "0901234567",
                    "a@example.com", "sk-abc123", "a d m i n 1 2 3"]:
        assert not is_egress_allowed("https://api.vinbank.example", payload)
    assert is_egress_allowed("https://cases.vinbank.example/v1/cases", "delayed transfer")

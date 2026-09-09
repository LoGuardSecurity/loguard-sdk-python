"""
LoGuard SDK v2 — unit tests
Run: pytest tests/ -v
Live tests: LOGUARD_API_KEY=lg_... LOGUARD_BASE_URL=http://... pytest -v -k Live
"""
from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from loguard import (
    AlertCondition,
    AlertRule,
    LoGuardAuthError,
    LoGuardNotInitializedError,
    LoGuardValidationError,
    monitor,
)
from loguard.monitor import _Monitor


# Fixtures
@pytest.fixture(autouse=True)
def fresh_monitor():
    """Give each test a fresh monitor instance."""
    m = _Monitor()
    yield m


def make_ingest_resp(inserted=1):
    return {
        "ok": True,
        "inserted": inserted,
        "dropped": 0,
        "alerts_fired": 0,
        "alerts": [],
        "plan": "free",
        "usage": {"used": 1, "limit": 1000, "month": "2025-03"},
    }


# Init
def test_init_sets_initialized(fresh_monitor):
    fresh_monitor.init(api_key="lg_test_key")
    assert fresh_monitor.is_initialized


def test_init_requires_api_key(fresh_monitor):
    with pytest.raises(LoGuardAuthError):
        fresh_monitor.init(api_key="")


def test_not_initialized_raises(fresh_monitor):
    with pytest.raises(LoGuardNotInitializedError):
        fresh_monitor.event(type="test", ip="1.2.3.4", path="/", status_code=200)


# Event building
def test_build_event_normalizes_path(fresh_monitor):
    fresh_monitor.init(api_key="lg_test")
    ev = fresh_monitor._build_event(
        type="login_failed", ip="1.2.3.4", path="login", status_code=401
    )
    assert ev.path.startswith("/")


def test_build_event_validates_status_code(fresh_monitor):
    fresh_monitor.init(api_key="lg_test")
    with pytest.raises(LoGuardValidationError):
        fresh_monitor._build_event(type="t", ip="1.2.3.4", path="/", status_code=99)


def test_build_event_requires_type(fresh_monitor):
    fresh_monitor.init(api_key="lg_test")
    with pytest.raises(LoGuardValidationError):
        fresh_monitor._build_event(type="", ip="1.2.3.4", path="/", status_code=200)


def test_build_event_injects_env(fresh_monitor):
    fresh_monitor.init(api_key="lg_test", env="staging")
    ev = fresh_monitor._build_event(type="t", ip="1.2.3.4", path="/", status_code=200)
    assert ev.meta["env"] == "staging"


# Ingest: sync
def test_event_sync_success(fresh_monitor):
    fresh_monitor.init(api_key="lg_test")
    resp_data = make_ingest_resp()

    with patch("loguard._transport.httpx.Client") as mock_cls:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = resp_data
        mock_resp.text = json.dumps(resp_data)
        mock_cls.return_value.__enter__.return_value.post.return_value = mock_resp

        result = fresh_monitor.event(type="login_failed", ip="1.2.3.4", path="/login", status_code=401)

    assert result.ok is True
    assert result.inserted == 1


def test_event_fire_and_forget_does_not_raise(fresh_monitor):
    fresh_monitor.init(api_key="lg_test")
    # Should not raise even if queue is full
    fresh_monitor.event_fire_and_forget(type="t", ip="1.2.3.4", path="/", status_code=200)


# Ingest: async
@pytest.mark.asyncio
async def test_aevent_success(fresh_monitor):
    fresh_monitor.init(api_key="lg_test")
    resp_data = make_ingest_resp()

    with patch("loguard._transport.httpx.AsyncClient") as mock_cls:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = resp_data
        mock_resp.text = json.dumps(resp_data)
        mock_cls.return_value.__aenter__.return_value.post = AsyncMock(
            return_value=mock_resp
        )

        result = await fresh_monitor.aevent(
            type="http_error", ip="1.2.3.4", path="/api", status_code=500
        )

    assert result.ok is True


# AlertRule models
def test_alert_condition_to_dict():
    c = AlertCondition(field="status_code", op="gte", value=400)
    d = c.to_dict()
    assert d == {"field": "status_code", "op": "gte", "value": 400}


def test_alert_condition_from_dict_roundtrip():
    c = AlertCondition(field="ip", op="eq", value="1.2.3.4")
    c2 = AlertCondition.from_dict(c.to_dict())
    assert c2.field == "ip"
    assert c2.value == "1.2.3.4"


def test_alert_rule_to_dict():
    rule = AlertRule(
        name="Test",
        conditions=[AlertCondition(field="type", op="eq", value="login_failed")],
        severity="high",
        actions=["notify"],
    )
    d = rule.to_dict()
    assert d["name"] == "Test"
    assert d["severity"] == "high"
    assert len(d["conditions"]) == 1


def test_alert_rule_from_dict():
    d = {
        "id": 42,
        "name": "Brute Force",
        "conditions": [{"field": "rate_per_minute", "op": "gt", "value": 10}],
        "severity": "critical",
        "actions": ["notify", "block"],
        "enabled": True,
        "logic": "and",
        "cooldown_sec": 30,
        "created_at": "2025-01-01T00:00:00Z",
    }
    rule = AlertRule.from_dict(d)
    assert rule.id == 42
    assert rule.severity == "critical"
    assert len(rule.conditions) == 1
    assert rule.conditions[0].value == 10




# Alerts client: mock
def test_alerts_create_mock(fresh_monitor):
    fresh_monitor.init(api_key="lg_test")
    server_resp = {
        "id": 1, "name": "Test Rule",
        "conditions": [{"field": "status_code", "op": "gte", "value": 400}],
        "severity": "medium", "actions": ["notify"],
        "enabled": True, "logic": "and", "cooldown_sec": 60,
    }

    with patch("loguard._transport.httpx.Client") as mock_cls:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = server_resp
        mock_resp.text = json.dumps(server_resp)
        mock_cls.return_value.__enter__.return_value.post.return_value = mock_resp

        rule = fresh_monitor.alerts.create(AlertRule(
            name="Test Rule",
            conditions=[AlertCondition(field="status_code", op="gte", value=400)],
        ))

    assert rule.id == 1
    assert rule.name == "Test Rule"


# Live tests (skipped unless env vars set)
class TestLive:
    """Live integration tests — require real server."""

    @pytest.fixture(autouse=True)
    def skip_without_key(self):
        if not os.getenv("LOGGUARD_API_KEY"):
            pytest.skip("LOGGUARD_API_KEY not set")

    @pytest.fixture(autouse=True)
    def live_monitor(self, skip_without_key):
        from loguard.monitor import _Monitor
        m = _Monitor()
        m.init(
            api_key=os.environ["LOGGUARD_API_KEY"],
            base_url=os.getenv("LOGGUARD_BASE_URL", "https://api.logguard.io"),
        )
        return m

    def test_live_event(self, live_monitor):
        result = live_monitor.event(
            type="login_failed", ip="1.2.3.4", path="/login", status_code=401
        )
        assert result.ok

    def test_live_alert_rule_crud(self, live_monitor):
        rule = live_monitor.alerts.create(AlertRule(
            name="SDK Test Rule",
            conditions=[AlertCondition(field="status_code", op="gte", value=400)],
            severity="low",
        ))
        assert rule.id is not None

        rules = live_monitor.alerts.list()
        assert any(r.id == rule.id for r in rules)

        rule.description = "updated"
        updated = live_monitor.alerts.update(rule)
        assert updated.description == "updated"

        live_monitor.alerts.delete(rule.id)

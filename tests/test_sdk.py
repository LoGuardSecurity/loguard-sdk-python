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

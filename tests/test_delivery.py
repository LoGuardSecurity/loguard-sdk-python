"""Background delivery fences, limits and lifecycle without external network."""

import asyncio
from contextvars import ContextVar
import json
import threading
import time
from unittest.mock import Mock

import pytest

from loguard.exceptions import LoGuardNotInitializedError, LoGuardValidationError
from loguard.monitor import _Monitor


def event(monitor, path="/"):
    monitor.event_fire_and_forget(
        type="http_request", ip="192.0.2.1", path=path, status_code=200
    )


@pytest.fixture
def delivery(monkeypatch):
    monitor = _Monitor()
    batches = []
    monkeypatch.setattr(
        monitor, "_send_events_sync", lambda batch: batches.append(list(batch))
    )
    monitor.init(api_key="test-local-key", env="tests")
    yield monitor, batches
    assert monitor.shutdown(3), "test worker did not finish"


def test_flush_and_shutdown_are_idempotent(delivery):
    monitor, batches = delivery
    for i in range(75):
        event(monitor, f"/{i}")
    assert monitor.flush(2)
    assert [ev.path for batch in batches for ev in batch] == [
        f"/{i}" for i in range(75)
    ]
    assert all(len(batch) <= 50 for batch in batches)
    assert monitor.delivery_stats["pending"] == 0
    assert monitor.shutdown(2)
    assert monitor.shutdown(0)
    event(monitor, "/after-stop")
    assert monitor.delivery_stats["dropped"] == 1
    assert "test-local-key" not in json.dumps(monitor.delivery_stats)


def test_timeout_does_not_block_or_cancel_inflight_delivery(delivery, monkeypatch):
    monitor, _ = delivery
    entered, release = threading.Event(), threading.Event()

    def sender(batch):
        entered.set()
        assert release.wait(3)

    monkeypatch.setattr(monitor, "_send_events_sync", sender)
    event(monitor)
    assert monitor.flush(0) is False
    assert entered.wait(2)
    try:
        started = time.monotonic()
        assert monitor.shutdown(0.02) is False
        assert time.monotonic() - started < 0.5
        assert monitor.delivery_stats["pending"] == 1
        with pytest.raises(LoGuardValidationError, match="draining"):
            monitor.init(api_key="other-key")
    finally:
        release.set()
    assert monitor.shutdown(2)


def test_overflow_drops_newest_and_keeps_queue_bounded(delivery, monkeypatch):
    monitor, _ = delivery
    entered, release = threading.Event(), threading.Event()

    def sender(batch):
        entered.set()
        assert release.wait(4)

    monkeypatch.setattr(monitor, "_send_events_sync", sender)
    event(monitor)
    monitor.flush(0)
    assert entered.wait(2)
    try:
        for i in range(3000):
            event(monitor, f"/{i}")
        stats = monitor.delivery_stats
        assert stats["queued"] == 2000
        assert stats["accepted"] == 2001
        assert stats["dropped"] == 1000
    finally:
        release.set()
    assert monitor.shutdown(3)
    assert monitor.delivery_stats["completed"] == 2001


def test_non_sdk_sender_failure_does_not_kill_worker(delivery, monkeypatch, caplog):
    monitor, batches = delivery

    def fail(batch):
        raise RuntimeError("secret-response-must-not-be-logged")

    monkeypatch.setattr(monitor, "_send_events_sync", fail)
    event(monitor)
    assert monitor.flush(2)
    assert monitor.delivery_stats["failed_batches"] == 1
    assert monitor.delivery_stats["worker_alive"]
    monkeypatch.setattr(
        monitor, "_send_events_sync", lambda batch: batches.append(list(batch))
    )
    event(monitor, "/recovered")
    assert monitor.flush(2)
    assert batches[-1][0].path == "/recovered"
    assert "secret-response" not in caplog.text


def test_many_producers_use_one_worker_and_finish(delivery, monkeypatch):
    monitor, batches = delivery
    worker_ids = set()

    def sender(batch):
        worker_ids.add(threading.get_ident())
        batches.append(list(batch))

    monkeypatch.setattr(monitor, "_send_events_sync", sender)
    producers = [
        threading.Thread(
            target=lambda n=n: [event(monitor, f"/{n}/{i}") for i in range(80)]
        )
        for n in range(8)
    ]
    for producer in producers:
        producer.start()
    for producer in producers:
        producer.join(2)
        assert not producer.is_alive()
    assert monitor.flush(3)
    assert len({ev.path for batch in batches for ev in batch}) == 640
    assert len(worker_ids) == 1


def test_flush_uses_an_event_fence_not_future_producers(delivery, monkeypatch):
    monitor, _ = delivery
    entered, release_first, release_later = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    waiting, flushed = threading.Event(), threading.Event()
    result = []

    def sender(batch):
        if batch[0].path == "/first":
            entered.set()
            assert release_first.wait(4)
        else:
            assert release_later.wait(4)

    monkeypatch.setattr(monitor, "_send_events_sync", sender)
    original_wait = monitor._faf_condition.wait

    def observed_wait(timeout):
        waiting.set()
        return original_wait(timeout)

    monkeypatch.setattr(monitor._faf_condition, "wait", observed_wait)
    event(monitor, "/first")
    monitor.flush(0)
    assert entered.wait(2)

    def flush():
        result.append(monitor.flush(2))
        flushed.set()

    thread = threading.Thread(target=flush)
    thread.start()
    try:
        assert waiting.wait(1)
        event(monitor, "/later")
        release_first.set()
        assert flushed.wait(1)
        assert result == [True]
    finally:
        release_first.set()
        release_later.set()
        thread.join(3)


def test_worker_does_not_inherit_request_context():
    context = ContextVar("request_context", default=None)
    token = context.set("request-secret")
    monitor = _Monitor()
    seen = []
    monitor._send_events_sync = lambda batch: seen.append(context.get())
    try:
        monitor.init(api_key="test")
        event(monitor)
        assert monitor.flush(2)
        assert seen == [None]
    finally:
        context.reset(token)
        assert monitor.shutdown(2)


def test_reinitialization_requires_shutdown(delivery):
    monitor, _ = delivery
    worker = monitor._faf_thread
    monitor.init(api_key="test-local-key", env="tests")
    assert monitor._faf_thread is worker
    with pytest.raises(LoGuardValidationError, match="shutdown"):
        monitor.init(api_key="different-project")
    assert monitor.shutdown(2)
    monitor.init(api_key="different-project")
    event(monitor)
    assert monitor.flush(2)


def test_reconfiguration_drops_a_stale_enqueue(delivery, monkeypatch):
    monitor, batches = delivery
    original = monitor._build_event
    entered, release = threading.Event(), threading.Event()

    def build(**kwargs):
        built = original(**kwargs)
        entered.set()
        assert release.wait(3)
        return built

    monkeypatch.setattr(monitor, "_build_event", build)
    thread = threading.Thread(target=lambda: event(monitor, "/old-project"))
    thread.start()
    try:
        assert entered.wait(1)
        assert monitor.shutdown(2)
        monitor.init(api_key="different-project")
    finally:
        release.set()
        thread.join(2)
    assert monitor.flush(2)
    assert monitor.delivery_stats["dropped"] == 1
    assert batches == []


def test_worker_can_request_shutdown_without_joining_itself(delivery, monkeypatch):
    monitor, _ = delivery
    results = []
    monkeypatch.setattr(
        monitor, "_send_events_sync", lambda batch: results.append(monitor.shutdown(0))
    )
    event(monitor)
    assert monitor.flush(2)
    assert monitor.shutdown(2)
    assert results == [False]


@pytest.mark.asyncio
async def test_async_flush_does_not_block_event_loop(delivery, monkeypatch):
    monitor, _ = delivery
    entered, release = threading.Event(), threading.Event()

    def sender(batch):
        entered.set()
        assert release.wait(3)

    monkeypatch.setattr(monitor, "_send_events_sync", sender)
    event(monitor)
    monitor.flush(0)
    assert await asyncio.to_thread(entered.wait, 2)
    flushing = asyncio.create_task(monitor.aflush(0.1))

    async def heartbeat():
        await asyncio.sleep(0.01)
        return not flushing.done()

    try:
        drained, responsive = await asyncio.gather(flushing, heartbeat())
        assert drained is False and responsive is True
    finally:
        release.set()
    assert await monitor.ashutdown(2)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": float("nan")},
        {"timeout": float("inf")},
        {"timeout": True},
        {"retries": 0},
        {"retries": True},
        {"retries": 1.5},
    ],
)
def test_invalid_transport_limits_rejected_before_thread_start(kwargs):
    monitor = _Monitor()
    with pytest.raises(LoGuardValidationError):
        monitor.init(api_key="test", **kwargs)
    assert monitor._faf_thread is None


@pytest.mark.parametrize(
    "timeout",
    [
        -1,
        float("inf"),
        float("nan"),
        True,
        None,
        threading.TIMEOUT_MAX * 2,
        pytest.param(1 << 100000, id="overflowing-number"),
    ],
)
def test_invalid_lifecycle_timeout_is_rejected(timeout):
    monitor = _Monitor()
    with pytest.raises(LoGuardValidationError):
        monitor.flush(timeout)
    with pytest.raises(LoGuardValidationError):
        monitor.shutdown(timeout)


def test_inherited_monitor_requires_child_initialization():
    monitor = _Monitor()
    monitor._owner_pid = -1
    monitor._initialized = True

    class InheritedLock:
        def __enter__(self):
            raise AssertionError("inherited lock acquired")

    monitor._faf_condition = InheritedLock()
    event(monitor)
    assert not monitor.is_initialized
    assert not monitor.flush(0)
    assert not monitor.shutdown(0)
    assert monitor.delivery_stats["forked"]
    with pytest.raises(LoGuardNotInitializedError):
        monitor.event(type="test", ip="192.0.2.1", path="/", status_code=200)
    monitor._send_events_sync = Mock()
    monitor.init(api_key="child-key")
    try:
        event(monitor)
        assert monitor.flush(2)
        assert not monitor.delivery_stats["forked"]
    finally:
        assert monitor.shutdown(2)


def test_uninitialized_background_calls_are_fail_open():
    monitor = _Monitor()
    event(monitor)
    assert monitor.flush(0)
    assert monitor.shutdown(0)


def test_debug_does_not_configure_application_root_logger():
    import logging

    root = logging.getLogger()
    sdk_log = logging.getLogger("loguard")
    original_level = sdk_log.level
    root_level, root_handlers = root.level, list(root.handlers)
    monitor = _Monitor()
    monitor._send_events_sync = Mock()
    try:
        monitor.init(api_key="test", debug=True)
        assert root.level == root_level
        assert root.handlers == root_handlers
    finally:
        monitor.shutdown(2)
        sdk_log.setLevel(original_level)


def test_thread_start_failure_leaves_monitor_retryable(monkeypatch):
    monitor = _Monitor()
    original_start = threading.Thread.start

    def fail_start(self):
        raise RuntimeError("thread allocation failed")

    with monkeypatch.context() as patcher:
        patcher.setattr(threading.Thread, "start", fail_start)
        with pytest.raises(RuntimeError, match="thread allocation"):
            monitor.init(api_key="test-local-key")
        assert not monitor.is_initialized
        assert monitor._faf_thread is None
        assert not monitor.delivery_stats["accepting"]

    assert threading.Thread.start is original_start
    monitor.init(api_key="test-local-key")
    assert monitor.is_initialized
    assert monitor.shutdown(2)

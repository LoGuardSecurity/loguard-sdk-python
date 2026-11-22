from __future__ import annotations

import asyncio
import logging
import math
import os
from contextvars import Context
import queue
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import _transport as _t
from ._version import __version__
from .exceptions import (
    LoGuardAuthError,
    LoGuardNotInitializedError,
    LoGuardValidationError,
)
from .models import (
    Event,
    IngestResult,
)

log = logging.getLogger("loguard")

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_RETRIES = 3
_DEFAULT_BASE_URL = "https://loguard.org"

_FAF_FLUSH_INTERVAL = 0.25
_FAF_MAX_BATCH = 50
_FAF_QUEUE_MAX = 2000


class _Monitor:
    """
    Global LoGuard monitor singleton.

    Usage:
        from loguard import monitor

        monitor.init(api_key="lg_live_xxx", env="production")

        # Track an event
        monitor.event(type="login_failed", ip="1.2.3.4", path="/login", status_code=401)
    """

    def __init__(self):
        self._api_key: Optional[str] = None
        self._base_url: str = _DEFAULT_BASE_URL
        self._env: str = "production"
        self._timeout: float = _DEFAULT_TIMEOUT
        self._retries: int = _DEFAULT_RETRIES
        self._initialized: bool = False

        self._default_service: Optional[str] = None
        self._configuration: Optional[tuple] = None
        self._reset_delivery_state()

    def _reset_delivery_state(self) -> None:
        # Forked children must not acquire locks or reuse queues inherited
        # from a process whose worker threads no longer exist there.
        self._owner_pid = os.getpid()
        self._faf_q: queue.Queue[Event] = queue.Queue(maxsize=_FAF_QUEUE_MAX)
        self._faf_thread: Optional[threading.Thread] = None
        self._faf_stop = threading.Event()
        self._faf_flush_requested = threading.Event()
        self._faf_condition = threading.Condition()
        self._faf_accepting = False
        self._faf_submitted = 0
        self._faf_completed = 0
        self._faf_dropped = 0
        self._faf_failed_batches = 0

    def init(
        self,
        *,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        env: str = "production",
        timeout: float = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        debug: bool = False,
        service: Optional[str] = None,
        allow_insecure_transport: bool = False,
    ) -> None:
        """Configure once per application worker, after forking.

        Repeating the same active configuration is idempotent. Stop background
        delivery before changing credentials or other transport settings.
        """
        if self._owner_pid != os.getpid():
            self._reset_delivery_state()
            self._initialized = False
            self._configuration = None
            self._api_key = None
        if not api_key or not api_key.strip():
            raise LoGuardAuthError("api_key is required")
        base_url = base_url.rstrip("/")
        if not base_url.lower().startswith("https://") and not allow_insecure_transport:
            raise LoGuardValidationError(
                "base_url must use https:// unless allow_insecure_transport=True"
            )
        try:
            configured_timeout = float(timeout)
        except (ValueError, TypeError, OverflowError):
            raise LoGuardValidationError(
                "timeout must be a finite positive number"
            ) from None
        if (
            isinstance(timeout, bool)
            or not math.isfinite(configured_timeout)
            or configured_timeout <= 0
        ):
            raise LoGuardValidationError("timeout must be a finite positive number")
        if type(retries) is not int or retries < 1:
            raise LoGuardValidationError("retries must be a positive integer")
        default_service = (
            service
            or os.environ.get("OTEL_SERVICE_NAME")
            or os.environ.get("SERVICE_NAME")
            or None
        )
        configuration = (
            api_key.strip(),
            base_url,
            env or "production",
            configured_timeout,
            retries,
            default_service,
        )
        if debug:
            log.setLevel(logging.DEBUG)
        with self._faf_condition:
            worker_alive = self._faf_thread is not None and self._faf_thread.is_alive()
            if self._initialized and self._faf_accepting:
                if self._configuration != configuration:
                    raise LoGuardValidationError(
                        "Call shutdown() before reconfiguring the monitor"
                    )
                if worker_alive:
                    return
            elif worker_alive:
                raise LoGuardValidationError(
                    "Previous background delivery is still draining"
                )
            if (
                self._configuration != configuration
                and self._faf_submitted != self._faf_completed
            ):
                raise LoGuardValidationError(
                    "Pending events must finish before monitor reconfiguration"
                )
            (
                self._api_key,
                self._base_url,
                self._env,
                self._timeout,
                self._retries,
                self._default_service,
            ) = configuration
            self._configuration = configuration
            self._initialized = True
            self._faf_accepting = True
            self._faf_stop.clear()
            self._faf_flush_requested.clear()
            # Context.run works on all supported runtimes and prevents request
            # credentials/contextvars from leaking into the delivery worker.
            self._faf_thread = threading.Thread(
                target=Context().run,
                args=(self._faf_worker,),
                name="loguard-sdk-delivery",
                daemon=True,
            )
            try:
                self._faf_thread.start()
            except Exception:
                self._initialized = False
                self._faf_accepting = False
                self._faf_thread = None
                raise
        if not base_url.lower().startswith("https://"):
            log.warning(
                "LoGuard transport uses plaintext HTTP; intended only for local development"
            )
        log.debug("LoGuard background delivery initialized")

    # Ingest: sync

    def event(
        self,
        *,
        type: str,
        ip: str,
        path: str,
        status_code: int,
        user_id: Optional[str] = None,
        service: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        ts: Optional[datetime] = None,
    ) -> IngestResult:
        """Track a single security event (synchronous, blocking)."""
        self._assert_initialized()
        ev = self._build_event(
            type=type,
            ip=ip,
            path=path,
            status_code=status_code,
            user_id=user_id,
            service=service,
            meta=meta,
            ts=ts,
        )
        return self._send_events_sync([ev])

    def event_batch(self, events: List[Dict[str, Any]]) -> IngestResult:
        """Track multiple events in one request (synchronous)."""
        self._assert_initialized()
        built = [self._build_event(**e) for e in events]
        return self._send_events_sync(built)

    def event_fire_and_forget(
        self,
        *,
        type: str,
        ip: str,
        path: str,
        status_code: int,
        user_id: Optional[str] = None,
        service: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        ts: Optional[datetime] = None,
    ) -> None:
        """
        Track event via background queue — never blocks, never raises.
        Ideal for production middleware (high-traffic apps).
        """
        if self._owner_pid != os.getpid():
            return
        configuration = self._configuration
        try:
            self._assert_initialized()
            ev = self._build_event(
                type=type,
                ip=ip,
                path=path,
                status_code=status_code,
                user_id=user_id,
                service=service,
                meta=meta,
                ts=ts,
            )
            with self._faf_condition:
                if not self._faf_accepting or configuration is not self._configuration:
                    self._faf_dropped += 1
                    return
                try:
                    self._faf_q.put_nowait(ev)
                except queue.Full:
                    self._faf_dropped += 1
                    return
                self._faf_submitted += 1
        except Exception:
            return

    # Ingest: async

    async def aevent(
        self,
        *,
        type: str,
        ip: str,
        path: str,
        status_code: int,
        user_id: Optional[str] = None,
        service: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        ts: Optional[datetime] = None,
    ) -> IngestResult:
        """Async version of event()."""
        self._assert_initialized()
        ev = self._build_event(
            type=type,
            ip=ip,
            path=path,
            status_code=status_code,
            user_id=user_id,
            service=service,
            meta=meta,
            ts=ts,
        )
        return await self._send_events_async([ev])

    async def aevent_batch(self, events: List[Dict[str, Any]]) -> IngestResult:
        """Async version of event_batch()."""
        self._assert_initialized()
        built = [self._build_event(**e) for e in events]
        return await self._send_events_async(built)

    # Properties

    @property
    def is_initialized(self) -> bool:
        return self._initialized and self._owner_pid == os.getpid()

    # Internal

    def _assert_initialized(self):
        if not self.is_initialized:
            raise LoGuardNotInitializedError(
                "LoGuard is not initialized. Call monitor.init(api_key=...) first."
            )

    @property
    def _headers(self) -> dict:
        return {
            "X-Api-Key": self._api_key,
            "Content-Type": "application/json",
            "User-Agent": f"loguard-python-sdk/{__version__}",
        }

    @property
    def _ingest_url(self) -> str:
        return f"{self._base_url}/v1/ingest"

    def _build_event(
        self,
        *,
        type: str,
        ip: str,
        path: str,
        status_code: int,
        user_id: Optional[str] = None,
        service: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        ts: Optional[datetime] = None,
        **_,
    ) -> Event:
        if not type:
            raise LoGuardValidationError("event type is required")
        if not ip:
            raise LoGuardValidationError("event ip is required")
        if not path:
            raise LoGuardValidationError("event path is required")

        sc = int(status_code)
        if sc < 100 or sc > 599:
            raise LoGuardValidationError("status_code must be in range 100..599")

        p = str(path).strip()
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1024:
            p = p[:1024]

        m = dict(meta) if meta else {}
        m["env"] = self._env

        _svc = service or self._default_service
        return Event(
            type=str(type).strip().lower()[:64],
            ip=str(ip).strip()[:64],
            path=p,
            status_code=sc,
            user_id=str(user_id)[:128] if user_id else None,
            service=str(_svc).strip().lower()[:64] if _svc else None,
            meta=m,
            ts=(ts or datetime.now(timezone.utc)).isoformat(),
        )

    def _send_events_sync(self, events: List[Event]) -> IngestResult:
        payload = {"events": [asdict(e) for e in events]}
        data = _t.send_sync(
            self._ingest_url,
            self._headers,
            payload,
            self._timeout,
            self._retries,
            api_key=self._api_key,
        )
        return _t.parse_ingest_response(data)

    async def _send_events_async(self, events: List[Event]) -> IngestResult:
        payload = {"events": [asdict(e) for e in events]}
        data = await _t.send_async(
            self._ingest_url,
            self._headers,
            payload,
            self._timeout,
            self._retries,
            api_key=self._api_key,
        )
        return _t.parse_ingest_response(data)

    @staticmethod
    def _delivery_timeout(timeout: float) -> float:
        if isinstance(timeout, bool):
            raise LoGuardValidationError("timeout must be finite and non-negative")
        try:
            value = float(timeout)
        except (TypeError, ValueError, OverflowError):
            raise LoGuardValidationError(
                "timeout must be finite and non-negative"
            ) from None
        if not math.isfinite(value) or value < 0 or value > threading.TIMEOUT_MAX:
            raise LoGuardValidationError(
                "timeout must be finite, non-negative and fit the platform wait limit"
            )
        return value

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for attempts on events accepted before this call.

        True means those delivery attempts finished, not that ingest accepted
        every event. New producers do not extend this call's event fence.
        """
        deadline = time.monotonic() + self._delivery_timeout(timeout)
        if self._owner_pid != os.getpid():
            return False
        with self._faf_condition:
            target = self._faf_submitted
            if self._faf_completed >= target:
                return True
            self._faf_flush_requested.set()
            if threading.current_thread() is self._faf_thread:
                return False
            while self._faf_completed < target:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._faf_condition.wait(min(remaining, threading.TIMEOUT_MAX))
            return True

    def shutdown(self, timeout: float = 5.0) -> bool:
        """Stop background admission and wait up to timeout seconds.

        On timeout the daemon worker continues draining with its configured
        transport limits. This method does not cancel an in-flight request.
        Direct event()/aevent() calls remain available.
        """
        deadline = time.monotonic() + self._delivery_timeout(timeout)
        if self._owner_pid != os.getpid():
            return False
        with self._faf_condition:
            self._faf_accepting = False
            self._faf_stop.set()
            self._faf_flush_requested.set()
            worker = self._faf_thread
        if worker is None:
            return True
        if threading.current_thread() is worker:
            return False
        worker.join(min(threading.TIMEOUT_MAX, max(0.0, deadline - time.monotonic())))
        with self._faf_condition:
            return not worker.is_alive() and self._faf_completed == self._faf_submitted

    async def aflush(self, timeout: float = 5.0) -> bool:
        """Async wrapper for flush(); does not block the event loop."""
        return await asyncio.to_thread(self.flush, timeout)

    async def ashutdown(self, timeout: float = 5.0) -> bool:
        """Async wrapper for shutdown(); does not block the event loop."""
        return await asyncio.to_thread(self.shutdown, timeout)

    @property
    def delivery_stats(self) -> dict[str, int | bool]:
        """Background delivery counters without credentials or event contents."""
        if self._owner_pid != os.getpid():
            return {"accepting": False, "worker_alive": False, "forked": True}
        with self._faf_condition:
            return {
                "accepting": self._faf_accepting,
                "worker_alive": self._faf_thread is not None
                and self._faf_thread.is_alive(),
                "accepted": self._faf_submitted,
                "completed": self._faf_completed,
                "pending": self._faf_submitted - self._faf_completed,
                "queued": self._faf_q.qsize(),
                "dropped": self._faf_dropped,
                "failed_batches": self._faf_failed_batches,
                "forked": False,
            }

    def _faf_worker(self) -> None:
        while True:
            if self._faf_stop.is_set() and self._faf_q.empty():
                return
            try:
                head = self._faf_q.get(timeout=0.05)
            except queue.Empty:
                continue
            pending = [head]
            deadline = time.monotonic() + _FAF_FLUSH_INTERVAL
            while len(pending) < _FAF_MAX_BATCH:
                if self._faf_stop.is_set() or self._faf_flush_requested.is_set():
                    try:
                        pending.append(self._faf_q.get_nowait())
                    except queue.Empty:
                        break
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    pending.append(self._faf_q.get(timeout=min(0.05, remaining)))
                except queue.Empty:
                    continue
            failed = False
            try:
                self._send_events_sync(pending)
            except Exception:
                # Transport/configuration failures must not kill the worker or
                # leave flush callers waiting forever. Do not log payloads/errors.
                failed = True
            finally:
                for _ in pending:
                    self._faf_q.task_done()
                with self._faf_condition:
                    self._faf_completed += len(pending)
                    self._faf_failed_batches += int(failed)
                    if self._faf_completed == self._faf_submitted:
                        self._faf_flush_requested.clear()
                    self._faf_condition.notify_all()


# Singleton
monitor = _Monitor()

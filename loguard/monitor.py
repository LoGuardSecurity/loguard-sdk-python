from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import _transport as _t
from .exceptions import (
    LoGuardAuthError,
    LoGuardError,
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

        self._faf_q: "queue.Queue[Event]" = queue.Queue(maxsize=_FAF_QUEUE_MAX)
        self._faf_thread: Optional[threading.Thread] = None
        self._faf_stop = threading.Event()

    # Init

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
        """
        Initialize the LoGuard monitor. Call once at application startup.

        Args:
            api_key:   Your LoGuard API key (from the dashboard)
            base_url:  LoGuard API base URL (default: https://loguard.org).
                       MUST use https:// -- your api_key is sent on every
                       request (see X-Api-Key header in _signing.py) and
                       must not travel over plaintext HTTP.
            env:       Environment tag — "production", "staging", "development"
            timeout:   HTTP request timeout in seconds (default: 10)
            retries:   Retry attempts on server errors (default: 3)
            debug:     Enable verbose debug logging
            allow_insecure_transport: Explicitly allow a non-https:// base_url
                       (e.g. a local proxy on your own trusted network during
                       development). Off by default -- fail closed, same as
                       the rest of LoGuard's internal-auth conventions. If you
                       set this, api_key and request signatures are sent in
                       cleartext; never use it against a real deployment.
        """
        if not api_key or not api_key.strip():
            raise LoGuardAuthError("api_key is required")

        base_url = base_url.rstrip("/")
        if not base_url.lower().startswith("https://"):
            if not allow_insecure_transport:
                raise LoGuardValidationError(
                    "base_url must use https:// -- your api_key is sent on every "
                    "request and must not travel over plaintext HTTP. If you really "
                    "need HTTP (e.g. a local proxy on a trusted network during "
                    "development), pass allow_insecure_transport=True explicitly."
                )
            log.warning(
                "LoGuard SDK initialized with allow_insecure_transport=True -- "
                "api_key and request signatures are being sent over plaintext. "
                "Use this ONLY for local development on a trusted network, "
                "never against a real deployment."
            )

        self._api_key = api_key.strip()
        self._base_url = base_url
        self._env = env or "production"
        self._timeout = float(timeout)
        self._retries = int(retries)
        self._initialized = True

        # Auto-detects service the same way the OTel folks settled on
        # (OTEL_SERVICE_NAME) -- with N microservices, you configure this
        # once in your infra (Helm/docker-compose/ECS task def), not as a
        # line of code in every single service. Deliberately not falling
        # back to hostname: in Docker/k8s that's usually a container/pod
        # ID with a random suffix that changes on every restart or
        # replica, which would break grouping "one service, many
        # instances" into anything meaningful.
        import os as _os_svc
        self._default_service = (
            service
            or _os_svc.environ.get("OTEL_SERVICE_NAME")
            or _os_svc.environ.get("SERVICE_NAME")
            or None
        )

        if debug:
            logging.basicConfig(level=logging.DEBUG)
            log.setLevel(logging.DEBUG)

        if not self._faf_thread or not self._faf_thread.is_alive():
            self._faf_stop.clear()
            self._faf_thread = threading.Thread(target=self._faf_worker, daemon=True)
            self._faf_thread.start()

        log.debug("LoGuard initialized env=%s base_url=%s", self._env, self._base_url)


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
            type=type, ip=ip, path=path, status_code=status_code,
            user_id=user_id, service=service, meta=meta, ts=ts,
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
        self._assert_initialized()
        try:
            ev = self._build_event(
                type=type, ip=ip, path=path, status_code=status_code,
                user_id=user_id, service=service, meta=meta, ts=ts,
            )
            self._faf_q.put_nowait(ev)
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
            type=type, ip=ip, path=path, status_code=status_code,
            user_id=user_id, service=service, meta=meta, ts=ts,
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
        return self._initialized

    # Internal

    def _assert_initialized(self):
        if not self._initialized:
            raise LoGuardNotInitializedError(
                "LoGuard is not initialized. Call monitor.init(api_key=...) first."
            )

    @property
    def _headers(self) -> dict:
        return {
            "X-Api-Key": self._api_key,
            "Content-Type": "application/json",
            "User-Agent": "loguard-python-sdk/2.0.0",
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
            self._ingest_url, self._headers, payload,
            self._timeout, self._retries,
            api_key=self._api_key,
        )
        return _t.parse_ingest_response(data)

    async def _send_events_async(self, events: List[Event]) -> IngestResult:
        payload = {"events": [asdict(e) for e in events]}
        data = await _t.send_async(
            self._ingest_url, self._headers, payload,
            self._timeout, self._retries,
            api_key=self._api_key,
        )
        return _t.parse_ingest_response(data)

    def _faf_worker(self) -> None:
        pending: List[Event] = []
        last_flush = time.time()

        while not self._faf_stop.is_set():
            try:
                ev = self._faf_q.get(timeout=0.1)
                pending.append(ev)
            except queue.Empty:
                pass

            now = time.time()
            should_flush = (
                    pending
                    and (len(pending) >= _FAF_MAX_BATCH or (now - last_flush) >= _FAF_FLUSH_INTERVAL)
            )

            if should_flush:
                batch = pending[:_FAF_MAX_BATCH]
                pending = pending[_FAF_MAX_BATCH:]
                last_flush = now
                try:
                    self._send_events_sync(batch)
                except LoGuardError:
                    continue

# Singleton
monitor = _Monitor()
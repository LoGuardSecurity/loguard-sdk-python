"""
LoGuard Python SDK
~~~~~~~~~~~~~~~~~~~

Official Python SDK for LoGuard — lightweight security event tracking.

Quick start:
    from loguard import monitor
    monitor.init(api_key="lg_live_xxx", env="production")

    # Track events
    monitor.event(type="login_failed", ip="1.2.3.4", path="/login", status_code=401)

    # Fire-and-forget (non-blocking, for production traffic)
    monitor.event_fire_and_forget(type="http_error", ip="1.2.3.4", path="/api", status_code=500)

Docs: https://docs.loguard.org/sdk/python
"""
try:
    from importlib.metadata import version
    __version__ = version("loguard")
except Exception:
    __version__ = "2.1.0"

from .monitor import monitor
from .models import (
    AlertOut,
    Event,
    IngestResult,
    UsageInfo,
)
from .exceptions import (
    LoGuardError,
    LoGuardNotInitializedError,
    LoGuardAuthError,
    LoGuardQuotaError,
    LoGuardConnectionError,
    LoGuardValidationError,
    LoGuardNotFoundError,
    LoGuardConflictError,
)

__all__ = [
    # Core
    "monitor",
    "__version__",
    # Models
    "Event",
    "IngestResult",
    "AlertOut",
    "UsageInfo",
    # Exceptions
    "LoGuardError",
    "LoGuardNotInitializedError",
    "LoGuardAuthError",
    "LoGuardQuotaError",
    "LoGuardConnectionError",
    "LoGuardValidationError",
    "LoGuardNotFoundError",
    "LoGuardConflictError",
]
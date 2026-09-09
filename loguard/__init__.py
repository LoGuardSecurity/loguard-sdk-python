"""
LoGuard Python SDK
~~~~~~~~~~~~~~~~~~~

Official Python SDK for LoGuard — lightweight security event tracking
with user-defined alert rules.

Quick start:
    from loguard import monitor
    from loguard.models import AlertRule, AlertCondition

    monitor.init(api_key="lg_live_xxx", env="production")

    # Track events
    monitor.event(type="login_failed", ip="1.2.3.4", path="/login", status_code=401)

    # Fire-and-forget (non-blocking, for production traffic)
    monitor.event_fire_and_forget(type="http_error", ip="1.2.3.4", path="/api", status_code=500)

    # Create an alert rule
    rule = monitor.alerts.create(AlertRule(
        name="Brute force",
        conditions=[
            AlertCondition(field="type",            op="eq",  value="login_failed"),
            AlertCondition(field="rate_per_minute", op="gt",  value=10),
        ],
        severity="high",
        actions=["notify", "block"],
    ))

Docs: https://docs.loguard.org/sdk/python
"""
try:
    from importlib.metadata import version
    __version__ = version("loguard")
except Exception:
    __version__ = "2.1.0"

from .monitor import monitor
from .models import (
    AlertCondition,
    AlertRule,
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
    "AlertRule",
    "AlertCondition",
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
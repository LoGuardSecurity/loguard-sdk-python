from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional


# Ingest

@dataclass
class Event:
    type: str
    ip: str
    path: str
    status_code: int
    ts: str
    user_id: Optional[str] = None
    service: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertOut:
    """An alert fired by the server in response to an ingest request."""
    kind: str = ""
    severity: str = ""
    ip: str = ""
    path: str = ""
    score: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    def __init__(self, **kwargs):
        self.kind = kwargs.get("kind", "")
        self.severity = kwargs.get("severity", "")
        self.ip = kwargs.get("ip", "")
        self.path = kwargs.get("path", "")
        self.score = int(kwargs.get("score", 0))
        self.details = kwargs.get("details", {})

    def __repr__(self):
        return f"Alert(kind={self.kind!r}, severity={self.severity!r}, ip={self.ip!r})"


@dataclass
class UsageInfo:
    used: int
    limit: int
    month: str

    @classmethod
    def from_dict(cls, d: dict) -> "UsageInfo":
        return cls(
            used=int(d.get("used", 0)),
            limit=int(d.get("limit", 0)),
            month=str(d.get("month", "")),
        )

    @property
    def remaining(self) -> int:
        if self.limit <= 0:
            return -1
        return max(0, self.limit - self.used)

    @property
    def is_near_limit(self) -> bool:
        if self.limit <= 0:
            return False
        return self.used / self.limit > 0.8

    def __repr__(self):
        if self.limit <= 0:
            return f"UsageInfo(used={self.used}, limit=unlimited, month={self.month!r})"
        return f"UsageInfo(used={self.used}/{self.limit}, remaining={self.remaining}, month={self.month!r})"


@dataclass
class IngestResult:
    ok: bool
    inserted: int
    dropped: int
    alerts_fired: int
    alerts: List[AlertOut]
    plan: str
    usage: Dict[str, Any]

    @property
    def usage_info(self) -> UsageInfo:
        return UsageInfo.from_dict(self.usage)

    def __repr__(self):
        return (
            f"IngestResult(ok={self.ok}, inserted={self.inserted}, "
            f"alerts_fired={self.alerts_fired}, plan={self.plan!r})"
        )

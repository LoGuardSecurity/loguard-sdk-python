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


# Alert Rules (user-defined)

AlertConditionField = Literal[
    "ip", "path", "status_code", "type", "user_id",
    "rate_per_minute", "rate_per_hour",
]

AlertConditionOp = Literal[
    "eq", "neq", "gt", "gte", "lt", "lte",
    "contains", "startswith", "endswith", "regex",
    "in", "not_in",
]

AlertSeverity = Literal["low", "medium", "high", "critical"]
AlertAction = Literal["notify", "block", "log"]


@dataclass
class AlertCondition:
    """
    A single condition in an alert rule.

    Examples:
        AlertCondition(field="status_code", op="gte", value=400)
        AlertCondition(field="ip", op="eq", value="1.2.3.4")
        AlertCondition(field="rate_per_minute", op="gt", value=60)
        AlertCondition(field="path", op="startswith", value="/admin")
        AlertCondition(field="type", op="in", value=["login_failed", "brute_force"])
    """
    field: AlertConditionField
    op: AlertConditionOp
    value: Any

    def to_dict(self) -> dict:
        return {"field": self.field, "op": self.op, "value": self.value}

    @classmethod
    def from_dict(cls, d: dict) -> "AlertCondition":
        return cls(field=d["field"], op=d["op"], value=d["value"])


@dataclass
class AlertRule:
    """
    A user-defined alert rule.

    The server evaluates these rules on every ingest and fires alerts when
    all conditions match.

    Attributes:
        id:           Rule ID (assigned by server, None before creation)
        name:         Human-readable rule name
        conditions:   List of conditions (AND logic by default)
        severity:     Alert severity: "low", "medium", "high", "critical"
        actions:      What to do when fired: "notify", "block", "log"
        enabled:      Whether the rule is active
        description:  Optional description
        logic:        "and" (all conditions) or "or" (any condition)
        cooldown_sec: Minimum seconds between repeated alerts for same IP (default 60)
        created_at:   ISO timestamp (set by server)
        updated_at:   ISO timestamp (set by server)
    """
    name: str
    conditions: List[AlertCondition]
    severity: AlertSeverity = "medium"
    actions: List[AlertAction] = field(default_factory=lambda: ["notify"])
    enabled: bool = True
    description: str = ""
    logic: Literal["and", "or"] = "and"
    cooldown_sec: int = 60
    id: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "conditions": [c.to_dict() for c in self.conditions],
            "severity": self.severity,
            "actions": self.actions,
            "enabled": self.enabled,
            "description": self.description,
            "logic": self.logic,
            "cooldown_sec": self.cooldown_sec,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AlertRule":
        return cls(
            id=d.get("id"),
            name=d["name"],
            conditions=[AlertCondition.from_dict(c) for c in d.get("conditions", [])],
            severity=d.get("severity", "medium"),
            actions=d.get("actions", ["notify"]),
            enabled=d.get("enabled", True),
            description=d.get("description", ""),
            logic=d.get("logic", "and"),
            cooldown_sec=int(d.get("cooldown_sec", 60)),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        )

    def __repr__(self):
        return (
            f"AlertRule(id={self.id}, name={self.name!r}, "
            f"severity={self.severity!r}, enabled={self.enabled})"
        )
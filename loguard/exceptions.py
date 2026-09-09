from __future__ import annotations


class LoGuardError(Exception):
    """Base exception for all LoGuard SDK errors."""


class LoGuardNotInitializedError(LoGuardError):
    """Raised when monitor.event() is called before monitor.init()."""


class LoGuardAuthError(LoGuardError):
    """Raised when API key is invalid, missing, or subscription expired."""


class LoGuardQuotaError(LoGuardError):
    """Raised when monthly event quota is exceeded."""


class LoGuardConnectionError(LoGuardError):
    """Raised when the LoGuard API is unreachable or returns a server error."""


class LoGuardValidationError(LoGuardError):
    """Raised when event data fails validation."""


class LoGuardNotFoundError(LoGuardError):
    """Raised when a requested resource (e.g. alert rule) is not found."""


class LoGuardConflictError(LoGuardError):
    """Raised when creating a resource that already exists (e.g. duplicate alert rule)."""
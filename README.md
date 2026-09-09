# LoGuard Python SDK

[![PyPI](https://img.shields.io/pypi/v/loguard.svg)](https://pypi.org/project/loguard/)
[![Python](https://img.shields.io/pypi/pyversions/loguard.svg)](https://pypi.org/project/loguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Official Python SDK for LoGuard security monitoring and threat detection.

The SDK sends application security events to LoGuard and provides integrations for Python applications, including FastAPI, Starlette, and Django.

## Installation

```bash
pip install loguard
```

For framework integrations:

```bash
pip install "loguard[fastapi]"
pip install "loguard[django]"
```

## Quick Start

```python
import os

from loguard import monitor

monitor.init(
    api_key=os.environ["LOGUARD_API_KEY"],
    base_url=os.environ.get("LOGUARD_BASE_URL", "https://loguard.org"),
    env=os.environ.get("LOGUARD_ENV", "production"),
)
```

### Send events

Synchronous events wait for the server response:

```python
result = monitor.event(
    type="login_failed",
    ip="1.2.3.4",
    path="/api/login",
    status_code=401,
    user_id="user_123",
    meta={"method": "POST"},
)

print(result)
```

For non-blocking event reporting:

```python
monitor.event_fire_and_forget(
    type="http_request",
    ip="1.2.3.4",
    path="/api/users",
    status_code=200,
)
```

Async applications can use the async methods:

```python
result = await monitor.aevent(
    type="login_failed",
    ip="1.2.3.4",
    path="/api/login",
    status_code=401,
)
```

Multiple events can be sent as a batch:

```python
result = monitor.event_batch([
    {
        "type": "http_request",
        "ip": "1.2.3.4",
        "path": "/",
        "status_code": 200,
    },
    {
        "type": "login_failed",
        "ip": "1.2.3.4",
        "path": "/login",
        "status_code": 401,
    },
    {
        "type": "http_request",
        "ip": "5.6.7.8",
        "path": "/.env",
        "status_code": 404,
    },
])

print(f"accepted={result.inserted} alerts={result.alerts_fired}")
```

Async batch ingestion is also available:

```python
result = await monitor.aevent_batch([...])
```

### Event types

| Type            | Description              |
| --------------- | ------------------------ |
| `http_request`  | Incoming HTTP request    |
| `login_failed`  | Failed authentication    |
| `login_success` | Successful login         |
| `forbidden`     | Access denied            |
| `waf_block`     | Request blocked by a WAF |
| `bot_detected`  | Bot traffic detected     |

## FastAPI / Starlette

Install the FastAPI integration:

```bash
pip install "loguard[fastapi]"
```

Then add the middleware:

```python
import os

from fastapi import FastAPI

from loguard import monitor
from loguard.integrations.fastapi import LoGuardMiddleware

app = FastAPI()

monitor.init(
    api_key=os.environ["LOGUARD_API_KEY"],
    base_url=os.environ.get("LOGUARD_BASE_URL", "https://loguard.org"),
)

app.add_middleware(
    LoGuardMiddleware,
    track_statuses={400, 401, 403, 404, 429, 500, 502, 503},
    get_user_id=lambda r: (
        r.state.user_id if hasattr(r.state, "user_id") else None
    ),
)
```

## Django

Install the Django integration:

```bash
pip install "loguard[django]"
```

Add the middleware to `settings.py`:

```python
MIDDLEWARE = [
    "loguard.integrations.django.LoGuardMiddleware",
    # ... other middleware
]

LOGUARD_TRACK_ALL = False
LOGUARD_TRACK_STATUSES = {400, 401, 403, 404, 429, 500, 502, 503}
```

Initialize the SDK from your application configuration:

```python
import os

from django.apps import AppConfig


class MyAppConfig(AppConfig):
    name = "myapp"

    def ready(self):
        from loguard import monitor

        monitor.init(
            api_key=os.environ["LOGGUARD_API_KEY"],
            base_url=os.environ.get(
                "LOGUARD_BASE_URL",
                "https://loguard.org",
            ),
            env=os.environ.get("LOGUARD_ENV", "production"),
        )
```

## Alert Rules

LoGuard can evaluate custom alert rules against ingested events.

```python
from loguard import monitor
from loguard.models import AlertRule, AlertCondition

rule = monitor.alerts.create(
    AlertRule(
        name="Brute force",
        conditions=[
            AlertCondition(
                field="type",
                op="eq",
                value="login_failed",
            ),
            AlertCondition(
                field="rate_per_minute",
                op="gt",
                value=10,
            ),
        ],
        severity="high",
        actions=["notify", "block"],
        logic="and",
        cooldown_sec=300,
    )
)

print(rule.id)
```

Rules can also be listed, updated, and deleted:

```python
rules = monitor.alerts.list()

rule.enabled = False
monitor.alerts.update(rule)

monitor.alerts.delete(rule.id)
```

Async variants are available:

```text
acreate
alist
aupdate
adelete
```

### Condition fields

| Field             | Type   | Description                          |
| ----------------- | ------ | ------------------------------------ |
| `type`            | string | Event type                           |
| `ip`              | string | Source IP address                    |
| `path`            | string | Request path                         |
| `status_code`     | int    | HTTP status code                     |
| `user_id`         | string | Authenticated user ID                |
| `rate_per_minute` | int    | Requests per minute from the same IP |
| `rate_per_hour`   | int    | Requests per hour from the same IP   |

### Operators

| Operator                               | Description        |
| -------------------------------------- | ------------------ |
| `eq` / `neq`                           | Equal / not equal  |
| `gt` / `gte` / `lt` / `lte`            | Numeric comparison |
| `contains` / `startswith` / `endswith` | String matching    |
| `regex`                                | Regular expression |
| `in` / `not_in`                        | Value in list      |

## Blocking

IP/CIDR/user/path/user-agent blocking happens server-side, driven by your alert rules — there's no `monitor.blacklist.*` client API. Send events with `monitor.event()`, and anything matching a rule with a `"block"` action gets enforced immediately, no extra call needed.

## IngestResult

Synchronous event methods return an `IngestResult`:

```python
result = monitor.event(
    type="login_failed",
    ip="1.2.3.4",
    path="/login",
    status_code=401,
)

result.ok
result.inserted
result.dropped
result.alerts_fired
result.alerts
result.plan
result.usage_info
```

`usage_info` contains the current usage information for the project.

```python
if result.usage_info.is_near_limit:
    print("Approaching monthly quota")
```

## Error Handling

The SDK exposes specific exception types for common API errors:

```python
from loguard.exceptions import (
    LogguardAuthError,
    LogguardQuotaError,
    LogguardConnectionError,
    LogguardValidationError,
    LogguardNotFoundError,
    LogguardConflictError,
)

try:
    monitor.event(
        type="login_failed",
        ip="1.2.3.4",
        path="/login",
        status_code=401,
    )
except LogguardQuotaError:
    pass
except LogguardConnectionError:
    pass
except LogguardAuthError:
    raise
```

`event_fire_and_forget()` is non-blocking and does not raise exceptions to the caller.

## Kernel Firewall

If the LoGuard daemon is installed and running on the host, the SDK can connect to it for kernel-level IP blocking.

```python
import os

from loguard import monitor

monitor.init(
    api_key=os.environ["LOGUARD_API_KEY"],
)

monitor.init_firewall(
    sock_path="/var/run/loguard.sock",
)

monitor.blacklist.block_ip(
    "1.2.3.4",
    reason="SQL_INJECTION",
)
```

Direct firewall operations are also available:

```python
monitor.firewall.block_ip(
    "1.2.3.4",
    duration=3600,
)

monitor.firewall.block_country("KP")

stats = monitor.firewall.get_stats()
```

If the daemon is unavailable, firewall integration is disabled and the SDK continues operating without kernel-level blocking.

## Environment Variables

| Variable           | Default               | Description          |
| ------------------ | --------------------- | -------------------- |
| `LOGUARD_API_KEY`  | —                     | Project API key      |
| `LOGUARD_BASE_URL` | `https://loguard.org` | LoGuard API base URL |
| `LOGUARD_ENV`      | `production`          | Environment name     |

## Links

* [LoGuard](https://loguard.org)
* [PyPI](https://pypi.org/project/loguard/)
* [GitHub](https://github.com/LoGuardSecurity/loguard-sdk-python)

## License

MIT

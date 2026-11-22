# LoGuard Python SDK

[![PyPI](https://img.shields.io/pypi/v/loguard.svg)](https://pypi.org/project/loguard/)
[![Python](https://img.shields.io/pypi/pyversions/loguard.svg)](https://pypi.org/project/loguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Official Python SDK for LoGuard security monitoring and threat detection. Requires Python 3.10 or later. Python 3.11–3.15 are the maintained runtime targets; Python 3.10 is tested for legacy compatibility.

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
            api_key=os.environ["LOGUARD_API_KEY"],
            base_url=os.environ.get(
                "LOGUARD_BASE_URL",
                "https://loguard.org",
            ),
            env=os.environ.get("LOGUARD_ENV", "production"),
        )
```

With a preloaded pre-fork server, initialize from the worker's post-fork hook
rather than the master's `AppConfig.ready()`.

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
    LoGuardAuthError,
    LoGuardQuotaError,
    LoGuardConnectionError,
    LoGuardValidationError,
    LoGuardNotFoundError,
    LoGuardConflictError,
)

try:
    monitor.event(
        type="login_failed",
        ip="1.2.3.4",
        path="/login",
        status_code=401,
    )
except LoGuardQuotaError:
    pass
except LoGuardConnectionError:
    pass
except LoGuardAuthError:
    raise
```

`event_fire_and_forget()` is non-blocking and does not raise exceptions to the caller.

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


## Automatic security capture

Enable capture explicitly; existing installations retain status-based selection
and do not collect query/body fields by default.

```python
app.add_middleware(
    LoGuardMiddleware,
    security_capture=True,
    max_body_bytes=32768,
    max_json_depth=8,
    trusted_proxies=["10.0.0.0/8"],  # Only proxy networks you control.
)
```

For Django, set `LOGUARD_SECURITY_CAPTURE = True`. Optional settings are
`LOGUARD_MAX_BODY_BYTES = 32768` and `LOGUARD_MAX_JSON_DEPTH = 8`.

Security capture selects all response statuses and emits `http_request`, or
`login_failed` for HTTP 401. Legacy FastAPI capture retains `http_error`.
An explicitly empty `track_statuses` disables status-based capture; it does not
override `track_all` or `security_capture`.

Both integrations enqueue events in a bounded background queue; requests do
not wait for ingest. Delivery remains best-effort and in-memory. Queue overflow,
exhausted transport retries and process termination can lose events. Initialize
the monitor once in each application worker after forking. Background lifecycle
methods and diagnostic counters are described below.

### Fields and limits

| Field | Policy |
| --- | --- |
| `meta.method` | HTTP method |
| `meta.duration_ms` | Time spent in the wrapped application; ASGI includes response streaming, Django excludes streaming iteration |
| `meta.query` | Up to 64 query pairs inspected; last inspected duplicate wins; maximum raw query 32 KiB |
| `meta.body` | JSON objects/arrays, `application/*+json`, or URL-encoded form fields; no multipart/files |
| `meta.headers` | Explicit `track_headers` / `LOGUARD_TRACK_HEADERS` allowlist only; up to 64 names, 512 UTF-8 bytes per value |

Secret-like field names are removed recursively before enqueueing. Values and
keys are limited to 4096 UTF-8 bytes, with a shared 64-field body budget. JSON
container depth defaults to 8. The configurable body limit must be 1..1048576
bytes and depth must be 1..32. Invalid limits fail at middleware construction.
Oversized bodies are omitted rather than partially parsed. A form-labeled body
starting with `{` or `[` is parsed as JSON. Form bracket syntax remains literal
Python form keys; it is not interpreted using PHP array semantics.

Field-name filtering cannot identify all personal or confidential data.
Non-secret fields can still contain sensitive values. Review your data policy
before enabling capture. Credential headers are blocked even if allowlisted;
other selected headers are not inspected for secrets embedded in their values.

### Body availability

ASGI middleware observes request chunks only when the application reads them.
It does not pre-read, drain, replace or replay the request stream. Only a fully
observed supported body is parsed. WebSocket and lifespan scopes pass through.
Response bodies are never captured or buffered.

Django supports both synchronous and native asynchronous middleware chains.
It observes bytes consumed through `request.read()`, `readline()`, iteration or
Django's body/form parsing, and preserves an existing body cache. It never
pre-reads or drains an unread stream. The original stream is restored unless
Django has replaced it with its own body cache. Multipart/file uploads are not
wrapped or captured.

Partial, pre-consumed or rewound streams yield `body_unavailable`. A streaming
response is returned unchanged without iteration or buffering; body reads
performed only while that response streams are outside this capture window.
Django's private `_stream` hook is isolated in the adapter and covered by
compatibility tests. Regression coverage includes Django 5.2 and current Django.

User IDs are read from already resolved sync/async authentication caches or an
already evaluated user object. Telemetry does not evaluate Django's lazy user
proxy or trigger authentication queries to obtain a user ID.

Omission reasons appear as boolean metadata: `body_unavailable`,
`body_too_large`, `body_unsupported_content_type`, `body_parse_error`,
`body_depth_exceeded`, `body_capture_error`, or `query_too_large`.

### Proxy trust and compatibility

Without trusted proxies, forwarded headers are ignored. With trusted proxies,
walk `X-Forwarded-For` from right to left and stop at the first untrusted hop.
Invalid or oversized chains fall back to the direct peer. Configure this only
for proxies that append or sanitize forwarding headers.

FastAPI middleware now uses the ASGI callable interface rather than
`BaseHTTPMiddleware.dispatch`. Registration with `app.add_middleware` remains
unchanged; subclasses overriding `dispatch` must migrate. Unhandled application
exceptions are re-raised unchanged; a failure before response start can queue
status 500. Capture failures never replace the application's response.

### Local regression checks

```bash
python -m pip install -e '.[dev,fastapi,django]'
python -m pytest -q
```

The standalone `*_e2e.py` scripts require explicitly configured live services;
they are not offline regression tests.


### Background delivery lifecycle

The monitor uses one daemon worker, at most 2000 waiting events and batches of
up to 50. Overflow drops the newest event. `event_fire_and_forget()` also drops
new events after shutdown; it never waits for network I/O or raises to its caller.
The worker starts with an empty context so it does not retain request ContextVars.

```python
# Stop request/event producers first, then wait for delivery attempts.
drained = monitor.flush(timeout=5.0)
stopped = monitor.shutdown(timeout=5.0)
```

`flush()` waits only for events accepted before that call. Later producers do
not extend its event fence. True means delivery attempts finished, not that
ingest accepted every event. Transport failures are counted; exhausted batches
are not persisted or requeued by the worker.

`shutdown()` stops background admission and allows at most the specified wait.
On timeout it returns False; the daemon continues draining with configured
transport timeouts/retries. It does not cancel an in-flight HTTP request. Process
exit can still lose queued events. Direct `event()`/`aevent()` calls remain
available. No global signal/atexit handlers or durable spool are installed.

Async lifecycle hooks should use the non-blocking wrappers:

```python
await monitor.aflush(timeout=5.0)
stopped = await monitor.ashutdown(timeout=5.0)
```

Cancelling those awaitables does not cancel delivery; their background wait is
still bounded by the supplied timeout. A FastAPI lifespan can own the monitor:

```python
from contextlib import asynccontextmanager
import logging
import os
from fastapi import FastAPI
from loguard import monitor

@asynccontextmanager
async def lifespan(app):
    monitor.init(api_key=os.environ["LOGUARD_API_KEY"])
    try:
        yield
    finally:
        if not await monitor.ashutdown(timeout=5.0):
            logging.getLogger("myapp").warning("Security telemetry is still draining")

app = FastAPI(lifespan=lifespan)
```

For Django, register shutdown with the hosting worker's lifecycle hook, after
request admission stops. With pre-fork servers, call `init()` after each fork;
inherited worker queues/locks are not reused in a child. Uninitialized or
inherited background reporting fails open until that child initializes.

Repeated `init()` with identical active configuration is idempotent. Stop
producers and finish shutdown before changing credentials or transport settings;
reconfiguration is rejected while the old worker drains. A stale enqueue from
a previous configuration is discarded. Transport timeout must be finite and
positive, retries a positive integer; lifecycle timeouts must be finite and
non-negative and within the platform thread-wait limit. `debug=True` changes only the SDK logger's level, leaving root
logging configuration under application control.

`monitor.delivery_stats` returns counters and state only: accepted, completed,
pending, queued, admission drops, failed batches, accepting and worker_alive.
Pending includes the in-flight batch. Completed counts finished attempts, including
transport failures; it is not an acceptance count. Forked, uninitialized child
state is identified by `forked=True`. No credentials or event contents are exposed.

The default pytest run excludes marked live integration tests and ignores the
standalone `*_e2e.py` command-line scripts during collection. Loopback tests
exercise real signed HTTP delivery without contacting production. Explicitly
select live tests with `-m integration` only when you intend to use a live service.
Those tests require both `LOGUARD_API_KEY` and `LOGUARD_BASE_URL`; they have no
default live endpoint.


### Shared HTTP capture acceptance

`contracts/http-capture-v1.json` defines 39 shared body-policy cases, executed
by this SDK's regression suite. They cover nested secret fields, encoded form
names, duplicates, media-type normalization, malformed JSON, empty bodies,
UTF-8 truncation, field budgets and depth/size boundaries. Native tests cover
framework stream handling and delivery separately. Passing these vectors does
not establish staging delivery or identical behavior for every possible input.
Filtering field names does not identify all personal or sensitive values.

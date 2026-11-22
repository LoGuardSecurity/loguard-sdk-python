# Python SDK integration

Status: documentation draft for the 2.2.0 candidate. Do not publish the installation commands as generally available until the package has been uploaded to PyPI and tested in a clean client environment. Published 2.1.0 is an older artifact.

## Requirements

- Python 3.10 or later, in the application's own virtual environment.
- A LoGuard project and its project API key.
- Outbound HTTPS access to the ingest endpoint configured for that project.
- Initialize once per application worker, after forking. An initialized monitor inherited by a forked child does not automatically start delivery there.

Built-in integrations in this candidate: FastAPI/Starlette and Django. Flask does not have a built-in integration in this source tree. Flask applications can call the explicit event API, but this alone does not enable automatic HTTP request capture.

## Installation after publication

```bash
python -m pip install 'loguard==2.2.0'
# For the Starlette middleware:
python -m pip install 'loguard[fastapi]==2.2.0'
# For Django:
python -m pip install 'loguard[django]==2.2.0'
python -m pip check
python -c 'import sys, importlib.metadata as m; print(sys.version); print(m.version("loguard"))'
```

The `fastapi` extra installs Starlette; install FastAPI separately if your application uses it. Pin the resulting dependency set in your normal lockfile.

## Credentials and configuration

Configure the hosting service's secret/environment mechanism with `LOGUARD_API_KEY`, `LOGUARD_BASE_URL` and `LOGUARD_ENV`. The base URL is the HTTPS origin only, without `/v1/ingest`; the SDK appends that path. Obtain the supported endpoint from your LoGuard project configuration. This candidate defaults to `https://loguard.org`; availability of a different API origin must be checked independently.

Do not put the API key in source code, browser JavaScript, screenshots or support output. Keep TLS verification enabled.

## First delivery check

Run this once in the application's environment using a separate test project, with the environment variables configured:

```python
import os
from loguard import monitor

monitor.init(
    api_key=os.environ['LOGUARD_API_KEY'],
    base_url=os.environ['LOGUARD_BASE_URL'],
    env=os.environ.get('LOGUARD_ENV', 'integration-test'),
    service='python-integration-check',
    timeout=5,
    retries=1,
)
try:
    result = monitor.event(
        type='http_request',
        ip='192.0.2.10',
        path='/loguard-integration-check',
        status_code=200,
        meta={'integration_check': True},
    )
    print({'ok': result.ok, 'accepted': result.inserted, 'dropped': result.dropped})
    if not result.ok or result.inserted != 1 or result.dropped:
        raise SystemExit('Expected exactly one accepted event')
finally:
    monitor.shutdown(timeout=5)
```

The IP is a documentation address, not a real visitor. This benign event checks acceptance; it is not expected to create a security finding. Confirm the corresponding event in the project's telemetry, using service, path and timestamp. An accepted ingest response does not prove that a detector ran or that an incident was created.

## FastAPI lifecycle and capture

```python
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from loguard import monitor
from loguard.integrations.fastapi import LoGuardMiddleware

@asynccontextmanager
async def lifespan(app):
    monitor.init(
        api_key=os.environ['LOGUARD_API_KEY'],
        base_url=os.environ['LOGUARD_BASE_URL'],
        env=os.environ.get('LOGUARD_ENV', 'production'),
        service='my-python-app',
    )
    try:
        yield
    finally:
        if not await monitor.ashutdown(timeout=5):
            logging.getLogger(__name__).warning('LoGuard delivery did not finish before timeout')

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    LoGuardMiddleware,
    security_capture=True,
    max_body_bytes=32768,
    max_json_depth=8,
    trusted_proxies=[],
)
```

Merge the lifespan logic with the application's existing startup/shutdown hooks. Capture mode observes all HTTP statuses. It captures bodies only when the application reads them; it does not force a body read. Binary, multipart and unsupported content types are not captured as bodies. Query/body size and depth limits apply. Credential header names are forbidden; optional headers use an explicit allowlist. Sensitive field names are filtered, but arbitrary text values are not classified for secrets or personal data. Review your data collection requirements before enabling capture.

Trust only actual immediate proxy addresses/CIDRs in `trusted_proxies`; determine them from the deployed topology. Forwarded headers from other peers are ignored. Validate visitor IP reporting through the real proxy chain before enabling response policies.

## Explicit events for other Python applications

Initialize the monitor in the worker startup hook, then call `monitor.event_fire_and_forget(...)` for non-blocking reporting, or `monitor.event(...)` when the caller explicitly needs the ingest response. Stop admission and call `monitor.shutdown(timeout=5)` in the worker shutdown hook. Do not initialize or shut down per request. Do not copy whole Flask request headers, bodies or session objects into `meta`: automatic field filtering applies to the capture integration, not to arbitrary custom metadata.

A dedicated, tested Flask request integration and exact Gunicorn/systemd lifecycle configuration remain required for a complete automatic Flask onboarding guide. Django has a built-in integration, but the project-specific settings and worker lifecycle should be validated before publishing a Django deployment recipe.

## Delivery behavior

- Background queue: up to 2,000 events in memory; up to 50 events per batch.
- Queue overflow, shutdown admission and delivery failures can lose events.
- No durable disk spool or restart recovery is provided.
- `flush(timeout=5)` waits for attempts on previously accepted events. A true return does not mean the server accepted them.
- `shutdown(timeout=5)` stops new background admission and bounds the wait. It does not cancel an in-flight network request.
- Inspect `monitor.delivery_stats` for pending, dropped and failed batch counters. These counters do not provide end-to-end detector confirmation.
- Network retries can duplicate events; exactly-once processing is not promised.
- SDK telemetry capture does not itself install a firewall or guarantee that attacks are blocked.

## Acceptance checklist

1. Record SDK version, application Python/framework versions and deployment topology.
2. Confirm a benign request still returns the application's expected result.
3. Confirm the explicit smoke event is accepted and visible in the correct project.
4. Confirm middleware events show the correct service, path, status and visitor IP.
5. Use only synthetic dummy credentials to verify captured output omits sensitive fields.
6. Run an approved synthetic detection check in a test project; record the event/finding identifiers and expected detector separately from acceptance.
7. Check pending/dropped/failed batch counters and graceful worker restart behavior.
8. Verify the application continues to respond during an ingest outage.

## Troubleshooting

- Installation rejected: inspect the Python executable used by the service, not only the shell Python; Python below 3.10 is unsupported by this candidate.
- 401/403: check project credentials and endpoint. Do not paste keys into support messages.
- 404 or HTML response: inspect endpoint routing and proxy/Cloudflare policy.
- Accepted event, no finding: a benign event need not trigger detection; check detector policy, plan and processing lag.
- Missing body: the application may not have read it, or size/content-type/depth limits may apply.
- Incorrect IP: validate the immediate proxy and forwarded-header trust chain.
- Lost events at restart: ensure worker startup initializes delivery after fork and shutdown allows time to drain; in-memory queues cannot survive a crash.

## Removal

Remove middleware/event calls and worker lifecycle hooks, redeploy the application, then remove the dependency using the application's normal dependency manager. Revoke the project key if this integration is retired. Do not uninstall a package while running workers still import it.

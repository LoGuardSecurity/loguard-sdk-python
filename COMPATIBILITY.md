# Python compatibility policy

The 2.2.0 candidate supports Python >=3.10. CI runs the offline regression suite on CPython 3.10–3.15, with current compatible dependencies and a baseline profile (httpx 0.27.2, Starlette 0.27.0, Django 5.2.x). Dependency resolution respects each package's Requires-Python metadata. This does not promise every historical Django/Starlette version works on every interpreter.

Python 3.11–3.15 are the maintained runtime targets. Python 3.10 is covered as legacy compatibility; upstream CPython support ended in October 2026. Python 3.9 and earlier are not supported by this candidate. PyPy and free-threaded builds are not covered by this matrix.

Worker threads run inside an explicitly empty context via Context.run. This provides the same request-context isolation on older runtimes without the Thread(context=...) API introduced in Python 3.14. Forked processes must initialize their own monitor after fork; no locks/queues are reused from the parent.

The canonical version lives in loguard/_version.py. Hatch reads that file for distribution metadata; imports and signed/unsigned User-Agent headers use it directly. No duplicate fallback version or broad import-time exception handler is used.

Capture, queue limits, flush/shutdown semantics and the external API remain unchanged. Background queues remain in memory. Flask automatic capture is not included.

The release checklist must include tests, wheel built from sdist, package metadata checks, a clean wheel installation and a live ingestion check in the actual client environment. A passing compatibility matrix is not proof of production detection or blocking.

References:
- https://docs.python.org/3/library/contextvars.html#contextvars.Context.run
- https://docs.python.org/3/library/threading.html#threading.Thread
- https://devguide.python.org/versions/

"""
test_sdk_e2e.py

Real end-to-end test: an actual FastAPI app with the actual LoGuardMiddleware
from the SDK, pointed at a live ingest server (http://localhost:8000). Not a
curl-based simulation -- the request goes through a real Starlette
TestClient -> real middleware.dispatch() -> real monitor.aevent() -> a real
httpx POST to /v1/ingest.
"""
import sys
import os

API_KEY = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("LOGUARD_API_KEY", "")
if not API_KEY:
    print("ERROR: pass an API key as the first argument or via LOGUARD_API_KEY")
    sys.exit(1)

from fastapi import FastAPI
from fastapi.testclient import TestClient

from loguard import monitor
from loguard.integrations.fastapi import LoGuardMiddleware, KNOWN_EXPLOIT_HEADERS

monitor.init(
    api_key=API_KEY, base_url="http://localhost:8000", env="e2e-sdk-test",
    allow_insecure_transport=True,  # local-only test against localhost
)

app = FastAPI()
app.add_middleware(
    LoGuardMiddleware,
    track_statuses={500},
    track_headers=KNOWN_EXPLOIT_HEADERS,
)


from fastapi.responses import JSONResponse


@app.get("/ecp/")
def ecp_endpoint():
    # Simulating a realistic scenario: the protected app returns a 500,
    # LoGuardMiddleware should catch it and send an event with the real
    # request headers (including the ProxyLogon pattern).
    # Returning (dict, 500) doesn't work as "body + status" in FastAPI
    # the way it does in Flask -- FastAPI would just serialize the whole
    # tuple as a 200 JSON body. An explicit JSONResponse is the correct way.
    return JSONResponse(content={"error": "internal"}, status_code=500)


client = TestClient(app)

print("Sending a request through the real LoGuardMiddleware (ProxyLogon headers)...")
resp = client.get(
    "/ecp/",
    headers={
        "X-AnonResource-Backend": "localhost/ecp/default.flt?~3",
        "X-BEResource": "localhost~1942",
        "User-Agent": "Mozilla/5.0 (real SDK e2e test)",
        "Cookie": "session=SHOULD_NEVER_BE_SENT",  # check that forbidden headers aren't sent
    },
)
print("App response:", resp.status_code)
print()
print("If the middleware worked, the event has already been sent to the live ingest server.")
print("Check detector.log for a detector_hit with name=cve_signature.")

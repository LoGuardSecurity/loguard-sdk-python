"""
test_django_sdk_e2e.py

Real end-to-end test of the Django integration: a minimal but genuine
Django app (django.conf.settings.configure() + one view), the actual
LoGuardMiddleware from the SDK, a real django.test.Client -- requests
actually go out to a live ingest server.
"""
import sys
import os

API_KEY = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("LOGUARD_API_KEY", "")
if not API_KEY:
    print("ERROR: pass an API key as the first argument")
    sys.exit(1)

import django
from django.conf import settings
from django.http import HttpResponse
from django.urls import path

from loguard.integrations.django import KNOWN_EXPLOIT_HEADERS

settings.configure(
    DEBUG=True,
    ALLOWED_HOSTS=["*"],
    SECRET_KEY="test-only-not-for-production",
    ROOT_URLCONF=__name__,
    MIDDLEWARE=["loguard.integrations.django.LoGuardMiddleware"],
    LOGUARD_TRACK_HEADERS=KNOWN_EXPLOIT_HEADERS,
    LOGUARD_TRACK_STATUSES={500},
    USE_TZ=True,
)


def ecp_view(request):
    return HttpResponse('{"error":"internal"}', status=500, content_type="application/json")


urlpatterns = [path("ecp/", ecp_view)]

django.setup()

from loguard import monitor
monitor.init(
    api_key=API_KEY, base_url="http://localhost:8000", env="e2e-django-sdk-test",
    allow_insecure_transport=True,
)

from django.test import Client

client = Client()
print("Sending a request through the real Django LoGuardMiddleware (ProxyLogon headers)...")
resp = client.get(
    "/ecp/",
    HTTP_X_ANONRESOURCE_BACKEND="localhost/ecp/default.flt?~3",
    HTTP_X_BERESOURCE="localhost~1942",
    HTTP_USER_AGENT="Mozilla/5.0 (real Django SDK e2e test)",
    HTTP_COOKIE="session=SHOULD_NEVER_BE_SENT",
)
print("App response:", resp.status_code)
print()
print("Waiting for the SDK's background worker thread (event_fire_and_forget,")
print("_FAF_FLUSH_INTERVAL=0.25s) to actually send the event over the network...")
import time
time.sleep(2)
print("Done -- the event should be on its way.")
print("Check detector.log for a detector_hit with name=cve_signature.")

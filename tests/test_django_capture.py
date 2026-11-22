"""Real Django sync/async pipelines and request-stream compatibility."""

import asyncio
from io import BytesIO
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import django
from django.apps import apps
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import HttpResponse, StreamingHttpResponse
from django.test import AsyncClient, Client, RequestFactory, override_settings
from django.urls import path
from django.utils.functional import SimpleLazyObject
import pytest

from loguard.integrations.django import LoGuardMiddleware

RAW = b'{"q":"test","password":"secret"}'


def read_view(request):
    assert request.read() == RAW
    return HttpResponse("ok")


def partial_view(request):
    assert request.read(5) == RAW[:5]
    return HttpResponse("ok")


async def async_view(request):
    await asyncio.sleep(0)
    assert request.read() == RAW
    return HttpResponse("async-ok")


def form_view(request):
    assert request.POST["password"] == "secret"
    return HttpResponse("ok")


def file_view(request):
    assert request.FILES["upload"].read() == b"file-secret"
    return HttpResponse("file-ok")


def large_view(request):
    assert request.read() == b"x" * 100
    return HttpResponse("large-ok")


urlpatterns = [
    path("read", read_view),
    path("partial", partial_view),
    path("async", async_view),
    path("form", form_view),
    path("file", file_view),
    path("large", large_view),
]


@pytest.fixture(autouse=True)
def configured_django():
    if not settings.configured:
        settings.configure(DEFAULT_CHARSET="utf-8")
    if not apps.ready:
        django.setup()
    with override_settings(
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["testserver"],
        SECRET_KEY="test-only-key",
        MIDDLEWARE=["loguard.integrations.django.LoGuardMiddleware"],
        LOGUARD_SECURITY_CAPTURE=True,
    ):
        yield


def request_factory():
    return RequestFactory().post(
        "/read?q=test&token=secret", RAW, content_type="application/json"
    )


def last_event(monitor):
    return monitor.event_fire_and_forget.call_args.kwargs


def test_real_wsgi_request_read_is_captured_without_body_cache():
    with patch("loguard.integrations.django._monitor") as monitor:
        response = Client().post(
            "/read?q=test&token=secret", RAW, content_type="application/json"
        )
    assert response.content == b"ok"
    event = last_event(monitor)
    assert event["meta"]["body"] == {"q": "test"}
    assert event["meta"]["query"] == {"q": "test"}
    assert "secret" not in json.dumps(event)


@pytest.mark.asyncio
async def test_real_async_django_pipeline():
    with patch("loguard.integrations.django._monitor") as monitor:
        response = await AsyncClient().post(
            "/async?q=test", RAW, content_type="application/json"
        )
    assert response.content == b"async-ok"
    assert last_event(monitor)["meta"]["body"] == {"q": "test"}
    assert monitor.event_fire_and_forget.call_count == 1


def test_partial_read_does_not_parse_or_drain_remaining_body():
    request = request_factory()
    original = request._stream
    with patch("loguard.integrations.django._monitor") as monitor:
        response = LoGuardMiddleware(partial_view)(request)
    assert response.content == b"ok"
    assert request._stream is original
    assert request.read() == RAW[5:]
    assert last_event(monitor)["meta"]["body_unavailable"]
    assert "body" not in last_event(monitor)["meta"]


def test_urlencoded_parser_semantics_are_unchanged():
    with patch("loguard.integrations.django._monitor") as monitor:
        response = Client().post(
            "/form",
            "q=test&password=secret",
            content_type="application/x-www-form-urlencoded",
        )
    assert response.content == b"ok"
    assert last_event(monitor)["meta"]["body"] == {"q": "test"}


def test_multipart_upload_is_neither_wrapped_nor_captured():
    with patch("loguard.integrations.django._monitor") as monitor:
        response = Client().post(
            "/file", {"upload": SimpleUploadedFile("sample.bin", b"file-secret")}
        )
    assert response.content == b"file-ok"
    assert last_event(monitor)["meta"]["body_unsupported_content_type"]
    assert "file-secret" not in json.dumps(last_event(monitor))


def test_large_body_reaches_application_but_is_omitted():
    with override_settings(LOGUARD_MAX_BODY_BYTES=8), patch(
        "loguard.integrations.django._monitor"
    ) as monitor:
        response = Client().post("/large", b"x" * 100, content_type="application/json")
    assert response.content == b"large-ok"
    assert last_event(monitor)["meta"]["body_too_large"]


def test_cached_body_preserves_django_cache_stream():
    request = request_factory()

    def view(req):
        assert req.body == RAW
        assert req.body == RAW
        return HttpResponse("ok")

    with patch("loguard.integrations.django._monitor") as monitor:
        LoGuardMiddleware(view)(request)
    assert request.body == RAW
    assert request._stream.read() == RAW
    assert last_event(monitor)["meta"]["body"] == {"q": "test"}


def test_preconsumed_request_is_not_reported_as_complete():
    request = request_factory()
    assert request.read(5) == RAW[:5]
    original = request._stream
    with patch("loguard.integrations.django._monitor") as monitor:
        LoGuardMiddleware(lambda req: HttpResponse("ok"))(request)
    assert request._stream is original
    assert request.read() == RAW[5:]
    assert last_event(monitor)["meta"]["body_unavailable"]


def test_private_stream_preconsumption_is_detected_when_seekable():
    request = request_factory()
    request._stream = BytesIO(RAW)
    request._stream.read(5)
    with patch("loguard.integrations.django._monitor") as monitor:
        LoGuardMiddleware(lambda req: (req.read(), HttpResponse("ok"))[1])(request)
    assert last_event(monitor)["meta"]["body_unavailable"]


def test_streaming_response_is_not_buffered_or_iterated():
    request = request_factory()
    chunks = []

    def produce():
        chunks.append("started")
        yield request.read()
        yield b"tail"

    def view(req):
        return StreamingHttpResponse(produce())

    with patch("loguard.integrations.django._monitor") as monitor:
        response = LoGuardMiddleware(view)(request)
    assert chunks == []
    assert last_event(monitor)["meta"]["body_unavailable"]
    assert list(response.streaming_content) == [RAW, b"tail"]
    response.close()


def test_application_exception_is_preserved_and_stream_restored():
    request = request_factory()
    original = request._stream
    error = ValueError("view failure")

    def fail(req):
        raise error

    with patch("loguard.integrations.django._monitor") as monitor:
        with pytest.raises(ValueError) as caught:
            LoGuardMiddleware(fail)(request)
    assert caught.value is error
    assert request._stream is original
    assert last_event(monitor)["status_code"] == 500


@pytest.mark.asyncio
async def test_cancellation_restores_stream_without_inventing_response():
    request = request_factory()
    original = request._stream

    async def cancelled(req):
        raise asyncio.CancelledError()

    with patch("loguard.integrations.django._monitor") as monitor:
        middleware = LoGuardMiddleware(cancelled)
        from asgiref.sync import iscoroutinefunction

        assert iscoroutinefunction(middleware)
        with pytest.raises(asyncio.CancelledError):
            await middleware(request)
    assert request._stream is original
    monitor.event_fire_and_forget.assert_not_called()


def test_collector_failure_does_not_replace_application_response():
    request = request_factory()
    original = request._stream
    response = HttpResponse("ok")
    with patch("loguard.integrations.django._monitor") as monitor:
        monitor.event_fire_and_forget.side_effect = RuntimeError("collector failed")
        assert LoGuardMiddleware(lambda req: response)(request) is response
    assert request._stream is original


def test_lazy_authentication_is_not_evaluated():
    request = request_factory()
    resolve = Mock(side_effect=AssertionError("unexpected authentication lookup"))
    request.user = SimpleLazyObject(resolve)
    with patch("loguard.integrations.django._monitor") as monitor:
        LoGuardMiddleware(lambda req: HttpResponse("ok"))(request)
    resolve.assert_not_called()
    assert last_event(monitor)["user_id"] is None


@pytest.mark.parametrize("cache", ["_cached_user", "_acached_user"])
def test_already_cached_authenticated_user_is_available(cache):
    request = request_factory()
    setattr(request, cache, SimpleNamespace(is_authenticated=True, pk=42))
    with patch("loguard.integrations.django._monitor") as monitor:
        LoGuardMiddleware(lambda req: HttpResponse("ok"))(request)
    assert last_event(monitor)["user_id"] == "42"


def test_rewinding_invalidates_capture_without_changing_reads():
    request = request_factory()
    request._stream = BytesIO(RAW)

    def view(req):
        assert req.read(5) == RAW[:5]
        req._stream.seek(0)
        assert req.read() == RAW
        return HttpResponse("ok")

    with patch("loguard.integrations.django._monitor") as monitor:
        LoGuardMiddleware(view)(request)
    assert last_event(monitor)["meta"]["body_unavailable"]


@pytest.mark.asyncio
async def test_async_streaming_response_is_preserved_without_late_capture():
    request = request_factory()
    started = []

    async def chunks():
        started.append(True)
        yield request.read()
        await asyncio.sleep(0)
        yield b"tail"

    async def view(req):
        return StreamingHttpResponse(chunks())

    with patch("loguard.integrations.django._monitor") as monitor:
        response = await LoGuardMiddleware(view)(request)
    assert started == []
    assert response.is_async
    assert last_event(monitor)["meta"]["body_unavailable"]
    assert [chunk async for chunk in response.streaming_content] == [RAW, b"tail"]
    response.close()

"""Privacy, resource limits and transparent HTTP integration regressions."""
import json
from unittest.mock import Mock, patch

import pytest

from loguard._capture import CapturePolicy
from loguard.integrations.fastapi import LoGuardMiddleware


def test_nested_secrets_and_utf8_limits():
    policy = CapturePolicy()
    raw = json.dumps({"password": "secret", "nested": {"api_key": "secret", "q": "é" * 5000}}).encode()
    result = policy.body(raw, "application/json")
    assert result["body"] == {"nested": {"q": "é" * 2048}}
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("raw,media,expected", [
    (b'{', 'application/json', 'body_parse_error'),
    (b'null', 'application/json', 'body_parse_error'),
    (b'\xff', 'application/json', 'body_parse_error'),
    (b'a' * 32769, 'application/json', 'body_too_large'),
    (b'file', 'multipart/form-data', 'body_unsupported_content_type'),
    (b'{"a":{"b":{}}}', 'application/json', 'body_depth_exceeded'),
])
def test_rejection_reasons(raw, media, expected):
    assert CapturePolicy(max_json_depth=2).body(raw, media) == {expected: True}


def test_form_and_mislabeled_json():
    p = CapturePolicy()
    assert p.body(b'q=test&password=secret', 'application/x-www-form-urlencoded') == {"body": {"q": "test"}}
    assert p.body(b'{"q":"test","token":"secret"}', 'application/x-www-form-urlencoded') == {"body": {"q": "test"}}
    assert p.body(b'{"q":1}', 'application/problem+json') == {"body": {"q": 1}}


def test_query_budget_duplicates_and_secrets():
    p = CapturePolicy()
    assert p.raw_query(b'q=one&q=two&token=secret') == {"query": {"q": "two"}}
    assert p.raw_query(b'x' * 32769) == {"query_too_large": True}
    assert len(p.raw_query('&'.join(f'q{i}=v' for i in range(100)).encode())["query"]) == 64


@pytest.mark.parametrize("kwargs", [{"max_body_bytes": 0}, {"max_json_depth": 33}, {"max_body_bytes": True}])
def test_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        CapturePolicy(**kwargs)


async def run_asgi(app, chunks, *, query=b'q=test&password=secret', content_type=b'application/json'):
    scope = {"type": "http", "http_version": "1.1", "method": "POST", "scheme": "http",
             "path": "/search", "raw_path": b'/search', "query_string": query,
             "headers": [(b'content-type', content_type), (b'authorization', b'secret')],
             "client": ('192.0.2.1', 1234), "server": ('test', 80)}
    sent, received = [], []
    iterator = iter(chunks)
    async def receive():
        msg = next(iterator)
        received.append(msg)
        return msg
    async def send(msg):
        sent.append(msg)
    await app(scope, receive, send)
    return sent, received


@pytest.mark.asyncio
async def test_asgi_preserves_chunked_request_and_response():
    chunks = [{"type": "http.request", "body": b'{"q":', "more_body": True},
              {"type": "http.request", "body": b'"test","password":"secret"}', "more_body": False}]
    async def app(scope, receive, send):
        assert await receive() is chunks[0]
        assert await receive() is chunks[1]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b'one', "more_body": True})
        await send({"type": "http.response.body", "body": b'two', "more_body": False})
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        sent, received = await run_asgi(LoGuardMiddleware(app, security_capture=True, track_headers=['authorization']), chunks)
    assert received == chunks
    assert [m.get('body') for m in sent[1:]] == [b'one', b'two']
    event = monitor.event_fire_and_forget.call_args.kwargs
    assert event['meta']['body'] == {"q": "test"}
    assert event['meta']['query'] == {"q": "test"}
    assert event['type'] == 'http_request'
    assert 'secret' not in json.dumps(event)
    monitor.aevent.assert_not_called()


@pytest.mark.asyncio
async def test_asgi_oversize_body_still_delivered_to_application():
    payload = b'x' * 100
    async def app(scope, receive, send):
        assert (await receive())["body"] == payload
        await send({"type": "http.response.start", "status": 200, "headers": []})
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        await run_asgi(LoGuardMiddleware(app, security_capture=True, max_body_bytes=8),
                       [{"type": "http.request", "body": payload}])
    assert monitor.event_fire_and_forget.call_args.kwargs['meta']['body_too_large']


@pytest.mark.asyncio
async def test_asgi_does_not_read_unconsumed_body_and_ignores_collector_failure():
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        monitor.event_fire_and_forget.side_effect = RuntimeError('collector failure')
        sent, received = await run_asgi(LoGuardMiddleware(app, security_capture=True), [])
    assert not received
    assert sent[0]['status'] == 200
    assert monitor.event_fire_and_forget.call_args.kwargs['meta']['body_unavailable']


@pytest.mark.asyncio
async def test_asgi_exception_is_preserved():
    error = RuntimeError('application failure')
    async def app(scope, receive, send):
        raise error
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        with pytest.raises(RuntimeError) as exc:
            await run_asgi(LoGuardMiddleware(app), [])
    assert exc.value is error
    assert monitor.event_fire_and_forget.call_args.kwargs['status_code'] == 500


@pytest.mark.asyncio
async def test_asgi_empty_status_set_disables_legacy_capture():
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 403, "headers": []})
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        await run_asgi(LoGuardMiddleware(app, track_statuses=set()), [])
    monitor.event_fire_and_forget.assert_not_called()


def django_request():
    from django.conf import settings
    if not settings.configured:
        settings.configure(DEFAULT_CHARSET='utf-8')
    from django.test import RequestFactory
    return RequestFactory().post('/search?q=test&token=secret',
                                 data=b'{"q":"test","password":"secret"}', content_type='application/json')


def test_django_cached_body_and_settings():
    from django.http import HttpResponse
    from django.test import override_settings
    from loguard.integrations.django import LoGuardMiddleware as DjangoMiddleware
    request = django_request()
    def view(req):
        assert json.loads(req.body)['password'] == 'secret'
        return HttpResponse('ok')
    with override_settings(LOGUARD_SECURITY_CAPTURE=True), patch('loguard.integrations.django._monitor') as monitor:
        response = DjangoMiddleware(view)(request)
    assert response.content == b'ok'
    event = monitor.event_fire_and_forget.call_args.kwargs
    assert event['meta']['body'] == {'q': 'test'}
    assert event['meta']['query'] == {'q': 'test'}
    assert 'secret' not in json.dumps(event)


def test_django_unread_stream_is_not_consumed():
    from django.http import HttpResponse
    from loguard.integrations.django import LoGuardMiddleware as DjangoMiddleware
    request = django_request()
    with patch('loguard.integrations.django._monitor') as monitor:
        DjangoMiddleware(lambda req: HttpResponse('ok'), security_capture=True)(request)
    assert not request._read_started
    assert monitor.event_fire_and_forget.call_args.kwargs['meta']['body_unavailable']
    assert request.read().startswith(b'{')


def test_django_empty_statuses_and_failure_isolation():
    from django.http import HttpResponse
    from loguard.integrations.django import LoGuardMiddleware as DjangoMiddleware
    with patch('loguard.integrations.django._monitor') as monitor:
        response = DjangoMiddleware(lambda req: HttpResponse(status=403), track_statuses=set())(django_request())
        monitor.event_fire_and_forget.assert_not_called()
        monitor.event_fire_and_forget.side_effect = RuntimeError('collector failure')
        assert DjangoMiddleware(lambda req: response, security_capture=True)(django_request()) is response


@pytest.mark.parametrize('peer,xff,expected', [
    ('192.0.2.1', '198.51.100.1', '192.0.2.1'),
    ('10.0.0.1', '198.51.100.9, 192.0.2.4', '192.0.2.4'),
    ('10.0.0.1', '192.0.2.4, 10.0.0.2', '192.0.2.4'),
    ('10.0.0.1', 'invalid, 10.0.0.2', '10.0.0.1'),
    ('10.0.0.1', ','.join(['10.0.0.2'] * 65), '10.0.0.1'),
])
def test_proxy_chain_stops_at_untrusted_hop(peer, xff, expected):
    from loguard._ip_utils import _parse_trusted_proxies, _resolve_proxy_chain
    assert _resolve_proxy_chain(peer, xff, _parse_trusted_proxies(['10.0.0.0/8'])) == expected


@pytest.mark.asyncio
async def test_real_starlette_request_body_and_streaming_response():
    import httpx
    from starlette.applications import Starlette
    from starlette.responses import StreamingResponse
    from starlette.routing import Route
    async def endpoint(request):
        assert (await request.json())['password'] == 'secret'
        async def chunks():
            yield b'first'
            yield b'second'
        return StreamingResponse(chunks())
    app = Starlette(routes=[Route('/search', endpoint, methods=['POST'])])
    app.add_middleware(LoGuardMiddleware, security_capture=True)
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            response = await client.post('/search', json={'q': 'test', 'password': 'secret'})
    assert response.content == b'firstsecond'
    assert monitor.event_fire_and_forget.call_args.kwargs['meta']['body'] == {'q': 'test'}


@pytest.mark.asyncio
async def test_non_http_scope_passes_through_unchanged():
    scope = {'type': 'lifespan'}
    receive, send = Mock(), Mock()
    async def app(actual_scope, actual_receive, actual_send):
        assert (actual_scope, actual_receive, actual_send) == (scope, receive, send)
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        await LoGuardMiddleware(app)(scope, receive, send)
    monitor.event_fire_and_forget.assert_not_called()


@pytest.mark.asyncio
async def test_partial_body_is_not_parsed():
    async def app(scope, receive, send):
        await receive()
        await send({'type': 'http.response.start', 'status': 401, 'headers': []})
    with patch('loguard.integrations.fastapi._monitor') as monitor:
        await run_asgi(LoGuardMiddleware(app, security_capture=True),
                       [{'type': 'http.request', 'body': b'{"q":', 'more_body': True}])
    event = monitor.event_fire_and_forget.call_args.kwargs
    assert event['type'] == 'login_failed'
    assert event['meta']['body_unavailable']
    assert 'body' not in event['meta']


def test_background_worker_batches_without_network():
    from loguard.monitor import _Monitor
    monitor = _Monitor()
    event = object()
    monitor._faf_q.put(event)
    monitor._faf_submitted = 1
    monitor._send_events_sync = Mock(side_effect=lambda batch: monitor._faf_stop.set())
    monitor._faf_worker()
    monitor._send_events_sync.assert_called_once_with([event])

"""The browser sensor is added to HTML pages by apply_token / apply_cookies.

Runs against real Flask, Django and Starlette response objects when those are
installed; each framework's tests are skipped otherwise.
"""
import asyncio
from types import SimpleNamespace

import pytest
from moonito import Config, VisitorTrafficFiltering

PAGE = '<!DOCTYPE html><html><head><title>Shop</title></head><body>Halo ñ 😀</body></html>'
ALLOW = {'data': {'status': {'need_to_block': False}, 'decision_id': 'd1', 'nonce': 'n1'}}


def client(**options):
    sdk = VisitorTrafficFiltering(Config(is_protected=True, api_public_key='pub_123', api_secret_key='sec', **options))
    sdk._request_analytics_api = lambda *a, **k: ALLOW
    return sdk


def request(**headers):
    base = {'Host': 'shop.example', 'User-Agent': 'browser', 'Accept': 'text/html'}
    base.update(headers)
    return SimpleNamespace(headers=base, remote_addr='185.137.164.30', host='shop.example',
                           url='https://shop.example/', path='/', full_path='/', method='GET',
                           cookies={}, scheme='https')


def count(body):
    return (body.decode('utf-8') if isinstance(body, bytes) else body).count('data-guard-sensor')


def test_insert_sensor_rules():
    sdk = client()
    out = sdk.insert_sensor(PAGE)
    assert out.count('data-guard-sensor') == 1
    assert 'sensor@1.1.1/t.js' in out and 'data-key="pub_123"' in out and 'integrity="sha384-' in out
    assert out.index('data-guard-sensor') < out.index('</head>')
    assert sdk.insert_sensor(out) is None, 'never twice'
    assert sdk.insert_sensor(PAGE.replace('<title>', '<meta http-equiv="Content-Security-Policy" content="x"><title>')) is None




def test_flask_page_gets_the_sensor_and_json_does_not():
    flask = pytest.importorskip('flask')
    sdk = client()

    assert sdk.evaluate_visitor(request()) is None
    response = sdk.apply_token(flask.Response(PAGE, mimetype='text/html'))
    assert count(response.get_data()) == 1
    assert int(response.headers['Content-Length']) == len(response.get_data())
    assert 'Halo ñ 😀' in response.get_data(as_text=True)
    assert response.headers.getlist('Set-Cookie'), 'context cookie still set'

    sdk.evaluate_visitor(request())
    response = sdk.apply_token(flask.Response('{"a":"</head>"}', mimetype='application/json'))
    assert count(response.get_data()) == 0

    sdk.evaluate_visitor(request())
    response = flask.Response(PAGE, mimetype='text/html')
    response.headers['Content-Security-Policy'] = "script-src 'self'"
    assert count(sdk.apply_token(response).get_data()) == 0

    sdk.evaluate_visitor(request())
    assert count(sdk.apply_token(flask.Response(PAGE, status=500, mimetype='text/html')).get_data()) == 0


def test_api_calls_assets_blocks_and_the_off_switch_get_nothing():
    flask = pytest.importorskip('flask')

    sdk = client()
    for headers in ({'Accept': 'application/json'}, {'X-Requested-With': 'XMLHttpRequest'}, {'Sec-Fetch-Dest': 'image'}):
        sdk.evaluate_visitor(request(**headers))
        assert count(sdk.apply_token(flask.Response(PAGE, mimetype='text/html')).get_data()) == 0, headers

    blocked = client()
    blocked._request_analytics_api = lambda *a, **k: {'data': {'status': {'need_to_block': True}}}
    assert blocked.evaluate_visitor(request())['need_to_block'] is True
    assert count(blocked.apply_token(flask.Response(PAGE, mimetype='text/html')).get_data()) == 0

    off = client(inject_sensor=False)
    off.evaluate_visitor(request())
    assert count(off.apply_token(flask.Response(PAGE, mimetype='text/html')).get_data()) == 0


def test_api_failure_lets_the_visitor_in_with_the_sensor():
    flask = pytest.importorskip('flask')
    sdk = client()

    def down(*a, **k):
        raise OSError('unreachable')

    sdk._request_analytics_api = down
    assert sdk.evaluate_visitor(request()) is None
    assert count(sdk.apply_token(flask.Response(PAGE, mimetype='text/html')).get_data()) == 1


def test_a_response_without_a_check_gets_nothing():
    flask = pytest.importorskip('flask')
    # apply_token called without evaluate_visitor in this request.
    assert count(client().apply_token(flask.Response(PAGE, mimetype='text/html')).get_data()) == 0


def test_django_response():
    pytest.importorskip('django')
    from django.conf import settings
    if not settings.configured:
        settings.configure(DEFAULT_CHARSET='utf-8')
    from django.http import HttpResponse, StreamingHttpResponse

    sdk = client()
    sdk.evaluate_visitor(request())
    response = HttpResponse(PAGE, content_type='text/html; charset=utf-8')
    response['Content-Length'] = str(len(response.content))
    response = sdk.apply_token(response)
    assert count(response.content) == 1
    assert int(response['Content-Length']) == len(response.content)

    sdk.evaluate_visitor(request())
    streaming = sdk.apply_token(StreamingHttpResponse(iter([PAGE]), content_type='text/html'))
    assert count(b''.join(streaming.streaming_content)) == 0, 'streamed responses are left alone'


def test_fastapi_style_streaming_and_plain_starlette_responses():
    pytest.importorskip('starlette')
    from starlette.responses import HTMLResponse, StreamingResponse

    sdk = client()
    result, cookies = sdk.evaluate_with_cookies(request())
    assert result is None

    async def chunks():
        yield PAGE[:30].encode()
        yield PAGE[30:].encode()

    streamed = StreamingResponse(chunks(), media_type='text/html')
    streamed.headers['content-length'] = str(len(PAGE.encode()))
    streamed = sdk.apply_cookies(streamed, cookies)
    assert 'content-length' not in streamed.headers

    async def collect(iterator):
        return b''.join([c async for c in iterator])

    body = asyncio.run(collect(streamed.body_iterator))
    assert count(body) == 1 and body.decode().endswith('</body></html>')

    result, cookies = sdk.evaluate_with_cookies(request())
    plain = sdk.apply_cookies(HTMLResponse(PAGE), cookies)
    assert count(plain.body) == 1
    assert int(plain.headers['content-length']) == len(plain.body)

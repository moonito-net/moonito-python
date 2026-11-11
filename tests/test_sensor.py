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
    param = sdk.relay_param()
    assert 'src="?%s=s&amp;v=1.2.0"' % param in out and 'data-key="pub_123"' in out and 'data-p="%s"' % param in out
    assert 'moonito' not in out.lower() and 'jsdelivr' not in out
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
    response.headers['Content-Security-Policy'] = "script-src https://cdn.example"
    assert count(sdk.apply_token(response).get_data()) == 0

    sdk.evaluate_visitor(request())
    response = flask.Response(PAGE, mimetype='text/html')
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    out = sdk.apply_token(response).get_data(as_text=True)
    assert count(out) == 1 and 'data-endpoint="/"' in out, 'a self policy must still get the sensor'

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


def relay_request(kind, method='GET', body=b'', **headers):
    sdk = client()
    req = request(**headers)
    req.method = method
    req.args = {sdk.relay_param(): kind}
    req.get_data = lambda cache=True: body
    return sdk, req


def test_relay_requests_are_answered_without_a_decision():
    flask = pytest.importorskip('flask')
    from moonito.sensor_script import SENSOR_SCRIPT

    calls = []
    sdk, req = relay_request('s')
    sdk._request_analytics_api = lambda *a, **k: calls.append(1) or ALLOW
    result = sdk.evaluate_visitor(req)
    assert result['sensor'] is True and result['content'] == SENSOR_SCRIPT
    response = sdk.apply_token(flask.Response(result['content'], mimetype='text/html'))
    assert response.headers['Content-Type'].startswith('application/javascript')
    assert 'immutable' in response.headers['Cache-Control']
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'moonito' not in response.get_data(as_text=True).lower()
    assert b'<script' not in response.get_data(), 'the script itself must not get a sensor tag'

    sdk2, ping = relay_request('p')
    sdk2._request_analytics_api = lambda *a, **k: calls.append(1) or ALLOW
    assert sdk2.evaluate_visitor(ping)['content'] == 204
    assert calls == [], 'a sensor request must not cost a decision'


def test_a_beacon_is_forwarded_off_the_request_thread():
    import threading
    sent = []
    done = threading.Event()
    sdk, req = relay_request('t', method='POST', body=b'{"k":"pub_123"}')
    sdk.relay_beacon = lambda ip, beacon: (sent.append((ip, beacon)), done.set())
    assert sdk.evaluate_visitor(req)['content'] == 204
    assert done.wait(2)
    assert sent == [('185.137.164.30', '{"k":"pub_123"}')]

    oversized_sdk, oversized = relay_request('t', method='POST', body=b'x' * 9000)
    oversized_sdk.relay_beacon = lambda ip, beacon: sent.append('oversized')
    oversized_sdk.evaluate_visitor(oversized)
    assert 'oversized' not in sent


def test_wrong_method_generic_or_foreign_parameter_is_just_a_page():
    sdk, req = relay_request('t', method='GET')
    assert sdk.evaluate_visitor(req) is None

    sdk = client()
    req = request()
    req.args = {'__vt': 's'}
    assert sdk.evaluate_visitor(req) is None

    other = VisitorTrafficFiltering(Config(is_protected=True, api_public_key='pub_456', api_secret_key='sec'))
    assert other.relay_param() != client().relay_param()


def test_relay_on_django_and_starlette_responses():
    pytest.importorskip('django')
    from django.conf import settings
    if not settings.configured:
        settings.configure(DEFAULT_CHARSET='utf-8')
    from django.http import HttpResponse

    sdk, req = relay_request('s')
    result = sdk.evaluate_visitor(req)
    response = sdk.apply_token(HttpResponse(result['content']))
    assert response['Content-Type'].startswith('application/javascript')

    pytest.importorskip('starlette')
    from starlette.responses import Response
    sdk, req = relay_request('s')
    result, cookies = sdk.evaluate_with_cookies(req)
    response = sdk.apply_cookies(Response(content=result['content'], media_type='text/html'), cookies)
    assert response.headers['content-type'].startswith('application/javascript')


def test_beacon_is_sent_to_the_relay_endpoint():
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading, json as _json
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.headers['X-Secret-Key'], _json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    sdk = VisitorTrafficFiltering(Config(is_protected=True, api_public_key='pub_123', api_secret_key='sec',
                                         endpoint='http://127.0.0.1:%d' % server.server_port))
    sdk.relay_beacon('203.0.113.9', '{"k":"pub_123"}')
    server.server_close()
    assert received == [('/api/v2/telemetry/relay', 'sec', {'ip': '203.0.113.9', 'p': '{"k":"pub_123"}'})]

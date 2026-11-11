import asyncio
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from types import SimpleNamespace
from urllib.parse import unquote

import pytest
from moonito import Config, VisitorTrafficFiltering


def request(identity='visitor'):
    return SimpleNamespace(headers={'Host': 'example.com', 'User-Agent': 'browser'},
                           remote_addr='185.137.164.30', host='example.com',
                           url='https://example.com/private', path='/private', full_path='/private',
                           method='GET', cookies={'__mo_ct': identity}, scheme='https')


def client(**options):
    return VisitorTrafficFiltering(Config(is_protected=True, api_public_key='dummy', api_secret_key='dummy', **options))


class Response:
    def __init__(self):
        self.cookies = {'session': ('existing', {})}

    def set_cookie(self, name, value, **options):
        self.cookies[name] = (value, options)


def verdict(identity='visitor', block=False, **extra):
    return {'data': {'status': {'need_to_block': block}, 'decision_id': identity,
                     'nonce': 'nonce-' + identity, 'set_client_token': {'value': 'token-' + identity}, **extra}}


@pytest.fixture
def api():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            received.append(body)
            # Same count/length limits as DecisionRequest in the application.
            valid = all(len(body.get(k, '')) <= n for k, n in
                        [('ua', 2048), ('events', 4096), ('method', 16), ('path', 512)])
            valid = valid and len(body.get('headers', {})) <= 64
            valid = valid and all(len(v) <= 2048 for v in body.get('headers', {}).values())
            self.send_response(200 if valid else 422)
            self.end_headers()
            self.wfile.write(json.dumps(verdict(block=True) if valid else {'error': {'message': 'validation'}}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield 'http://127.0.0.1:' + str(server.server_port), received
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.mark.parametrize('overflow', ['headers', 'path', 'ua', 'method', 'combined'])
def test_real_http_contract_still_blocks(api, overflow):
    endpoint, received = api
    sdk = client(endpoint=endpoint)
    req = request()
    if overflow in ('headers', 'combined'):
        req.headers.update({'X-Test-' + str(i): '😀' * 3000 for i in range(100)})
        req.headers.update({'Authorization': 'secret', 'Cookie': 'session', 'Proxy-Authorization': 'secret'})
    if overflow in ('path', 'combined'):
        req.path = req.full_path = '/' + '😀' * 5000
    if overflow in ('ua', 'combined'):
        req.headers['User-Agent'] = '😀' * 3000
    if overflow in ('method', 'combined'):
        req.method = 'A' * 30
    result = sdk.evaluate_visitor(req)
    assert result and result['need_to_block'] is True
    assert len(received) == 1
    assert not ({n.lower() for n in received[0].get('headers', {})} & {'cookie', 'authorization', 'proxy-authorization'})


def test_context_without_new_identity_and_cookie_consumed_once():
    sdk = client()
    sdk._request_analytics_api = lambda *a, **kw: verdict(set_client_token=None)
    assert sdk.evaluate_visitor(request()) is None
    response = sdk.apply_token(Response())
    assert unquote(response.cookies['__mo_cx'][0]) == 'visitor:nonce-visitor'
    assert response.cookies['__mo_cx'][1]['max_age'] == 120
    assert response.cookies['__mo_cx'][1]['secure'] is True
    assert 'session' in response.cookies and '__mo_ct' not in response.cookies
    assert '__mo_cx' not in sdk.apply_token(Response()).cookies


def test_concurrent_threadpool_snapshot_never_crosses_visitors():
    sdk = client()
    sdk._request_analytics_api = lambda *a, **kw: verdict(kw['client_token'])

    async def run():
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = await asyncio.gather(*[loop.run_in_executor(pool, sdk.evaluate_with_cookies, request(str(i))) for i in range(80)])
        for i, (result, cookies) in enumerate(results):
            assert result is None
            response = sdk.apply_cookies(Response(), cookies)
            assert response.cookies['__mo_ct'][0] == 'token-' + str(i)
            assert unquote(response.cookies['__mo_cx'][0]) == str(i) + ':nonce-' + str(i)

    asyncio.run(run())


def test_concurrent_async_contexts_are_isolated():
    sdk = client()
    sdk._request_analytics_api = lambda *a, **kw: verdict(kw['client_token'])

    async def one(i):
        sdk.evaluate_visitor(request(str(i)))
        await asyncio.sleep(0)
        response = sdk.apply_token(Response())
        assert response.cookies['__mo_ct'][0] == 'token-' + str(i)

    async def run():
        await asyncio.gather(*(one(i) for i in range(80)))
    asyncio.run(run())


def test_unusual_response_does_not_break_application():
    sdk = client()
    sdk._request_analytics_api = lambda *a, **kw: verdict()
    sdk.evaluate_visitor(request())
    response = object()
    assert sdk.apply_token(response) is response


@pytest.mark.parametrize('action, expected', [('allow', None), ('block', True), ('challenge', True)])
def test_challenge_behavior(action, expected):
    sdk = client(challenge_action=action)
    sdk._request_analytics_api = lambda *a, **kw: verdict(challenge_url='https://challenge.example/check')
    result = sdk.evaluate_visitor(request())
    assert (bool(result) if result else None) == expected
    if action == 'challenge':
        assert 'sessionStorage' in result['content']


@pytest.mark.parametrize('reply', [{'error': {'message': 'expired'}}, ValueError('network')])
def test_api_failure_clears_pending_cookies_and_keeps_fail_open(reply):
    sdk = client()
    sdk._request_analytics_api = lambda *a, **kw: verdict()
    sdk.evaluate_visitor(request())
    def fail(*a, **kw):
        if isinstance(reply, Exception):
            raise reply
        return reply
    sdk._request_analytics_api = fail
    assert sdk.evaluate_visitor(request()) is None
    assert set(sdk.apply_token(Response()).cookies) == {'session'}

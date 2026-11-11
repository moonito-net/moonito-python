"""
Moonito Visitor Traffic Filtering Package for Python
"""

import urllib.parse
import urllib.request
import http.client
import ipaddress
import json
from html import escape as html_escape
import re
import logging
import secrets
import hmac
import hashlib
import threading
from .sensor_script import SENSOR_SCRIPT, SENSOR_VERSION as RELAY_SENSOR_VERSION
from contextvars import ContextVar
from typing import Optional, Dict, Any, Union
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger('moonito')

# Only reaching the API is timed. Once connected the SDK waits for the decision
# however long it takes, because a check that gives up early lets the visitor
# through unchecked, and blocking them is the reason this library is installed.
CONNECT_TIMEOUT_SECONDS = 10

# Used only for fetching the unwanted-visitor page (action 3).
REQUEST_TIMEOUT_SECONDS = 15

# Cloudflare's published edge ranges. CF-Connecting-IP is only read from these.
CLOUDFLARE_RANGES = [ipaddress.ip_network(r) for r in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
)]


class Config:
    """Configuration for Visitor Traffic Filtering"""
    def __init__(
        self,
        is_protected: bool,
        api_public_key: str,
        api_secret_key: str,
        unwanted_visitor_to: Optional[str] = None,
        unwanted_visitor_action: Optional[int] = None,
        challenge_action: str = 'allow',
        endpoint: Optional[str] = None,
        trusted_proxies: Optional[list] = None,
        inject_sensor: bool = True
    ):
        self.is_protected = is_protected
        self.api_public_key = api_public_key
        self.api_secret_key = api_secret_key
        self.unwanted_visitor_to = unwanted_visitor_to
        self.unwanted_visitor_action = unwanted_visitor_action
        self.endpoint = endpoint

        # Public proxy or load balancer addresses whose X-Forwarded-For may be
        # believed. Private addresses and Cloudflare need no listing.
        self.trusted_proxies = trusted_proxies or []

        # Add the browser sensor to HTML pages in apply_token/apply_cookies,
        # so there is no second script to paste. Pages that are compressed,
        # carry a Content-Security-Policy, or already have it are left alone.
        self.inject_sensor = inject_sensor

        # What to do when the engine asks for a challenge.
        #
        #   allow      treat it as an allow and log it. The default.
        #   block      treat it as a block.
        #   challenge  actually show the interstitial.
        #
        # The default is 'allow' on purpose, matching the PHP SDK. Turning a
        # scored challenge into a real page interruption changes what a visitor
        # sees, and that is the site owner's decision, not a side effect of
        # taking an upgrade.
        self.challenge_action = challenge_action


class VisitorTrafficFiltering:
    """Main class for handling visitor traffic filtering"""
    
    BYPASS_HEADER = 'X-VTF-Bypass'
    BYPASS_TOKEN_HEADER = 'X-VTF-Token'
    
    def __init__(self, config: Config):
        """
        Initialize the VisitorTrafficFiltering handler.
        
        Args:
            config: Configuration object with protection settings and API keys
        """
        self.config = config
        self.bypass_token = self._generate_secure_token()

        # Isolated across both worker threads and concurrent async requests.
        self._token = ContextVar('moonito_token', default=None)
        self._context_cookie = ContextVar('moonito_context', default=None)
        self._sensor = ContextVar('moonito_sensor', default=False)
        self._relay = ContextVar('moonito_relay', default=None)
        self._page_path = ContextVar('moonito_page_path', default='')

    @property
    def pending_token(self):
        return self._token.get()

    @pending_token.setter
    def pending_token(self, value):
        self._token.set(value)
    
    def apply_token(self, response):
        """Set identity and sensor context cookies on a framework response.

        Call this once per request, after evaluate_visitor. It is a no-op when
        there is nothing to set, so it is safe to call unconditionally.
        """
        cookies = tuple(c for c in (self.pending_token, self._context_cookie.get(), self._sensor_marker(), self._relay_marker()) if c)
        self.pending_token = None
        self._context_cookie.set(None)
        self._sensor.set(False)
        self._relay.set(None)
        return self.apply_cookies(response, cookies)

    def evaluate_with_cookies(self, request):
        """Return (verdict, cookies) together when checking in a thread pool.

        Context changes inside a worker do not propagate to the async caller.
        Pass this explicit snapshot to apply_cookies in the calling task.
        """
        result = self.evaluate_visitor(request)
        cookies = tuple(c.copy() for c in (self.pending_token, self._context_cookie.get(), self._sensor_marker(), self._relay_marker()) if c)
        self.pending_token = None
        self._context_cookie.set(None)
        self._sensor.set(False)
        self._relay.set(None)
        return result, cookies

    def apply_cookies(self, response, cookies):
        """Apply the cookie snapshot returned by evaluate_with_cookies."""
        for descriptor in cookies:
            if descriptor.get('sensor'):
                self._add_sensor(response, descriptor.get('path') or '')
                continue
            if descriptor.get('relay'):
                self._shape_relay_response(response, descriptor['relay'])
                continue
            try:
                response.set_cookie(
                    descriptor['name'], descriptor['value'],
                    max_age=descriptor['max_age'], path='/', samesite='Lax',
                    secure=descriptor.get('secure', False), httponly=False,
                )
            except Exception:
                logger.warning('moonito: response did not accept the %s cookie', descriptor.get('name', 'Moonito'))
        return response

    # A sensor tag pasted by hand from the CDN; recognised so it is never doubled.
    SENSOR_PATH = '/gh/moonito-net/sensor@'
    MAX_BEACON = 8192
    SENSOR_MARKER = 'data-guard-sensor'
    SENSOR_MAX_BYTES = 5 * 1024 * 1024

    def relay_param(self) -> str:
        """The query parameter the sensor's requests use on this site.

        Derived from the public key, so every site has its own: no URL pattern
        an ad blocker list could match across customers, and no clash with the
        site's own parameters. Same rule in every SDK.
        """
        digest = hashlib.sha256(('sensor|' + str(self.config.api_public_key)).encode('utf-8')).hexdigest()
        return '_' + digest[:7]

    def _query_value(self, request, name: str) -> Optional[str]:
        for attr in ('args', 'GET', 'query_params'):  # Flask, Django, Starlette
            source = getattr(request, attr, None)
            if source is not None and hasattr(source, 'get'):
                try:
                    value = source.get(name)
                except Exception:
                    value = None
                if value is not None:
                    return str(value)
        return None

    def _relay_kind(self, request) -> Optional[str]:
        kind = self._query_value(request, self.relay_param())
        method = str(getattr(request, 'method', 'GET') or 'GET').upper()
        if kind in ('s', 'p'):
            return kind if method in ('GET', 'HEAD') else None
        return 't' if kind == 't' and method == 'POST' else None

    def _request_body(self, request) -> bytes:
        try:
            if hasattr(request, 'get_data'):  # Flask
                return request.get_data(cache=True) or b''
            body = getattr(request, 'body', None)  # Django
            if isinstance(body, (bytes, bytearray)):
                return bytes(body)
            cached = getattr(request, '_body', None)  # Starlette, once read with await request.body()
            if isinstance(cached, (bytes, bytearray)):
                return bytes(cached)
        except Exception:
            pass
        return b''

    def _answer_relay(self, kind: str, request) -> Dict[str, Any]:
        """The integration returns this like any answered request; apply_token
        or apply_cookies then gives it the right headers."""
        self._relay.set(kind)

        if kind == 's':
            return {'need_to_block': True, 'sensor': True, 'detect_activity': None, 'content': SENSOR_SCRIPT}

        if kind == 't':
            beacon = self._request_body(request)[:self.MAX_BEACON + 1]
            if beacon and len(beacon) <= self.MAX_BEACON:
                ip = self._get_client_ip(request)
                # After the browser has its answer, off the request thread.
                threading.Thread(target=self.relay_beacon, args=(ip, beacon.decode('utf-8', 'replace')), daemon=True).start()

        return {'need_to_block': True, 'sensor': True, 'detect_activity': None, 'content': 204}

    def relay_beacon(self, ip: str, beacon: str) -> None:
        """Forward a sensor beacon to Moonito, server to server. Two seconds at most; never raises."""
        if not self._is_valid_ip(ip) or not beacon:
            return
        try:
            body = json.dumps({'ip': ip, 'p': beacon}).encode('utf-8')
            req = urllib.request.Request(self._endpoint() + '/api/v2/telemetry/relay', data=body, method='POST', headers={
                'Content-Type': 'application/json',
                'User-Agent': f'Moonito-Python/{self.VERSION}',
                'X-Public-Key': self.config.api_public_key,
                'X-Secret-Key': self.config.api_secret_key,
            })
            with urllib.request.urlopen(req, timeout=2) as response:
                response.read()
        except Exception as error:
            logger.debug('moonito: sensor beacon not forwarded: %s', error)

    def _relay_marker(self):
        kind = self._relay.get()
        return {'relay': kind} if kind else None

    @staticmethod
    def _set_header(response, name: str, value: str) -> None:
        headers = getattr(response, 'headers', None)
        try:
            if headers is not None:
                headers[name] = value
            else:
                response[name] = value
        except Exception:
            try:
                response[name] = value
            except Exception:
                pass

    def _shape_relay_response(self, response, kind: str) -> None:
        if kind == 's':
            if hasattr(response, 'mimetype'):
                try:
                    response.mimetype = 'application/javascript'
                except Exception:
                    pass
            self._set_header(response, 'Content-Type', 'application/javascript; charset=utf-8')
            # Versioned URL, so the browser keeps it for a year.
            self._set_header(response, 'Cache-Control', 'public, max-age=31536000, immutable')
            self._set_header(response, 'X-Content-Type-Options', 'nosniff')
        else:
            self._set_header(response, 'Cache-Control', 'no-store, private')

    def _sensor_marker(self):
        if self._sensor.get() and getattr(self.config, 'inject_sensor', True) and self.config.api_public_key:
            return {'sensor': True, 'path': self._page_path.get()}
        return None

    def _wants_page(self, request) -> bool:
        """A page request, not an API call or an asset."""
        method = str(getattr(request, 'method', 'GET') or 'GET').upper()
        if method not in ('GET', 'POST'):
            return False
        if (self._header(request, 'X-Requested-With') or '').lower() == 'xmlhttprequest':
            return False
        accept = (self._header(request, 'Accept') or '').lower()
        if accept and 'text/html' not in accept and '*/*' not in accept:
            return False
        dest = (self._header(request, 'Sec-Fetch-Dest') or '').lower()
        return dest in ('', 'document', 'iframe')

    def insert_sensor(self, html: str, path: str = '') -> Optional[str]:
        """The page with the sensor tag added, or None to leave it alone."""
        if not html or self.SENSOR_PATH in html or self.SENSOR_MARKER in html:
            return None
        if re.search(r'<meta[^>]+http-equiv\s*=\s*["\']?content-security-policy', html, re.I):
            return None
        key = html_escape(str(self.config.api_public_key), quote=True)
        param = self.relay_param()
        # Served by this SDK from the page's own URL (_answer_relay): no other
        # host, nothing that names the service.
        at = html_escape(path, quote=True)
        tag = '<script defer src="%s?%s=s&amp;v=%s"%s data-key="%s" data-p="%s" %s></script>' % (
            at, param, RELAY_SENSOR_VERSION, (' data-endpoint="%s"' % at) if at else '', key, param, self.SENSOR_MARKER)
        head = re.search(r'</head>', html, re.I)
        if head:
            return html[:head.start()] + tag + html[head.start():]
        body = re.search(r'<body\b[^>]*>', html, re.I)
        if body:
            return html[:body.end()] + tag + html[body.end():]
        return None

    @staticmethod
    def _response_header(response, name: str) -> Optional[str]:
        headers = getattr(response, 'headers', None)
        try:
            if headers is not None and hasattr(headers, 'get'):
                value = headers.get(name)
                if value is None:
                    value = headers.get(name.lower())
                return value
            if hasattr(response, 'get'):
                return response.get(name)
        except Exception:
            return None
        return None

    def _sensor_target(self, response) -> bool:
        """Whether this response is a whole HTML page we may touch."""
        status = int(getattr(response, 'status_code', 200) or 200)
        if status < 200 or status >= 300 or status == 204:
            return False
        content_type = (self._response_header(response, 'Content-Type') or '').lower()
        if 'text/html' not in content_type:
            return False
        if self._response_header(response, 'Content-Encoding'):
            return False
        if not self._csp_allows_self(self._response_header(response, 'Content-Security-Policy')):
            return False
        if 'attachment' in (self._response_header(response, 'Content-Disposition') or '').lower():
            return False
        return True

    @staticmethod
    def _csp_allows_self(header) -> bool:
        """The sensor is served from the site itself, so 'self' for scripts and
        requests is all it needs. Nonce or 'strict-dynamic' policies are left alone."""
        if not header:
            return True
        directives = {}
        for part in str(header).split(';'):
            tokens = part.strip().split()
            if tokens and tokens[0].lower() not in directives:
                directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
        script = directives.get('script-src-elem') or directives.get('script-src') or directives.get('default-src')
        connect = directives.get('connect-src') or directives.get('default-src')

        def allows(sources):
            return sources is None or ("'none'" not in sources and ("'self'" in sources or '*' in sources))

        return not (script and "'strict-dynamic'" in script) and allows(script) and allows(connect)

    def _safe_path(self, request) -> str:
        """This page's own path, known to reach this SDK. Written into the tag so
        the sensor always comes back to it, even with a <base href> or after a
        single-page app changes the address."""
        path = str(self._get_path(request) or '/').split('?', 1)[0]
        return path if re.match(r'^/[^\s"<>\\]{0,2047}$', path) else '/'

    def _with_sensor(self, body, path: str = '') -> Optional[bytes]:
        if isinstance(body, str):
            body = body.encode('utf-8')
        if not isinstance(body, (bytes, bytearray)) or not body or len(body) > self.SENSOR_MAX_BYTES:
            return None
        try:
            changed = self.insert_sensor(bytes(body).decode('utf-8'), path)
        except UnicodeDecodeError:
            return None
        return changed.encode('utf-8') if changed is not None else None

    def _add_sensor(self, response, path: str = '') -> None:
        """Insert the sensor into a Flask, Django or Starlette response. Never raises."""
        try:
            if not self._sensor_target(response):
                return

            # Flask / Werkzeug
            if hasattr(response, 'get_data') and hasattr(response, 'set_data'):
                if getattr(response, 'direct_passthrough', False) or getattr(response, 'is_streamed', False):
                    return
                new = self._with_sensor(response.get_data(), path)
                if new is not None:
                    response.set_data(new)
                return

            # Django
            if hasattr(response, 'streaming') and hasattr(response, 'content'):
                if response.streaming:
                    return
                new = self._with_sensor(response.content, path)
                if new is not None:
                    response.content = new
                    if response.has_header('Content-Length'):
                        response['Content-Length'] = str(len(new))
                return

            # Starlette / FastAPI: what call_next returns streams its body.
            if hasattr(response, 'body_iterator'):
                original = response.body_iterator
                limit = self.SENSOR_MAX_BYTES
                add = self._with_sensor

                async def with_sensor():
                    chunks, size = [], 0
                    async for chunk in original:
                        if isinstance(chunk, str):
                            chunk = chunk.encode('utf-8')
                        chunks.append(chunk)
                        size += len(chunk)
                        if size > limit:
                            for held in chunks:
                                yield held
                            async for rest in original:
                                yield rest
                            return
                    body = b''.join(chunks)
                    new = add(body, path)
                    yield new if new is not None else body

                response.body_iterator = with_sensor()
                if 'content-length' in response.headers:
                    del response.headers['content-length']
                return

            # Starlette Response built in full
            if isinstance(getattr(response, 'body', None), (bytes, bytearray)):
                new = self._with_sensor(response.body, path)
                if new is not None:
                    response.body = new
                    response.headers['content-length'] = str(len(new))
        except Exception as error:
            logger.warning('moonito: sensor not added: %s', error)

    def _generate_secure_token(self) -> str:
        """Generate a secure random token for bypass validation"""
        return secrets.token_hex(32)
    
    def _is_valid_bypass_token(self, token: Optional[str]) -> bool:
        """
        Validate if the bypass token is correct using timing-safe comparison
        
        Args:
            token: The token to validate
            
        Returns:
            True if token is valid, False otherwise
        """
        if not token:
            return False
        try:
            return hmac.compare_digest(token, self.bypass_token)
        except Exception:
            return False
    
    def evaluate_visitor(self, request) -> Optional[Dict[str, Any]]:
        """
        Evaluate a visitor request (for Flask/Django/FastAPI).
        
        Args:
            request: The request object from your web framework
            
        Returns:
            Dictionary with blocking information or None if visitor is allowed
            
        Never raises. When the check cannot run (unreachable API, a refusal
        such as an expired plan, an unreadable address) the visitor is let
        through and the reason goes to the 'moonito' logger. Raising here used
        to turn a protection problem into a 500 for every visitor.
        """
        try:
            return self._evaluate_visitor(request)
        except Exception as error:
            logger.warning('moonito: check could not run, visitor allowed: %s', error)
            return None

    def _evaluate_visitor(self, request) -> Optional[Dict[str, Any]]:
        self.pending_token = None
        self._context_cookie.set(None)
        self._sensor.set(False)
        self._relay.set(None)

        if not self.config.is_protected:
            return None

        # The browser sensor's own requests (script, timing, beacon) come to
        # this same URL with a parameter only this site uses. Answered here,
        # before any decision, so the browser only ever talks to this site.
        relay = self._relay_kind(request) if getattr(self.config, 'inject_sensor', True) else None
        if relay is not None:
            return self._answer_relay(relay, request)
        
        # Check for valid bypass token
        bypass_header = self._header(request, self.BYPASS_HEADER)
        token_header = self._header(request, self.BYPASS_TOKEN_HEADER)
        
        if bypass_header == '1' and self._is_valid_bypass_token(token_header):
            return None
        
        # Get current URL
        current_url = self._get_current_url(request)
        
        # Skip filtering if current URL matches the unwantedVisitorTo
        if self.config.unwanted_visitor_to and self._urls_match(
            current_url, self.config.unwanted_visitor_to
        ):
            return None
        
        # Extract request information
        client_ip = self._get_client_ip(request)
        user_agent = self._header(request, 'User-Agent') or ''
        url = self._get_path(request)
        domain = self._get_host(request)

        if not self._is_valid_ip(client_ip):
            raise ValueError("could not determine the visitor IP")

        # Set before the API call, so a visitor let through because the check
        # could not run still gets the sensor. Cleared again on a block.
        self._sensor.set(self._wants_page(request))
        self._page_path.set(self._safe_path(request))

        response_data = self._request_analytics_api(
            client_ip, user_agent, url, domain,
            client_token=self._read_client_token(request),
            request_headers=self._collect_headers(request),
            challenge_pass=self._read_challenge_pass(request),
            method=getattr(request, 'method', None),
            path=url,
        )

        if response_data.get('error'):
            error_msg = response_data['error'].get('message', 'Unknown error')
            if isinstance(error_msg, list):
                error_msg = ', '.join(error_msg)
            raise Exception(f"API refused the check: {error_msg}")

        # Kept per request context so a caller can apply it to whatever
        # response their framework ends up sending. Without this the
        # visitor is anonymous on every request and the detectors that
        # reason across requests never get anything to work with.
        self.pending_token = self.client_token_cookie(response_data)
        data = response_data.get('data', {})
        secure = str(getattr(request, 'scheme', '') or urlparse(current_url).scheme) == 'https'
        if self.pending_token:
            self.pending_token['secure'] = secure
        if data.get('decision_id') and data.get('nonce'):
            self._context_cookie.set({
                'name': '__mo_cx',
                'value': urllib.parse.quote(str(data['decision_id']) + ':' + str(data['nonce']), safe=''),
                'max_age': 120, 'secure': secure,
            })

        need_to_block = response_data.get('data', {}).get('status', {}).get('need_to_block', False)
        detect_activity = response_data.get('data', {}).get('status', {}).get('detect_activity')

        if need_to_block:
            self._sensor.set(False)
            return {
                'need_to_block': True,
                'detect_activity': detect_activity,
                'content': self._get_blocked_content()
            }

        # A challenge is outranked by a block, so it is only considered
        # once the visitor was not blocked outright.
        challenge_url = response_data.get('data', {}).get('challenge_url')

        if isinstance(challenge_url, str) and challenge_url:
            action = getattr(self.config, 'challenge_action', 'allow')

            if action == 'challenge':
                self._sensor.set(False)
                return {
                    'need_to_block': False,
                    'challenge': True,
                    'detect_activity': detect_activity,
                    'content': self.challenge_html(request, challenge_url),
                }

            if action == 'block':
                self._sensor.set(False)
                return {
                    'need_to_block': True,
                    'detect_activity': detect_activity,
                    'content': self._get_blocked_content(),
                }

            # 'allow' falls through: the verdict is logged server side and
            # the visitor is not interrupted.

        return None

    def evaluate_visitor_manually(
        self, ip: str, user_agent: str, event: str, domain: str
    ) -> Dict[str, Any]:
        """
        Manually evaluate visitor data using provided parameters.
        
        Args:
            ip: The IP address of the visitor
            user_agent: The user agent string of the visitor
            event: The event/path associated with the visitor
            domain: The domain to be sent to the analytics API
            
        Returns:
            Dictionary containing need_to_block, detect_activity, and content
            
        Never raises: when the check cannot run the visitor is reported as
        allowed and the reason goes to the 'moonito' logger.
        """
        try:
            return self._evaluate_visitor_manually(ip, user_agent, event, domain)
        except Exception as error:
            logger.warning('moonito: check could not run, visitor allowed: %s', error)
            return {'need_to_block': False, 'detect_activity': None, 'content': None}

    def _evaluate_visitor_manually(
        self, ip: str, user_agent: str, event: str, domain: str
    ) -> Dict[str, Any]:
        if not self.config.is_protected:
            return {
                'need_to_block': False,
                'detect_activity': None,
                'content': None
            }
        
        # Skip filtering if event path matches the unwantedVisitorTo
        if self.config.unwanted_visitor_to:
            if event.startswith('http://') or event.startswith('https://'):
                current_url = event
            else:
                normalized_path = event if event.startswith('/') else f'/{event}'
                current_url = f'https://{domain}{normalized_path}'
            
            if self._urls_match(current_url, self.config.unwanted_visitor_to):
                return {
                    'need_to_block': False,
                    'detect_activity': None,
                    'content': None
                }
        
        if not self._is_valid_ip(ip):
            raise ValueError("Invalid IP address.")

        response_data = self._request_analytics_api(ip, user_agent, event, domain)

        if response_data.get('error'):
            error_msg = response_data['error'].get('message', 'Unknown error')
            if isinstance(error_msg, list):
                error_msg = ', '.join(error_msg)
            raise Exception(f"API refused the check: {error_msg}")

        need_to_block = response_data.get('data', {}).get('status', {}).get('need_to_block', False)
        detect_activity = response_data.get('data', {}).get('status', {}).get('detect_activity')

        if need_to_block:
            return {
                'need_to_block': True,
                'detect_activity': detect_activity,
                'content': self._get_blocked_content()
            }

        return {
            'need_to_block': False,
            'detect_activity': detect_activity,
            'content': None
        }

    VERSION = '2.4.0'
    IDENTITY_COOKIE = '__mo_ct'
    PASS_COOKIE = '__mo_pass'

    def challenge_html(self, request, challenge_url: str) -> str:
        """The page that carries the visitor to the challenge and back.

        A plain redirect would be simpler and would lose every POST. Somebody
        halfway through a checkout would return to an empty form and blame the
        site, so the body is stashed in sessionStorage on the customer's own
        origin and replayed when the challenge sends them back.

        The stash cannot hold a file input, because script cannot put a file
        back into a form. That is said plainly rather than silently dropped.
        """
        method = str(getattr(request, 'method', 'GET') or 'GET').upper()
        fields = self._flatten_body(request) if method == 'POST' else {}

        content_type = ''

        try:
            content_type = request.headers.get('Content-Type', '') or ''
        except Exception:
            content_type = ''

        has_upload = method == 'POST' and content_type.startswith('multipart/form-data')

        stash = json.dumps({
            'u': str(getattr(request, 'full_path', None) or getattr(request, 'path', '/') or '/'),
            'm': method,
            'f': fields,
        })

        note = ('<p>You will need to choose your file again after this check.</p>'
                if has_upload else '')

        # Encoded twice: once for the value, once so the result is a JavaScript
        # string literal, then < is escaped so it cannot close the script tag.
        payload = json.dumps(stash).replace('<', '\\u003c')
        target = json.dumps(challenge_url).replace('<', '\\u003c')

        return (
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta name="robots" content="noindex, nofollow">'
            '<title>Checking your browser</title></head>'
            '<body><p>Checking your browser before you continue.</p>' + note +
            '<script>(function(){try{sessionStorage.setItem("__mo_resume",' +
            payload + ');}catch(e){}location.replace(' + target + ');})();</script>'
            '<noscript><p>JavaScript is required to continue.</p></noscript>'
            '</body></html>'
        )

    def _flatten_body(self, request) -> Dict[str, str]:
        """Form fields as name/value pairs, capped.

        A body big enough to fill sessionStorage would break the resume rather
        than help it, so anything past the cap is dropped and the visitor
        retypes it. That beats a page that silently fails to load.
        """
        out: Dict[str, str] = {}

        try:
            form = getattr(request, 'form', None)

            if form is None:
                return out

            items = form.lists() if hasattr(form, 'lists') else form.items()

            for name, value in items:
                if len(out) >= 200:
                    break

                if isinstance(value, (list, tuple)):
                    value = value[0] if value else ''

                text = str(value)

                if len(text) <= 8192:
                    out[str(name)] = text
        except Exception:
            # A framework whose request object works differently. The visitor
            # still gets the challenge, they just retype the form.
            return {}

        return out

    def _request_analytics_api(
        self, ip: str, user_agent: str, event: str, domain: str,
        client_token: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        challenge_pass: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ask the decision API what to do with this visitor.

        v2 rather than v1, because v1 has no way to say "challenge". The two
        endpoints are metered the same and return the same body; v2 adds
        challenge_url, decision_id and nonce. On v1 a challenge verdict
        collapses to allow before it reaches the caller, since the server will
        not hand back an instruction the client cannot carry out. A v1 SDK
        therefore lets a suspected rotating proxy through while the log records
        it as challenged, which reads like the visitor was stopped when they
        were not.
        """
        body: Dict[str, Any] = {
            'ip': ip,
            'ua': user_agent[:2048],
            'events': event[:4096],
            'domain': domain,
            'sdk': f'python/{self.VERSION}',
        }

        if client_token:
            body['client_token'] = client_token

        # Proof this visitor already solved a challenge. Without it they are
        # asked again on the very next request, which is a loop.
        if challenge_pass:
            body['challenge_pass'] = challenge_pass

        if method:
            body['method'] = method[:16]

        if path:
            body['path'] = path[:512]

        headers_out = {}
        for name, value in (request_headers or {}).items():
            if str(name).lower() in ('cookie', 'authorization', 'proxy-authorization'):
                continue
            if isinstance(value, str):
                headers_out[name] = value[:2048]
                if len(headers_out) >= 64:
                    break

        if headers_out:
            body['headers'] = headers_out

        payload = json.dumps(body).encode('utf-8')
        url = f'{self._endpoint()}/api/v2/decision'

        headers = {
            'User-Agent': f'Moonito-Python/{self.VERSION}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Public-Key': self.config.api_public_key,
            'X-Secret-Key': self.config.api_secret_key,
        }

        parsed = urlparse(url)
        connection_class = http.client.HTTPConnection if parsed.scheme == 'http' else http.client.HTTPSConnection
        connection = connection_class(parsed.hostname, parsed.port, timeout=CONNECT_TIMEOUT_SECONDS)

        try:
            connection.connect()
            # Connected: from here on wait for the decision however long it takes.
            connection.sock.settimeout(None)
            connection.request('POST', parsed.path, body=payload, headers=headers)
            response = connection.getresponse()
            data = response.read().decode('utf-8')
        except (OSError, http.client.HTTPException) as e:
            raise Exception(f"API request failed: {str(e)}")
        finally:
            connection.close()

        try:
            decoded = json.loads(data)
        except ValueError:
            raise Exception(f"API answered HTTP {response.status} without JSON")

        if not isinstance(decoded, dict):
            raise Exception(f"API answered HTTP {response.status} with an unexpected body")

        return decoded

    def _endpoint(self) -> str:
        configured = getattr(self.config, 'endpoint', None)

        if isinstance(configured, str) and configured:
            return configured.rstrip('/')

        return 'https://moonito.net'

    def _read_challenge_pass(self, request) -> Optional[str]:
        """The proof that this visitor already passed a challenge.

        Forwarded without validation. The pass is signed with the domain
        secret, so checking it here would mean reimplementing the MAC in every
        language. The server checks it and a forged one simply fails there.
        """
        try:
            cookies = getattr(request, 'cookies', None) or getattr(request, 'COOKIES', None) or {}
            value = cookies.get(self.PASS_COOKIE)
        except Exception:
            return None

        if not isinstance(value, str) or not value or len(value) > 1024:
            return None

        return value

    def _read_client_token(self, request) -> Optional[str]:
        """The visitor's identity token, if they are carrying one.

        Read without any attempt to validate it. The SDK cannot: the signing
        key is server side and shipping it to every install would make it
        public. Possessing a token confers no trust, it only tells the API
        whose history to consult, so passing a forged one along is harmless.
        """
        try:
            cookies = getattr(request, 'cookies', None) or getattr(request, 'COOKIES', None) or {}
            value = cookies.get(self.IDENTITY_COOKIE)
        except Exception:
            return None

        if not isinstance(value, str) or not value or len(value) > 96:
            return None

        return value

    def _collect_headers(self, request) -> Dict[str, str]:
        """The request headers, for server side fingerprinting."""
        try:
            items = dict(getattr(request, 'headers', {}) or {})
        except Exception:
            return {}

        out = {}

        for name, value in items.items():
            # Never forward the visitor's own credentials.
            if str(name).lower() in ('cookie', 'authorization', 'proxy-authorization'):
                continue

            if isinstance(value, str):
                out[str(name)] = value

        return out

    def client_token_cookie(self, response_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """The cookie the caller should set, or None.

        Returned rather than set, because this SDK does not know whether it is
        inside Flask, Django or something else. The framework adapters call
        this and set it their own way.
        """
        descriptor = (response_data or {}).get('data', {}).get('set_client_token')

        if not isinstance(descriptor, dict) or not descriptor.get('value'):
            return None

        return {
            'name': descriptor.get('name', self.IDENTITY_COOKIE),
            'value': descriptor['value'],
            'max_age': int(descriptor.get('max_age') or 7776000),
            'path': '/',
            'samesite': 'Lax',
            'httponly': False,
        }

    def _get_blocked_content(self) -> Union[int, str]:
        """Return content for blocked visitors based on configuration"""
        if self.config.unwanted_visitor_to:
            # Check if it's a status code
            try:
                status_code = int(self.config.unwanted_visitor_to)
                if 100 <= status_code <= 599:
                    return status_code
                return 500
            except ValueError:
                pass
            
            if self.config.unwanted_visitor_action == 2:
                # Return iframe
                return f'''<iframe src="{self.config.unwanted_visitor_to}" width="100%" height="100%" align="left"></iframe>
                    <style>body {{ padding: 0; margin: 0; }} iframe {{ margin: 0; padding: 0; border: 0; }}</style>'''
            elif self.config.unwanted_visitor_action == 3:
                # Fetch and return content
                try:
                    return self._http_request_with_bypass(self.config.unwanted_visitor_to)
                except Exception as error:
                    print(f"Error fetching content: {error}")
                    return '<p>Content not available</p>'
            else:
                # Return redirect HTML
                return f'''
                <p>Redirecting to <a href="{self.config.unwanted_visitor_to}">{self.config.unwanted_visitor_to}</a></p>
                <script>
                    setTimeout(function() {{
                        window.location.href = "{self.config.unwanted_visitor_to}";
                    }}, 1000);
                </script>'''
        
        return '<p>Access Denied!</p>'
    
    def _http_request_with_bypass(self, url: str) -> str:
        """Make an HTTP request with bypass headers to prevent loops"""
        headers = {
            self.BYPASS_HEADER: '1',
            self.BYPASS_TOKEN_HEADER: self.bypass_token
        }
        
        req = urllib.request.Request(url, headers=headers)
        
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return response.read().decode('utf-8')
        except (urllib.error.URLError, TimeoutError) as e:
            raise Exception(f"Request failed: {str(e)}")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate if an IP address is valid (IPv4 or IPv6)"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _header(self, request, name: str) -> Optional[str]:
        """A request header, case-insensitively, on Flask, Django or Starlette."""
        headers = getattr(request, 'headers', None)

        if headers is not None:
            try:
                value = headers.get(name)
                if value is None:
                    value = headers.get(name.lower())
                if value is not None:
                    return value
            except Exception:
                pass

        meta = getattr(request, 'META', None)

        if isinstance(meta, dict):
            return meta.get('HTTP_' + name.upper().replace('-', '_'))

        return None

    def _remote_addr(self, request) -> str:
        """The address that actually connected, on Flask, Django or Starlette."""
        remote = getattr(request, 'remote_addr', None)

        if not remote:
            meta = getattr(request, 'META', None)
            if isinstance(meta, dict):
                remote = meta.get('REMOTE_ADDR')

        if not remote:
            client = getattr(request, 'client', None)
            remote = getattr(client, 'host', None)

        return str(remote or '')

    def _get_path(self, request) -> str:
        url = getattr(request, 'url', None)

        if url is not None and hasattr(url, 'path') and not isinstance(url, str):
            return url.path or '/'

        return getattr(request, 'path', None) or '/'

    def _get_host(self, request) -> str:
        host = None
        get_host = getattr(request, 'get_host', None)

        if callable(get_host):
            try:
                host = get_host()
            except Exception:
                host = None

        if not host:
            host = getattr(request, 'host', None)

        if not host or not isinstance(host, str):
            host = self._header(request, 'Host') or ''

        host = host.lower()

        if host.startswith('['):
            return host.split(']')[0] + ']'

        return host.rsplit(':', 1)[0] if host.count(':') == 1 else host

    def _ip(self, value: str):
        try:
            ip = ipaddress.ip_address(value.strip().strip('[]'))
        except ValueError:
            return None

        mapped = getattr(ip, 'ipv4_mapped', None)

        return mapped or ip

    def _in_ranges(self, ip, ranges) -> bool:
        for network in ranges:
            if ip.version == network.version and ip in network:
                return True

        return False

    def _trusted_networks(self):
        networks = []

        for entry in getattr(self.config, 'trusted_proxies', None) or []:
            try:
                networks.append(ipaddress.ip_network(str(entry), strict=False))
            except ValueError:
                continue

        return networks

    def _get_client_ip(self, request) -> str:
        """The visitor's address.

        Forwarded headers are set by whoever makes the request, so they are
        only believed when the connection came from a proxy: a private address,
        one listed in trusted_proxies, or Cloudflare for CF-Connecting-IP.
        Taking the first X-Forwarded-For value as before let a bot claim any
        clean address it liked.
        """
        remote = self._ip(self._remote_addr(request))

        if remote is None:
            return ''

        trusted = self._trusted_networks()
        from_cloudflare = self._in_ranges(remote, CLOUDFLARE_RANGES)
        from_proxy = from_cloudflare or remote.is_private or remote.is_loopback or self._in_ranges(remote, trusted)

        if not from_proxy:
            return str(remote)

        if from_cloudflare:
            cf = self._ip(self._header(request, 'CF-Connecting-IP') or '')
            if cf is not None:
                return str(cf)

        forwarded = self._header(request, 'X-Forwarded-For') or ''

        for part in reversed(forwarded.split(',')):
            candidate = self._ip(part)

            if candidate is None:
                continue

            if candidate.is_private or candidate.is_loopback or self._in_ranges(candidate, trusted) \
                    or self._in_ranges(candidate, CLOUDFLARE_RANGES):
                continue

            return str(candidate)

        return str(remote)

    def _get_current_url(self, request) -> str:
        """Get the current full URL from the request"""
        scheme = getattr(request, 'scheme', None)
        if not isinstance(scheme, str):
            scheme = getattr(getattr(request, 'url', None), 'scheme', None) or 'http'

        query = getattr(request, 'query_string', None)
        if isinstance(query, bytes):
            query = query.decode('utf-8', 'replace')
        elif not isinstance(query, str):
            query = getattr(getattr(request, 'url', None), 'query', None) \
                or (getattr(request, 'META', None) or {}).get('QUERY_STRING', '') or ''

        url = f"{scheme}://{self._get_host(request)}{self._get_path(request)}"
        if query:
            url += f"?{query}"

        return url
    
    def _urls_match(self, current_url: str, target_url: str) -> bool:
        """
        Compare two URLs to check if they match.
        Handles both full URLs and relative paths.
        """
        try:
            # If targetUrl is a full URL
            if target_url.startswith('http://') or target_url.startswith('https://'):
                current_parsed = urlparse(current_url)
                target_parsed = urlparse(target_url)
                
                # Compare host and path, ignoring protocol
                return (current_parsed.netloc == target_parsed.netloc and
                        current_parsed.path == target_parsed.path and
                        current_parsed.query == target_parsed.query)
            
            # If targetUrl is a relative path
            current_parsed = urlparse(current_url)
            current_path = current_parsed.path
            if current_parsed.query:
                current_path += f"?{current_parsed.query}"
            
            return current_path == target_url or current_parsed.path == target_url
            
        except Exception:
            # Fallback to simple string comparison
            return target_url in current_url

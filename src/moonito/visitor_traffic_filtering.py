"""
Moonito Visitor Traffic Filtering Package for Python
"""

import urllib.parse
import urllib.request
import http.client
import ipaddress
import json
import logging
import secrets
import hmac
import threading
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
        trusted_proxies: Optional[list] = None
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

        # Per thread, so on a threaded server one visitor's identity cookie can
        # never be handed to another visitor's response.
        self._local = threading.local()

    @property
    def pending_token(self):
        return getattr(self._local, 'pending_token', None)

    @pending_token.setter
    def pending_token(self, value):
        self._local.pending_token = value
    
    def apply_token(self, response):
        """Set the identity cookie on a framework response, if one is due.

        Call this once per request, after evaluate_visitor. It is a no-op when
        there is nothing to set, so it is safe to call unconditionally.
        """
        descriptor = getattr(self, 'pending_token', None)

        if not descriptor:
            return response

        self.pending_token = None

        try:
            response.set_cookie(
                descriptor['name'],
                descriptor['value'],
                max_age=descriptor['max_age'],
                path='/',
                samesite='Lax',
            )
        except Exception:
            # A framework whose response object works differently. The visitor
            # simply stays anonymous, which is a supported mode.
            pass

        return response

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

        if not self.config.is_protected:
            return None
        
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

        # Kept per thread so a caller can apply it to whatever
        # response their framework ends up sending. Without this the
        # visitor is anonymous on every request and the detectors that
        # reason across requests never get anything to work with.
        self.pending_token = self.client_token_cookie(response_data)

        need_to_block = response_data.get('data', {}).get('status', {}).get('need_to_block', False)
        detect_activity = response_data.get('data', {}).get('status', {}).get('detect_activity')

        if need_to_block:
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
                return {
                    'need_to_block': False,
                    'challenge': True,
                    'detect_activity': detect_activity,
                    'content': self.challenge_html(request, challenge_url),
                }

            if action == 'block':
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

    VERSION = '2.2.0'
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
            'ua': user_agent,
            'events': event,
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
            body['method'] = method

        if path:
            body['path'] = path

        headers_out = {
            name: value
            for name, value in (request_headers or {}).items()
            if isinstance(value, str) and len(value) <= 2048
        }

        if headers_out:
            body['headers'] = headers_out

        payload = json.dumps(body).encode('utf-8')
        url = f'{self._endpoint()}/api/v2/decision'

        headers = {
            'User-Agent': user_agent,
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
"""
Moonito Visitor Traffic Filtering Package for Python
"""

import urllib.parse
import urllib.request
import json
import secrets
import hmac
from typing import Optional, Dict, Any, Union
from urllib.parse import urlparse, parse_qs

# urlopen without a timeout inherits the global default socket timeout, which
# is None, so a call could wait indefinitely and the visitor's page waited with
# it. The install snippet already promised callers "bounded timeouts"; this is
# what makes that true.
#
# Generous rather than tight: a check that gives up early is recorded as "could
# not run" and the visitor is let through unchecked, which is the failure this
# library exists to prevent.
REQUEST_TIMEOUT_SECONDS = 15


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
        endpoint: Optional[str] = None
    ):
        self.is_protected = is_protected
        self.api_public_key = api_public_key
        self.api_secret_key = api_secret_key
        self.unwanted_visitor_to = unwanted_visitor_to
        self.unwanted_visitor_action = unwanted_visitor_action
        self.endpoint = endpoint

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
            
        Raises:
            Exception: If there's an issue with the IP address or API request
        """
        if not self.config.is_protected:
            return None
        
        # Check for valid bypass token
        bypass_header = request.headers.get(self.BYPASS_HEADER.lower())
        token_header = request.headers.get(self.BYPASS_TOKEN_HEADER.lower())
        
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
        user_agent = request.headers.get('User-Agent', '')
        url = request.path
        domain = request.host.lower() if hasattr(request, 'host') else ''
        
        if not self._is_valid_ip(client_ip):
            raise ValueError("Invalid IP address.")
        
        try:
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
                raise Exception(f"Requesting analytics error: {error_msg}")
            
            # Kept on the instance so a caller can apply it to whatever
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
            
        except Exception as error:
            print(f"Error handling visitor: {error}")
            raise Exception(f"Error handling visitor: {str(error)}")
    
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
            
        Raises:
            Exception: If there's an issue with the IP address or API request
        """
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
        
        try:
            response_data = self._request_analytics_api(ip, user_agent, event, domain)
            
            if response_data.get('error'):
                error_msg = response_data['error'].get('message', 'Unknown error')
                if isinstance(error_msg, list):
                    error_msg = ', '.join(error_msg)
                raise Exception(f"Requesting analytics error: {error_msg}")
            
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
            
        except Exception as error:
            print(f"Error handling visitor manually: {error}")
            raise Exception(f"Error handling visitor manually: {str(error)}")
    
    VERSION = '2.0.0'
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

        req = urllib.request.Request(url, data=payload, headers=headers, method='POST')

        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                data = response.read().decode('utf-8')
                return json.loads(data)
        except (urllib.error.URLError, TimeoutError) as e:
            # A connect timeout arrives wrapped in URLError, a read timeout as
            # a bare TimeoutError. Both mean the same thing to the caller.
            raise Exception(f"API request failed: {str(e)}")

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
            cookies = getattr(request, 'cookies', None) or {}
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
            cookies = getattr(request, 'cookies', None) or {}
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
    
    def _get_client_ip(self, request) -> str:
        """Extract client IP from request, considering proxies"""
        # Try X-Forwarded-For first (for proxied requests)
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            # X-Forwarded-For can contain multiple IPs, get the first one
            return forwarded.split(',')[0].strip()
        
        # Fall back to remote_addr
        return getattr(request, 'remote_addr', '127.0.0.1')
    
    def _get_current_url(self, request) -> str:
        """Get the current full URL from the request"""
        scheme = request.scheme if hasattr(request, 'scheme') else 'http'
        host = request.host if hasattr(request, 'host') else ''
        path = request.path if hasattr(request, 'path') else ''
        query = request.query_string.decode('utf-8') if hasattr(request, 'query_string') else ''
        
        url = f"{scheme}://{host}{path}"
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
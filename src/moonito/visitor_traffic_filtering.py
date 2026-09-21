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


class Config:
    """Configuration for Visitor Traffic Filtering"""
    def __init__(
        self,
        is_protected: bool,
        api_public_key: str,
        api_secret_key: str,
        unwanted_visitor_to: Optional[str] = None,
        unwanted_visitor_action: Optional[int] = None
    ):
        self.is_protected = is_protected
        self.api_public_key = api_public_key
        self.api_secret_key = api_secret_key
        self.unwanted_visitor_to = unwanted_visitor_to
        self.unwanted_visitor_action = unwanted_visitor_action


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

    def _request_analytics_api(
        self, ip: str, user_agent: str, event: str, domain: str,
        client_token: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make a request to the analytics API.

        client_token and request_headers are optional and additive. They are
        what the rotation detectors need: without them the API can only judge a
        request on its own address and user agent, which is exactly what a
        rotating residential pool is built to defeat. A caller that sends
        neither gets the same answer it has always got.
        """
        params = {
            'ip': ip,
            'ua': user_agent,
            'events': event,
            'domain': domain,
            'sdk': f'python/{self.VERSION}',
        }

        if client_token:
            params['client_token'] = client_token

        for name, value in (request_headers or {}).items():
            if isinstance(value, str) and len(value) <= 2048:
                params[f'headers[{name}]'] = value

        query_params = urllib.parse.urlencode(params)
        
        url = f'https://moonito.net/api/v1/analytics?{query_params}'
        
        headers = {
            'User-Agent': user_agent,
            'X-Public-Key': self.config.api_public_key,
            'X-Secret-Key': self.config.api_secret_key,
        }
        
        req = urllib.request.Request(url, headers=headers)
        
        try:
            with urllib.request.urlopen(req) as response:
                data = response.read().decode('utf-8')
                return json.loads(data)
        except urllib.error.URLError as e:
            raise Exception(f"API request failed: {str(e)}")
    
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
            with urllib.request.urlopen(req) as response:
                return response.read().decode('utf-8')
        except urllib.error.URLError as e:
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
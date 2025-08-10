"""
HTTP client utility for VulnMind
"""

import asyncio
import aiohttp
import ssl
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin
import time

from vulnmind.core.models import HttpRequest, HttpResponse, ScanConfig
from vulnmind.utils.logger import get_logger

logger = get_logger(__name__)


class HttpClient:
    """Async HTTP client for vulnerability scanning"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.follow_redirects = config.follow_redirects
        self.request_count = 0
        self.total_response_time = 0.0
        
        # Configure SSL context
        self.ssl_context = self._create_ssl_context()
        
        # Configure connector
        self.connector_kwargs = {
            'ssl': self.ssl_context,
            'limit': config.max_concurrent_requests * 2,  # Connection pool size
            'limit_per_host': config.max_concurrent_requests,
            'ttl_dns_cache': 300,  # DNS cache TTL
            'use_dns_cache': True,
        }
        
        # Default headers
        self.default_headers = {
            'User-Agent': config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Add custom headers from config
        self.default_headers.update(config.headers)
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context based on configuration"""
        context = ssl.create_default_context()
        
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        return context
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self.session is None or self.session.closed:
            # Configure timeout
            timeout = aiohttp.ClientTimeout(
                total=self.config.request_timeout * 2,
                connect=self.config.request_timeout,
                sock_read=self.config.request_timeout
            )
            
            # Create connector
            connector = aiohttp.TCPConnector(**self.connector_kwargs)
            
            # Create session
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.default_headers,
                cookies=self.config.cookies,
                auto_decompress=True
            )
        
        return self.session
    
    async def get(self, url: str, params: Dict[str, str] = None, 
                  headers: Dict[str, str] = None, **kwargs) -> Optional[HttpResponse]:
        """Perform GET request"""
        return await self._request('GET', url, params=params, headers=headers, **kwargs)
    
    async def post(self, url: str, data: Dict[str, str] = None, 
                   json_data: Dict[str, Any] = None, headers: Dict[str, str] = None, 
                   **kwargs) -> Optional[HttpResponse]:
        """Perform POST request"""
        return await self._request('POST', url, data=data, json=json_data, headers=headers, **kwargs)
    
    async def put(self, url: str, data: Dict[str, str] = None, 
                  json_data: Dict[str, Any] = None, headers: Dict[str, str] = None, 
                  **kwargs) -> Optional[HttpResponse]:
        """Perform PUT request"""
        return await self._request('PUT', url, data=data, json=json_data, headers=headers, **kwargs)
    
    async def delete(self, url: str, headers: Dict[str, str] = None, 
                     **kwargs) -> Optional[HttpResponse]:
        """Perform DELETE request"""
        return await self._request('DELETE', url, headers=headers, **kwargs)
    
    async def head(self, url: str, headers: Dict[str, str] = None, 
                   **kwargs) -> Optional[HttpResponse]:
        """Perform HEAD request"""
        return await self._request('HEAD', url, headers=headers, **kwargs)
    
    async def options(self, url: str, headers: Dict[str, str] = None, 
                      **kwargs) -> Optional[HttpResponse]:
        """Perform OPTIONS request"""
        return await self._request('OPTIONS', url, headers=headers, **kwargs)
    
    async def _request(self, method: str, url: str, **kwargs) -> Optional[HttpResponse]:
        """Perform HTTP request with error handling and rate limiting"""
        session = await self._get_session()
        start_time = time.time()
        
        try:
            # Prepare request parameters
            request_kwargs = self._prepare_request_kwargs(kwargs)
            
            # Add proxy if configured
            if self.config.proxy:
                request_kwargs['proxy'] = self.config.proxy
            
            # Handle redirects
            request_kwargs['allow_redirects'] = self.follow_redirects
            
            # Perform request
            async with session.request(method, url, **request_kwargs) as response:
                # Read response content
                text_content = await response.text()
                
                # Calculate response time
                elapsed = time.time() - start_time
                self.total_response_time += elapsed
                self.request_count += 1
                
                # Extract cookies
                cookies = {}
                for cookie in response.cookies.values():
                    cookies[cookie.key] = cookie.value
                
                # Create response object
                http_response = HttpResponse(
                    status=response.status,
                    headers=dict(response.headers),
                    text=text_content,
                    url=str(response.url),
                    elapsed=elapsed,
                    cookies=cookies
                )
                
                # Log request details
                logger.debug(f"{method} {url} -> {response.status} ({elapsed:.2f}s)")
                
                return http_response
                
        except asyncio.TimeoutError:
            logger.warning(f"Request timeout: {method} {url}")
            return None
        
        except aiohttp.ClientError as e:
            logger.warning(f"Client error: {method} {url} - {str(e)}")
            return None
        
        except Exception as e:
            logger.error(f"Unexpected error: {method} {url} - {str(e)}")
            return None
    
    def _prepare_request_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare request kwargs, merging with defaults"""
        request_kwargs = {}
        
        # Handle headers
        headers = self.default_headers.copy()
        if 'headers' in kwargs and kwargs['headers']:
            headers.update(kwargs['headers'])
        request_kwargs['headers'] = headers
        
        # Handle parameters
        if 'params' in kwargs:
            request_kwargs['params'] = kwargs['params']
        
        # Handle data
        if 'data' in kwargs:
            request_kwargs['data'] = kwargs['data']
        
        # Handle JSON data
        if 'json' in kwargs:
            request_kwargs['json'] = kwargs['json']
        
        # Handle files
        if 'files' in kwargs:
            request_kwargs['data'] = kwargs['files']
        
        # Handle authentication
        if self.config.authentication:
            auth_type = self.config.authentication.get('type', 'basic')
            if auth_type == 'basic':
                import aiohttp
                username = self.config.authentication.get('username')
                password = self.config.authentication.get('password')
                if username and password:
                    request_kwargs['auth'] = aiohttp.BasicAuth(username, password)
            elif auth_type == 'bearer':
                token = self.config.authentication.get('token')
                if token:
                    if 'headers' not in request_kwargs:
                        request_kwargs['headers'] = {}
                    request_kwargs['headers']['Authorization'] = f"Bearer {token}"
        
        return request_kwargs
    
    async def test_connectivity(self, url: str) -> bool:
        """Test basic connectivity to URL"""
        try:
            response = await self.head(url)
            return response is not None and 200 <= response.status < 500
        except Exception:
            try:
                # Fallback to GET request
                response = await self.get(url)
                return response is not None and 200 <= response.status < 500
            except Exception:
                return False
    
    async def detect_technologies(self, url: str) -> Dict[str, List[str]]:
        """Detect web technologies used by the target"""
        technologies = {
            'web_servers': [],
            'frameworks': [],
            'languages': [],
            'databases': [],
            'cms': []
        }
        
        try:
            response = await self.get(url)
            if not response:
                return technologies
            
            # Analyze headers
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Web servers
            if 'server' in headers:
                server = headers['server'].lower()
                if 'apache' in server:
                    technologies['web_servers'].append('Apache')
                elif 'nginx' in server:
                    technologies['web_servers'].append('Nginx')
                elif 'iis' in server:
                    technologies['web_servers'].append('IIS')
                elif 'lighttpd' in server:
                    technologies['web_servers'].append('Lighttpd')
            
            # Frameworks and languages
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by'].lower()
                if 'php' in powered_by:
                    technologies['languages'].append('PHP')
                elif 'asp.net' in powered_by:
                    technologies['frameworks'].append('ASP.NET')
                    technologies['languages'].append('C#')
                elif 'express' in powered_by:
                    technologies['frameworks'].append('Express')
                    technologies['languages'].append('Node.js')
            
            # Analyze response content
            content_lower = response.text.lower()
            
            # CMS detection
            cms_signatures = {
                'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
                'drupal': ['drupal.js', 'sites/default', 'misc/drupal.js'],
                'joomla': ['joomla', 'administrator/components', 'templates/system'],
                'magento': ['mage/cookies.js', 'skin/frontend', 'magento']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content_lower for sig in signatures):
                    technologies['cms'].append(cms.title())
            
            # Framework detection
            framework_signatures = {
                'react': ['react', 'reactjs'],
                'vue': ['vue.js', 'vuejs'],
                'angular': ['angular', 'ng-'],
                'jquery': ['jquery'],
                'bootstrap': ['bootstrap']
            }
            
            for framework, signatures in framework_signatures.items():
                if any(sig in content_lower for sig in signatures):
                    technologies['frameworks'].append(framework.title())
            
            # Language detection from content
            if '<?php' in content_lower:
                technologies['languages'].append('PHP')
            if 'jsp:' in content_lower or '.jsp' in content_lower:
                technologies['languages'].append('JSP')
            if 'asp:' in content_lower or '.aspx' in content_lower:
                technologies['languages'].append('ASP.NET')
        
        except Exception as e:
            logger.debug(f"Technology detection failed: {str(e)}")
        
        return technologies
    
    async def check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check for security headers"""
        security_analysis = {
            'present_headers': {},
            'missing_headers': [],
            'security_score': 0
        }
        
        try:
            response = await self.get(url)
            if not response:
                return security_analysis
            
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Security headers to check
            security_headers = {
                'strict-transport-security': 'HSTS',
                'content-security-policy': 'CSP',
                'x-frame-options': 'X-Frame-Options',
                'x-content-type-options': 'X-Content-Type-Options',
                'x-xss-protection': 'X-XSS-Protection',
                'referrer-policy': 'Referrer-Policy',
                'permissions-policy': 'Permissions-Policy'
            }
            
            score = 0
            for header, name in security_headers.items():
                if header in headers:
                    security_analysis['present_headers'][name] = headers[header]
                    score += 1
                else:
                    security_analysis['missing_headers'].append(name)
            
            security_analysis['security_score'] = (score / len(security_headers)) * 100
        
        except Exception as e:
            logger.debug(f"Security header check failed: {str(e)}")
        
        return security_analysis
    
    def get_stats(self) -> Dict[str, Any]:
        """Get HTTP client statistics"""
        avg_response_time = (self.total_response_time / self.request_count 
                           if self.request_count > 0 else 0)
        
        return {
            'total_requests': self.request_count,
            'total_response_time': self.total_response_time,
            'average_response_time': avg_response_time,
            'requests_per_second': (self.request_count / self.total_response_time 
                                  if self.total_response_time > 0 else 0)
        }
    
    async def close(self):
        """Close HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()

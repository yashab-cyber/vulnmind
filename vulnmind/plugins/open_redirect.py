"""
Open Redirect detection plugin
"""

from typing import List, Dict, Any
from urllib.parse import urlparse

from vulnmind.plugins.base import ParameterPlugin
from vulnmind.core.models import VulnType, SeverityLevel


class OpenRedirectPlugin(ParameterPlugin):
    """Open Redirect vulnerability detection plugin"""
    
    def __init__(self):
        super().__init__()
        self.vuln_type = VulnType.OPEN_REDIRECT
        self.severity = SeverityLevel.MEDIUM
    
    def get_payloads(self) -> List[str]:
        """Get open redirect payloads"""
        return [
            # Direct external URLs
            "http://evil.com",
            "https://evil.com",
            "http://attacker.com",
            "https://attacker.com",
            "http://google.com",
            "https://google.com",
            
            # Protocol relative URLs
            "//evil.com",
            "//attacker.com",
            "//google.com",
            
            # Encoded URLs
            "http%3A//evil.com",
            "https%3A//evil.com",
            "%2F%2Fevil.com",
            
            # JavaScript URLs
            "javascript:alert('Redirect')",
            "javascript://evil.com",
            
            # Data URLs
            "data:text/html,<script>location='http://evil.com'</script>",
            
            # Domain confusion
            "http://evil.com.target.com",
            "http://target.com.evil.com",
            "http://target-evil.com",
            
            # Path-based redirects
            "/redirect/http://evil.com",
            "/redirect?url=http://evil.com",
            "/goto/http://evil.com",
            
            # Subdomain redirects
            "http://subdomain.evil.com",
            "https://evil.target.com",
            
            # IP addresses
            "http://127.0.0.1:8080",
            "http://192.168.1.1",
            "http://10.0.0.1",
            
            # Localhost variations
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            
            # URL shorteners
            "http://bit.ly/evil",
            "http://tinyurl.com/evil",
            
            # Unicode domains
            "http://еvil.com",  # Cyrillic 'e'
            "http://gооgle.com",  # Cyrillic 'o'
            
            # Case variations
            "HTTP://EVIL.COM",
            "hTTp://eVIl.CoM",
            
            # Bypass attempts
            "http://target.com@evil.com",
            "http://target.com:80@evil.com",
            "http://evil.com%23@target.com",
            "http://evil.com%2523@target.com",
            
            # Hex encoded
            "http://0x7f000001",  # 127.0.0.1
            "http://017700000001",  # 127.0.0.1 in octal
            
            # Double slashes
            "http:///evil.com",
            "https:///evil.com",
            
            # Tab and newline injection
            "http://evil.com\t.target.com",
            "http://evil.com\n.target.com",
            
            # CRLF injection
            "http://evil.com\r\n.target.com",
            
            # Backslash variations
            "http:\\\\evil.com",
            "https:\\\\evil.com",
            
            # Mixed protocols
            "ftp://evil.com",
            "file://evil.com",
            "gopher://evil.com",
        ]
    
    def detect_vulnerability(self, response_text: str, payload: str) -> bool:
        """Detect open redirect vulnerability"""
        # Check if we got redirected to the malicious domain
        evil_domains = [
            'evil.com', 'attacker.com', 'google.com',
            'bit.ly', 'tinyurl.com'
        ]
        
        response_lower = response_text.lower()
        
        # Look for redirect indicators in response
        for domain in evil_domains:
            if domain in payload.lower() and domain in response_lower:
                return True
        
        # Check for Location header indicators in HTML
        redirect_patterns = [
            'location.href', 'window.location', 'document.location',
            'location.replace', 'location.assign', 'meta http-equiv="refresh"'
        ]
        
        for pattern in redirect_patterns:
            if pattern in response_lower:
                # Check if our payload domain appears near the redirect code
                for domain in evil_domains:
                    if domain in payload.lower():
                        # Look for the domain within 100 characters of redirect code
                        pattern_pos = response_lower.find(pattern)
                        if pattern_pos != -1:
                            context = response_lower[max(0, pattern_pos-50):pattern_pos+100]
                            if domain in context:
                                return True
        
        # Check for HTTP refresh headers in HTML
        if 'http-equiv="refresh"' in response_lower and 'url=' in response_lower:
            for domain in evil_domains:
                if domain in payload.lower() and domain in response_lower:
                    return True
        
        return False
    
    async def test_payload(self, url: str, parameter: str, payload: str, 
                          http_client, method: str = 'GET') -> Any:
        """Test open redirect payload with redirect following disabled"""
        try:
            self.scan_stats['requests_made'] += 1
            
            # Temporarily disable redirect following to catch redirects
            original_follow_redirects = http_client.follow_redirects
            http_client.follow_redirects = False
            
            try:
                if method.upper() == 'GET':
                    response = await http_client.get(url, params={parameter: payload})
                else:
                    response = await http_client.post(url, data={parameter: payload})
                
                if response:
                    # Check for HTTP redirect status codes
                    if 300 <= response.status < 400:
                        location_header = response.headers.get('location', '')
                        if self._is_malicious_redirect(location_header, payload):
                            confidence = 0.9  # High confidence for HTTP redirects
                            
                            from vulnmind.core.models import Vulnerability
                            vulnerability = Vulnerability(
                                vuln_type=self.vuln_type,
                                severity=self.severity,
                                url=url,
                                parameter=parameter,
                                payload=payload,
                                description=self.get_description(),
                                evidence=f"HTTP {response.status} redirect to: {location_header}",
                                remediation=self.get_remediation(),
                                confidence=confidence,
                                detected_by=self.name
                            )
                            
                            self.scan_stats['vulnerabilities_found'] += 1
                            return vulnerability
                    
                    # Check for client-side redirects in response body
                    elif self.detect_vulnerability(response.text, payload):
                        confidence = self.calculate_confidence(response.text, payload)
                        
                        from vulnmind.core.models import Vulnerability
                        vulnerability = Vulnerability(
                            vuln_type=self.vuln_type,
                            severity=self.severity,
                            url=url,
                            parameter=parameter,
                            payload=payload,
                            description=self.get_description(),
                            evidence=self.extract_evidence(response.text, payload),
                            remediation=self.get_remediation(),
                            confidence=confidence,
                            detected_by=self.name
                        )
                        
                        self.scan_stats['vulnerabilities_found'] += 1
                        return vulnerability
                        
            finally:
                # Restore original redirect setting
                http_client.follow_redirects = original_follow_redirects
                
        except Exception as e:
            from vulnmind.utils.logger import get_logger
            logger = get_logger(__name__)
            logger.debug(f"Open redirect payload test failed: {str(e)}")
        
        return None
    
    def _is_malicious_redirect(self, location: str, payload: str) -> bool:
        """Check if redirect location is malicious"""
        if not location:
            return False
        
        # Parse the redirect URL
        try:
            parsed = urlparse(location)
            payload_parsed = urlparse(payload)
            
            # Check if redirect goes to external domain from payload
            if payload_parsed.netloc and parsed.netloc:
                return payload_parsed.netloc in parsed.netloc or parsed.netloc in payload_parsed.netloc
            
            # Check for malicious domains
            evil_domains = ['evil.com', 'attacker.com', 'google.com']
            for domain in evil_domains:
                if domain in location.lower() and domain in payload.lower():
                    return True
                    
        except Exception:
            pass
        
        return payload in location
    
    def calculate_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence for open redirect detection"""
        confidence = 0.4  # Base confidence
        
        # Higher confidence for client-side redirects
        redirect_indicators = [
            'location.href', 'window.location', 'document.location',
            'location.replace', 'location.assign'
        ]
        
        response_lower = response_text.lower()
        for indicator in redirect_indicators:
            if indicator in response_lower:
                confidence += 0.2
                break
        
        # Check for payload reflection
        evil_domains = ['evil.com', 'attacker.com', 'google.com']
        for domain in evil_domains:
            if domain in payload.lower() and domain in response_lower:
                confidence += 0.3
                break
        
        # Check for meta refresh
        if 'http-equiv="refresh"' in response_lower:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def get_description(self) -> str:
        """Get vulnerability description"""
        return (
            "Open Redirect vulnerability allows attackers to redirect users to "
            "malicious websites by manipulating URL parameters. This can be used "
            "for phishing attacks or malware distribution."
        )
    
    def get_remediation(self) -> str:
        """Get remediation advice"""
        return (
            "Validate and whitelist redirect URLs against a list of allowed domains. "
            "Use relative URLs for internal redirects. Implement proper URL validation "
            "and sanitization. Avoid using user input directly in redirect functions. "
            "Consider using indirect references instead of direct URLs."
        )
    
    def get_cwe_id(self) -> int:
        """Get CWE ID for Open Redirect"""
        return 601
    
    def get_references(self) -> List[str]:
        """Get reference URLs"""
        return [
            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
            "https://cwe.mitre.org/data/definitions/601.html",
            "https://portswigger.net/web-security/host-header/exploiting/open-redirection"
        ]

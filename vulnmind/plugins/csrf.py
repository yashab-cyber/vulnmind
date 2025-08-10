"""
CSRF (Cross-Site Request Forgery) detection plugin
"""

import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup

from vulnmind.plugins.base import BasePlugin
from vulnmind.core.models import VulnType, SeverityLevel, Vulnerability
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from vulnmind.utils.http import HttpClient
from vulnmind.utils.logger import get_logger

logger = get_logger(__name__)


class CSRFPlugin(BasePlugin):
    """CSRF vulnerability detection plugin"""
    
    def __init__(self):
        super().__init__()
        self.vuln_type = VulnType.CSRF
        self.severity = SeverityLevel.MEDIUM
    
    async def scan(self, url: str, http_client: 'HttpClient', config: Dict[str, Any]) -> List[Vulnerability]:
        """Scan for CSRF vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get the page content
            response = await http_client.get(url)
            if not response:
                return vulnerabilities
            
            # Parse HTML to find forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for i, form in enumerate(forms):
                vuln = await self._analyze_form(form, url, http_client, i)
                if vuln:
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"CSRF scan failed: {str(e)}")
        
        return vulnerabilities
    
    async def _analyze_form(self, form, base_url: str, http_client: 'HttpClient', form_index: int) -> Vulnerability:
        """Analyze a form for CSRF protection"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Skip GET forms for CSRF (less critical)
        if method == 'GET':
            return None
        
        # Check for CSRF tokens
        has_csrf_token = self._has_csrf_protection(form)
        
        if not has_csrf_token:
            # Test if form submission works without CSRF token
            form_url = self._resolve_form_url(action, base_url)
            form_data = self._extract_form_data(form)
            
            # Try to submit the form
            success = await self._test_form_submission(form_url, form_data, http_client)
            
            if success:
                confidence = 0.8 if method == 'POST' else 0.6
                
                return Vulnerability(
                    vuln_type=self.vuln_type,
                    severity=self.severity,
                    url=form_url,
                    parameter=f"Form #{form_index + 1}",
                    payload="No CSRF token required",
                    description=self.get_description(),
                    evidence=f"Form accepts {method} requests without CSRF protection",
                    remediation=self.get_remediation(),
                    confidence=confidence,
                    detected_by=self.name
                )
        
        return None
    
    def _has_csrf_protection(self, form) -> bool:
        """Check if form has CSRF protection mechanisms"""
        # Look for common CSRF token field names
        csrf_field_names = [
            'csrf_token', 'csrf', '_token', 'authenticity_token',
            'csrftoken', 'csrf-token', '_csrf', 'csrfmiddlewaretoken',
            '_csrftoken', 'anti_forgery_token', '_xsrf'
        ]
        
        # Check input fields
        inputs = form.find_all(['input', 'textarea'])
        for inp in inputs:
            name = inp.get('name', '').lower()
            input_type = inp.get('type', '').lower()
            
            # Look for hidden CSRF token fields
            if input_type == 'hidden' and any(csrf_name in name for csrf_name in csrf_field_names):
                return True
            
            # Look for any field with CSRF-like name
            if any(csrf_name in name for csrf_name in csrf_field_names):
                return True
        
        # Check for CSRF protection in meta tags (some frameworks use this)
        if form.find_parent('html'):
            meta_tags = form.find_parent('html').find_all('meta', attrs={'name': True})
            for meta in meta_tags:
                meta_name = meta.get('name', '').lower()
                if any(csrf_name in meta_name for csrf_name in csrf_field_names):
                    return True
        
        return False
    
    def _resolve_form_url(self, action: str, base_url: str) -> str:
        """Resolve form action URL"""
        if not action:
            return base_url
        
        if action.startswith('http'):
            return action
        
        from urllib.parse import urljoin
        return urljoin(base_url, action)
    
    def _extract_form_data(self, form) -> Dict[str, str]:
        """Extract form data for submission"""
        form_data = {}
        
        inputs = form.find_all(['input', 'textarea', 'select'])
        for inp in inputs:
            name = inp.get('name')
            if not name:
                continue
            
            input_type = inp.get('type', 'text').lower()
            
            if input_type == 'submit':
                continue
            elif input_type == 'checkbox':
                form_data[name] = 'on' if inp.get('checked') else ''
            elif input_type == 'radio':
                if inp.get('checked'):
                    form_data[name] = inp.get('value', 'on')
            elif inp.name == 'select':
                # Get first option value
                option = inp.find('option')
                form_data[name] = option.get('value', '') if option else ''
            else:
                form_data[name] = inp.get('value', 'test_value')
        
        return form_data
    
    async def _test_form_submission(self, url: str, data: Dict[str, str], http_client: 'HttpClient') -> bool:
        """Test if form submission succeeds without CSRF token"""
        try:
            # Remove any potential CSRF tokens from data
            csrf_keys = [key for key in data.keys() 
                        if any(csrf_name in key.lower() for csrf_name in 
                              ['csrf', 'token', '_token', 'authenticity', 'xsrf'])]
            
            for key in csrf_keys:
                del data[key]
            
            # Submit the form
            response = await http_client.post(url, data=data)
            
            if response:
                # Check if submission was successful
                # Look for common success indicators vs error indicators
                response_text = response.text.lower()
                
                # Error indicators
                error_indicators = [
                    'csrf', 'token', 'forbidden', 'unauthorized', 'invalid',
                    'error', 'fail', 'reject', 'deny', '403', '401'
                ]
                
                for indicator in error_indicators:
                    if indicator in response_text:
                        return False
                
                # Success indicators
                success_indicators = [
                    'success', 'complete', 'saved', 'updated', 'created',
                    'thank you', 'submitted', 'redirect'
                ]
                
                for indicator in success_indicators:
                    if indicator in response_text:
                        return True
                
                # If status code is 2xx or 3xx, consider it successful
                if 200 <= response.status < 400:
                    return True
        
        except Exception as e:
            logger.debug(f"Form submission test failed: {str(e)}")
        
        return False
    
    def get_payloads(self) -> List[str]:
        """CSRF doesn't use traditional payloads"""
        return []
    
    def detect_vulnerability(self, response_text: str, payload: str) -> bool:
        """CSRF detection is form-based, not payload-based"""
        return False
    
    def get_description(self) -> str:
        """Get vulnerability description"""
        return (
            "Cross-Site Request Forgery (CSRF) vulnerability allows attackers to "
            "perform unauthorized actions on behalf of authenticated users by "
            "tricking them into submitting malicious requests."
        )
    
    def get_remediation(self) -> str:
        """Get remediation advice"""
        return (
            "Implement CSRF tokens in all state-changing forms. Use the "
            "Synchronizer Token Pattern or Double Submit Cookies. Verify the "
            "HTTP Referer header. Implement SameSite cookie attribute. "
            "Consider using framework-provided CSRF protection mechanisms."
        )
    
    def get_cwe_id(self) -> int:
        """Get CWE ID for CSRF"""
        return 352
    
    def get_references(self) -> List[str]:
        """Get reference URLs"""
        return [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cwe.mitre.org/data/definitions/352.html",
            "https://portswigger.net/web-security/csrf"
        ]

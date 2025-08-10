"""
Base plugin class for vulnerability detection
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, TYPE_CHECKING

from vulnmind.core.models import Vulnerability, VulnType, SeverityLevel, PluginResult
from vulnmind.utils.logger import get_logger

if TYPE_CHECKING:
    from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from vulnmind.utils.http import HttpClient

logger = get_logger(__name__)


class BasePlugin(ABC):
    """Base class for all vulnerability detection plugins"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.vuln_type = None
        self.severity = SeverityLevel.MEDIUM
        self.payloads = []
        self.detection_patterns = []
        self.scan_stats = {
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'scan_time': 0.0
        }
    
    @abstractmethod
    async def scan(self, url: str, http_client: 'HttpClient', config: Dict[str, Any]) -> List[Vulnerability]:
        """Scan URL for specific vulnerability type"""
        pass
    
    @abstractmethod
    def get_payloads(self) -> List[str]:
        """Get attack payloads for this vulnerability type"""
        pass
    
    @abstractmethod
    def detect_vulnerability(self, response_text: str, payload: str) -> bool:
        """Detect if response indicates vulnerability"""
        pass
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this plugin"""
        return {
            'scan_depth': 'medium',
            'timeout': 10,
            'max_payloads': 50,
            'confidence_threshold': 0.5
        }
    
    async def test_payload(self, url: str, parameter: str, payload: str, 
                          http_client: 'HttpClient', method: str = 'GET') -> Optional[Vulnerability]:
        """Test a single payload against a parameter"""
        try:
            self.scan_stats['requests_made'] += 1
            
            if method.upper() == 'GET':
                response = await http_client.get(url, params={parameter: payload})
            else:
                response = await http_client.post(url, data={parameter: payload})
            
            if response and self.detect_vulnerability(response.text, payload):
                confidence = self.calculate_confidence(response.text, payload)
                
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
                
        except Exception as e:
            logger.debug(f"Payload test failed for {self.name}: {str(e)}")
        
        return None
    
    def calculate_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence level for vulnerability detection"""
        confidence = 0.5  # Base confidence
        
        # Check for exact payload reflection
        if payload in response_text:
            confidence += 0.3
        
        # Check for error patterns
        error_patterns = [
            'error', 'exception', 'warning', 'mysql', 'sql',
            'oracle', 'postgresql', 'sqlite', 'syntax error'
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in response_text.lower():
                confidence += 0.1
                break
        
        return min(confidence, 1.0)
    
    def extract_evidence(self, response_text: str, payload: str) -> str:
        """Extract evidence of vulnerability from response"""
        # Look for payload in response
        if payload in response_text:
            start = max(0, response_text.find(payload) - 50)
            end = min(len(response_text), response_text.find(payload) + len(payload) + 50)
            return response_text[start:end].strip()
        
        # Look for error messages
        error_indicators = ['error', 'exception', 'warning', 'failed']
        for indicator in error_indicators:
            if indicator.lower() in response_text.lower():
                lines = response_text.split('\n')
                for line in lines:
                    if indicator.lower() in line.lower():
                        return line.strip()
        
        return "Vulnerability detected in response"
    
    @abstractmethod
    def get_description(self) -> str:
        """Get vulnerability description"""
        pass
    
    @abstractmethod
    def get_remediation(self) -> str:
        """Get remediation advice"""
        pass
    
    def get_cwe_id(self) -> Optional[int]:
        """Get CWE ID for this vulnerability type"""
        return None
    
    def get_references(self) -> List[str]:
        """Get reference URLs for this vulnerability type"""
        return []


class ParameterPlugin(BasePlugin):
    """Base class for parameter-based vulnerability testing"""
    
    async def scan(self, url: str, http_client: 'HttpClient', config: Dict[str, Any]) -> List[Vulnerability]:
        """Scan URL parameters for vulnerabilities"""
        vulnerabilities = []
        start_time = time.time()
        
        try:
            # Get URL parameters
            parameters = await self._extract_parameters(url, http_client)
            payloads = self.get_payloads()
            
            # Limit payloads based on scan depth
            max_payloads = self._get_max_payloads(config)
            payloads = payloads[:max_payloads]
            
            # Test each parameter with each payload
            for param_name, param_info in parameters.items():
                for payload in payloads:
                    vuln = await self.test_payload(
                        url=param_info['url'],
                        parameter=param_name,
                        payload=payload,
                        http_client=http_client,
                        method=param_info.get('method', 'GET')
                    )
                    
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                        # Early termination if vulnerability found and scan depth is basic
                        if config.get('scan_depth') == 'basic':
                            break
        
        except Exception as e:
            logger.error(f"Parameter scan failed for {self.name}: {str(e)}")
        
        self.scan_stats['scan_time'] = time.time() - start_time
        return vulnerabilities
    
    async def _extract_parameters(self, url: str, http_client: 'HttpClient') -> Dict[str, Dict[str, str]]:
        """Extract parameters from URL and forms"""
        parameters = {}
        
        try:
            # Get page content
            response = await http_client.get(url)
            if not response:
                return parameters
            
            # Parse URL parameters
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name, values in url_params.items():
                parameters[param_name] = {
                    'url': url,
                    'method': 'GET',
                    'type': 'url_param',
                    'value': values[0] if values else ''
                }
            
            # Parse forms from HTML
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                form_url = url if not action else (
                    action if action.startswith('http') else f"{url.rstrip('/')}/{action.lstrip('/')}"
                )
                
                for inp in form.find_all(['input', 'textarea']):
                    name = inp.get('name')
                    if name and inp.get('type') != 'submit':
                        parameters[name] = {
                            'url': form_url,
                            'method': method,
                            'type': 'form_param',
                            'value': inp.get('value', '')
                        }
        
        except Exception as e:
            logger.debug(f"Parameter extraction failed: {str(e)}")
        
        return parameters
    
    def _get_max_payloads(self, config: Dict[str, Any]) -> int:
        """Get maximum number of payloads based on scan depth"""
        depth = config.get('scan_depth', 'medium')
        
        if depth == 'basic':
            return 10
        elif depth == 'medium':
            return 25
        else:  # deep
            return 50


class HeaderPlugin(BasePlugin):
    """Base class for header-based vulnerability testing"""
    
    async def scan(self, url: str, http_client: 'HttpClient', config: Dict[str, Any]) -> List[Vulnerability]:
        """Scan HTTP headers for vulnerabilities"""
        vulnerabilities = []
        start_time = time.time()
        
        try:
            payloads = self.get_payloads()
            max_payloads = self._get_max_payloads(config)
            payloads = payloads[:max_payloads]
            
            # Test common injection points in headers
            test_headers = [
                'User-Agent', 'Referer', 'X-Forwarded-For',
                'X-Real-IP', 'X-Originating-IP', 'Host'
            ]
            
            for header_name in test_headers:
                for payload in payloads:
                    vuln = await self.test_header_payload(
                        url, header_name, payload, http_client
                    )
                    
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                        if config.get('scan_depth') == 'basic':
                            break
        
        except Exception as e:
            logger.error(f"Header scan failed for {self.name}: {str(e)}")
        
        self.scan_stats['scan_time'] = time.time() - start_time
        return vulnerabilities
    
    async def test_header_payload(self, url: str, header_name: str, payload: str, 
                                 http_client: 'HttpClient') -> Optional[Vulnerability]:
        """Test payload in HTTP header"""
        try:
            self.scan_stats['requests_made'] += 1
            
            headers = {header_name: payload}
            response = await http_client.get(url, headers=headers)
            
            if response and self.detect_vulnerability(response.text, payload):
                confidence = self.calculate_confidence(response.text, payload)
                
                vulnerability = Vulnerability(
                    vuln_type=self.vuln_type,
                    severity=self.severity,
                    url=url,
                    parameter=f"Header: {header_name}",
                    payload=payload,
                    description=self.get_description(),
                    evidence=self.extract_evidence(response.text, payload),
                    remediation=self.get_remediation(),
                    confidence=confidence,
                    detected_by=self.name
                )
                
                self.scan_stats['vulnerabilities_found'] += 1
                return vulnerability
                
        except Exception as e:
            logger.debug(f"Header payload test failed: {str(e)}")
        
        return None
    
    def _get_max_payloads(self, config: Dict[str, Any]) -> int:
        """Get maximum number of payloads based on scan depth"""
        depth = config.get('scan_depth', 'medium')
        
        if depth == 'basic':
            return 5
        elif depth == 'medium':
            return 15
        else:  # deep
            return 30

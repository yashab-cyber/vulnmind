"""
Data models for VulnMind scanner
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(Enum):
    """Vulnerability types"""
    SQL_INJECTION = "sql_injection"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    COMMAND_INJECTION = "command_injection"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    AUTHENTICATION_BYPASS = "auth_bypass"
    SESSION_FIXATION = "session_fixation"
    INSECURE_DIRECT_OBJECT_REFERENCE = "idor"


@dataclass
class HttpRequest:
    """HTTP request representation"""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class HttpResponse:
    """HTTP response representation"""
    status: int
    headers: Dict[str, str]
    text: str
    url: str
    elapsed: float
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """Vulnerability finding"""
    vuln_type: VulnType
    severity: SeverityLevel
    url: str
    parameter: str
    payload: str
    description: str
    evidence: str
    remediation: str
    confidence: float
    detected_by: str = ""
    timestamp: float = field(default_factory=time.time)
    cvss_score: Optional[float] = None
    cwe_id: Optional[int] = None
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'vuln_type': self.vuln_type.value,
            'severity': self.severity.value,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'detected_by': self.detected_by,
            'timestamp': self.timestamp,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'references': self.references
        }


@dataclass
class ScanResult:
    """Complete scan result"""
    target_url: str
    start_time: float
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    scan_stats: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        vuln_types = {}
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.value] += 1
            vuln_type = vuln.vuln_type.value
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        return {
            'target_url': self.target_url,
            'scan_duration': self.duration,
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_counts,
            'vulnerability_types': vuln_types,
            'scan_stats': self.scan_stats,
            'timestamp': self.start_time
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'target_url': self.target_url,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'scan_stats': self.scan_stats,
            'error': self.error,
            'summary': self.get_summary()
        }


@dataclass
class ScanConfig:
    """Scanner configuration"""
    target_url: str
    ai_mode: bool = False
    max_concurrent_requests: int = 10
    request_timeout: int = 30
    user_agent: str = "VulnMind/1.0"
    proxy: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[Dict[str, str]] = None
    scan_depth: str = "medium"  # basic, medium, deep
    follow_redirects: bool = True
    verify_ssl: bool = True
    ai_analyzer: Optional[Any] = None
    plugin_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation"""
        if not self.target_url:
            raise ValueError("target_url is required")
        
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = f"https://{self.target_url}"


@dataclass
class PluginResult:
    """Result from a plugin scan"""
    plugin_name: str
    vulnerabilities: List[Vulnerability]
    scan_time: float
    requests_made: int
    errors: List[str] = field(default_factory=list)


@dataclass
class LearningData:
    """Data collected for self-awareness learning"""
    timestamp: float
    target_url: str
    scan_efficiency: float
    vulnerability_count: int
    false_positive_rate: float
    successful_payloads: Dict[str, List[str]]
    response_patterns: Dict[str, Any]
    adaptation_data: Dict[str, Any] = field(default_factory=dict)

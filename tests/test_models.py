"""
Test core models for VulnMind
"""

import pytest
from datetime import datetime
import time
from vulnmind.core.models import Vulnerability, ScanResult, ScanConfig, VulnType, SeverityLevel


class TestVulnerability:
    """Test Vulnerability model"""
    
    def test_vulnerability_creation(self):
        """Test creating a vulnerability"""
        vuln = Vulnerability(
            vuln_type=VulnType.SQL_INJECTION,
            url="https://example.com/login",
            parameter="username",
            payload="' OR 1=1--",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            description="SQL injection vulnerability",
            evidence="Error message revealing database structure",
            remediation="Use parameterized queries"
        )
        
        assert vuln.vuln_type == VulnType.SQL_INJECTION
        assert vuln.url == "https://example.com/login"
        assert vuln.parameter == "username"
        assert vuln.severity == SeverityLevel.HIGH
        assert vuln.confidence == 0.9
        assert vuln.description == "SQL injection vulnerability"
        assert vuln.payload == "' OR 1=1--"
        assert vuln.evidence == "Error message revealing database structure"
    
    def test_vulnerability_to_dict(self):
        """Test vulnerability serialization to dict"""
        vuln = Vulnerability(
            vuln_type=VulnType.XSS_REFLECTED,
            url="https://example.com/search",
            parameter="q",
            payload="<script>alert('xss')</script>",
            severity=SeverityLevel.MEDIUM,
            confidence=0.8,
            description="XSS vulnerability",
            evidence="Script executed",
            remediation="Sanitize input"
        )
        
        data = vuln.to_dict()
        
        assert data['vuln_type'] == 'xss_reflected'
        assert data['url'] == 'https://example.com/search'
        assert data['parameter'] == 'q'
        assert data['severity'] == 'medium'
        assert data['confidence'] == 0.8
        assert data['description'] == 'XSS vulnerability'
        assert data['payload'] == "<script>alert('xss')</script>"


class TestScanResult:
    """Test ScanResult model"""
    
    def test_scan_result_creation(self):
        """Test creating a scan result"""
        start_time = time.time()
        vulns = [
            Vulnerability(
                vuln_type=VulnType.SQL_INJECTION,
                url="https://example.com/login",
                parameter="username",
                payload="' OR 1=1--",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                description="SQL injection",
                evidence="SQL error",
                remediation="Use parameterized queries"
            )
        ]
        
        result = ScanResult(
            target_url="https://example.com",
            start_time=start_time,
            vulnerabilities=vulns
        )
        
        assert result.target_url == "https://example.com"
        assert result.start_time == start_time
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].vuln_type == VulnType.SQL_INJECTION
    
    def test_scan_result_to_dict(self):
        """Test scan result serialization to dict"""
        start_time = time.time()
        end_time = time.time()
        vulns = []
        
        result = ScanResult(
            target_url="https://example.com",
            start_time=start_time,
            end_time=end_time,
            vulnerabilities=vulns,
            duration=5.0
        )
        
        data = result.to_dict()
        
        assert data['target_url'] == "https://example.com"
        assert data['start_time'] == start_time
        assert data['end_time'] == end_time
        assert data['duration'] == 5.0
        assert data['vulnerabilities'] == []
    
    def test_scan_result_summary(self):
        """Test scan result summary generation"""
        start_time = time.time()
        vulns = [
            Vulnerability(
                vuln_type=VulnType.SQL_INJECTION,
                url="https://example.com/login",
                parameter="username",
                payload="' OR 1=1--",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                description="SQL injection",
                evidence="SQL error",
                remediation="Use parameterized queries"
            ),
            Vulnerability(
                vuln_type=VulnType.XSS_REFLECTED,
                url="https://example.com/search",
                parameter="q",
                payload="<script>alert('xss')</script>",
                severity=SeverityLevel.MEDIUM,
                confidence=0.8,
                description="XSS vulnerability",
                evidence="Script executed",
                remediation="Sanitize input"
            )
        ]
        
        result = ScanResult(
            target_url="https://example.com",
            start_time=start_time,
            vulnerabilities=vulns
        )
        
        summary = result.get_summary()
        
        assert summary['total_vulnerabilities'] == 2
        assert summary['severity_breakdown']['high'] == 1
        assert summary['severity_breakdown']['medium'] == 1
        assert summary['vulnerability_types']['sql_injection'] == 1
        assert summary['vulnerability_types']['xss_reflected'] == 1


class TestScanConfig:
    """Test ScanConfig model"""
    
    def test_scan_config_creation(self):
        """Test creating a scan config"""
        config = ScanConfig(
            target_url="https://example.com",
            scan_depth="deep",
            max_concurrent_requests=5
        )
        
        assert config.target_url == "https://example.com"
        assert config.scan_depth == "deep"
        assert config.max_concurrent_requests == 5
    
    def test_scan_config_defaults(self):
        """Test scan config default values"""
        config = ScanConfig(target_url="https://example.com")
        
        assert config.target_url == "https://example.com"
        assert config.scan_depth == "medium"
        assert config.max_concurrent_requests == 10
        assert config.request_timeout == 30
        assert config.follow_redirects is True
        assert config.ai_mode is False
    
    def test_scan_config_url_normalization(self):
        """Test URL normalization in config"""
        config = ScanConfig(target_url="example.com")
        assert config.target_url == "https://example.com"
        
        config2 = ScanConfig(target_url="http://example.com")
        assert config2.target_url == "http://example.com"
    
    def test_scan_config_validation(self):
        """Test config validation"""
        with pytest.raises(ValueError):
            ScanConfig(target_url="")


if __name__ == "__main__":
    pytest.main([__file__])

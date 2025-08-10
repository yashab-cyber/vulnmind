"""
Test SQL injection plugin
"""

import pytest
from unittest.mock import Mock, patch
from vulnmind.plugins.sql_injection import SQLInjectionPlugin
from vulnmind.core.models import VulnType, SeverityLevel


@pytest.fixture
def plugin():
    """Create SQL injection plugin instance"""
    return SQLInjectionPlugin()


@pytest.fixture
def mock_http_client():
    """Create mock HTTP client"""
    client = Mock()
    client.get = Mock()
    client.post = Mock()
    return client


class TestSQLInjectionPlugin:
    """Test SQL injection plugin"""
    
    def test_plugin_initialization(self, plugin):
        """Test plugin initialization"""
        assert plugin.name == "SQL Injection"
        assert plugin.description == "Detects SQL injection vulnerabilities"
        assert plugin.vulnerability_type == VulnType.SQL_INJECTION
        assert len(plugin.payloads) > 0
        assert len(plugin.error_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_scan_get_parameter(self, plugin, mock_http_client):
        """Test scanning GET parameters for SQL injection"""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.text = "MySQL error: You have an error in your SQL syntax"
        mock_response.status = 500
        mock_http_client.get.return_value = mock_response
        
        url = "https://example.com/search?q=test"
        vulns = await plugin.scan(url, mock_http_client)
        
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.type == VulnType.SQL_INJECTION
        assert vuln.url.startswith("https://example.com/search")
        assert vuln.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_scan_post_parameter(self, plugin, mock_http_client):
        """Test scanning POST parameters for SQL injection"""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.text = "ORA-00933: SQL command not properly ended"
        mock_response.status = 500
        mock_http_client.post.return_value = mock_response
        
        url = "https://example.com/login"
        data = {"username": "test", "password": "test"}
        vulns = await plugin.scan_form(url, data, mock_http_client)
        
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.type == VulnType.SQL_INJECTION
        assert vuln.url == "https://example.com/login"
        assert vuln.confidence > 0.7
    
    @pytest.mark.asyncio
    async def test_no_vulnerability_found(self, plugin, mock_http_client):
        """Test when no SQL injection vulnerability is found"""
        # Mock normal response
        mock_response = Mock()
        mock_response.text = "Welcome to our website"
        mock_response.status = 200
        mock_http_client.get.return_value = mock_response
        
        url = "https://example.com/page"
        vulns = await plugin.scan(url, mock_http_client)
        
        assert len(vulns) == 0
    
    def test_calculate_confidence_high(self, plugin):
        """Test confidence calculation for high confidence indicators"""
        response_text = "MySQL error: You have an error in your SQL syntax near"
        confidence = plugin._calculate_confidence(response_text)
        
        assert confidence >= 0.9
    
    def test_calculate_confidence_medium(self, plugin):
        """Test confidence calculation for medium confidence indicators"""
        response_text = "Warning: mysql_fetch_array()"
        confidence = plugin._calculate_confidence(response_text)
        
        assert 0.5 <= confidence < 0.9
    
    def test_calculate_confidence_low(self, plugin):
        """Test confidence calculation for low confidence indicators"""
        response_text = "Normal page content"
        confidence = plugin._calculate_confidence(response_text)
        
        assert confidence == 0.0
    
    def test_detect_sql_errors(self, plugin):
        """Test SQL error detection"""
        test_cases = [
            ("MySQL error in query", True),
            ("ORA-00933: SQL command", True),
            ("Microsoft OLE DB Provider", True),
            ("PostgreSQL query failed", True),
            ("SQLite error", True),
            ("Normal response", False),
            ("", False),
        ]
        
        for text, expected in test_cases:
            result = any(pattern.search(text.lower()) for pattern in plugin.error_patterns)
            assert result == expected, f"Failed for text: {text}"


if __name__ == "__main__":
    pytest.main([__file__])

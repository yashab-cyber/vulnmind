"""
Test configuration for VulnMind
"""

import pytest
from vulnmind.config import VulnMindConfig, load_config, validate_config


class TestVulnMindConfig:
    """Test VulnMindConfig class"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = VulnMindConfig()
        
        assert config.max_concurrent_requests == 10
        assert config.request_timeout == 30
        assert config.user_agent == "VulnMind/1.0"
        assert config.default_scan_depth == "medium"
        assert config.follow_redirects is True
        assert config.verify_ssl is True
        
        assert config.ai_enabled is False
        assert config.openai_api_key is None
        assert config.ai_model == "gpt-4"
        assert config.ai_temperature == 0.1
        
        assert config.learning_rate == 0.1
        assert config.adaptation_threshold == 0.7
        assert config.memory_size == 1000
        assert config.confidence_threshold == 0.5
        
        assert config.enabled_plugins == []
        assert config.disabled_plugins == []
        assert config.plugin_configs == {}
        
        assert config.log_level == "INFO"
        assert config.log_file is None
        
        assert config.default_report_format == "json"
        assert config.report_directory == "./reports"
    
    def test_config_validation_valid(self):
        """Test configuration validation with valid values"""
        config = VulnMindConfig()
        assert validate_config(config) is True
    
    def test_config_validation_invalid_concurrent_requests(self):
        """Test configuration validation with invalid concurrent requests"""
        config = VulnMindConfig(max_concurrent_requests=0)
        assert validate_config(config) is False
        
        config = VulnMindConfig(max_concurrent_requests=101)
        assert validate_config(config) is False
    
    def test_config_validation_invalid_timeout(self):
        """Test configuration validation with invalid timeout"""
        config = VulnMindConfig(request_timeout=0)
        assert validate_config(config) is False
        
        config = VulnMindConfig(request_timeout=301)
        assert validate_config(config) is False
    
    def test_config_validation_invalid_scan_depth(self):
        """Test configuration validation with invalid scan depth"""
        config = VulnMindConfig(default_scan_depth="invalid")
        assert validate_config(config) is False
    
    def test_config_validation_invalid_ai_temperature(self):
        """Test configuration validation with invalid AI temperature"""
        config = VulnMindConfig(ai_temperature=-0.1)
        assert validate_config(config) is False
        
        config = VulnMindConfig(ai_temperature=2.1)
        assert validate_config(config) is False
    
    def test_config_validation_invalid_learning_rate(self):
        """Test configuration validation with invalid learning rate"""
        config = VulnMindConfig(learning_rate=0.0)
        assert validate_config(config) is False
        
        config = VulnMindConfig(learning_rate=1.1)
        assert validate_config(config) is False
    
    def test_config_validation_invalid_log_level(self):
        """Test configuration validation with invalid log level"""
        config = VulnMindConfig(log_level="INVALID")
        assert validate_config(config) is False
    
    def test_config_validation_invalid_report_format(self):
        """Test configuration validation with invalid report format"""
        config = VulnMindConfig(default_report_format="invalid")
        assert validate_config(config) is False


if __name__ == "__main__":
    pytest.main([__file__])

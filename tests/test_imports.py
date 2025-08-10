"""
Test package initialization
"""

import pytest


class TestPackageImports:
    """Test package imports work correctly"""
    
    def test_import_main_package(self):
        """Test importing main package"""
        import vulnmind
        assert hasattr(vulnmind, '__version__')
    
    def test_import_core_modules(self):
        """Test importing core modules"""
        from vulnmind.core import scanner, models
        assert scanner.Scanner is not None
        assert models.Vulnerability is not None
    
    def test_import_plugins(self):
        """Test importing plugin modules"""
        from vulnmind.plugins import sql_injection, xss, csrf
        assert sql_injection.SQLInjectionPlugin is not None
        assert xss.XSSPlugin is not None
        assert csrf.CSRFPlugin is not None
    
    def test_import_utils(self):
        """Test importing utility modules"""
        from vulnmind.utils import http, logger, helpers
        assert http.HttpClient is not None
        assert logger.get_logger is not None
        assert helpers.is_valid_ip is not None
    
    def test_import_ai_modules(self):
        """Test importing AI modules"""
        from vulnmind.ai import analyzer, self_awareness
        assert analyzer.AIAnalyzer is not None
        assert self_awareness.SelfAwarenessModule is not None
    
    def test_import_reports(self):
        """Test importing report modules"""
        from vulnmind.reports import generator
        assert generator.JSONReportGenerator is not None
        assert generator.HTMLReportGenerator is not None
    
    def test_import_cli(self):
        """Test importing CLI modules"""
        from vulnmind.cli.main import main
        assert callable(main)
    
    def test_import_config(self):
        """Test importing config module"""
        from vulnmind import config
        assert config.VulnMindConfig is not None


if __name__ == "__main__":
    pytest.main([__file__])

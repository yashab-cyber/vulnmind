"""
Core package initialization
"""

from .models import (
    Vulnerability, ScanResult, ScanConfig, HttpRequest, HttpResponse,
    SeverityLevel, VulnType, PluginResult, LearningData
)
from .scanner import Scanner, CrawlerModule, create_scanner

__all__ = [
    'Vulnerability', 'ScanResult', 'ScanConfig', 'HttpRequest', 'HttpResponse',
    'SeverityLevel', 'VulnType', 'PluginResult', 'LearningData',
    'Scanner', 'CrawlerModule', 'create_scanner'
]

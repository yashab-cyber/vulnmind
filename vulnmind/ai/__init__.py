"""
AI module initialization
"""

from .analyzer import AIAnalyzer, create_ai_analyzer
from .self_awareness import SelfAwarenessModule, AdaptationMetrics, AdaptationConfig, create_self_awareness_module

__all__ = [
    'AIAnalyzer', 'create_ai_analyzer',
    'SelfAwarenessModule', 'AdaptationMetrics', 'AdaptationConfig', 'create_self_awareness_module'
]

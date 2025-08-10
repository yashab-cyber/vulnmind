"""
Self-awareness module for VulnMind
"""

import time
import json
import statistics
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

from vulnmind.core.models import Vulnerability, LearningData
from vulnmind.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AdaptationMetrics:
    """Metrics for self-awareness and adaptation"""
    scan_efficiency: float = 0.0
    false_positive_rate: float = 0.0
    payload_success_rate: Dict[str, float] = field(default_factory=dict)
    response_time_avg: float = 0.0
    vulnerability_detection_rate: float = 0.0
    adaptation_confidence: float = 0.5


@dataclass
class AdaptationConfig:
    """Configuration for self-awareness adaptation"""
    learning_rate: float = 0.1
    adaptation_threshold: float = 0.7
    memory_size: int = 1000
    confidence_threshold: float = 0.5
    payload_adaptation_enabled: bool = True
    depth_adaptation_enabled: bool = True
    timing_adaptation_enabled: bool = True


class SelfAwarenessModule:
    """Self-awareness and adaptation module"""
    
    def __init__(self, config: AdaptationConfig = None):
        self.config = config or AdaptationConfig()
        self.metrics = AdaptationMetrics()
        self.learning_history: List[LearningData] = []
        self.adaptation_rules = {}
        self.payload_performance = {}
        self.scan_patterns = {}
        self.performance_trends = {
            'efficiency': [],
            'false_positives': [],
            'response_times': []
        }
        
        # Load existing learning data
        self._load_learning_data()
    
    def record_scan_results(self, vulnerabilities: List[Vulnerability], scan_stats: Dict[str, Any]):
        """Record scan results for learning"""
        timestamp = time.time()
        
        # Calculate metrics
        total_requests = scan_stats.get('requests_sent', 1)
        vuln_count = len(vulnerabilities)
        scan_efficiency = vuln_count / total_requests if total_requests > 0 else 0
        
        # Calculate false positive rate (simplified)
        low_confidence_count = sum(1 for v in vulnerabilities if v.confidence < 0.5)
        false_positive_rate = low_confidence_count / vuln_count if vuln_count > 0 else 0
        
        # Analyze payload performance
        payload_performance = self._analyze_payload_performance(vulnerabilities)
        
        # Create learning data entry
        learning_entry = LearningData(
            timestamp=timestamp,
            target_url=scan_stats.get('target_url', ''),
            scan_efficiency=scan_efficiency,
            vulnerability_count=vuln_count,
            false_positive_rate=false_positive_rate,
            successful_payloads=payload_performance,
            response_patterns=self._extract_response_patterns(vulnerabilities),
            adaptation_data={
                'total_requests': total_requests,
                'scan_duration': scan_stats.get('duration', 0),
                'plugin_performance': self._analyze_plugin_performance(vulnerabilities)
            }
        )
        
        self.learning_history.append(learning_entry)
        
        # Update current metrics
        self._update_metrics(learning_entry)
        
        # Trigger adaptation if needed
        if self._should_adapt():
            self._adapt_strategies()
        
        # Maintain memory limit
        if len(self.learning_history) > self.config.memory_size:
            self.learning_history = self.learning_history[-self.config.memory_size:]
        
        # Save learning data
        self._save_learning_data()
        
        logger.info(f"Recorded scan results: Efficiency={scan_efficiency:.3f}, "
                   f"FP Rate={false_positive_rate:.3f}, Vulns={vuln_count}")
    
    def _analyze_payload_performance(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[str]]:
        """Analyze which payloads were successful"""
        payload_performance = {}
        
        for vuln in vulnerabilities:
            plugin_name = vuln.detected_by
            if plugin_name not in payload_performance:
                payload_performance[plugin_name] = []
            
            if vuln.payload and vuln.confidence >= self.config.confidence_threshold:
                payload_performance[plugin_name].append(vuln.payload)
        
        return payload_performance
    
    def _extract_response_patterns(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Extract patterns from vulnerability responses"""
        patterns = {
            'common_error_messages': [],
            'response_lengths': [],
            'status_codes': [],
            'timing_patterns': []
        }
        
        for vuln in vulnerabilities:
            if vuln.evidence:
                # Extract common error messages
                error_indicators = ['error', 'exception', 'warning', 'failed']
                for indicator in error_indicators:
                    if indicator.lower() in vuln.evidence.lower():
                        patterns['common_error_messages'].append(indicator)
        
        return patterns
    
    def _analyze_plugin_performance(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Dict[str, Any]]:
        """Analyze performance of individual plugins"""
        plugin_performance = {}
        
        for vuln in vulnerabilities:
            plugin_name = vuln.detected_by
            if plugin_name not in plugin_performance:
                plugin_performance[plugin_name] = {
                    'total_findings': 0,
                    'high_confidence_findings': 0,
                    'avg_confidence': 0.0,
                    'severity_distribution': {}
                }
            
            plugin_performance[plugin_name]['total_findings'] += 1
            
            if vuln.confidence >= 0.7:
                plugin_performance[plugin_name]['high_confidence_findings'] += 1
            
            severity = vuln.severity.value
            plugin_performance[plugin_name]['severity_distribution'][severity] = \
                plugin_performance[plugin_name]['severity_distribution'].get(severity, 0) + 1
        
        # Calculate average confidence per plugin
        for plugin_name in plugin_performance:
            plugin_vulns = [v for v in vulnerabilities if v.detected_by == plugin_name]
            if plugin_vulns:
                avg_confidence = sum(v.confidence for v in plugin_vulns) / len(plugin_vulns)
                plugin_performance[plugin_name]['avg_confidence'] = avg_confidence
        
        return plugin_performance
    
    def _update_metrics(self, learning_entry: LearningData):
        """Update current metrics based on new learning data"""
        # Update efficiency trend
        self.performance_trends['efficiency'].append(learning_entry.scan_efficiency)
        self.performance_trends['false_positives'].append(learning_entry.false_positive_rate)
        
        # Keep only recent trends
        max_trend_size = 50
        for trend in self.performance_trends.values():
            if len(trend) > max_trend_size:
                trend[:] = trend[-max_trend_size:]
        
        # Update current metrics
        if self.performance_trends['efficiency']:
            self.metrics.scan_efficiency = statistics.mean(self.performance_trends['efficiency'])
        
        if self.performance_trends['false_positives']:
            self.metrics.false_positive_rate = statistics.mean(self.performance_trends['false_positives'])
        
        # Update payload success rates
        for plugin_name, payloads in learning_entry.successful_payloads.items():
            if plugin_name not in self.metrics.payload_success_rate:
                self.metrics.payload_success_rate[plugin_name] = 0.0
            
            # Simple moving average
            current_rate = self.metrics.payload_success_rate[plugin_name]
            new_rate = len(payloads) / max(1, learning_entry.vulnerability_count)
            self.metrics.payload_success_rate[plugin_name] = (
                current_rate * (1 - self.config.learning_rate) + 
                new_rate * self.config.learning_rate
            )
    
    def _should_adapt(self) -> bool:
        """Determine if adaptation should be triggered"""
        # Need minimum data points
        if len(self.learning_history) < 10:
            return False
        
        # Check if efficiency is below threshold
        if self.metrics.scan_efficiency < self.config.adaptation_threshold:
            return True
        
        # Check if false positive rate is too high
        if self.metrics.false_positive_rate > 0.5:
            return True
        
        # Check for declining performance trends
        if len(self.performance_trends['efficiency']) >= 10:
            recent_efficiency = statistics.mean(self.performance_trends['efficiency'][-5:])
            older_efficiency = statistics.mean(self.performance_trends['efficiency'][-10:-5])
            
            if recent_efficiency < older_efficiency * 0.8:  # 20% decline
                return True
        
        return False
    
    def _adapt_strategies(self):
        """Adapt scanning strategies based on learning"""
        logger.info("Triggering self-adaptation based on performance metrics")
        
        adaptations = {}
        
        # Payload adaptation
        if self.config.payload_adaptation_enabled:
            adaptations['payloads'] = self._adapt_payload_strategy()
        
        # Scan depth adaptation
        if self.config.depth_adaptation_enabled:
            adaptations['scan_depth'] = self._adapt_scan_depth()
        
        # Timing adaptation
        if self.config.timing_adaptation_enabled:
            adaptations['timing'] = self._adapt_timing_strategy()
        
        # Plugin priority adaptation
        adaptations['plugin_priority'] = self._adapt_plugin_priorities()
        
        self.adaptation_rules.update(adaptations)
        
        logger.info(f"Applied adaptations: {list(adaptations.keys())}")
    
    def _adapt_payload_strategy(self) -> Dict[str, Any]:
        """Adapt payload selection strategy"""
        payload_adaptations = {}
        
        # Analyze successful payloads from recent scans
        recent_data = self.learning_history[-20:]  # Last 20 scans
        
        payload_success_count = {}
        for entry in recent_data:
            for plugin_name, payloads in entry.successful_payloads.items():
                if plugin_name not in payload_success_count:
                    payload_success_count[plugin_name] = {}
                
                for payload in payloads:
                    payload_success_count[plugin_name][payload] = \
                        payload_success_count[plugin_name].get(payload, 0) + 1
        
        # Select top performing payloads for each plugin
        for plugin_name, payload_counts in payload_success_count.items():
            if payload_counts:
                # Sort by success count
                sorted_payloads = sorted(payload_counts.items(), key=lambda x: x[1], reverse=True)
                top_payloads = [payload for payload, count in sorted_payloads[:15]]  # Top 15
                
                payload_adaptations[plugin_name] = {
                    'priority_payloads': top_payloads,
                    'success_threshold': max(2, statistics.mean(payload_counts.values()))
                }
        
        return payload_adaptations
    
    def _adapt_scan_depth(self) -> str:
        """Adapt scan depth based on efficiency"""
        if self.metrics.scan_efficiency > 0.8:
            return 'deep'  # High efficiency, can afford deeper scans
        elif self.metrics.scan_efficiency > 0.5:
            return 'medium'
        else:
            return 'basic'  # Low efficiency, focus on high-impact tests
    
    def _adapt_timing_strategy(self) -> Dict[str, Any]:
        """Adapt timing and concurrency based on performance"""
        timing_adaptations = {}
        
        # Analyze response times from recent scans
        if len(self.performance_trends['response_times']) > 0:
            avg_response_time = statistics.mean(self.performance_trends['response_times'])
            
            if avg_response_time > 5.0:  # Slow responses
                timing_adaptations['max_concurrent_requests'] = max(3, 
                    int(10 * 0.8))  # Reduce concurrency
                timing_adaptations['request_timeout'] = min(60, int(avg_response_time * 2))
            else:  # Fast responses
                timing_adaptations['max_concurrent_requests'] = min(20, 
                    int(10 * 1.2))  # Increase concurrency
                timing_adaptations['request_timeout'] = max(10, int(avg_response_time * 3))
        
        return timing_adaptations
    
    def _adapt_plugin_priorities(self) -> Dict[str, float]:
        """Adapt plugin priorities based on success rates"""
        plugin_priorities = {}
        
        # Analyze plugin performance from recent scans
        recent_data = self.learning_history[-30:]  # Last 30 scans
        
        plugin_stats = {}
        for entry in recent_data:
            if 'plugin_performance' in entry.adaptation_data:
                for plugin_name, performance in entry.adaptation_data['plugin_performance'].items():
                    if plugin_name not in plugin_stats:
                        plugin_stats[plugin_name] = {
                            'total_findings': 0,
                            'high_confidence_findings': 0,
                            'scan_count': 0
                        }
                    
                    plugin_stats[plugin_name]['total_findings'] += performance.get('total_findings', 0)
                    plugin_stats[plugin_name]['high_confidence_findings'] += performance.get('high_confidence_findings', 0)
                    plugin_stats[plugin_name]['scan_count'] += 1
        
        # Calculate priority scores
        for plugin_name, stats in plugin_stats.items():
            if stats['scan_count'] > 0:
                avg_findings = stats['total_findings'] / stats['scan_count']
                high_conf_ratio = stats['high_confidence_findings'] / max(1, stats['total_findings'])
                
                # Priority score based on findings and confidence
                priority_score = (avg_findings * 0.6 + high_conf_ratio * 0.4)
                plugin_priorities[plugin_name] = max(0.1, min(1.0, priority_score))
        
        return plugin_priorities
    
    def get_adaptive_config(self, plugin_name: str = None) -> Dict[str, Any]:
        """Get adaptive configuration for plugins"""
        config = {}
        
        # Apply general adaptations
        if 'scan_depth' in self.adaptation_rules:
            config['scan_depth'] = self.adaptation_rules['scan_depth']
        
        if 'timing' in self.adaptation_rules:
            config.update(self.adaptation_rules['timing'])
        
        # Apply plugin-specific adaptations
        if plugin_name and 'payloads' in self.adaptation_rules:
            if plugin_name in self.adaptation_rules['payloads']:
                config.update(self.adaptation_rules['payloads'][plugin_name])
        
        if plugin_name and 'plugin_priority' in self.adaptation_rules:
            if plugin_name in self.adaptation_rules['plugin_priority']:
                config['priority_weight'] = self.adaptation_rules['plugin_priority'][plugin_name]
        
        return config
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        return {
            'current_metrics': {
                'scan_efficiency': self.metrics.scan_efficiency,
                'false_positive_rate': self.metrics.false_positive_rate,
                'payload_success_rates': self.metrics.payload_success_rate.copy()
            },
            'performance_trends': {
                'efficiency_trend': self.performance_trends['efficiency'][-10:],
                'false_positive_trend': self.performance_trends['false_positives'][-10:]
            },
            'adaptation_status': {
                'total_adaptations': len(self.adaptation_rules),
                'active_rules': list(self.adaptation_rules.keys()),
                'last_adaptation': max([entry.timestamp for entry in self.learning_history[-5:]], 
                                     default=0) if self.learning_history else 0
            },
            'learning_summary': {
                'total_scans_recorded': len(self.learning_history),
                'memory_utilization': len(self.learning_history) / self.config.memory_size,
                'adaptation_confidence': self.metrics.adaptation_confidence
            }
        }
    
    def _save_learning_data(self):
        """Save learning data to disk"""
        try:
            learning_file = Path('vulnmind_learning.json')
            
            # Prepare data for serialization
            data = {
                'metrics': {
                    'scan_efficiency': self.metrics.scan_efficiency,
                    'false_positive_rate': self.metrics.false_positive_rate,
                    'payload_success_rate': self.metrics.payload_success_rate
                },
                'adaptation_rules': self.adaptation_rules,
                'performance_trends': self.performance_trends,
                'learning_history_summary': {
                    'count': len(self.learning_history),
                    'latest_timestamp': self.learning_history[-1].timestamp if self.learning_history else 0
                }
            }
            
            with open(learning_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save learning data: {str(e)}")
    
    def _load_learning_data(self):
        """Load learning data from disk"""
        try:
            learning_file = Path('vulnmind_learning.json')
            
            if learning_file.exists():
                with open(learning_file, 'r') as f:
                    data = json.load(f)
                
                # Restore metrics
                metrics_data = data.get('metrics', {})
                self.metrics.scan_efficiency = metrics_data.get('scan_efficiency', 0.0)
                self.metrics.false_positive_rate = metrics_data.get('false_positive_rate', 0.0)
                self.metrics.payload_success_rate = metrics_data.get('payload_success_rate', {})
                
                # Restore adaptation rules
                self.adaptation_rules = data.get('adaptation_rules', {})
                
                # Restore performance trends
                self.performance_trends = data.get('performance_trends', {
                    'efficiency': [],
                    'false_positives': [],
                    'response_times': []
                })
                
                logger.info("Loaded previous learning data")
                
        except Exception as e:
            logger.error(f"Failed to load learning data: {str(e)}")


def create_self_awareness_module(config: AdaptationConfig = None) -> SelfAwarenessModule:
    """Factory function to create self-awareness module"""
    return SelfAwarenessModule(config or AdaptationConfig())

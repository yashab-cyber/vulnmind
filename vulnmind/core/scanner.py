"""
Core scanner module for VulnMind
"""

import asyncio
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, TYPE_CHECKING
import logging
from urllib.parse import urljoin, urlparse
import re

from bs4 import BeautifulSoup

from vulnmind.core.models import (
    ScanResult, ScanConfig, Vulnerability, VulnType, SeverityLevel
)

if TYPE_CHECKING:
    from vulnmind.utils.http import HttpClient
    from vulnmind.plugins.base import BasePlugin

from vulnmind.utils.logger import get_logger

logger = get_logger(__name__)


class Scanner:
    """Main scanning engine with self-awareness capabilities"""
    
    def __init__(self, config: ScanConfig):
        from vulnmind.utils.http import HttpClient  # Import here to avoid circular import
        
        self.config = config
        self.http_client = HttpClient(config)
        self.plugins: List['BasePlugin'] = []
        self.scan_stats = {
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'false_positives': 0,
            'scan_efficiency': 0.0,
            'avg_response_time': 0.0
        }
        self.adaptive_payloads = {}
        self.learning_data = []
import asyncio
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, TYPE_CHECKING
import logging
from urllib.parse import urljoin, urlparse
import re

from vulnmind.core.models import (
    ScanResult, ScanConfig, Vulnerability, VulnType, SeverityLevel
)

if TYPE_CHECKING:
    from vulnmind.utils.http import HttpClient
    from vulnmind.plugins.base import BasePlugin

from vulnmind.utils.logger import get_logger

logger = get_logger(__name__)


class Scanner:
    """Main scanning engine with self-awareness capabilities"""
    
    def __init__(self, config: ScanConfig):
        from vulnmind.utils.http import HttpClient  # Import here to avoid circular import
        
        self.config = config
        self.http_client = HttpClient(config)
        self.plugins: List['BasePlugin'] = []
        self.scan_stats = {
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'false_positives': 0,
            'scan_efficiency': 0.0,
            'avg_response_time': 0.0
        }
        self.adaptive_payloads = {}
        self.learning_data = []
        
    def register_plugin(self, plugin: 'BasePlugin'):
        """Register a vulnerability detection plugin"""
        self.plugins.append(plugin)
        logger.info(f"Registered plugin: {plugin.__class__.__name__}")
    
    async def scan(self, target_url: str) -> ScanResult:
        """Perform comprehensive security scan"""
        logger.info(f"Starting scan for {target_url}")
        start_time = time.time()
        
        # Initialize scan result
        result = ScanResult(
            target_url=target_url,
            start_time=start_time,
            vulnerabilities=[],
            scan_stats={}
        )
        
        try:
            # Phase 1: Discovery and reconnaissance
            logger.info("Phase 1: Discovery and reconnaissance")
            urls = await self._discover_urls(target_url)
            
            # Phase 2: Vulnerability scanning with self-adaptation
            logger.info("Phase 2: Vulnerability scanning")
            vulnerabilities = await self._scan_vulnerabilities(urls)
            
            # Phase 3: AI analysis (if enabled)
            if self.config.ai_mode:
                logger.info("Phase 3: AI analysis")
                vulnerabilities = await self._ai_analyze(vulnerabilities)
            
            # Phase 4: Self-awareness updates
            await self._update_self_awareness(vulnerabilities)
            
            result.vulnerabilities = vulnerabilities
            result.end_time = time.time()
            result.duration = result.end_time - result.start_time
            result.scan_stats = self.scan_stats.copy()
            
            logger.info(f"Scan completed in {result.duration:.2f}s. Found {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            result.error = str(e)
        
        finally:
            await self.http_client.close()
        
        return result
    
    async def _discover_urls(self, target_url: str) -> List[str]:
        """Discover URLs for scanning"""
        urls = {target_url}
        
        try:
            # Get base page content
            response = await self.http_client.get(target_url)
            if not response:
                return [target_url]
            
            soup = BeautifulSoup(response.text, 'html.parser')
            base_domain = urlparse(target_url).netloc
            
            # Extract links
            for link in soup.find_all(['a', 'form']):
                href = link.get('href') or link.get('action')
                if href:
                    full_url = urljoin(target_url, href)
                    parsed = urlparse(full_url)
                    
                    # Only include same-domain URLs
                    if parsed.netloc == base_domain:
                        urls.add(full_url)
            
            # Discover common paths
            common_paths = [
                '/admin', '/login', '/api', '/upload', '/search',
                '/contact', '/register', '/profile', '/settings'
            ]
            
            for path in common_paths:
                test_url = urljoin(target_url, path)
                response = await self.http_client.get(test_url)
                if response and response.status == 200:
                    urls.add(test_url)
            
        except Exception as e:
            logger.warning(f"URL discovery failed: {str(e)}")
        
        logger.info(f"Discovered {len(urls)} URLs for scanning")
        return list(urls)
    
    async def _scan_vulnerabilities(self, urls: List[str]) -> List[Vulnerability]:
        """Scan for vulnerabilities using all registered plugins"""
        all_vulnerabilities = []
        
        # Create semaphore for concurrent requests
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        
        async def scan_url_with_plugins(url: str):
            async with semaphore:
                url_vulnerabilities = []
                for plugin in self.plugins:
                    try:
                        # Adapt scan depth based on previous findings
                        plugin_config = self._adapt_plugin_config(plugin, url)
                        vulns = await plugin.scan(url, self.http_client, plugin_config)
                        url_vulnerabilities.extend(vulns)
                    except Exception as e:
                        logger.error(f"Plugin {plugin.__class__.__name__} failed on {url}: {str(e)}")
                
                return url_vulnerabilities
        
        # Scan all URLs concurrently
        tasks = [scan_url_with_plugins(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results
        for result in results:
            if isinstance(result, list):
                all_vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Scan task failed: {str(result)}")
        
        # Filter duplicates and false positives
        filtered_vulnerabilities = self._filter_vulnerabilities(all_vulnerabilities)
        
        return filtered_vulnerabilities
    
    def _adapt_plugin_config(self, plugin: 'BasePlugin', url: str) -> Dict[str, Any]:
        """Adapt plugin configuration based on self-awareness data"""
        base_config = plugin.get_default_config()
        
        # Adapt payloads based on previous success
        plugin_name = plugin.__class__.__name__
        if plugin_name in self.adaptive_payloads:
            successful_payloads = self.adaptive_payloads[plugin_name]
            base_config['priority_payloads'] = successful_payloads[:10]  # Top 10 successful
        
        # Adapt scan depth based on efficiency
        if self.scan_stats['scan_efficiency'] > 0.8:
            base_config['scan_depth'] = 'deep'
        elif self.scan_stats['scan_efficiency'] > 0.5:
            base_config['scan_depth'] = 'medium'
        else:
            base_config['scan_depth'] = 'basic'
        
        return base_config
    
    def _filter_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Filter duplicates and false positives"""
        seen = set()
        filtered = []
        
        for vuln in vulnerabilities:
            # Create unique identifier
            vuln_id = f"{vuln.url}:{vuln.vuln_type}:{vuln.parameter}"
            
            if vuln_id not in seen:
                seen.add(vuln_id)
                # Apply confidence threshold
                if vuln.confidence >= 0.5:  # Minimum confidence threshold
                    filtered.append(vuln)
        
        return filtered
    
    async def _ai_analyze(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Use AI to analyze and enhance vulnerability detection"""
        if not self.config.ai_analyzer:
            return vulnerabilities
        
        try:
            enhanced_vulns = await self.config.ai_analyzer.analyze_vulnerabilities(vulnerabilities)
            return enhanced_vulns
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return vulnerabilities
    
    async def _update_self_awareness(self, vulnerabilities: List[Vulnerability]):
        """Update self-awareness metrics and adapt future scans"""
        # Update statistics
        self.scan_stats['vulnerabilities_found'] = len(vulnerabilities)
        
        # Calculate efficiency (vulnerabilities found / requests sent)
        if self.scan_stats['requests_sent'] > 0:
            self.scan_stats['scan_efficiency'] = (
                self.scan_stats['vulnerabilities_found'] / self.scan_stats['requests_sent']
            )
        
        # Update adaptive payloads based on successful detections
        for vuln in vulnerabilities:
            plugin_name = vuln.detected_by
            if plugin_name not in self.adaptive_payloads:
                self.adaptive_payloads[plugin_name] = []
            
            if vuln.payload and vuln.payload not in self.adaptive_payloads[plugin_name]:
                self.adaptive_payloads[plugin_name].append(vuln.payload)
        
        # Store learning data for future improvements
        learning_entry = {
            'timestamp': time.time(),
            'scan_efficiency': self.scan_stats['scan_efficiency'],
            'vulnerabilities_found': len(vulnerabilities),
            'successful_payloads': self.adaptive_payloads.copy()
        }
        self.learning_data.append(learning_entry)
        
        # Keep only recent learning data (last 100 scans)
        if len(self.learning_data) > 100:
            self.learning_data = self.learning_data[-100:]
        
        logger.info(f"Self-awareness updated: Efficiency={self.scan_stats['scan_efficiency']:.2f}")


class CrawlerModule:
    """Web crawler for discovering endpoints and forms"""
    
    def __init__(self, http_client: 'HttpClient'):
        self.http_client = http_client
        self.visited_urls = set()
        self.discovered_forms = []
        self.discovered_parameters = {}
    
    async def crawl(self, start_url: str, max_depth: int = 3) -> Dict[str, Any]:
        """Crawl website to discover attack surface"""
        results = {
            'urls': set(),
            'forms': [],
            'parameters': {},
            'cookies': {},
            'headers': {}
        }
        
        await self._crawl_recursive(start_url, max_depth, results)
        
        return {
            'urls': list(results['urls']),
            'forms': results['forms'],
            'parameters': results['parameters'],
            'cookies': results['cookies'],
            'headers': results['headers']
        }
    
    async def _crawl_recursive(self, url: str, depth: int, results: Dict[str, Any]):
        """Recursive crawling with depth limit"""
        if depth <= 0 or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        results['urls'].add(url)
        
        try:
            response = await self.http_client.get(url)
            if not response:
                return
            
            # Extract cookies
            if hasattr(response, 'cookies'):
                for cookie in response.cookies:
                    results['cookies'][cookie.name] = {
                        'value': cookie.value,
                        'secure': cookie.secure,
                        'httponly': hasattr(cookie, 'httponly') and cookie.httponly
                    }
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Extract form inputs
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    input_data = {
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    }
                    form_data['inputs'].append(input_data)
                
                results['forms'].append(form_data)
            
            # Extract links for further crawling
            base_domain = urlparse(url).netloc
            links = soup.find_all('a', href=True)
            
            for link in links:
                href = link['href']
                full_url = urljoin(url, href)
                parsed_url = urlparse(full_url)
                
                # Only crawl same domain
                if parsed_url.netloc == base_domain:
                    await self._crawl_recursive(full_url, depth - 1, results)
        
        except Exception as e:
            logger.warning(f"Crawling failed for {url}: {str(e)}")


def create_scanner(config: ScanConfig) -> Scanner:
    """Factory function to create a configured scanner instance"""
    scanner = Scanner(config)
    
    # Register all available plugins
    from vulnmind.plugins import (
        SQLInjectionPlugin, XSSPlugin, CSRFPlugin,
        OpenRedirectPlugin, CommandInjectionPlugin, DirectoryTraversalPlugin
    )
    
    plugins = [
        SQLInjectionPlugin(),
        XSSPlugin(),
        CSRFPlugin(),
        OpenRedirectPlugin(),
        CommandInjectionPlugin(),
        DirectoryTraversalPlugin()
    ]
    
    for plugin in plugins:
        scanner.register_plugin(plugin)
    
    return scanner

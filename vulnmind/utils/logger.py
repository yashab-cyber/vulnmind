"""
Logging utility for VulnMind
"""

import logging
import sys
import os
from typing import Optional
from logging.handlers import RotatingFileHandler
from pathlib import Path
import colorama
from colorama import Fore, Back, Style

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.YELLOW + Style.BRIGHT
    }
    
    def format(self, record):
        # Add color to levelname
        if record.levelname in self.COLORS:
            colored_levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
            record.levelname = colored_levelname
        
        # Format timestamp
        if hasattr(record, 'created'):
            import time
            record.asctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.created))
        
        return super().format(record)


class VulnMindLogger:
    """Custom logger for VulnMind with colored output and file logging"""
    
    def __init__(self, name: str = 'vulnmind', level: str = 'INFO', log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Prevent adding multiple handlers
        if self.logger.handlers:
            return
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = ColoredFormatter(
            fmt=f'{Fore.WHITE}[%(asctime)s]{Style.RESET_ALL} %(levelname)s {Fore.BLUE}%(name)s{Style.RESET_ALL}: %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (if specified)
        if log_file:
            try:
                # Create log directory if it doesn't exist
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Rotating file handler to prevent large log files
                file_handler = RotatingFileHandler(
                    log_file, 
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                )
                
                file_formatter = logging.Formatter(
                    fmt='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(file_formatter)
                self.logger.addHandler(file_handler)
                
            except Exception as e:
                self.logger.warning(f"Failed to setup file logging: {e}")
    
    def get_logger(self):
        """Get the configured logger"""
        return self.logger


# Global logger instance
_global_logger: Optional[VulnMindLogger] = None


def setup_logging(level: str = None, log_file: str = None) -> logging.Logger:
    """Setup global logging configuration"""
    global _global_logger
    
    # Get level from environment if not specified
    if level is None:
        level = os.getenv('LOG_LEVEL', 'INFO')
    
    # Get log file from environment if not specified
    if log_file is None:
        log_file = os.getenv('LOG_FILE')
    
    _global_logger = VulnMindLogger('vulnmind', level, log_file)
    return _global_logger.get_logger()


def get_logger(name: str = None) -> logging.Logger:
    """Get logger instance"""
    global _global_logger
    
    if _global_logger is None:
        setup_logging()
    
    if name:
        # Create child logger
        return logging.getLogger(name)
    else:
        return _global_logger.get_logger()


class ScanProgressLogger:
    """Specialized logger for scan progress tracking"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.current_phase = ""
        self.total_urls = 0
        self.processed_urls = 0
        self.vulnerabilities_found = 0
    
    def start_scan(self, target_url: str, total_urls: int = 1):
        """Log scan start"""
        self.total_urls = total_urls
        self.processed_urls = 0
        self.vulnerabilities_found = 0
        
        self.logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        self.logger.info(f"{Fore.CYAN}Starting VulnMind scan for: {Fore.WHITE}{target_url}{Style.RESET_ALL}")
        self.logger.info(f"{Fore.CYAN}Total URLs to scan: {self.total_urls}{Style.RESET_ALL}")
        self.logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    def start_phase(self, phase_name: str):
        """Log phase start"""
        self.current_phase = phase_name
        self.logger.info(f"{Fore.YELLOW}📋 Phase: {phase_name}{Style.RESET_ALL}")
    
    def log_url_progress(self, url: str):
        """Log URL processing progress"""
        self.processed_urls += 1
        progress = (self.processed_urls / self.total_urls) * 100 if self.total_urls > 0 else 0
        
        self.logger.info(f"{Fore.BLUE}🔍 [{progress:.1f}%] Scanning: {url}{Style.RESET_ALL}")
    
    def log_vulnerability_found(self, vuln_type: str, url: str, severity: str):
        """Log vulnerability discovery"""
        self.vulnerabilities_found += 1
        
        # Color by severity
        severity_colors = {
            'critical': Fore.RED + Back.WHITE + Style.BRIGHT,
            'high': Fore.RED + Style.BRIGHT,
            'medium': Fore.YELLOW + Style.BRIGHT,
            'low': Fore.CYAN,
            'info': Fore.WHITE
        }
        
        severity_color = severity_colors.get(severity.lower(), Fore.WHITE)
        
        self.logger.warning(f"{Fore.RED}🚨 VULNERABILITY FOUND:{Style.RESET_ALL} "
                          f"{severity_color}{severity.upper()}{Style.RESET_ALL} "
                          f"{Fore.WHITE}{vuln_type}{Style.RESET_ALL} at {Fore.BLUE}{url}{Style.RESET_ALL}")
    
    def log_plugin_start(self, plugin_name: str, url: str):
        """Log plugin execution start"""
        self.logger.debug(f"  🔧 Running {plugin_name} on {url}")
    
    def log_plugin_complete(self, plugin_name: str, vulnerabilities_found: int, duration: float):
        """Log plugin execution completion"""
        if vulnerabilities_found > 0:
            self.logger.info(f"  ✅ {plugin_name}: {vulnerabilities_found} vulnerabilities found ({duration:.2f}s)")
        else:
            self.logger.debug(f"  ✅ {plugin_name}: No vulnerabilities found ({duration:.2f}s)")
    
    def complete_scan(self, duration: float, total_vulnerabilities: int):
        """Log scan completion"""
        self.logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        self.logger.info(f"{Fore.GREEN}✅ Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
        self.logger.info(f"{Fore.WHITE}📊 URLs scanned: {self.processed_urls}{Style.RESET_ALL}")
        
        if total_vulnerabilities > 0:
            self.logger.warning(f"{Fore.RED}🚨 Total vulnerabilities found: {total_vulnerabilities}{Style.RESET_ALL}")
        else:
            self.logger.info(f"{Fore.GREEN}✅ No vulnerabilities found{Style.RESET_ALL}")
        
        self.logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    def log_error(self, message: str, exception: Exception = None):
        """Log error with optional exception details"""
        self.logger.error(f"{Fore.RED}❌ {message}{Style.RESET_ALL}")
        
        if exception:
            self.logger.debug(f"Exception details: {str(exception)}")
    
    def log_ai_analysis(self, vulnerabilities_before: int, vulnerabilities_after: int):
        """Log AI analysis results"""
        filtered_count = vulnerabilities_before - vulnerabilities_after
        
        if filtered_count > 0:
            self.logger.info(f"{Fore.MAGENTA}🤖 AI Analysis: Filtered out {filtered_count} potential false positives{Style.RESET_ALL}")
        else:
            self.logger.info(f"{Fore.MAGENTA}🤖 AI Analysis: All vulnerabilities validated{Style.RESET_ALL}")
    
    def log_self_awareness(self, efficiency: float, adaptations: int):
        """Log self-awareness updates"""
        self.logger.info(f"{Fore.CYAN}🧠 Self-Awareness: Efficiency={efficiency:.2f}, Adaptations={adaptations}{Style.RESET_ALL}")


def create_scan_logger(logger: logging.Logger = None) -> ScanProgressLogger:
    """Create scan progress logger"""
    if logger is None:
        logger = get_logger()
    
    return ScanProgressLogger(logger)


# Utility functions for common log patterns
def log_banner():
    """Log VulnMind banner"""
    logger = get_logger()
    
    banner = f"""
{Fore.CYAN}
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███╗   ███╗██╗███╗   ██╗██╗     
██║   ██║██║   ██║██║     ████╗  ██║████╗ ████║██║████╗  ██║██║     
██║   ██║██║   ██║██║     ██╔██╗ ██║██╔████╔██║██║██╔██╗ ██║██║     
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║╚██╔╝██║██║██║╚██╗██║██║     
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║ ╚═╝ ██║██║██║ ╚████║███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}              AI-Powered Self-Aware DAST Scanner{Style.RESET_ALL}
{Fore.YELLOW}                     Version 1.0.0{Style.RESET_ALL}
"""
    
    for line in banner.split('\n'):
        logger.info(line)


def log_configuration(config):
    """Log scanner configuration"""
    logger = get_logger()
    
    logger.info(f"{Fore.WHITE}Configuration:{Style.RESET_ALL}")
    logger.info(f"  Target: {config.target_url}")
    logger.info(f"  AI Mode: {'Enabled' if config.ai_mode else 'Disabled'}")
    logger.info(f"  Scan Depth: {config.scan_depth}")
    logger.info(f"  Max Concurrent Requests: {config.max_concurrent_requests}")
    logger.info(f"  Request Timeout: {config.request_timeout}s")
    logger.info(f"  Follow Redirects: {config.follow_redirects}")
    logger.info(f"  Verify SSL: {config.verify_ssl}")

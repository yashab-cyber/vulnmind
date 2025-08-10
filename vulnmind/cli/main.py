"""
Main CLI interface for VulnMind
"""

import asyncio
import os
import sys
import argparse
from typing import Optional
from pathlib import Path

from vulnmind.core import create_scanner, ScanConfig
from vulnmind.ai import create_ai_analyzer, create_self_awareness_module, AdaptationConfig
from vulnmind.reports import generate_report
from vulnmind.utils import (
    setup_logging, get_logger, create_scan_logger, log_banner, log_configuration,
    validate_url, normalize_url
)

logger = get_logger(__name__)


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        prog='vulnmind',
        description='VulnMind - AI-Powered Self-Aware DAST Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnmind --target https://example.com
  vulnmind --target https://example.com --ai-mode --report html
  vulnmind --target https://example.com --depth deep --concurrent 20
  vulnmind --target https://example.com --proxy http://127.0.0.1:8080
        """
    )
    
    # Required arguments
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target URL to scan (e.g., https://example.com)'
    )
    
    # Output options
    parser.add_argument(
        '--report', '-r',
        choices=['json', 'html', 'both'],
        default='json',
        help='Report format (default: json)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path (auto-generated if not specified)'
    )
    
    # AI options
    parser.add_argument(
        '--ai-mode',
        action='store_true',
        help='Enable AI analysis for enhanced vulnerability detection'
    )
    
    parser.add_argument(
        '--ai-model',
        default='gpt-4',
        help='AI model to use (default: gpt-4)'
    )
    
    parser.add_argument(
        '--openai-api-key',
        help='OpenAI API key (or set OPENAI_API_KEY environment variable)'
    )
    
    # Scanning options
    parser.add_argument(
        '--depth',
        choices=['basic', 'medium', 'deep'],
        default='medium',
        help='Scan depth (default: medium)'
    )
    
    parser.add_argument(
        '--concurrent',
        type=int,
        default=10,
        help='Maximum concurrent requests (default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--user-agent',
        default='VulnMind/1.0',
        help='User agent string (default: VulnMind/1.0)'
    )
    
    parser.add_argument(
        '--proxy',
        help='HTTP proxy URL (e.g., http://127.0.0.1:8080)'
    )
    
    parser.add_argument(
        '--headers',
        action='append',
        help='Custom headers (format: "Name: Value")'
    )
    
    parser.add_argument(
        '--cookies',
        help='Cookies string (format: "name1=value1; name2=value2")'
    )
    
    # Authentication options
    parser.add_argument(
        '--auth-type',
        choices=['basic', 'bearer'],
        help='Authentication type'
    )
    
    parser.add_argument(
        '--auth-username',
        help='Username for basic authentication'
    )
    
    parser.add_argument(
        '--auth-password',
        help='Password for basic authentication'
    )
    
    parser.add_argument(
        '--auth-token',
        help='Token for bearer authentication'
    )
    
    # SSL options
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    
    parser.add_argument(
        '--no-follow-redirects',
        action='store_true',
        help='Disable following redirects'
    )
    
    # Plugin options
    parser.add_argument(
        '--plugins',
        help='Comma-separated list of plugins to enable (default: all)'
    )
    
    parser.add_argument(
        '--exclude-plugins',
        help='Comma-separated list of plugins to exclude'
    )
    
    # Logging options
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--log-file',
        help='Log file path'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress output except errors'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    # Self-awareness options
    parser.add_argument(
        '--learning-rate',
        type=float,
        default=0.1,
        help='Learning rate for self-awareness (default: 0.1)'
    )
    
    parser.add_argument(
        '--adaptation-threshold',
        type=float,
        default=0.7,
        help='Adaptation threshold for efficiency (default: 0.7)'
    )
    
    # Utility options
    parser.add_argument(
        '--version',
        action='version',
        version='VulnMind 1.0.0'
    )
    
    return parser


def parse_headers(header_list: list) -> dict:
    """Parse header list into dictionary"""
    headers = {}
    
    if header_list:
        for header in header_list:
            if ':' in header:
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()
    
    return headers


def parse_cookies(cookie_string: str) -> dict:
    """Parse cookie string into dictionary"""
    cookies = {}
    
    if cookie_string:
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()
    
    return cookies


def setup_authentication(args) -> Optional[dict]:
    """Setup authentication configuration"""
    if args.auth_type:
        auth_config = {'type': args.auth_type}
        
        if args.auth_type == 'basic':
            if args.auth_username and args.auth_password:
                auth_config.update({
                    'username': args.auth_username,
                    'password': args.auth_password
                })
            else:
                logger.warning("Basic auth specified but username/password missing")
                return None
        
        elif args.auth_type == 'bearer':
            if args.auth_token:
                auth_config['token'] = args.auth_token
            else:
                logger.warning("Bearer auth specified but token missing")
                return None
        
        return auth_config
    
    return None


def create_scan_config(args) -> ScanConfig:
    """Create scan configuration from arguments"""
    # Setup authentication
    authentication = setup_authentication(args)
    
    # Parse headers and cookies
    headers = parse_headers(args.headers or [])
    cookies = parse_cookies(args.cookies or "")
    
    # Create AI analyzer if enabled
    ai_analyzer = None
    if args.ai_mode:
        api_key = args.openai_api_key or os.getenv('OPENAI_API_KEY')
        if api_key:
            ai_analyzer = create_ai_analyzer(
                api_key=api_key,
                model=args.ai_model,
                temperature=0.1
            )
        else:
            logger.warning("AI mode enabled but no OpenAI API key provided")
    
    # Create scan configuration
    config = ScanConfig(
        target_url=normalize_url(args.target),
        ai_mode=args.ai_mode,
        max_concurrent_requests=args.concurrent,
        request_timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        headers=headers,
        cookies=cookies,
        authentication=authentication,
        scan_depth=args.depth,
        follow_redirects=not args.no_follow_redirects,
        verify_ssl=not args.no_verify_ssl,
        ai_analyzer=ai_analyzer
    )
    
    return config


def setup_self_awareness(args):
    """Setup self-awareness module"""
    adaptation_config = AdaptationConfig(
        learning_rate=args.learning_rate,
        adaptation_threshold=args.adaptation_threshold,
        memory_size=1000,
        confidence_threshold=0.5
    )
    
    return create_self_awareness_module(adaptation_config)


async def run_scan(config: ScanConfig, args) -> int:
    """Run the vulnerability scan"""
    try:
        # Create scanner
        scanner = create_scanner(config)
        
        # Setup self-awareness
        self_awareness = setup_self_awareness(args)
        
        # Create scan logger
        scan_logger = create_scan_logger()
        
        # Start scan
        scan_logger.start_scan(config.target_url)
        
        # Perform scan
        scan_result = await scanner.scan(config.target_url)
        
        # Record results for self-awareness
        self_awareness.record_scan_results(
            scan_result.vulnerabilities,
            scan_result.scan_stats
        )
        
        # Log completion
        scan_logger.complete_scan(
            scan_result.duration or 0,
            len(scan_result.vulnerabilities)
        )
        
        # Generate reports
        if scan_result.error:
            logger.error(f"Scan failed: {scan_result.error}")
            return 1
        
        # Generate reports
        await generate_reports(scan_result, args)
        
        # Log self-awareness metrics
        performance_report = self_awareness.get_performance_report()
        scan_logger.log_self_awareness(
            performance_report['current_metrics']['scan_efficiency'],
            performance_report['adaptation_status']['total_adaptations']
        )
        
        # Exit code based on vulnerabilities found
        if scan_result.vulnerabilities:
            critical_high = sum(1 for v in scan_result.vulnerabilities 
                              if v.severity.value in ['critical', 'high'])
            return 2 if critical_high > 0 else 1
        else:
            return 0
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130
    
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        return 1


async def generate_reports(scan_result, args):
    """Generate scan reports"""
    if args.report in ['json', 'both']:
        json_path = generate_report(scan_result, 'json', args.output)
        if json_path:
            logger.info(f"📄 JSON report: {json_path}")
    
    if args.report in ['html', 'both']:
        html_output = args.output
        if html_output and not html_output.endswith('.html'):
            html_output = html_output.replace('.json', '.html')
        
        html_path = generate_report(scan_result, 'html', html_output)
        if html_path:
            logger.info(f"📄 HTML report: {html_path}")


def validate_arguments(args) -> bool:
    """Validate command line arguments"""
    # Validate target URL
    if not validate_url(args.target):
        logger.error(f"Invalid target URL: {args.target}")
        return False
    
    # Validate concurrent requests
    if args.concurrent < 1 or args.concurrent > 100:
        logger.error("Concurrent requests must be between 1 and 100")
        return False
    
    # Validate timeout
    if args.timeout < 1 or args.timeout > 300:
        logger.error("Timeout must be between 1 and 300 seconds")
        return False
    
    # Validate learning rate
    if not 0.01 <= args.learning_rate <= 1.0:
        logger.error("Learning rate must be between 0.01 and 1.0")
        return False
    
    # Validate adaptation threshold
    if not 0.1 <= args.adaptation_threshold <= 1.0:
        logger.error("Adaptation threshold must be between 0.1 and 1.0")
        return False
    
    return True


async def async_main():
    """Async CLI entry point"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = 'ERROR' if args.quiet else ('DEBUG' if args.verbose else args.log_level)
    setup_logging(level=log_level, log_file=args.log_file)
    
    # Show banner
    if not args.quiet:
        log_banner()
    
    # Validate arguments
    if not validate_arguments(args):
        sys.exit(1)
    
    # Create scan configuration
    try:
        config = create_scan_config(args)
    except Exception as e:
        logger.error(f"Configuration error: {str(e)}")
        sys.exit(1)
    
    # Log configuration
    if not args.quiet:
        log_configuration(config)
    
    # Run scan
    exit_code = await run_scan(config, args)
    sys.exit(exit_code)


def main():
    """Main CLI entry point"""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

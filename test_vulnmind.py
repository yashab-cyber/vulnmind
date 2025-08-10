#!/usr/bin/env python3
"""
Simple test script to verify VulnMind core functionality
"""

import asyncio
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnmind.core.models import ScanConfig
from vulnmind.core.scanner import create_scanner


async def test_basic_scan():
    """Test basic scanning functionality"""
    print("Testing VulnMind basic functionality...")
    
    # Create configuration
    config = ScanConfig(
        target_url="https://httpbin.org/html",
        max_concurrent_requests=2,
        request_timeout=10
    )
    
    print(f"✓ Configuration created for target: {config.target_url}")
    
    # Create scanner
    try:
        scanner = create_scanner(config)
        print(f"✓ Scanner created with {len(scanner.plugins)} plugins")
        
        # Perform scan
        print("Starting scan...")
        result = await scanner.scan(config.target_url)
        
        print(f"✓ Scan completed in {result.duration:.2f}s")
        print(f"✓ Found {len(result.vulnerabilities)} vulnerabilities")
        print(f"✓ Scan statistics: {result.scan_stats}")
        
        if result.error:
            print(f"⚠ Warning: {result.error}")
        else:
            print("✓ Scan completed successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_basic_scan())
    sys.exit(0 if success else 1)

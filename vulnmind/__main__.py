#!/usr/bin/env python3
"""
VulnMind CLI Entry Point
"""

import sys
import asyncio
from vulnmind.cli.main import main

if __name__ == "__main__":
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

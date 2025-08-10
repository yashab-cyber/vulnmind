"""
Test configuration
"""

import pytest
import asyncio


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Test configuration
pytest_plugins = ["pytest_asyncio"]

# Async test timeout
@pytest.fixture(autouse=True)
def setup_test_timeout():
    """Setup test timeout for async tests"""
    import asyncio
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())

# Contributing to VulnMind 🛡️

Thank you for your interest in contributing to VulnMind! We welcome contributions from the cybersecurity community and appreciate your help in making web applications more secure.

## 🌟 How to Contribute

### 🐛 Reporting Bugs

If you find a bug, please create an issue with:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment details** (OS, Python version, etc.)
- **Screenshots or logs** if applicable

### 💡 Suggesting Features

We love new ideas! Please create an issue with:

- **Clear description** of the feature
- **Use case** explaining why it's needed
- **Proposed implementation** (if you have ideas)
- **Examples** of similar features in other tools

### 🔧 Code Contributions

#### Development Setup

1. **Fork the repository**
```bash
git clone https://github.com/YOUR_USERNAME/vulnmind.git
cd vulnmind
```

2. **Set up development environment**
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

3. **Install pre-commit hooks**
```bash
pre-commit install
```

#### Making Changes

1. **Create a feature branch**
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

2. **Make your changes**
   - Follow our coding standards (see below)
   - Add tests for new functionality
   - Update documentation if needed

3. **Run tests**
```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=vulnmind

# Run specific tests
python -m pytest tests/test_scanner.py
```

4. **Commit your changes**
```bash
git add .
git commit -m "feat: add new vulnerability detection plugin"
```

5. **Push and create PR**
```bash
git push origin feature/your-feature-name
```

## 📋 Coding Standards

### Code Style

- **PEP 8**: Follow Python PEP 8 style guidelines
- **Type hints**: Use type annotations for all functions
- **Docstrings**: Document all public functions and classes
- **Line length**: Maximum 88 characters (Black formatter)

### Example Code Style

```python
from typing import List, Optional
import asyncio

class VulnerabilityPlugin:
    """Base class for vulnerability detection plugins.
    
    Args:
        name: Plugin name identifier
        description: Human-readable description
    """
    
    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description
    
    async def check(self, url: str, **kwargs) -> List[Vulnerability]:
        """Check for vulnerabilities at the given URL.
        
        Args:
            url: Target URL to test
            **kwargs: Additional parameters
            
        Returns:
            List of detected vulnerabilities
        """
        raise NotImplementedError("Subclasses must implement check method")
```

### Commit Message Format

Use conventional commits format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(plugins): add GraphQL injection detection
fix(scanner): resolve race condition in concurrent scanning
docs(readme): update installation instructions
test(ai): add unit tests for AI analyzer
```

## 🔌 Plugin Development

### Creating a New Vulnerability Plugin

1. **Create plugin file**
```bash
touch vulnmind/plugins/your_plugin.py
```

2. **Implement the plugin**
```python
from typing import List
from vulnmind.plugins.base import BasePlugin
from vulnmind.core.models import Vulnerability

class YourVulnerabilityPlugin(BasePlugin):
    name = "your_vulnerability"
    description = "Description of your vulnerability check"
    
    async def check(self, url: str, **kwargs) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Your detection logic here
        
        return vulnerabilities
```

3. **Add tests**
```python
# tests/test_your_plugin.py
import pytest
from vulnmind.plugins.your_plugin import YourVulnerabilityPlugin

@pytest.mark.asyncio
async def test_your_plugin_detection():
    plugin = YourVulnerabilityPlugin()
    results = await plugin.check("https://example.com")
    assert isinstance(results, list)
```

4. **Register the plugin**
Add your plugin to the registry in `vulnmind/core/scanner.py`

### Plugin Guidelines

- **Single responsibility**: Each plugin should detect one type of vulnerability
- **Async operations**: All network operations must be async
- **Error handling**: Gracefully handle network errors and timeouts
- **Performance**: Consider rate limiting and resource usage
- **Documentation**: Provide clear docstrings and examples

## 🧪 Testing Guidelines

### Test Structure

```
tests/
├── unit/                 # Unit tests
│   ├── test_scanner.py
│   └── test_plugins.py
├── integration/          # Integration tests
│   └── test_full_scan.py
└── fixtures/            # Test data and fixtures
    └── test_responses.py
```

### Writing Tests

- **Coverage**: Aim for >90% test coverage
- **Isolation**: Tests should not depend on external services
- **Mocking**: Mock HTTP requests and external dependencies
- **Async tests**: Use `@pytest.mark.asyncio` for async functions

### Example Test

```python
import pytest
from unittest.mock import AsyncMock, patch
from vulnmind.plugins.sql_injection import SQLInjectionPlugin

@pytest.mark.asyncio
async def test_sql_injection_detection():
    plugin = SQLInjectionPlugin()
    
    with patch('vulnmind.utils.http.HttpClient.get') as mock_get:
        mock_get.return_value = AsyncMock(
            text="SQL error: syntax error",
            status_code=500
        )
        
        results = await plugin.check("https://example.com/search?q=test")
        assert len(results) > 0
        assert results[0].type == "sql_injection"
```

## 📚 Documentation

### Types of Documentation

1. **Code Documentation**
   - Docstrings for all public APIs
   - Type hints for all functions
   - Inline comments for complex logic

2. **User Documentation**
   - README updates for new features
   - Usage examples
   - Configuration guides

3. **Developer Documentation**
   - Architecture decisions
   - Plugin development guides
   - API references

### Documentation Style

- **Clear and concise**: Use simple, direct language
- **Examples**: Provide practical examples
- **Up-to-date**: Keep documentation current with code changes
- **Accessible**: Consider different skill levels

## 🏷️ Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in `setup.py`
- [ ] Tag created and pushed
- [ ] GitHub release created
- [ ] PyPI package published

## 🤝 Code Review Process

### What We Look For

1. **Functionality**: Does the code work as intended?
2. **Security**: Are there any security implications?
3. **Performance**: Is the code efficient?
4. **Maintainability**: Is the code readable and well-structured?
5. **Tests**: Are there adequate tests?
6. **Documentation**: Is the code properly documented?

### Review Timeline

- **Initial review**: Within 48 hours
- **Follow-up reviews**: Within 24 hours
- **Security-related PRs**: Priority review

## 🏆 Recognition

Contributors will be recognized in:

- **README.md**: Contributors section
- **CHANGELOG.md**: Release notes
- **GitHub releases**: Special mentions
- **Social media**: Feature announcements

### Hall of Fame

Top contributors may receive:

- **Collaborator access** to the repository
- **Special badges** in discussions
- **Early access** to new features
- **Exclusive merchandise** (when available)

## 📞 Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Email**: yashabalam707@gmail.com (for sensitive issues)
- **WhatsApp**: [Business Channel](https://whatsapp.com/channel/0029Vaoa1GfKLaHlL0Kc8k1q)

### Response Times

- **Bug reports**: 24-48 hours
- **Feature requests**: 48-72 hours
- **Security issues**: 12-24 hours
- **General questions**: 24-48 hours

## 📋 Contributor License Agreement

By contributing to VulnMind, you agree that:

1. **Your contributions** will be licensed under the same MIT license
2. **You have the right** to submit the contribution
3. **ZehraSec and Yashab Alam** may use your contributions
4. **You retain copyright** to your contributions

## 🎯 Current Priorities

### High Priority
- [ ] Additional OWASP Top 10 vulnerability plugins
- [ ] Performance optimizations for large-scale scanning
- [ ] Enhanced AI model integration
- [ ] CI/CD pipeline integration tools

### Medium Priority
- [ ] Web dashboard for scan management
- [ ] API security testing modules
- [ ] Cloud deployment guides
- [ ] Mobile app companion

### Low Priority
- [ ] Additional output formats
- [ ] Plugin marketplace
- [ ] Community templates
- [ ] Internationalization

## 🙏 Thank You!

Thank you for contributing to VulnMind and helping make the web more secure! Every contribution, no matter how small, makes a difference.

---

**Questions?** Feel free to reach out to us through any of our communication channels. We're here to help!

**Made with ❤️ by the VulnMind community**

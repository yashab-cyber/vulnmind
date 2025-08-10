#!/usr/bin/env python3
"""
Setup script for VulnMind - AI-Powered Self-Aware DAST Scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README.md
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
requirements_file = this_directory / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file) as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="vulnmind",
    version="1.0.0",
    author="VulnMind Team",
    author_email="team@vulnmind.ai",
    description="AI-Powered Self-Aware DAST Scanner for Advanced Web Application Security Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vulnmind/vulnmind",
    project_urls={
        "Bug Tracker": "https://github.com/vulnmind/vulnmind/issues",
        "Documentation": "https://docs.vulnmind.ai",
        "Source": "https://github.com/vulnmind/vulnmind",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-asyncio>=0.18.0",
            "pytest-cov>=2.12.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
            "pre-commit>=2.15.0",
        ],
        "docs": [
            "sphinx>=4.0.0",
            "sphinx-rtd-theme>=0.5.0",
            "myst-parser>=0.15.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vulnmind=vulnmind.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "vulnmind": [
            "reports/templates/*.html",
            "reports/templates/*.css",
            "reports/templates/*.js",
        ],
    },
    zip_safe=False,
    keywords=[
        "security",
        "vulnerability",
        "scanner",
        "dast",
        "ai",
        "web",
        "penetration-testing",
        "cybersecurity",
    ],
)

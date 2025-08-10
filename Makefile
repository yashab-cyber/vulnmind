.PHONY: help install install-dev test lint format clean build docs run example

# Default target
help:
	@echo "VulnMind - AI-Powered Self-Aware DAST Scanner"
	@echo ""
	@echo "Available targets:"
	@echo "  install     - Install package in production mode"
	@echo "  install-dev - Install package in development mode"
	@echo "  test        - Run tests"
	@echo "  lint        - Run linting checks"
	@echo "  format      - Format code with black"
	@echo "  clean       - Clean build artifacts"
	@echo "  build       - Build package"
	@echo "  docs        - Generate documentation"
	@echo "  run         - Run VulnMind with example target"
	@echo "  example     - Run example scan"

# Installation
install:
	pip install -r requirements.txt
	pip install -e .

install-dev:
	pip install -r requirements.txt
	pip install -e ".[dev]"

# Testing
test:
	python -m pytest tests/ -v

test-cov:
	python -m pytest tests/ -v --cov=vulnmind --cov-report=html --cov-report=term

# Code quality
lint:
	flake8 vulnmind/ tests/
	mypy vulnmind/

format:
	black vulnmind/ tests/
	isort vulnmind/ tests/

# Build and packaging
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python setup.py sdist bdist_wheel

# Documentation
docs:
	@echo "Documentation generation not yet implemented"

# Example usage
run:
	@echo "Running VulnMind with example configuration..."
	python -m vulnmind.cli.main --help

example:
	@echo "Running example scan (requires target URL)..."
	@echo "Usage: make example TARGET=https://example.com"
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: Please provide TARGET variable"; \
		echo "Example: make example TARGET=https://httpbin.org"; \
	else \
		python -m vulnmind.cli.main --target $(TARGET) --report-format json --output ./reports/example-scan.json; \
	fi

# Development helpers
setup-dev: install-dev
	pre-commit install

check: lint test

release: clean test lint build
	@echo "Package is ready for release"

# Docker targets (if Docker is available)
docker-build:
	@if command -v docker >/dev/null 2>&1; then \
		echo "Building Docker image..."; \
		docker build -t vulnmind:latest .; \
	else \
		echo "Docker not available"; \
	fi

docker-run:
	@if command -v docker >/dev/null 2>&1; then \
		echo "Running VulnMind in Docker..."; \
		docker run --rm -it vulnmind:latest --help; \
	else \
		echo "Docker not available"; \
	fi

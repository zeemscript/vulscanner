# VulnScan AI Makefile
# Easy commands for development and testing

.PHONY: help install test lint format security clean docker-build docker-run

# Default target
help:
	@echo "VulnScan AI - Available Commands:"
	@echo ""
	@echo "Development:"
	@echo "  install     - Install basic dependencies"
	@echo "  install-full - Install all dependencies (including dev tools)"
	@echo "  install-dev - Install in development mode"
	@echo "  test        - Run tests"
	@echo "  test-with-coverage - Run tests with coverage report"
	@echo "  lint        - Run linting"
	@echo "  format      - Format code"
	@echo "  security    - Run security checks"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo ""
	@echo "Utilities:"
	@echo "  clean       - Clean up generated files"
	@echo "  scan-example - Run example scan"

# Development commands
install:
	pip install -r requirements-basic.txt

install-full:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest tests/ -v

test-with-coverage:
	pytest tests/ -v --cov=vulnscan_ai --cov-report=term-missing

test-fast:
	pytest tests/ -v -m "not slow"

lint:
	flake8 vulnscan_ai/ tests/
	mypy vulnscan_ai/

format:
	black vulnscan_ai/ tests/
	isort vulnscan_ai/ tests/

security:
	safety check
	bandit -r vulnscan_ai/

# Docker commands
docker-build:
	docker build -t vulnscan-ai .

docker-run:
	docker run --rm -it vulnscan-ai

# Example scan
scan-example:
	python -m vulnscan_ai.main httpbin.org --scan-types web ssl --output json

# Clean up
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/

# Full development setup
setup: install-dev
	@echo "Setting up development environment..."
	@echo "Copy env.example to .env and update with your API keys"
	@echo "Run 'make test' to verify installation"

# Analysis Engine

The brain of Code Archaeologist - a Python microservice that detects vulnerabilities, architecture violations, and "vibe coding" patterns in AI-generated codebases.

## Features

- **418+ Vulnerability Patterns** across OWASP 2013-2024
- **Self-Validating** - Tests against known vulnerabilities on startup
- **Confidence Scoring** - Every finding includes confidence level
- **Framework-Specific** - Deep knowledge of Django, React, FastAPI, Flask
- **AI-Powered Fixes** - Generates fixes using Claude API
- **Race Condition Detection** - Specialized TOCTOU and async race detection

## Architecture

```
analysis-engine/
├── core/              # Core scanning logic
├── detectors/         # Specific vulnerability detectors
├── frameworks/        # Framework-specific analyzers
├── owasp/            # OWASP pattern libraries
├── ai/               # AI fix generation
├── reports/          # Report generation
├── database/         # Data models and storage
└── api/              # FastAPI REST API
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run self-validation tests
pytest tests/

# Start the API server
python -m api.main

# Or use the CLI
python -m cli.main analyze /path/to/project
```

## API Endpoints

```
POST /api/v1/scan          - Scan a codebase
GET  /api/v1/scan/{id}     - Get scan results
POST /api/v1/fix           - Generate fix for an issue
GET  /api/v1/patterns      - List all patterns
GET  /api/v1/health        - Health check
```

## Adding New Patterns

See [CONTRIBUTING.md](../docs/CONTRIBUTING.md) for guidelines on adding new vulnerability patterns.

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov --cov-fail-under=85

# Run specific test file
pytest tests/detectors/test_sql_injection.py
```

## Code Quality

```bash
# Format code
black . && isort .

# Lint
ruff check .

# Type checking
mypy .
```

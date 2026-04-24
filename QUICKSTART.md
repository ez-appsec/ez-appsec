# Developer Quick Reference

Quick commands for development and testing.

## Setup

```bash
# Clone repository
git clone https://github.com/ez-appsec/ez-appsec.git
cd ez-appsec

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install development dependencies
pip install pytest pytest-cov pytest-xdist
pip install flake8 black isort pylint bandit safety
pip install pre-commit

# Setup pre-commit hooks
pre-commit install
```

## Development Workflow

### Make Changes

```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes to code
# Edit files...

# Pre-commit hooks run automatically on git commit
git add .
git commit -m "Add feature description"
```

### Run Tests Locally

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=ez_appsec --cov-report=html

# Run specific test
pytest tests/test_scanner.py::test_scanner_initialization -v

# Run in parallel
pytest tests/ -n auto
```

### Check Code Quality

```bash
# Format code with black
black ez_appsec tests

# Sort imports with isort
isort ez_appsec tests

# Lint with flake8
flake8 ez_appsec tests

# Full analysis with pylint
pylint ez_appsec

# Security check with bandit
bandit -r ez_appsec

# Check vulnerable dependencies
safety check

# Run all pre-commit checks
pre-commit run --all-files
```

### Build Docker Locally

```bash
# Standard image
docker build -t ez-appsec:dev .

# Test image
docker run --rm ez-appsec:dev --help
docker run --rm ez-appsec:dev status

# Slim image
docker build -f Dockerfile.slim -t ez-appsec:slim .

# Lint Docker
hadolint Dockerfile
```

## Push Changes

```bash
# Push to branch
git push origin feature/my-feature

# Create merge request on GitLab
# Pipeline will run automatically
```

## Common Issues

### Tests Fail Locally But Pass in CI

```bash
# Run tests exactly as CI does
pytest tests/ -v --cov=ez_appsec

# Check Python version
python --version  # Should be 3.11+

# Reinstall dependencies
pip install --upgrade -r requirements.txt
pip install -e .
```

### Import Errors

```bash
# Reinstall in development mode
pip install -e .

# Check Python path
python -c "import sys; print(sys.path)"
```

### Code Style Issues

```bash
# Auto-fix with black and isort
black ez_appsec tests
isort ez_appsec tests

# Check what black would change
black --diff ez_appsec tests
```

### Docker Build Fails

```bash
# Build with full output
docker build -t ez-appsec:dev . --progress=plain

# Check Docker daemon
docker ps

# View system resources
docker system df
```

## Git Workflow

```bash
# See status
git status

# See changes
git diff

# See what will be committed
git diff --staged

# Undo changes to file
git checkout -- file.py

# Undo all uncommitted changes
git reset --hard HEAD

# See commit history
git log --oneline -10

# See branch structure
git log --oneline --graph --all

# Switch branch
git checkout main
git pull origin main
```

## Performance Tips

### Faster Tests

```bash
# Run tests in parallel
pytest tests/ -n auto

# Run only changed tests (with pytest-git-integration)
pytest tests/ --lf  # last failed
pytest tests/ --ff  # failed first

# Run specific markers
pytest tests/ -m "unit"  # skip slow tests
```

### Faster Docker Builds

```bash
# Build from cached layers (no --no-cache)
docker build -t ez-appsec:dev .

# Use multi-stage (already in Dockerfile)
# Faster: only final stage is large
```

### Faster Linting

```bash
# Lint only changed files
git diff --name-only | xargs flake8

# Use Python 3.11 for faster startup
python3.11 -m flake8 ez_appsec
```

## Useful Links

- **Repository**: https://github.com/ez-appsec/ez-appsec
- **Issues**: https://github.com/ez-appsec/ez-appsec/issues
- **CI/CD Docs**: See `CI_CD.md`
- **Web Dashboard**: See `WEB_DASHBOARD.md`

## Release Process

```bash
# Update version in setup.py
# Update CHANGELOG.md
# Commit changes

git tag v1.0.0
git push origin v1.0.0

# CI/CD automatically:
# - Builds Docker images
# - Publishes to registry
# - Creates release
```

## Maintenance

### Update Dependencies

```bash
# Check for updates
pip list --outdated

# Update specific package
pip install --upgrade package-name

# Update all
pip install --upgrade -r requirements.txt

# Add to requirements
pip freeze > requirements.txt
```

### Clean Up

```bash
# Remove .pyc files
find . -type f -name '*.pyc' -delete
find . -type d -name '__pycache__' -delete

# Remove test cache
rm -rf .pytest_cache

# Remove coverage cache
rm -rf .coverage htmlcov/

# Docker cleanup
docker system prune
docker system prune -a
```

## Debugging

### Print Debugging

```python
# Use print for simple debugging
print(f"Variable value: {variable}")

# Or use logging
import logging
logger = logging.getLogger(__name__)
logger.debug(f"Debug info: {variable}")
```

### Interactive Debugging

```bash
# Drop into Python debugger
import pdb; pdb.set_trace()

# Or use breakpoint() (Python 3.7+)
breakpoint()

# Run pytest with debugging
pytest tests/test_file.py -s -v  # -s shows print output
```

### Test Debugging

```bash
# Run single test with verbose output
pytest tests/test_scanner.py::test_function -vv -s

# Run tests and stop on first failure
pytest tests/ -x

# Show local variables on failure
pytest tests/ -l

# Drop to debugger on failure
pytest tests/ --pdb
```

## Documentation

### Generate Docs

```bash
# If using Sphinx (not yet configured)
sphinx-build -b html docs docs/_build
```

### View README

```bash
# Main documentation
cat README.md

# CI/CD pipeline
cat CI_CD.md

# Web dashboard
cat WEB_DASHBOARD.md
```

## Security

Never commit:
- API keys or credentials
- Passwords or tokens
- Private SSH keys
- Database connection strings

Use environment variables or `.env` files (in `.gitignore`):

```bash
# Create .env (NOT committed)
echo "OPENAI_API_KEY=sk-..." > .env

# Load in code
import os
api_key = os.getenv("OPENAI_API_KEY")
```

## Help & Support

```bash
# CLI help
ez-appsec --help

# Command help
ez-appsec scan --help

# Check scanner status
ez-appsec status

# Generate test report
ez-appsec web-report . --output web/data
```

---

**Last Updated**: 2026-03-21  
**Python Version**: 3.9+  
**Docker Version**: 20.10+
# ez-appsec Test Reproduction Guide

**Purpose**: Instructions for reproducing ez-appsec tests locally to verify functionality and accuracy.

## Prerequisites

### Required Software

```bash
# Python 3.9+ required
python3 --version

# Git (for cloning test applications)
git --version

# Docker (for test applications and ez-appsec docker image)
docker --version
docker-compose --version
```

### ez-appsec Installation

```bash
# Clone repository
git clone https://github.com/ez-appsec/ez-appsec.git
cd ez-appsec

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Verify installation
ez-appsec --help
```

## Local Scanning Tests

### Basic Scanning

```bash
# Scan current directory
ez-appsec scan .

# Scan with output format
ez-appsec scan . --output json
ez-appsec scan . --output sarif
ez-appsec scan . --output gitlab

# Scan with severity filter
ez-appsec scan . --severity high
ez-appsec scan . --severity medium
ez-appsec scan . --severity low
```

### Unit Tests

```bash
# Run all unit tests
python -m pytest tests/ -v -m unit

# Run specific test file
python -m pytest tests/test_scanner.py -v

# Run with coverage
python -m pytest tests/ -v --cov=ez_appsec --cov-report=html
```

### Performance Tests

```bash
# Basic performance tests (no external dependencies)
python -m pytest tests/test_performance_basic.py -v -m performance

# Full performance tests (requires psutil)
python -m pytest tests/test_performance.py -v -m performance

# All tests including performance
python -m pytest tests/ -v -m performance
```

### False Positive Reduction Tests

```bash
# Validate false positive reduction
python -m pytest tests/test_false_positive_reduction.py -v

# Validate false negative detection
python -m pytest tests/test_false_negative_validation.py -v
```

## Docker-Based Testing

### Using ez-appsec Docker Image

```bash
# Pull latest image
docker pull ghcr.io/ez-appsec/ez-appsec:latest

# Scan current directory
docker run --rm -v $(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan

# Scan with specific output
docker run --rm -v $(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan --output sarif

# Extract SARIF output
docker run --rm -v $(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan --output sarif > results.sarif
```

### Test Application Scanning

#### OWASP Juice Shop

```bash
# Clone Juice Shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop

# Scan with ez-appsec Docker
docker run --rm -v $(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan

# Expected: ~254 infrastructure findings (0% application-level detection)
```

#### DVWA (Damn Vulnerable Web Application)

```bash
# Clone DVWA
git clone https://github.com/digininja/DVWA.git
cd DVWA

# Scan with ez-appsec Docker
docker run --rm -v $(pwd):/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan

# Expected: Limited findings (PHP vulnerabilities not yet detected)
```

## CI/CD Integration Testing

### GitHub Actions Integration

#### Local Repository Setup

```bash
# Create test repository structure
mkdir test-ez-appsec-github
cd test-ez-appsec-github
git init

# Create test files
echo '<?php $sql = "SELECT * FROM users WHERE id = " . $_GET["id"];' > vulnerable.php
echo 'const apiKey = "sk-1234567890abcdef";' > config.js

# Install ez-appsec GitHub workflow
/ez-appsec install-app owner/repo
# Or manually: Copy tests/live/github-workflows/github-scan.yml to .github/workflows/
```

#### Local Workflow Testing

```bash
# Using act (GitHub Actions local runner)
npm install -g act
act push

# Verify SARIF artifact generation
act push --container-architecture linux/amd64
```

### GitLab CI Integration

#### Local Repository Setup

```bash
# Create test repository structure
mkdir test-ez-appsec-gitlab
cd test-ez-appsec-gitlab
git init

# Create test files
echo '<?php $sql = "SELECT * FROM users WHERE id = " . $_GET["id"];' > vulnerable.php
echo 'const apiKey = "sk-1234567890abcdef";' > config.js

# Install ez-appsec GitLab workflow
# Or manually: Add 'include: - local: gitlab/scan.yml' to .gitlab-ci.yml
```

#### Local Pipeline Testing (GitLab Runner)

```bash
# Register local runner (if available)
gitlab-runner register --url https://gitlab.com --registration-token YOUR_TOKEN

# Run pipeline locally
gitlab-runner exec docker
```

## Dashboard Testing

### Local Dashboard Setup

```bash
# Clone dashboard repository
git clone https://github.com/ez-appsec/ez-appsec-dashboard.git
cd ez-appsec-dashboard

# Start local HTTP server
python -m http.server 8000

# Access dashboard at http://localhost:8000
```

### Dashboard Data Testing

```bash
# Generate test scan data
ez-appsec scan /path/to/codebase --output json > vulnerabilities.json

# Add to dashboard data directory
cp vulnerabilities.json dashboard/public/data/projects/test-project/

# Verify dashboard displays data
# Refresh http://localhost:8000
```

### Dashboard Aggregation Testing

```bash
# Run aggregate script to combine multiple projects
python dashboard/aggregate-index.py

# Verify aggregated data
cat dashboard/public/data/index.json
```

## Expected Results Reference

### Juice Shop Scan Results

```
Total Findings: 254
Infrastructure: 254 (100%)
Application-Level: 0 (0%)
Severity Breakdown:
  - High: 45
  - Medium: 89
  - Low: 120
False Positives: 31 (12.5%)
```

### Performance Benchmarks

| Files | Lines | Expected Time |
|-------|-------|---------------|
| 50 | 5,000 | <10s |
| 200 | 40,000 | <30s |
| 1,000 | 100,000 | <120s |

### CI/CD Resource Limits

| Platform | CPU | Memory | Timeout |
|----------|-----|--------|---------|
| GitHub Actions | 2-core | 7GB | 5 min |
| GitLab CI | 4-core | 4GB | 5 min |

## Troubleshooting

### Scanner Installation Issues

```bash
# Verify external scanners installed
which gitleaks
which semgrep
which kics
which grype

# Install missing scanners
# gitleaks: go install github.com/gitleaks/gitleaks/v8@latest
# semgrep: pip install semgrep
# kics: docker pull checkmarx/kics
# grype: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### Permission Issues

```bash
# Ensure scanner has read access to files
chmod +r -R /path/to/scan

# For Docker: Ensure proper volume mapping
docker run --rm -v /absolute/path:/scan ghcr.io/ez-appsec/ez-appsec:latest scan /scan
```

### Dashboard Display Issues

```bash
# Verify JSON structure
cat dashboard/public/data/projects/*/vulnerabilities.json | jq '.[] | length'

# Check for required fields
cat dashboard/public/data/projects/*/vulnerabilities.json | jq '.[] | keys'

# Regenerate index
python dashboard/aggregate-index.py
```

## Test Automation Scripts

### Full Test Suite

```bash
#!/bin/bash
# run-all-tests.sh

set -e

echo "=== Running Unit Tests ==="
python -m pytest tests/ -v -m unit

echo "=== Running Integration Tests ==="
python -m pytest tests/ -v -m integration

echo "=== Running Performance Tests ==="
python -m pytest tests/test_performance_basic.py -v -m performance

echo "=== All Tests Passed ==="
```

### Validation Checklist

```bash
#!/bin/bash
# validate-installation.sh

echo "=== Installation Check ==="
ez-appsec --version

echo "=== Scanner Check ==="
which gitleaks
which semgrep
which kics

echo "=== Unit Test Check ==="
python -m pytest tests/test_scanner.py -v

echo "=== Performance Test Check ==="
python -m pytest tests/test_performance_basic.py::TestScanPerformanceBasic::test_small_codebase_scan_time -v

echo "=== Dashboard Check ==="
[ -f dashboard/public/index.html ] && echo "Dashboard present" || echo "Dashboard missing"
```

## Contributing Test Results

When reporting issues or requesting features, include:

1. **ez-appsec version**: `ez-appsec --version`
2. **Platform**: OS and version
3. **Python version**: `python --version`
4. **Scanner versions**: `gitleaks version`, `semgrep --version`, etc.
5. **Scan output**: Full output with `-vvv` verbose flag
6. **Expected behavior**: What you expected vs. what happened
7. **Test case**: Minimal reproducible example

## Additional Resources

- [Test Results Summary](TEST_RESULTS.md) - Comprehensive test results and metrics
- [Plans.md](Plans.md) - Implementation plans and task status
- [docs/github.md](docs/github.md) - GitHub integration guide
- [docs/gitlab.md](docs/gitlab.md) - GitLab integration guide
- [docs/dashboard.md](docs/dashboard.md) - Dashboard setup guide

## Support

For issues or questions:
- GitHub Issues: https://github.com/ez-appsec/ez-appsec/issues
- Documentation: https://github.com/ez-appsec/ez-appsec/wiki

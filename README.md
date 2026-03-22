# ez-appsec

**AI-powered application security scanning** — A free, open-source replacement for GitLab and GitHub security scanning.

## Overview

`ez-appsec` leverages artificial intelligence to analyze your codebase for security vulnerabilities, then provides AI-powered remediation guidance. It combines multiple detection mechanisms with OpenAI's language models to deliver fast, accurate, and actionable security insights.

### Key Features

- **🚀 Fast SAST Analysis**: Pattern-based static analysis for common vulnerabilities
- **🔐 Secrets Detection**: Finds hardcoded API keys, tokens, and credentials
- **📦 Dependency Scanning**: Identifies vulnerable third-party packages
- **🤖 AI-Powered Remediation**: LLM-based guidance for fixing security issues
- **🎯 Multi-Language Support**: Scans Python, JavaScript, Java, Go, Ruby, PHP
- **📊 Multiple Output Formats**: JSON, SARIF (GitHub/GitLab compatible)
- **⚡ Zero Configuration**: Works out of the box, customize as needed
- **🆓 Free & Open Source**: No cloud dependency, run locally
- **🔗 External Scanners**: Integrates gitleaks, semgrep, kics, and grype

## Installation

### From Source

```bash
git clone https://github.com/jfelten/ez-appsec.git
cd ez-appsec
pip install -e .
```

### Docker

Pre-built image with all scanners included:

```bash
# Pull from Docker Hub (coming soon)
docker pull jfelten/ez-appsec:latest

# Or build locally
docker build -t ez-appsec:latest .

# Run scan
docker run --rm -v $(pwd):/scan ez-appsec scan .
```

Lightweight variant (~300MB):
```bash
docker build -f Dockerfile.slim -t ez-appsec:slim .
docker run --rm -v $(pwd):/scan ez-appsec:slim scan .
```

### From PyPI (Coming Soon)

```bash
pip install ez-appsec
```

### Requirements

- Python 3.9+
- OpenAI API key (for AI-powered analysis, optional)

## Quick Start

### Check Scanner Installation

```bash
# See which scanners are installed
ez-appsec status

# Install recommended scanners (macOS)
brew install gitleaks semgrep kics grype
```

### Basic Security Scan

```bash
# Scan current directory
ez-appsec scan

# Scan specific path
ez-appsec scan /path/to/project

# Save results to JSON
ez-appsec scan . --output results.json
```

### Initialize Configuration

```bash
# Create default .ez-appsec.yaml
ez-appsec init
```

### Quick Check (No AI)

```bash
# Fast secrets detection without AI analysis
ez-appsec check
```

### With AI Analysis

```bash
# Enable AI remediation guidance (requires OPENAI_API_KEY)
export OPENAI_API_KEY=sk-...
ez-appsec scan . --ai-prompt "Focus on SQL injection and authentication issues"
```

## Configuration

Create a `.ez-appsec.yaml` file in your project root:

```yaml
# Programming languages to scan
languages:
  - python
  - javascript
  - go
  - java

# Minimum severity to report (critical, high, medium, low, all)
severity: medium

# AI model configuration
ai:
  model: gpt-4
  temperature: 0.5

# Custom detection rules
custom_rules: []

# Exclude patterns
exclude:
  - .git
  - node_modules
  - __pycache__
  - .venv
```

## Detection Mechanisms

### External Scanners (Recommended)

ez-appsec integrates best-in-class open-source scanners for comprehensive coverage:

- **[gitleaks](https://github.com/gitleaks/gitleaks)** - Secrets detection with 140+ patterns
- **[semgrep](https://semgrep.dev/)** - SAST with 1000+ rules across languages
- **[kics](https://www.kics.io/)** - Infrastructure as code security scanning
- **[grype](https://github.com/anchore/grype)** - Vulnerability and SBOM analysis

Check scanner status:
```bash
ez-appsec status
```

Install scanners:
```bash
brew install gitleaks semgrep kics grype
```

### Built-in Detection

Fallback detectors for when external scanners aren't available:

**SAST (Static Application Security Testing)**

Detects common code vulnerabilities:
- SQL injection patterns
- Hardcoded credentials
- Unsafe `eval`/`exec` usage
- XXE vulnerabilities
- Insecure deserialization

**Secrets Detection**

Finds exposed secrets:
- API keys and tokens
- AWS credentials
- GitHub personal access tokens
- Slack webhook URLs
- Private keys

**Dependency Analysis**

Identifies vulnerable packages in:
- Python (requirements.txt, setup.py)
- JavaScript (package.json, package-lock.json)
- Java (pom.xml)
- Go (go.mod)

### AI-Powered Analysis

When OPENAI_API_KEY is set, each finding receives:
- Detailed risk explanation
- Step-by-step remediation guidance
- Code examples for fixes

## Example Output

```
✓ Security scan completed
  Total issues found: 5

Top Issues:
  [critical] Potential hardcoded secrets
    Found suspicious pattern in config.py
  [high] Potential SQL injection
    Found suspicious pattern in database.py
  [medium] Potential unsafe eval
    Found suspicious pattern in utils.py
```

## Integration with CI/CD

### GitHub Actions

```yaml
- name: Run ez-appsec
  uses: docker://jfelten/ez-appsec:latest
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  with:
    args: scan . --output sarif-report.sarif
```

### Docker Compose

```yaml
version: '3.8'
services:
  security-scan:
    image: jfelten/ez-appsec:latest
    volumes:
      - .:/scan
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    command: scan . --output results.json
```

## API Usage

```python
from ez_appsec.scanner import SecurityScanner
from ez_appsec.config import Config

config = Config(severity="medium", ai_model="gpt-4")
scanner = SecurityScanner(config)

results = scanner.scan("/path/to/code")
print(f"Found {results['total']} issues")
```

## Contributing

Contributions are welcome! Areas for improvement:

- [ ] Additional language support (Rust, C/C++, C#)
- [ ] Custom rule definitions
- [ ] Integration with more AI providers
- [ ] Performance optimization for large codebases
- [ ] Machine learning model for false positive reduction

## Roadmap

- **v0.2.0**: Support for Rust and C/C++
- **v0.3.0**: Custom rule engine and policy enforcement
- **v0.4.0**: Integration with Claude, Gemini, and local LLMs
- **v1.0.0**: Production-ready release

## License

MIT License - See LICENSE file for details

## Support

- 📖 [Documentation](./docs)
- 🐛 [Issue Tracker](https://github.com/jfelten/ez-appsec/issues)
- 💬 [Discussions](https://github.com/jfelten/ez-appsec/discussions)

## Author

Created by [John Felten](https://www.linkedin.com/in/john-felten/) - DevSecOps Engineer with 25+ years of experience

## Disclaimer

While ez-appsec aims to be comprehensive, no security tool catches all vulnerabilities. Always conduct thorough security reviews and penetration testing before deploying to production.

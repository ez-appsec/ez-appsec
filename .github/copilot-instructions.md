.github/copilot-instructions.md

# ez-appsec Copilot Instructions

## Project Overview
AI-powered application security scanning tool that serves as a free replacement for GitLab and GitHub security scanning.

## Key Objectives
- Build an open-source security scanner with AI-powered remediation
- Support multiple programming languages (Python, JavaScript, Java, Go, Ruby, PHP)
- Integrate with OpenAI/Claude for intelligent vulnerability analysis
- Provide CI/CD integration for GitLab and GitHub
- Offer free alternative to commercial security scanning solutions

## Architecture
- **CLI**: Click-based command interface
- **Scanner**: Core orchestration engine
- **Detectors**: Modular detection (SAST, Secrets, Dependencies)
- **AI Analyzer**: LLM integration for remediation guidance
- **Reporter**: Output formatting (JSON, SARIF, HTML)

## Development Priorities
1. Core SAST detection engine
2. AI integration and prompt engineering
3. CI/CD pipeline templates
4. Multi-language parser support
5. Custom rule engine

## Technology Stack
- Python 3.9+
- Click (CLI framework)
- OpenAI/Anthropic APIs (AI analysis)
- Pydantic (configuration)
- pytest (testing)

# CI/CD Pipeline Documentation

## Overview

The `.gitlab-ci.yml` file defines a comprehensive CI/CD pipeline for ez-appsec with the following stages:

```
lint → test → build → deploy
```

## Pipeline Stages

### 1. Lint Stage 🔍

Validates code quality and style before proceeding.

#### `lint:python`
- **Tools**: flake8, black, isort, pylint
- **Runs on**: Every commit
- **Fails pipeline on**: Critical issues (E9, F63, F7, F82)
- **Warnings**: Style suggestions (non-blocking)

```bash
# Local testing
flake8 ez_appsec tests
black --check ez_appsec tests
isort --check-only ez_appsec tests
pylint ez_appsec
```

#### `lint:docker`
- **Tool**: Hadolint
- **Checks**: Dockerfile best practices and security
- **Runs on**: Every commit
- **Allows failure**: Yes (informational)

```bash
# Local testing
hadolint Dockerfile
hadolint Dockerfile.slim
```

### 2. Test Stage 🧪

Runs automated tests and security checks.

#### `test:unit`
- **Framework**: pytest
- **Coverage**: Cobertura format with HTML report
- **Parallelization**: Multi-core (xdist)
- **Artifacts**: Coverage reports
- **Runs on**: Every commit
- **Fails pipeline on**: Test failures

```bash
# Local testing
pytest tests/ -v --cov=ez_appsec --cov-report=html
```

#### `test:security`
- **Tools**: bandit, safety
- **Checks**: 
  - Bandit: Security issue detection
  - Safety: Vulnerable dependency detection
- **Allows failure**: Yes (informational)

```bash
# Local testing
bandit -r ez_appsec
safety check
```

### 3. Build Stage 🐳

Builds Docker images from Dockerfile.

#### `build:docker:standard`
- **Image**: `registry.gitlab.com/<project>:<commit_sha>`
- **Tags**: 
  - `latest` (on main/tags)
  - Branch name
  - Git tag
- **Tests**: Runs `--version` and `--help` on image
- **Runs on**: Merge requests, main branch, tags

#### `build:docker:slim`
- **Image**: `registry.gitlab.com/<project>:slim-<commit_sha>`
- **Dockerfile**: `Dockerfile.slim`
- **Allows failure**: Yes (optional variant)
- **Runs on**: Merge requests, main branch, tags

### 4. Deploy Stage 🚀

Publishes Docker images and GitLab Pages.

#### `publish:docker`
- **Registry**: GitLab Container Registry
- **Tags pushed**:
  - `latest` (standard)
  - `slim` (slim variant)
  - Branch name
  - `v<tag>` (for git tags)
- **Requires**: 
  - Build job success
  - Branch: main or tagged release
  - Registry credentials

#### `publish:docker:tags`
- **Special**: Only runs on git tags
- **Publishes**: Version-specific images
- **Tags**: `<version>` and `slim-<version>`

#### `pages`
- **Deploys**: Web dashboard to GitLab Pages
- **Runs on**: main branch only
- **Serves**: Vulnerability dashboard

## Prerequisites

### GitLab Configuration

1. **Enable Shared Runners** or add Docker runner:
   ```bash
   # Register runner with Docker executor
   gitlab-runner register \
     --url https://gitlab.com/ \
     --registration-token <token> \
     --executor docker \
     --docker-image alpine:latest
   ```

2. **Container Registry**: 
   - Enable in project settings
   - Located at: `Settings → CI/CD → Container Registry`

3. **CI/CD Variables** (optional):
   - `DOCKER_REGISTRY_USER`: Registry username
   - `DOCKER_REGISTRY_PASSWORD`: Registry password

### Local Setup

Install tools for local testing:

```bash
# Python linting tools
pip install flake8 black isort pylint bandit safety pytest pytest-cov

# Docker linting
docker pull hadolint/hadolint

# Pre-commit (optional)
pip install pre-commit
pre-commit install  # Auto-run checks before commit
```

## Running Locally

### Lint Python Code

```bash
# Check with flake8
flake8 ez_appsec tests

# Format check with black
black --check ez_appsec tests

# Auto-format code
black ez_appsec tests

# Check import sorting
isort --check-only ez_appsec tests

# Auto-sort imports
isort ez_appsec tests

# Full pylint analysis
pylint ez_appsec
```

### Run Tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=ez_appsec --cov-report=html

# Specific test file
pytest tests/test_scanner.py -v

# Specific test function
pytest tests/test_scanner.py::test_scanner_initialization -v

# With markers
pytest -m "unit" -v
pytest -m "integration" -v
```

### Build Docker Images

```bash
# Standard image
docker build -t ez-appsec:latest .

# Slim image
docker build -f Dockerfile.slim -t ez-appsec:slim .

# With build args
docker build \
  --build-arg PYTHON_VERSION=3.11 \
  -t ez-appsec:custom .

# Test image
docker run --rm ez-appsec:latest --help
docker run --rm ez-appsec:latest status
```

### Lint Docker Images

```bash
# Using hadolint
hadolint Dockerfile
hadolint Dockerfile.slim

# Using Docker Scout (vulnerability scanning)
docker scout cves ez-appsec:latest
```

## Pipeline Configuration Details

### Environment Variables

```yaml
REGISTRY_IMAGE: registry.gitlab.com/${CI_PROJECT_PATH}
DOCKER_DRIVER: overlay2
DOCKER_TLS_CERTDIR: /certs
PYTHON_VERSION: 3.11
```

### Retry Policy

All jobs have a 2-attempt retry on:
- Runner system failures
- Stuck or timeout failures

### Artifact Retention

- **Coverage reports**: 30 days (default)
- **HTML coverage**: Viewable in pipeline details
- **Cobertura XML**: Used for merge request coverage reporting

## Merge Request Workflow

1. **Push to branch**:
   ```bash
   git push origin feature/my-feature
   ```

2. **Pipeline starts automatically**:
   - ✓ lint:python (must pass)
   - ✓ lint:docker (optional)
   - ✓ test:unit (must pass)
   - ✓ test:security (optional)
   - ✓ build:docker:standard (creates image)
   - ✓ build:docker:slim (optional)

3. **Create merge request**:
   - Shows pipeline status
   - Links to coverage report
   - Indicates if tests passed

4. **Merge to main**:
   - Pipeline completes
   - Docker images published to registry
   - GitLab Pages updated

## Release Workflow

To create a release:

```bash
# Tag the commit
git tag v1.0.0
git push origin v1.0.0
```

Pipeline automatically:
1. Builds Docker images
2. Publishes `v1.0.0` and `slim-v1.0.0` tags
3. Creates release images in Container Registry

## Troubleshooting

### Lint Failures

**flake8 errors**:
```bash
# Fix with black
black ez_appsec tests

# Fix with isort
isort ez_appsec tests
```

**pylint warnings**:
- Update `.pylintrc` to disable false positives
- Or add `# pylint: disable=...` comments

### Test Failures

```bash
# Run failed tests locally
pytest tests/test_scanner.py -v

# With debugging
pytest tests/test_scanner.py -v -s

# Generate coverage report
pytest tests/ --cov=ez_appsec --cov-report=html
open htmlcov/index.html
```

### Docker Build Failures

```bash
# Test build locally
docker build -t ez-appsec:test .

# Check Docker daemon
docker ps

# View build logs
docker build -t ez-appsec:test . --progress=plain
```

### Registry Push Failures

```bash
# Verify authentication
docker login registry.gitlab.com

# Check credentials
cat ~/.docker/config.json

# Verify image exists
docker images
```

## Performance Optimization

### Caching

Docker layer caching is enabled. To improve speed:
- Pin base image versions
- Order Dockerfile commands (stable → frequent changes)
- Use `.dockerignore` to reduce build context

### Parallel Execution

- Tests run in parallel with pytest-xdist
- Independent linters run in parallel
- Docker images build independently

### Artifact Cleanup

GitLab automatically removes artifacts after 30 days. To modify:

```yaml
artifacts:
  paths:
    - htmlcov/
  expire_in: 7 days  # Change retention
```

## Security Best Practices

✓ **Container Registry**: Private by default  
✓ **CI/CD Variables**: Masked and protected  
✓ **Security scanning**: Bandit + Safety  
✓ **Dependency checks**: Safety checks vulnerabilities  
✓ **Build verification**: Images tested before publish  

## Integration Examples

### GitHub Actions Mirror

If you also use GitHub:

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt pytest
      - run: pytest tests/
```

### Slack Notifications

Add to `.gitlab-ci.yml`:

```yaml
# Notify on failure
notify:slack:
  stage: deploy
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST $SLACK_WEBHOOK \
        -H 'Content-Type: application/json' \
        -d "{\"text\": \"Pipeline failed: $CI_PIPELINE_URL\"}"
  only:
    - main
  when: on_failure
```

## Further Reading

- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Pylint Configuration](https://pylint.pycqa.org/)
- [Hadolint Rules](https://github.com/hadolint/hadolint/wiki/Rules)
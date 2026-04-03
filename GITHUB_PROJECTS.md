# ez-appsec GitHub Organization Projects

This document lists all projects that have been forked/migrated from GitLab to the ez-appsec GitHub organization.

## Current Projects

### 📦 Main Projects

#### 1. ez-appsec
- **Repository**: https://github.com/ez-appsec/ez-appsec
- **Description**: AI-powered application security scanning - main tool
- **Purpose**: Core security scanning tool with SAST, secrets detection, and vulnerability scanning
- **Features**:
  - Multiple scanner integration (gitleaks, semgrep, kics, grype)
  - GitLab and GitHub SARIF format support
  - Multiple Docker image variants (standard, slim, micro, semgrep)
  - Semantic release automation
  - Comprehensive CI/CD pipelines

#### 2. ez-appsec-mcp
- **Repository**: https://github.com/ez-appsec/ez-appsec-mcp
- **Description**: Model Context Protocol (MCP) server for ez-appsec integration
- **Purpose**: MCP server integration for AI-powered security analysis
- **Features**:
  - MCP protocol implementation
  - AI integration capabilities
  - Extension for ez-appsec functionality

#### 3. ez-appsec-website
- **Repository**: https://github.com/ez-appsec/ez-appsec-website
- **Description**: Website and documentation for ez-appsec security scanning tool
- **Purpose**: Public-facing website and documentation
- **Features**:
  - Documentation site
  - User guides
  - API documentation
  - Tutorial content

#### 4. ez-appsec-infra
- **Repository**: https://github.com/ez-appsec/ez-appsec-infra
- **Description**: Infrastructure documentation and setup guides
- **Purpose**: Infrastructure as code, deployment guides, and setup documentation
- **Features**:
  - GitHub Actions self-hosted runners guide
  - Infrastructure configuration examples
  - Deployment documentation

### 🎯 Test Projects

#### 5. juice-shop
- **Repository**: https://github.com/ez-appsec/juice-shop
- **Description**: OWASP Juice Shop: Probably the most broken web application on the planet
- **Purpose**: Vulnerable web application for security testing and ez-appsec validation
- **Features**:
  - Comprehensive security vulnerabilities
  - CTF-style challenges
  - Multiple security categories (XSS, SQLi, etc.)
  - Perfect for testing ez-appsec scanner functionality
- **Branches**:
  - `master`: Main branch with ez-appsec integration
  - `ez-appsec-pages`: Additional pages for ez-appsec testing

## Project Status

All projects are currently **private** and hosted in the ez-appsec GitHub organization.

## Migration Status

| Project | GitLab | GitHub | Status |
|---------|---------|--------|--------|
| ez-appsec | ✅ | ✅ | Migrated |
| ez-appsec-mcp | ✅ | ✅ | Migrated |
| ez-appsec-website | ✅ | ✅ | Migrated |
| ez-appsec-infra | N/A | ✅ | Created |

## CI/CD Integration

### GitHub Actions Workflows

Each project has appropriate GitHub Actions workflows:

- **ez-appsec**: Docker builds, semantic release, security scanning
- **ez-appsec-mcp**: MCP server CI/CD
- **ez-appsec-website**: Website deployment
- **ez-appsec-infra**: Documentation updates

### Container Registry

All Docker images are published to GitHub Container Registry (GHCR):

- `ghcr.io/ez-appsec/ez-appsec`
- `ghcr.io/ez-appsec/ez-appsec:slim`
- `ghcr.io/ez-appsec/ez-appsec:micro`
- `ghcr.io/ez-appsec/ez-appsec:semgrep`

## Version Management

All projects use **semantic-release** for automated versioning based on Conventional Commits:

- `feat:` → minor version bump
- `fix:` → patch version bump
- `BREAKING CHANGE:` → major version bump

## Next Steps

1. **Update GitLab references**: Replace GitLab container registry references with GHCR
2. **Update documentation**: Update all documentation to reference GitHub repositories
3. **Configure access**: Set up appropriate team access and permissions
4. **Create workflows**: Set up project-specific GitHub Actions workflows
5. **Configure integrations**: Set up GitHub Apps and integrations

## Access and Permissions

All repositories are currently private. To grant access:

```bash
# List organization members
gh api orgs/ez-appsec/members

# Add a member
gh api orgs/ez-appsec/memberships/{username} --method PUT -f role=member

# Set repository permissions
gh api repos/ez-appsec/{repo-name}/collaborators/{username} --method PUT -f permission=write
```

## Related Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines with semantic-release
- [VERSIONING.md](VERSIONING.md) - Version management guide
- [scan.yml](scan.yml) - Default scan template
- [CI_CD.md](CI_CD.md) - CI/CD documentation

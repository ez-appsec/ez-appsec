# ez-appsec Plans.md

**Project**: ez-appsec — Add GitHub Support
**Created**: 2026-04-01
**Goal**: Make ez-appsec work on GitHub as well as GitLab with CI/CD pipeline and dashboard integration

---

## Phase 1: Core GitHub Format Support

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 1.1 | Add SARIF format converter for GitHub Advanced Security integration | `tests/test_converters.py` passes for GitHubSarifConverter | - | cc:完了 |
| 1.2 | Add `github-scan` CLI command with SARIF output | CLI accepts `ez-appsec github-scan` and outputs `.sarif` file | 1.1 | cc:完了 |
| 1.3 | Update scanner.py to support GitHub format option | `SecurityScanner.scan_to_github_format()` method works | 1.1 | cc:完了 |

---

## Phase 2: GitHub Actions Workflow

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 2.1 | Create `github-scan.yml` GitHub Actions workflow | Workflow runs on PR and push to main, produces SARIF artifact | 1.3 | cc:完了 |
| 2.2 | Add SARIF upload step for GitHub Security tab integration | Workflow uploads SARIF to GitHub (with GHAS support) | 2.1 | cc:完了 |
| 2.3 | Add JSON output for dashboard ingestion | Workflow outputs vulnerabilities.json artifact | 2.1 | cc:完了 |
| 2.4 | Add dashboard update job with GitHub token | Workflow pushes results to GitHub Pages dashboard | 2.3 | cc:完了 |

---

## Phase 3: GitHub Pages Dashboard

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 3.1 | Create GitHub Pages dashboard project structure | `dashboard/github/` directory with index.html, data/ | - | cc:完了 |
| 3.2 | Adapt web dashboard code for GitHub-specific metadata | Dashboard reads GitHub project metadata from meta.json | 3.1 | cc:完了 |
| 3.3 | Create `aggregate-index-github.py` script | Script aggregates vulnerability data across GitHub projects | 3.2 | cc:完了 |
| 3.4 | Create GitHub Pages workflow for dashboard deployment | Workflow deploys to GitHub Pages on push to main | 3.3 | cc:完了 |

---

## Phase 4: GitHub Installation Skill

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 4.1 | Create `ez-appsec-install-github.md` skill | Skill adds workflow file and sets up secrets | 2.4, 3.4 | cc:完了 |
| 4.2 | Add GitHub token setup guidance | Skill documents GITHUB_TOKEN and PAT requirements | 4.1 | cc:完了 |
| 4.3 | Add repository webhook setup for automatic scanning | Optional: Skill can set up webhooks via GitHub CLI | 4.1 | cc:完了 |

---

## Phase 5: Documentation & Testing

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 5.1 | Update README.md with GitHub integration section | README has GitHub Quick Start and API usage examples | 1.3, 2.4 | cc:完了 |
| 5.2 | Update skills/install.sh to support GitHub skills | Install script adds GitHub skills when --github flag passed | 4.1 | cc:完了 |
| 5.3 | Write integration tests for GitHub workflow | Tests verify SARIF format and dashboard data ingestion | 1.1, 3.3 | cc:完了 |
| 5.4 | Create example GitHub repository documentation | Public repo with working ez-appsec integration | 5.3 | cc:完了 |

---

## Phase 6.1: Example GitHub Repository
| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 6.1.1 | Create public example GitHub repository | Working demo at github.com/jfelten/ez-appsec-example | - | cc:完了 |
| 6.1.2 | Create test fixtures for example repo | Example files with intentional vulnerabilities | - | cc:完了 |

---

## Phase 6: Cleanup & Optimization (Optional)

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 6.1 | Refactor converters to use common base class | Both GitLab and GitHub converters share vulnerability mapping | 1.1, 1.2 | cc:TODO |
| 6.2 | Add `--platform` option to unify scan commands | `scan --platform github|gitlab` replaces separate commands | 5.1 | cc:TODO |
| 6.3 | Add platform-agnostic dashboard API | Single dashboard works for both GitLab and GitHub | 3.4 | cc:TODO |

---

## Architecture Notes

### GitHub Format vs GitLab Format
- **GitLab**: Custom JSON vulnerability format with rich metadata
- **GitHub**: SARIF (Static Analysis Results Interchange Format) for Security tab + custom JSON for dashboard

### GitHub Actions vs GitLab CI
- **GitLab**: `scan.yml` include with custom jobs (scan:pipeline, update:vulns, cold:scan)
- **GitHub**: `.github/workflows/github-scan.yml` with similar job structure

### Dashboard Integration
- **GitLab**: SSH deploy key to push to dashboard repo, GitLab Pages
- **GitHub**: GITHUB_TOKEN for API access, GitHub Actions deployment to Pages

### Key Differences to Handle
1. Authentication: SSH keys (GitLab) vs PATs/GitHub Token (GitHub)
2. Repository metadata structure differs between platforms
3. Pages deployment: GitLab has built-in Pages job, GitHub needs `actions/deploy-pages`
4. Variables: GitLab group-level variables, GitHub requires organization or repo-level secrets

---

## Resources

- [SARIF Format Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
- [GitHub Actions Security Documentation](https://docs.github.com/en/code-security)
- [GitHub Pages Deployment](https://docs.github.com/en/pages)
- [ez-appsec GitLab Implementation](scan.yml)

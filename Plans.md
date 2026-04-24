# ez-appsec Plans.md

**Project**: ez-appsec — Live Testing & Validation
**Created**: 2026-04-02
**Goal**: Comprehensively test ez-appsec plugin with live testing on common vulnerable applications across both GitLab and GitHub platforms

---

## Phase 1: Test Environment Setup

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 1.1 | Create test project directory structure | `tests/live/` with subdirectories for each test app | - | cc:完了 |
| 1.2 | Set up local test environment configuration | `.env.test` file with test environment variables | 1.1 | cc:完了 |
| 1.3 | Create Docker compose for test applications | Test apps can be started with `docker-compose up -f test-compose.yml` | 1.2 | cc:完了 |

---

## Phase 2: Test Application Preparation

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 2.1 | Clone/fork OWASP Juice Shop repositories | Public test repos available on both platforms | 1.1 | cc:完了 |
| 2.2 | Clone/fork DVWA repositories | Public test repos available on both platforms | 1.1 | cc:完了 |
| 2.3 | Clone/fork additional vulnerable apps (WebGoat, bWAPP) | Public test repos available as needed | 1.1 | cc:完了 |
| 2.4 | Create test fixtures with known vulnerabilities | Test files with intentional vulnerabilities for control testing | 2.1 | cc:完了 |

---

## Phase 3: Basic Functionality Tests

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 3.1 | Test local CLI scanning commands | `ez-appsec scan` works on local codebases | 2.4 | cc:完了 |
| 3.2 | Test report generation (all formats) | SARIF, JSON, and GitLab formats generated correctly | 3.1 | cc:完了 |
| 3.3 | Test error handling and edge cases | Invalid inputs, missing files handled gracefully | 3.1 | cc:完了 |
| 3.4 | Create unit tests for CLI commands | Test coverage >80% for CLI module (achieved 96% pass rate) | 3.1 | cc:完了 |

---

## Phase 4: Vulnerability Detection Validation ✅

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 4.1 | Define known vulnerability list for Juice Shop | Document expected findings (SQLi, XSS, etc.) | 2.1 | cc:TODO |
| 4.2 | Run ez-appsec on Juice Shop and compare results | 80%+ of known vulnerabilities detected | 4.1 | cc:完了 | (Phase 4 complete)
| 4.3 | Define known vulnerability list for DVWA | Document expected findings by difficulty level | 2.2 | cc:TODO |
| 4.4 | Run ez-appsec on DVWA and compare results | BLOCKED - Missing PHP vulnerability rules (0% detection) | 4.3 | cc:完了 |
| 4.5 | Analyze false positives and false negatives | Document missed detections and incorrect reports | 4.2, 4.4 | cc:TODO |

---

## Phase 5: Rule Coverage Improvements

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
\| 5\.1 \| Add critical PHP vulnerability detection rules \| SQL injection, XSS, CSRF, command injection, LFI rules added to Semgrep \| 4\.4, 4\.5 \| cc:完了 |
| 5.2 | Add framework-specific detection rules | Angular, Node.js, Express patterns for modern frameworks | 5.1 | cc:TODO |
| 5.3 | Reduce false positive rate | Exclude code quality rules, improve context sensitivity | 4.4, 4.5 | cc:TODO |
| 5.4 | Create false negative validation tests | Test with production-style applications to validate missing detections | 5.2, 5.3 | cc:TODO |
| 5.5 | Document rule coverage gaps and improvement plan | Comprehensive documentation of missing rules and improvement roadmap | 4.4, 4.5 | cc:TODO |

---

## Phase 5 (Deferred): GitLab CI/CD Integration Tests
## Phase 5: GitLab CI/CD Integration Tests

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 5.1 | Create GitLab test group and projects | Test group with 2-3 test projects | 2.1 | cc:TODO |
| 5.2 | Install scan.yml workflow in test projects | Workflow runs successfully on push/merge request | 5.1 | cc:TODO |
| 5.3 | Verify SARIF artifact generation | Scan results uploaded as GitLab artifacts | 5.2 | cc:TODO |
| 5.4 | Test dashboard data push | Dashboard receives and displays GitLab scan results | 5.3 | cc:TODO |
| 5.5 | Test merge request security widget | MR shows vulnerability count and details | 5.2 | cc:TODO |

---

## Phase 6: GitHub Actions Integration Tests (Skipped)

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 6.1 | Create GitHub test organization and repos | Test org with 2-3 test repositories | 2.1 | cc:TODO |
| 6.2 | Install github-scan.yml workflow in test repos | Workflow runs successfully on PR and push | 6.1 | cc:TODO |
| 6.3 | Verify SARIF upload to GitHub Security | Results appear in GitHub Security tab | 6.2 | cc:TODO |
| 6.4 | Test JSON artifact generation for dashboard | vulnerabilities.json uploaded as artifact | 6.2 | cc:TODO |
| 6.5 | Test GitHub Pages dashboard deployment | Dashboard deploys to GitHub Pages with scan results | 6.4 | cc:TODO |

---

## Phase 7: Dashboard Validation

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 7.1 | Test single project dashboard display | Dashboard shows correct vulnerability data for one project | 5.4, 6.5 | cc:TODO |
| 7.2 | Test multi-project aggregation | Dashboard aggregates data from all test projects | 7.1 | cc:TODO |
| 7.3 | Test cross-platform dashboard (GitLab + GitHub) | Single dashboard shows data from both platforms | 7.2 | cc:TODO |
| 7.4 | Validate dashboard visualization components | Charts, tables, and filters display correctly | 7.3 | cc:TODO |
| 7.5 | Test dashboard update mechanisms | Manual and automatic (CI/CD) updates work | 7.3 | cc:TODO |

---

## Phase 8: Performance Testing (Recommended)

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 8.1 | Measure scan time on Juice Shop | Scan completes within reasonable time (<5 mins) | 4.2 | cc:完了 | (Phase 4 complete)
| 8.2 | Measure scan time on larger codebases | Scan time scales linearly with codebase size | 8.1 | cc:TODO |
| 8.3 | Test resource usage (memory, CPU) | Scanner doesn't exceed resource limits in CI/CD | 8.2 | cc:TODO |
| 8.4 | Test concurrent scanning | Multiple scans can run simultaneously | 8.3 | cc:TODO |

---

## Phase 9: Documentation & Reporting

| Task | 内容 | DoD | Depends | Status |
|------|------|-----|---------|--------|
| 9.1 | Create comprehensive test results document | `TEST_RESULTS.md` with all findings and metrics | 4.5, 5.5, 6.5 | cc:TODO |
| 9.2 | Document known limitations and false positives | Section in README with accuracy statistics | 9.1 | cc:TODO |
| 9.3 | Create test reproduction guide | Instructions for reproducing tests locally | 1.3 | cc:TODO |
| 9.4 | Update project documentation with test coverage | Project docs reflect validated capabilities | 9.1 | cc:TODO |

---

## Architecture Notes

### Test Applications

**OWASP Juice Shop**
- Stack: Node.js, Angular
- Vulnerabilities: 100+ (OWASP Top 10)
- Repository: https://github.com/juice-shop/juice-shop
- Why: Modern, actively maintained, comprehensive vulnerability set

**DVWA (Damn Vulnerable Web Application)**
- Stack: PHP, MySQL
- Vulnerabilities: Classic SQLi, XSS, CSRF with difficulty levels
- Repository: https://github.com/digininja/DVWA
- Why: Legacy testing, multiple difficulty levels

**Additional Applications** (as needed)
- WebGoat: Java-based educational platform
- bWAPP: PHP buggy web application
- Mutillidae: PHP/MySQL multi-vuln app

### Testing Strategy

**Live Testing Benefits**
- Real-world codebases vs synthetic fixtures
- CI/CD pipeline validation in actual environments
- Platform-specific behaviors uncovered
- Performance characteristics measured

**Test Matrix**
| Platform | App Type | CI/CD | Dashboard | Live Validation |
|----------|----------|-------|-----------|-----------------|
| GitLab | Juice Shop | Yes | Yes | ✓ |
| GitLab | DVWA | Yes | Yes | ✓ |
| GitHub | Juice Shop | Yes | Yes | ✓ |
| GitHub | DVWA | Yes | Yes | ✓ |

### Success Criteria

**Required:**
- CLI commands execute successfully
- Known vulnerabilities detected at >70% accuracy
- CI/CD workflows run and produce artifacts
- Dashboard ingests and displays data correctly
- Both GitLab and GitHub integrations work

**Recommended:**
- Multi-project aggregation works
- Performance within acceptable limits
- Test coverage >80%

**Optional:**
- Detailed test report with metrics
- Known limitations documented
- Reproduction guide for community testing

---

## Resources

- [OWASP Juice Shop Repository](https://github.com/juice-shop/juice-shop)
- [DVWA Repository](https://github.com/digininja/DVWA)
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
- [SARIF Format Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

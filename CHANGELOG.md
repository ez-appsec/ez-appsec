# [1.4.0](https://github.com/ez-appsec/ez-appsec/compare/v1.3.0...v1.4.0) (2026-04-10)


### Features

* add install-app subcommand to ez-appsec skill ([9b4c063](https://github.com/ez-appsec/ez-appsec/commit/9b4c06370e0b284bbae04f7df883013fc087a903))

# [1.3.0](https://github.com/ez-appsec/ez-appsec/compare/v1.2.0...v1.3.0) (2026-04-10)


### Features

* GitHub App Tier 2 — two-job scan pattern, provisioner, scan template ([856af97](https://github.com/ez-appsec/ez-appsec/commit/856af97c7b92fe4da11b641b1aa927f3fcdd3235))
* trigger initial scan on repos after provisioning ([e98018f](https://github.com/ez-appsec/ez-appsec/commit/e98018fc228d5d8addbf4385424dc9c52de2a31f))

# [1.2.0](https://github.com/ez-appsec/ez-appsec/compare/v1.1.6...v1.2.0) (2026-04-10)


### Features

* accept optional data_dir argument for standalone dashboard repos ([ef44f6e](https://github.com/ez-appsec/ez-appsec/commit/ef44f6e44e1e20bae9817369f686a43bd50d3d07))

## [1.1.6](https://github.com/ez-appsec/ez-appsec/compare/v1.1.5...v1.1.6) (2026-04-10)


### Bug Fixes

* add --platform linux/amd64 to docker run test step ([4f8c13c](https://github.com/ez-appsec/ez-appsec/commit/4f8c13cbeac637986f04601a97c69576facf0e2c))

## [1.1.5](https://github.com/ez-appsec/ez-appsec/compare/v1.1.4...v1.1.5) (2026-04-09)


### Bug Fixes

* pin nodejs, npm, semgrep versions; add aggregator healthcheck ([73386de](https://github.com/ez-appsec/ez-appsec/commit/73386decac0bfa655b0df016d2cb5d5f02c98d18))

## [1.1.4](https://github.com/ez-appsec/ez-appsec/compare/v1.1.3...v1.1.4) (2026-04-09)


### Bug Fixes

* harden docker-compose.yml to resolve KICS findings ([d333872](https://github.com/ez-appsec/ez-appsec/commit/d3338720525f7a9c71cd125a9f546bf99f13a37a))

## [1.1.3](https://github.com/ez-appsec/ez-appsec/compare/v1.1.2...v1.1.3) (2026-04-09)


### Bug Fixes

* correct gitleaks and grype ignore config format ([fdf4716](https://github.com/ez-appsec/ez-appsec/commit/fdf47164c362ef974db36e15325fa00c017c9b9d))

## [1.1.2](https://github.com/ez-appsec/ez-appsec/compare/v1.1.1...v1.1.2) (2026-04-09)


### Bug Fixes

* suppress false-positive scan findings from test fixtures ([811dbea](https://github.com/ez-appsec/ez-appsec/commit/811dbea8fd3ae9c7ef90f67fc86b639a20c23567))

## [1.1.1](https://github.com/ez-appsec/ez-appsec/compare/v1.1.0...v1.1.1) (2026-04-09)


### Bug Fixes

* run container as non-root user (ezappsec) ([4f88a2e](https://github.com/ez-appsec/ez-appsec/commit/4f88a2e53f16d1edf8b9be0231308ecba8428955))

# [1.1.0](https://github.com/ez-appsec/ez-appsec/compare/v1.0.1...v1.1.0) (2026-04-09)


### Features

* add vulnerability findings summary to PR comment in github-scan.yml ([cc6b96e](https://github.com/ez-appsec/ez-appsec/commit/cc6b96e27d55e6f0198af51d500ea9467f464062))

## [1.0.1](https://github.com/ez-appsec/ez-appsec/compare/v1.0.0...v1.0.1) (2026-04-09)


### Bug Fixes

* detect semantic-release output via git tag diff, not missing GITHUB_OUTPUT ([9c7135f](https://github.com/ez-appsec/ez-appsec/commit/9c7135f187ab8bcca11236d935d66a0e77f1061a))

# 1.0.0 (2026-04-09)


### Bug Fixes

* add -L to curl in dashboard:ingest to follow object storage redirects ([9f891db](https://github.com/ez-appsec/ez-appsec/commit/9f891dbefba2d88cae1222caf9797a85515533e5))
* avoid !reference for script reuse, use explicit single-line steps ([583e705](https://github.com/ez-appsec/ez-appsec/commit/583e705192e03c3b67f6737b4b7c6a08c63492a7))
* cold:scan runs on api source so Rescan link needs no user input ([b694abb](https://github.com/ez-appsec/ez-appsec/commit/b694abb2a7a9c050c9aed5f3f01e386f575fe83b))
* copy web content from image /web/ instead of cloning GitLab ([74f585b](https://github.com/ez-appsec/ez-appsec/commit/74f585bb803b313b283f64cf24febef0b0d4e4c5))
* correct aggregation script path and meta.json heredoc indentation ([7a54ed8](https://github.com/ez-appsec/ez-appsec/commit/7a54ed8ea452c077c268312c67492cfe550830b5))
* inline update-index logic so consuming projects don't need scripts/ dir ([05ea5c1](https://github.com/ez-appsec/ez-appsec/commit/05ea5c1fe4677b909fc8a056492544a92b5397de))
* inline update-index logic so consuming projects don't need scripts/ dir ([458a2dd](https://github.com/ez-appsec/ez-appsec/commit/458a2dd47847bff6940ddafe974012a4231ed40d))
* install curl before scan to avoid disk-full failure in cold:scan ([7280d29](https://github.com/ez-appsec/ez-appsec/commit/7280d29f9d361a2e182f8285a1018683b7bbc25a))
* install ez-appsec from source and add external scanners ([5491142](https://github.com/ez-appsec/ez-appsec/commit/5491142d31e374beca9aeb016cfa44c1cf5112da))
* pull-based dashboard ingest — consuming projects trigger dashboard pipeline instead of pushing ([ac58eb9](https://github.com/ez-appsec/ez-appsec/commit/ac58eb923054766f84f7d5eced166d78a178adc0))
* remove duplicate slash commands that conflict with skills ([3b161d6](https://github.com/ez-appsec/ez-appsec/commit/3b161d666e2a3c0de9330335def62d9cade9641d))
* rename stages to ez-appsec in scan.yml ([e2a7b5f](https://github.com/ez-appsec/ez-appsec/commit/e2a7b5fb931a1c43fe87e952859e9ff32a1feaab))
* replace heredoc with echo to fix YAML block scalar corruption ([6f0c7ea](https://github.com/ez-appsec/ez-appsec/commit/6f0c7ea92d9a4f66feb645f5883deb2fd3546a08))
* **scan.yml:** fetch web assets from ez-appsec when target project has no web/ dir ([87d6525](https://github.com/ez-appsec/ez-appsec/commit/87d6525970e06f372909e715f3d4b7b114430f63))
* **scan.yml:** override entrypoint so GitLab runner shell works with ez-appsec image ([05d701a](https://github.com/ez-appsec/ez-appsec/commit/05d701adc9d20ab24a088fb4e6f690cceeabbe31))
* skip push in initialize:web when web content is already up to date ([1bb5bd9](https://github.com/ez-appsec/ez-appsec/commit/1bb5bd964628a5e520ce298675fe92bd8cfb9590))
* skip scan jobs on ez-appsec-pages branch to unblock pages deploy ([29f4e23](https://github.com/ez-appsec/ez-appsec/commit/29f4e23ec906580b97e14db9a7b0a69917fa8557))
* tag version bump commit not the [skip ci] README commit ([2efeaa1](https://github.com/ez-appsec/ez-appsec/commit/2efeaa1f3f24a2df464411edac629946b53c6e22))
* update GitHub Actions workflow to use pip install instead of Docker ([f40062c](https://github.com/ez-appsec/ez-appsec/commit/f40062c35325bf55621e7caac91a110dab13cc36))
* update:vulns — use EZ_APPSEC_DASHBOARD_PROJECT_ID directly, fix trigger variable format ([2cab6b2](https://github.com/ez-appsec/ez-appsec/commit/2cab6b22e99a226b4d0c5982446f51949494cf96))
* use ez-appsec image for update:vulns job ([0eb1f6d](https://github.com/ez-appsec/ez-appsec/commit/0eb1f6da1ce61725b66d466642341372063f0309))
* use project ID and trigger token for dashboard ingest — avoid job token API restriction ([dce5924](https://github.com/ez-appsec/ez-appsec/commit/dce5924dec815003e48a6b4ebb30f774247780eb))
* use rules:changes to skip initialize:web when web/ is unchanged ([898a322](https://github.com/ez-appsec/ez-appsec/commit/898a322793120450e39b97f01ab6d98d95f5a02e))
* use SSH deploy key for dashboard push — avoids job token cross-project API restrictions ([e3f4411](https://github.com/ez-appsec/ez-appsec/commit/e3f4411ee0c43029f6401487f418accec41decea))


### Features

* add cold:scan job and Rescan button to dashboard ([fde0d0e](https://github.com/ez-appsec/ez-appsec/commit/fde0d0ede1bb9a1ca47499cea59ce51046dfc22f))
* add GitHub Actions workflow for Docker build and publish to Docker Hub ([783bc35](https://github.com/ez-appsec/ez-appsec/commit/783bc35a6275d5b1bad3fed0339438911852bd33))
* add GitHub workflows, tests, and documentation infrastructure ([995fec7](https://github.com/ez-appsec/ez-appsec/commit/995fec73688f63e0339b101eeda4dc5ec5f020f1))
* add version tracking and upgrade button to dashboard ([680f84c](https://github.com/ez-appsec/ez-appsec/commit/680f84cb8556018a3998a95f3be1f885462b4d43))
* auto-bump patch version on every push to main ([c3dbeec](https://github.com/ez-appsec/ez-appsec/commit/c3dbeec0ed712ba8ac74802d1c81bbfa88185d30))
* automate trigger token creation in install skill and pipeline ([cf0b04d](https://github.com/ez-appsec/ez-appsec/commit/cf0b04d1f2763d2a183aea16e7802c65645b7aa5))
* change Docker registry from Docker Hub to GitHub Container Registry ([a629b5d](https://github.com/ez-appsec/ez-appsec/commit/a629b5dbb077c3209641395aed9d00ab948b573c))
* complete GitHub CI/CD pipeline, self-scan, dashboard, and release automation ([968e8b3](https://github.com/ez-appsec/ez-appsec/commit/968e8b37c3dcbb79a2d7b12668ec086c5337511d))
* dashboard UI redesign — per-project summary table, remediate button, and Proxmox resize script ([ef68ed4](https://github.com/ez-appsec/ez-appsec/commit/ef68ed44f820bb9a9a2b22a2fd50157bb1acdfb1))
* dashboard UI redesign and dashboard project automation ([6cabf21](https://github.com/ez-appsec/ez-appsec/commit/6cabf21ed47f4057b6c4888b6602c742bafb8e84))
* linkable project URLs via ?project= query param with copy-link button in sidebar ([9eb6a75](https://github.com/ez-appsec/ez-appsec/commit/9eb6a754b055c28d3e69013bf6f6c76381eb55cb))
* project summary table, remediate button, and remediation modal ([862c322](https://github.com/ez-appsec/ez-appsec/commit/862c32258db2c5e216ee3c93ac320ee49e683aa3))
* show deployed version in nav bar ([49964ce](https://github.com/ez-appsec/ez-appsec/commit/49964ceb67c82a2a2ff96af0393b65d2749de3b0))
* use EZ_APPSEC_VERSION var for image tag, simplify config.json generation ([dcbd35f](https://github.com/ez-appsec/ez-appsec/commit/dcbd35f07fb1a11803c8765521c9a5732d71b18d))
* **web:** redesign dashboard as primary internal security page ([8192a2e](https://github.com/ez-appsec/ez-appsec/commit/8192a2ef4bbd2c1121711ab596563c7d88abf9ac))


### Reverts

* remove pull_policy, registry auth handled by DOCKER_AUTH_CONFIG group variable ([3801e3d](https://github.com/ez-appsec/ez-appsec/commit/3801e3d52cbfc82ae2ae5a623848a9dc6bc22d45))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.18] - 2026-04-02

### Added
- GitHub Actions workflow for Docker build and publish to GitHub Container Registry
- Semantic release automation for version management
- Comprehensive test suite with coverage reporting
- Security scanning integration with GitHub Advanced Security
- Support for GitHub Container Registry (ghcr.io)

### Changed
- Migrated from GitLab CI to GitHub Actions
- Updated Docker image references to use GitHub Container Registry
- Improved version handling with semantic-release
- Removed manual version bumping in favor of Conventional Commits

### Fixed
- Removed pinned semgrep version for better multi-architecture compatibility
- Fixed YAML syntax issues in GitHub Actions workflows

### Infrastructure
- Moved infrastructure documentation to separate repository (ez-appsec/ez-appsec-infra)

## [0.1.17] - 2026-03-25

### Features
- Initial ez-appsec release
- Support for gitleaks, semgrep, kics, and grype scanners
- GitLab and GitHub SARIF format support
- Multiple Docker image variants (standard, slim, micro, semgrep)

## [0.1.0] - 2026-03-25

### Added
- AI-powered security scanning with OpenAI LLM remediation guidance
- External scanner integration: gitleaks, semgrep, kics, grype
- Multiple output formats: JSON, SARIF, GitLab Vulnerability Format
- Multi-architecture Docker images: standard, slim, micro, semgrep variants
- GitLab CI/CD scan template (`scan.yml`) for easy project integration
- Claude Code slash commands `/ez-appsec-scan` and `/ez-appsec-install`
- Web dashboard for scan results
- CLI with `--version`, `--help`, and `scan` subcommand

[0.1.18]: https://github.com/ez-appsec/ez-appsec/compare/v0.1.17...v0.1.18
[0.1.17]: https://github.com/ez-appsec/ez-appsec/compare/v0.1.0...v0.1.17
[0.1.0]: https://github.com/ez-appsec/ez-appsec/releases/tag/v0.1.0

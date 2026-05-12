## [1.7.18](https://github.com/ez-appsec/ez-appsec/compare/v1.7.17...v1.7.18) (2026-05-12)


### Bug Fixes

* resolve merge conflict in README.md heading ([e6e613b](https://github.com/ez-appsec/ez-appsec/commit/e6e613bc5b274c1b4803c76f8c88323f5d647035))
* security and usability improvements from 3-pass PR review ([583b9e4](https://github.com/ez-appsec/ez-appsec/commit/583b9e4cdd1b37d673a6f0ee436477ef5115ea2a))


### Features

* add Claude-powered security agent with tool-use loop (PLAN-21) ([668892f](https://github.com/ez-appsec/ez-appsec/commit/668892f8aebdea15c323c8f2bbaebee5d5e9e567))
* add GitHub Projects V2 plan management scripts ([1f09745](https://github.com/ez-appsec/ez-appsec/commit/1f09745c748864b51f83d9933aed2385b4f98076))

## [1.7.17](https://github.com/ez-appsec/ez-appsec/compare/v1.7.16...v1.7.17) (2026-05-10)


### Features

* SBOM generation via grype CycloneDX (PLAN-10) ([#31](https://github.com/ez-appsec/ez-appsec/issues/31)) ([4b8c8b6](https://github.com/ez-appsec/ez-appsec/commit/4b8c8b6c409bbeb8018b06db773bdf9a473a0bd8))

## [1.7.16](https://github.com/ez-appsec/ez-appsec/compare/v1.7.15...v1.7.16) (2026-05-09)


### Bug Fixes

* address code review findings for compliance reporter ([68b2174](https://github.com/ez-appsec/ez-appsec/commit/68b217496964876f68ffa3199ae177c426c973cf))


### Features

* add compliance report generation for SOC2, PCI-DSS, HIPAA (PLAN-12) ([9ebbf64](https://github.com/ez-appsec/ez-appsec/commit/9ebbf6450ef6d545caa8039809acc970a0bf952c))

## [1.7.15](https://github.com/ez-appsec/ez-appsec/compare/v1.7.14...v1.7.15) (2026-05-08)


### Bug Fixes

* address security review findings for license compliance checking ([bf4269f](https://github.com/ez-appsec/ez-appsec/commit/bf4269fc1c3559f8558f6cc9630ea3dbf730cecf))
* license findings bypass ignore rules, broken diff parser, unchecked syft exit ([6b055cf](https://github.com/ez-appsec/ez-appsec/commit/6b055cfb549693e0315a7a902e628d966fe6a50e))
* resolve all CI test failures across 8 files ([7d06e08](https://github.com/ez-appsec/ez-appsec/commit/7d06e080a834d3733f8989f0cc9fc973302b772c))


### Features

* add Jira issue sync for scan findings (PLAN-08) ([7726fd3](https://github.com/ez-appsec/ez-appsec/commit/7726fd37172fe5f2a6ab59de691126236fc56162))
* add license compliance checking via syft SBOM analysis (PLAN-11) ([0147227](https://github.com/ez-appsec/ez-appsec/commit/01472270c43f7c082a295f8f82633d0e1bf4a0b2))
* add policy engine for scan threshold enforcement (PLAN-09) ([8f53a39](https://github.com/ez-appsec/ez-appsec/commit/8f53a396735688c7ad223722226bad24eb24e7a7))

## [1.7.14](https://github.com/ez-appsec/ez-appsec/compare/v1.7.13...v1.7.14) (2026-04-29)


### Features

* add Jira issue sync for scan findings (PLAN-08) ([024b92a](https://github.com/ez-appsec/ez-appsec/commit/024b92aa5741d06cf4f19659b826554a957dc3d1))
* add policy engine for scan threshold enforcement (PLAN-09) ([6321514](https://github.com/ez-appsec/ez-appsec/commit/6321514461e5afa06f0dfa22976c050323672572))

## [1.7.13](https://github.com/ez-appsec/ez-appsec/compare/v1.7.12...v1.7.13) (2026-04-28)


### Features

* add Slack/Teams webhook notifications for scan findings (PLAN-07) ([e67c898](https://github.com/ez-appsec/ez-appsec/commit/e67c8988aff99bccd99773881fed3462f0ab74ca))

## [1.7.12](https://github.com/ez-appsec/ez-appsec/compare/v1.7.11...v1.7.12) (2026-04-28)


### Features

* add baseline comparison for scan findings (PLAN-03) ([1d9b7a6](https://github.com/ez-appsec/ez-appsec/commit/1d9b7a6fb8a7236692ea8f561c940d449feaf0b0))
* add finding ownership and SLA tracking (PLAN-06) ([0ef9cca](https://github.com/ez-appsec/ez-appsec/commit/0ef9cca7225afe21b0d613723a3fd70e58a9ecd7))
* add fix-pr command to auto-bump vulnerable dependencies (PLAN-04) ([0261d7e](https://github.com/ez-appsec/ez-appsec/commit/0261d7ee2dab31778074dfdc62251077d8a4a3a5))
* add scan history tracking with trend indicators and sparklines (PLAN-05) ([a658bf9](https://github.com/ez-appsec/ez-appsec/commit/a658bf95da60d0b68985d90f59e274f1d20536cd))

## [1.7.11](https://github.com/ez-appsec/ez-appsec/compare/v1.7.10...v1.7.11) (2026-04-24)


### Features

* add gitlab/scan.yml (moved from scan.yml at root) ([395c25a](https://github.com/ez-appsec/ez-appsec/commit/395c25ad2b54956ddcbb24fd7e7a7b1c0e3335cb))

## [1.7.10](https://github.com/ez-appsec/ez-appsec/compare/v1.7.9...v1.7.10) (2026-04-21)


### Features

* improve demo dashboard with curated findings and new UI features ([f6591ca](https://github.com/ez-appsec/ez-appsec/commit/f6591cad582471faf037a49463db799089014335))

## [1.7.9](https://github.com/ez-appsec/ez-appsec/compare/v1.7.8...v1.7.9) (2026-04-14)


### Bug Fixes

* screenshot generator timeout — serve mock vulns for all /data/vulnerabilities/* paths ([47ac0a7](https://github.com/ez-appsec/ez-appsec/commit/47ac0a7288307f6891c522a5d0782600d3dc1240))

## [1.7.8](https://github.com/ez-appsec/ez-appsec/compare/v1.7.7...v1.7.8) (2026-04-14)


### Bug Fixes

* downgrade @semantic-release/exec to v6 for compatibility with semantic-release v22 ([81a13f6](https://github.com/ez-appsec/ez-appsec/commit/81a13f6bb60194e8cb571684682c79ffc58219f7))
* stamp VERSION file on release and auto-update dashboard UI assets after release ([3392f9d](https://github.com/ez-appsec/ez-appsec/commit/3392f9d96391df6707029426ab0b292ae235f150))

## [1.7.7](https://github.com/ez-appsec/ez-appsec/compare/v1.7.6...v1.7.7) (2026-04-14)


### Features

* add /ez-appsec update command — reinstalls latest skills with version diff report ([3df99b4](https://github.com/ez-appsec/ez-appsec/commit/3df99b4fe7405136ce343cf00d7e4ef6ce59cfe7))

## [1.7.6](https://github.com/ez-appsec/ez-appsec/compare/v1.7.5...v1.7.6) (2026-04-14)


### Features

* add version stamping to skills — installer tags dispatcher with version, /ez-appsec version subcommand reads it ([1489685](https://github.com/ez-appsec/ez-appsec/commit/148968583775e21ba75690bbb1b11d677e3f5934))

## [1.7.5](https://github.com/ez-appsec/ez-appsec/compare/v1.7.4...v1.7.5) (2026-04-14)


### Features

* add /ez-appsec test command — LLM-executable harness for all commands ([b05bc01](https://github.com/ez-appsec/ez-appsec/commit/b05bc0113801c9cf2031d4929cc0def4bb5114f3))

## [1.7.4](https://github.com/ez-appsec/ez-appsec/compare/v1.7.3...v1.7.4) (2026-04-14)


### Features

* add /ez-appsec remediate command — severity/risk-balanced fix plan with minimal prompting ([6c8090b](https://github.com/ez-appsec/ez-appsec/commit/6c8090ba1de123990fa19eb5fb4f9edf1c432c60))

## [1.7.3](https://github.com/ez-appsec/ez-appsec/compare/v1.7.2...v1.7.3) (2026-04-14)


### Features

* add /ez-appsec scan-context command — scan with Docker and load findings into context ([28d2abe](https://github.com/ez-appsec/ez-appsec/commit/28d2abe55ed4649d38ce485cfe9416f7e53cafda))

## [1.7.2](https://github.com/ez-appsec/ez-appsec/compare/v1.7.1...v1.7.2) (2026-04-14)


### Features

* add /ez-appsec load command to pull project vulns from dashboard into context ([ef60555](https://github.com/ez-appsec/ez-appsec/commit/ef605555bc85f0bbc4e9bfc505ab596f34ce4a70))

## [1.7.1](https://github.com/ez-appsec/ez-appsec/compare/v1.7.0...v1.7.1) (2026-04-14)


### Bug Fixes

* add openssh-client to runtime image; remove runtime apk-add from ingest-script ([31476d3](https://github.com/ez-appsec/ez-appsec/commit/31476d34731337b7051d6a162a19d8621092f49f))
* correct YAML syntax in mint-token step ([8986712](https://github.com/ez-appsec/ez-appsec/commit/89867126a1959192c627c422d3284c33fbddb895))
* remove secrets from release workflow if condition (not allowed in GitHub Actions) ([c018bd1](https://github.com/ez-appsec/ez-appsec/commit/c018bd1eca6a8119afb104c10667c34814a723ba))
* remove secrets from workflow if condition (not allowed) and add continue-on-error ([3228a66](https://github.com/ez-appsec/ez-appsec/commit/3228a66072012b9a7ebc2f26c6321a710f1f9605))
* run scan on master branch (for repos using master instead of main) ([0d08e50](https://github.com/ez-appsec/ez-appsec/commit/0d08e50aeda875172af94ea6a50ba7f247df7ed7))
* use GitHub App token in dashboard workflows instead of GITHUB_TOKEN ([9ae3173](https://github.com/ez-appsec/ez-appsec/commit/9ae3173256142a6d90415fc6f8b03b393139c755))


### Features

* add update-dashboard command and remove DASHBOARD_PUSH_TOKEN ([eba69f0](https://github.com/ez-appsec/ez-appsec/commit/eba69f098e49c36c343748779e9d33628c9af4a7))

# [1.7.0](https://github.com/ez-appsec/ez-appsec/compare/v1.6.0...v1.7.0) (2026-04-10)


### Features

* add uninstall-app skill — removes workflow, secrets, variables, and dashboard data ([438a482](https://github.com/ez-appsec/ez-appsec/commit/438a482d49f3fc9fe3110cf2d98e59de8645af0f))

# [1.6.0](https://github.com/ez-appsec/ez-appsec/compare/v1.5.0...v1.6.0) (2026-04-10)


### Features

* harden install-app skill — pre-flight checks, error remediations, retry logic, dynamic branch ([5f97a91](https://github.com/ez-appsec/ez-appsec/commit/5f97a912273be2f4114785d804217d8663b94296))

# [1.5.0](https://github.com/ez-appsec/ez-appsec/compare/v1.4.1...v1.5.0) (2026-04-10)


### Features

* add version-check job (warning only); streamline install-app skill to single script ([6b0397b](https://github.com/ez-appsec/ez-appsec/commit/6b0397b9baa5141ba047242fe8e22c81d6c73654))

## [1.4.1](https://github.com/ez-appsec/ez-appsec/compare/v1.4.0...v1.4.1) (2026-04-10)


### Bug Fixes

* use workflow file presence to detect prior provisioning (installation API requires App JWT) ([984538c](https://github.com/ez-appsec/ez-appsec/commit/984538c4c8a2bc5feaf7c5dd80244e0f4bd11f59))

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

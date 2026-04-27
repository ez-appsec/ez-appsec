"""Tests for automated fix PRs (PLAN-04)"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from tempfile import TemporaryDirectory

from ez_appsec.fix_pr import (
    VulnerableDependency,
    EcosystemFixPlan,
    parse_grype_findings,
    parse_gitlab_findings,
    group_by_ecosystem,
    apply_version_bump,
    build_pr_body,
    build_branch_name,
    build_pr_title,
    create_github_pr,
    create_gitlab_mr,
    _extract_fixed_version,
    _bump_package_json,
    _bump_requirements_txt,
    _bump_go_mod,
    _bump_gemfile,
    _bump_pom_xml,
)


SAMPLE_GRYPE_OUTPUT = {
    "matches": [
        {
            "artifact": {
                "name": "lodash",
                "version": "4.17.15",
                "type": "npm",
            },
            "vulnerability": {
                "id": "CVE-2021-23337",
                "severity": "High",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                "fix": {"versions": ["4.17.21"]},
                "cvss": [{"metrics": {"baseScore": 7.2}}],
            },
        },
        {
            "artifact": {
                "name": "express",
                "version": "4.17.1",
                "type": "npm",
            },
            "vulnerability": {
                "id": "CVE-2024-29041",
                "severity": "Medium",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-29041",
                "fix": {"versions": ["4.19.2"]},
                "cvss": [{"metrics": {"baseScore": 6.1}}],
            },
        },
        {
            "artifact": {
                "name": "requests",
                "version": "2.25.0",
                "type": "python",
            },
            "vulnerability": {
                "id": "CVE-2023-32681",
                "severity": "Medium",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
                "fix": {"versions": ["2.31.0"]},
                "cvss": [],
            },
        },
        {
            "artifact": {
                "name": "unfixable-pkg",
                "version": "1.0.0",
                "type": "npm",
            },
            "vulnerability": {
                "id": "CVE-2099-99999",
                "severity": "Low",
                "fix": {"versions": []},
                "cvss": [],
            },
        },
    ]
}


class TestParseGrypeFindings:
    def test_parses_fixable_deps(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE_OUTPUT))

        deps = parse_grype_findings(str(grype_file))
        assert len(deps) == 3  # unfixable-pkg excluded

    def test_skips_unfixable(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE_OUTPUT))

        deps = parse_grype_findings(str(grype_file))
        names = [d.package for d in deps]
        assert "unfixable-pkg" not in names

    def test_extracts_cvss_score(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE_OUTPUT))

        deps = parse_grype_findings(str(grype_file))
        lodash = next(d for d in deps if d.package == "lodash")
        assert lodash.cvss_score == 7.2

    def test_handles_missing_cvss(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE_OUTPUT))

        deps = parse_grype_findings(str(grype_file))
        requests_dep = next(d for d in deps if d.package == "requests")
        assert requests_dep.cvss_score is None

    def test_extracts_cve_and_severity(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE_OUTPUT))

        deps = parse_grype_findings(str(grype_file))
        lodash = next(d for d in deps if d.package == "lodash")
        assert lodash.cve_id == "CVE-2021-23337"
        assert lodash.severity == "High"
        assert lodash.fixed_version == "4.17.21"

    def test_empty_matches(self, tmp_path):
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps({"matches": []}))
        assert parse_grype_findings(str(grype_file)) == []


class TestParseGitlabFindings:
    def test_parses_dependency_findings(self, tmp_path):
        vulns = {
            "vulnerabilities": [
                {
                    "severity": "high",
                    "solution": "Upgrade to version 2.31.0",
                    "location": {
                        "dependency": {
                            "package": {"name": "requests"},
                            "version": "2.25.0",
                        }
                    },
                    "identifiers": [{"type": "cve", "value": "CVE-2023-32681"}],
                    "links": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"}],
                }
            ]
        }
        f = tmp_path / "vulns.json"
        f.write_text(json.dumps(vulns))

        deps = parse_gitlab_findings(str(f))
        assert len(deps) == 1
        assert deps[0].package == "requests"
        assert deps[0].fixed_version == "2.31.0"

    def test_skips_non_dependency_findings(self, tmp_path):
        vulns = {
            "vulnerabilities": [
                {
                    "severity": "high",
                    "solution": "Fix the code",
                    "location": {"file": "app.py", "start_line": 10},
                    "identifiers": [{"type": "cwe", "value": "CWE-89"}],
                }
            ]
        }
        f = tmp_path / "vulns.json"
        f.write_text(json.dumps(vulns))
        assert parse_gitlab_findings(str(f)) == []

    def test_skips_findings_without_fix_version(self, tmp_path):
        vulns = {
            "vulnerabilities": [
                {
                    "severity": "high",
                    "solution": "No known fix available",
                    "location": {
                        "dependency": {
                            "package": {"name": "somepkg"},
                            "version": "1.0.0",
                        }
                    },
                    "identifiers": [],
                }
            ]
        }
        f = tmp_path / "vulns.json"
        f.write_text(json.dumps(vulns))
        assert parse_gitlab_findings(str(f)) == []


class TestExtractFixedVersion:
    def test_upgrade_to_pattern(self):
        assert _extract_fixed_version("Upgrade to 2.31.0", "pkg") == "2.31.0"

    def test_update_to_version(self):
        assert _extract_fixed_version("Update to version 1.5.3", "pkg") == "1.5.3"

    def test_gte_pattern(self):
        assert _extract_fixed_version(">= 3.0.1", "pkg") == "3.0.1"

    def test_version_or_later(self):
        assert _extract_fixed_version("version 4.2.0 or later", "pkg") == "4.2.0"

    def test_no_version_found(self):
        assert _extract_fixed_version("No fix available", "pkg") == ""

    def test_empty_solution(self):
        assert _extract_fixed_version("", "pkg") == ""


class TestGroupByEcosystem:
    def test_groups_by_manifest(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("")

        deps = [
            VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
            VulnerableDependency("requests", "2.25.0", "2.31.0", "CVE-2", "Medium"),
        ]

        plans = group_by_ecosystem(deps, str(tmp_path))
        assert len(plans) >= 1

    def test_skips_ecosystem_without_manifest(self, tmp_path):
        deps = [
            VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
        ]
        plans = group_by_ecosystem(deps, str(tmp_path))
        assert len(plans) == 0

    def test_multiple_deps_same_ecosystem(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        deps = [
            VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
            VulnerableDependency("express", "4.17.1", "4.19.2", "CVE-2", "Medium"),
        ]
        plans = group_by_ecosystem(deps, str(tmp_path))
        npm_plan = next((p for p in plans if p.ecosystem == "npm"), None)
        assert npm_plan is not None
        assert len(npm_plan.fixes) == 2


class TestBumpPackageJson:
    def test_bumps_caret_dependency(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.15"},
        }))

        fixes = [VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High")]
        modified = _bump_package_json(pkg, fixes)

        assert len(modified) == 1
        data = json.loads(pkg.read_text())
        assert data["dependencies"]["lodash"] == "^4.17.21"

    def test_bumps_tilde_dependency(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "~4.17.1"},
        }))

        fixes = [VulnerableDependency("express", "4.17.1", "4.19.2", "CVE-2", "Medium")]
        modified = _bump_package_json(pkg, fixes)

        assert len(modified) == 1
        data = json.loads(pkg.read_text())
        assert data["dependencies"]["express"] == "~4.19.2"

    def test_bumps_exact_version(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"lodash": "4.17.15"},
        }))

        fixes = [VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High")]
        _bump_package_json(pkg, fixes)

        data = json.loads(pkg.read_text())
        assert data["dependencies"]["lodash"] == "4.17.21"

    def test_bumps_dev_dependency(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {},
            "devDependencies": {"jest": "^27.0.0"},
        }))

        fixes = [VulnerableDependency("jest", "27.0.0", "29.7.0", "CVE-3", "Low")]
        _bump_package_json(pkg, fixes)

        data = json.loads(pkg.read_text())
        assert data["devDependencies"]["jest"] == "^29.7.0"

    def test_no_match_returns_empty(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"other-pkg": "1.0.0"}}))

        fixes = [VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High")]
        modified = _bump_package_json(pkg, fixes)
        assert modified == []


class TestBumpRequirementsTxt:
    def test_bumps_pinned_version(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.25.0\nflask>=2.0\n")

        fixes = [VulnerableDependency("requests", "2.25.0", "2.31.0", "CVE-1", "Medium")]
        modified = _bump_requirements_txt(req, fixes)

        assert len(modified) == 1
        content = req.read_text()
        assert "requests>=2.31.0" in content
        assert "flask>=2.0" in content

    def test_preserves_comments(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# deps\nrequests==2.25.0\n# end\n")

        fixes = [VulnerableDependency("requests", "2.25.0", "2.31.0", "CVE-1", "Medium")]
        _bump_requirements_txt(req, fixes)

        content = req.read_text()
        assert "# deps" in content
        assert "# end" in content

    def test_no_match_returns_empty(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\n")

        fixes = [VulnerableDependency("requests", "2.25.0", "2.31.0", "CVE-1", "Medium")]
        assert _bump_requirements_txt(req, fixes) == []

    def test_handles_hyphen_underscore_normalization(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("my-package==1.0.0\n")

        fixes = [VulnerableDependency("my_package", "1.0.0", "1.1.0", "CVE-1", "Medium")]
        modified = _bump_requirements_txt(req, fixes)
        assert len(modified) == 1


class TestBumpGoMod:
    def test_bumps_go_dependency(self, tmp_path):
        gomod = tmp_path / "go.mod"
        gomod.write_text(
            "module example.com/myapp\n\ngo 1.21\n\nrequire (\n"
            "\tgithub.com/gin-gonic/gin v1.9.0\n"
            "\tgolang.org/x/net v0.7.0\n"
            ")\n"
        )

        fixes = [VulnerableDependency("golang.org/x/net", "0.7.0", "0.17.0", "CVE-1", "High")]
        modified = _bump_go_mod(gomod, fixes)

        assert len(modified) == 1
        content = gomod.read_text()
        assert "v0.17.0" in content
        assert "v1.9.0" in content  # gin unchanged


class TestBumpGemfile:
    def test_bumps_gem_version(self, tmp_path):
        gemfile = tmp_path / "Gemfile"
        gemfile.write_text(
            'source "https://rubygems.org"\n'
            'gem "rails", "~> 6.1.0"\n'
            'gem "puma", "~> 5.0"\n'
        )

        fixes = [VulnerableDependency("rails", "6.1.0", "6.1.7.6", "CVE-1", "High")]
        modified = _bump_gemfile(gemfile, fixes)

        assert len(modified) == 1
        content = gemfile.read_text()
        assert "6.1.7.6" in content
        assert '"puma"' in content


class TestBumpPomXml:
    def test_bumps_maven_version(self, tmp_path):
        pom = tmp_path / "pom.xml"
        pom.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.apache.commons</groupId>\n"
            "      <artifactId>commons-text</artifactId>\n"
            "      <version>1.9</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n"
        )

        fixes = [VulnerableDependency(
            "org.apache.commons:commons-text", "1.9", "1.10.0", "CVE-2022-42889", "Critical"
        )]
        modified = _bump_pom_xml(pom, fixes)

        assert len(modified) == 1
        content = pom.read_text()
        assert "1.10.0" in content


class TestBuildPrBody:
    def test_contains_cve_table(self):
        plans = [
            EcosystemFixPlan(
                ecosystem="npm",
                manifest_file="package.json",
                fixes=[
                    VulnerableDependency(
                        "lodash", "4.17.15", "4.17.21", "CVE-2021-23337",
                        "High", 7.2, "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
                    ),
                ],
            )
        ]
        body = build_pr_body(plans)

        assert "CVE-2021-23337" in body
        assert "lodash" in body
        assert "4.17.15" in body
        assert "4.17.21" in body
        assert "7.2" in body
        assert "package.json" in body

    def test_multiple_ecosystems(self):
        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High", 7.2),
            ]),
            EcosystemFixPlan("python", "requirements.txt", [
                VulnerableDependency("requests", "2.25.0", "2.31.0", "CVE-2", "Medium"),
            ]),
        ]
        body = build_pr_body(plans)
        assert "npm" in body
        assert "python" in body
        assert "package.json" in body
        assert "requirements.txt" in body

    def test_na_for_missing_cvss(self):
        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("pkg", "1.0", "2.0", "CVE-1", "Low"),
            ]),
        ]
        body = build_pr_body(plans)
        assert "N/A" in body


class TestBuildBranchName:
    def test_format(self):
        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("a", "1", "2", "CVE-1", "H"),
                VulnerableDependency("b", "1", "2", "CVE-2", "H"),
            ]),
        ]
        name = build_branch_name(plans)
        assert name == "ez-appsec/fix-npm-2-cves"

    def test_multiple_ecosystems(self):
        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("a", "1", "2", "CVE-1", "H"),
            ]),
            EcosystemFixPlan("python", "requirements.txt", [
                VulnerableDependency("b", "1", "2", "CVE-2", "M"),
            ]),
        ]
        name = build_branch_name(plans)
        assert "npm" in name
        assert "python" in name
        assert "2-cves" in name


class TestBuildPrTitle:
    def test_format(self):
        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("a", "1", "2", "CVE-1", "H"),
            ]),
        ]
        title = build_pr_title(plans)
        assert "1 vulnerable" in title
        assert "npm" in title


class TestCreateGithubPr:
    @patch("ez_appsec.fix_pr.subprocess.run")
    @patch("ez_appsec.fix_pr.apply_version_bump")
    def test_creates_pr_with_correct_commands(self, mock_bump, mock_run):
        mock_bump.return_value = ["package.json"]
        mock_run.return_value = MagicMock(returncode=0, stdout="https://github.com/owner/repo/pull/42\n", stderr="")

        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High", 7.2),
            ]),
        ]

        result = create_github_pr("owner/repo", "/tmp/repo", plans, token="fake-token")

        assert result["pr_url"] == "https://github.com/owner/repo/pull/42"
        assert result["files_modified"] == ["package.json"]
        assert result["dry_run"] is False

        git_calls = [c for c in mock_run.call_args_list if c[0][0][0] == "git"]
        assert any("checkout" in str(c) for c in git_calls)
        assert any("add" in str(c) for c in git_calls)
        assert any("commit" in str(c) for c in git_calls)
        assert any("push" in str(c) for c in git_calls)

        gh_call = next(c for c in mock_run.call_args_list if c[0][0][0] == "gh")
        assert "pr" in gh_call[0][0]
        assert "create" in gh_call[0][0]
        assert "--repo" in gh_call[0][0]
        assert "owner/repo" in gh_call[0][0]

    @patch("ez_appsec.fix_pr.subprocess.run")
    @patch("ez_appsec.fix_pr.apply_version_bump")
    def test_dry_run_skips_git_and_gh(self, mock_bump, mock_run):
        mock_bump.return_value = ["package.json"]

        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
            ]),
        ]

        result = create_github_pr("owner/repo", "/tmp/repo", plans, dry_run=True)

        assert result["dry_run"] is True
        assert result["pr_url"] is None
        mock_run.assert_not_called()

    @patch("ez_appsec.fix_pr.apply_version_bump")
    def test_no_modifications_returns_error(self, mock_bump):
        mock_bump.return_value = []

        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
            ]),
        ]

        result = create_github_pr("owner/repo", "/tmp/repo", plans)
        assert result.get("error")
        assert result["pr_url"] is None

    @patch("ez_appsec.fix_pr.subprocess.run")
    @patch("ez_appsec.fix_pr.apply_version_bump")
    def test_gh_failure_raises(self, mock_bump, mock_run):
        mock_bump.return_value = ["package.json"]

        def side_effect(args, **kwargs):
            if args[0] == "gh":
                return MagicMock(returncode=1, stderr="auth required", stdout="")
            return MagicMock(returncode=0, stderr="", stdout="")

        mock_run.side_effect = side_effect

        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
            ]),
        ]

        with pytest.raises(RuntimeError, match="gh pr create failed"):
            create_github_pr("owner/repo", "/tmp/repo", plans, token="t")

    @patch("ez_appsec.fix_pr.subprocess.run")
    @patch("ez_appsec.fix_pr.apply_version_bump")
    def test_branch_name_in_push(self, mock_bump, mock_run):
        mock_bump.return_value = ["package.json"]
        mock_run.return_value = MagicMock(returncode=0, stdout="https://gh/pr/1\n", stderr="")

        plans = [
            EcosystemFixPlan("npm", "package.json", [
                VulnerableDependency("a", "1", "2", "CVE-1", "H"),
                VulnerableDependency("b", "1", "2", "CVE-2", "H"),
            ]),
        ]

        create_github_pr("owner/repo", "/tmp/repo", plans, token="t")

        push_call = next(
            c for c in mock_run.call_args_list
            if c[0][0][0] == "git" and "push" in c[0][0]
        )
        assert "ez-appsec/fix-npm-2-cves" in push_call[0][0]


class TestCreateGitlabMr:
    @patch("ez_appsec.fix_pr.subprocess.run")
    @patch("ez_appsec.fix_pr.apply_version_bump")
    def test_creates_mr(self, mock_bump, mock_run):
        mock_bump.return_value = ["requirements.txt"]
        mock_run.return_value = MagicMock(
            returncode=0, stdout="https://gitlab.com/group/repo/-/merge_requests/7\n", stderr=""
        )

        plans = [
            EcosystemFixPlan("python", "requirements.txt", [
                VulnerableDependency("requests", "2.25.0", "2.31.0", "CVE-1", "Medium"),
            ]),
        ]

        result = create_gitlab_mr("12345", "/tmp/repo", plans, token="glpat-xxx")

        assert result["mr_url"] == "https://gitlab.com/group/repo/-/merge_requests/7"
        assert result["files_modified"] == ["requirements.txt"]

        glab_call = next(c for c in mock_run.call_args_list if c[0][0][0] == "glab")
        assert "mr" in glab_call[0][0]
        assert "create" in glab_call[0][0]

    @patch("ez_appsec.fix_pr.apply_version_bump")
    def test_no_modifications_returns_error(self, mock_bump):
        mock_bump.return_value = []

        plans = [
            EcosystemFixPlan("python", "requirements.txt", [
                VulnerableDependency("requests", "2.25.0", "2.31.0", "CVE-1", "Medium"),
            ]),
        ]

        result = create_gitlab_mr("12345", "/tmp/repo", plans)
        assert result.get("error")


class TestApplyVersionBump:
    def test_delegates_to_correct_bumper(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"lodash": "^4.17.15"}}))

        plan = EcosystemFixPlan("npm", "package.json", [
            VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
        ])

        modified = apply_version_bump(plan, str(tmp_path))
        assert len(modified) == 1
        data = json.loads(pkg.read_text())
        assert data["dependencies"]["lodash"] == "^4.17.21"

    def test_missing_manifest_returns_empty(self, tmp_path):
        plan = EcosystemFixPlan("npm", "package.json", [
            VulnerableDependency("lodash", "4.17.15", "4.17.21", "CVE-1", "High"),
        ])

        modified = apply_version_bump(plan, str(tmp_path))
        assert modified == []


class TestEndToEnd:
    """Integration-style tests with real files, mocked git/gh."""

    @patch("ez_appsec.fix_pr.subprocess.run")
    def test_grype_to_github_pr(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="https://gh/pr/1\n", stderr="")

        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps({
            "matches": [
                {
                    "artifact": {"name": "lodash", "version": "4.17.15", "type": "npm"},
                    "vulnerability": {
                        "id": "CVE-2021-23337", "severity": "High",
                        "fix": {"versions": ["4.17.21"]}, "cvss": [],
                    },
                }
            ]
        }))

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.15"},
        }))

        deps = parse_grype_findings(str(grype_file))
        plans = group_by_ecosystem(deps, str(repo_dir))
        assert len(plans) == 1

        result = create_github_pr("owner/repo", str(repo_dir), plans, token="t")
        assert result["pr_url"] == "https://gh/pr/1"

        data = json.loads((repo_dir / "package.json").read_text())
        assert data["dependencies"]["lodash"] == "^4.17.21"

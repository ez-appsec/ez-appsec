"""Tests for secret rotation automation (PLAN-17)"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from ez_appsec.secret_rotator import (
    DetectedSecret,
    RotationResult,
    classify_secret,
    get_provider,
    parse_gitleaks_findings,
    rotate_secrets,
    replace_hardcoded_secret,
    build_rotation_pr_body,
    build_rotation_branch_name,
    build_rotation_pr_title,
    create_rotation_pr,
    create_secret_store,
    AWSKeyProvider,
    GitHubPATProvider,
    GitLabPATProvider,
    GitHubActionsSecretStore,
    GitLabCIVariableStore,
    VaultSecretStore,
    _build_env_var_name,
)


SAMPLE_GITLEAKS_OUTPUT = [
    {
        "RuleID": "aws-access-key-id",
        "Match": "AKIAIOSFODNN7EXAMPLE",
        "File": "config.py",
        "StartLine": 10,
        "StartColumn": 15,
        "EndColumn": 35,
        "Commit": "abc123",
    },
    {
        "RuleID": "github-pat",
        "Match": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "File": "deploy.sh",
        "StartLine": 5,
        "StartColumn": 12,
        "EndColumn": 52,
        "Commit": "def456",
    },
    {
        "RuleID": "gitlab-pat",
        "Match": "glpat-xxxxxxxxxxxxxxxxxxxx",
        "File": "ci/settings.yaml",
        "StartLine": 22,
        "StartColumn": 10,
        "EndColumn": 36,
        "Commit": "ghi789",
    },
    {
        "RuleID": "generic-api-key",
        "Match": "sk-1234567890abcdef",
        "File": "app.py",
        "StartLine": 1,
        "StartColumn": 1,
        "EndColumn": 19,
        "Commit": "jkl012",
    },
]


def _secret(rule_id="aws-access-key-id", match="AKIAIOSFODNN7EXAMPLE",
            file="config.py", line=10, **overrides):
    base = DetectedSecret(
        rule_id=rule_id,
        secret_type=classify_secret(rule_id) or "unknown",
        file=file,
        line=line,
        match=match,
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


class TestClassifySecret:
    def test_aws_key(self):
        assert classify_secret("aws-access-key-id") == "aws"
        assert classify_secret("aws-secret-access-key") == "aws"

    def test_github_pat(self):
        assert classify_secret("github-pat") == "github_pat"
        assert classify_secret("github-fine-grained-pat") == "github_pat"

    def test_gitlab_pat(self):
        assert classify_secret("gitlab-pat") == "gitlab_pat"
        assert classify_secret("gitlab-ptt") == "gitlab_pat"

    def test_unknown_returns_none(self):
        assert classify_secret("generic-api-key") is None
        assert classify_secret("slack-token") is None


class TestGetProvider:
    def test_aws_provider(self):
        provider = get_provider("aws-access-key-id")
        assert isinstance(provider, AWSKeyProvider)

    def test_github_provider(self):
        provider = get_provider("github-pat")
        assert isinstance(provider, GitHubPATProvider)

    def test_gitlab_provider(self):
        provider = get_provider("gitlab-pat")
        assert isinstance(provider, GitLabPATProvider)

    def test_unknown_returns_none(self):
        assert get_provider("generic-api-key") is None


class TestParseGitleaksFindings:
    def test_parses_rotatable_secrets(self, tmp_path):
        findings_file = tmp_path / "gitleaks.json"
        findings_file.write_text(json.dumps(SAMPLE_GITLEAKS_OUTPUT))

        secrets = parse_gitleaks_findings(str(findings_file))
        assert len(secrets) == 3  # generic-api-key excluded

    def test_skips_unsupported_rule_ids(self, tmp_path):
        findings_file = tmp_path / "gitleaks.json"
        findings_file.write_text(json.dumps([
            {"RuleID": "generic-api-key", "Match": "sk-xxx", "File": "a.py", "StartLine": 1},
        ]))

        secrets = parse_gitleaks_findings(str(findings_file))
        assert len(secrets) == 0

    def test_extracts_fields_correctly(self, tmp_path):
        findings_file = tmp_path / "gitleaks.json"
        findings_file.write_text(json.dumps([SAMPLE_GITLEAKS_OUTPUT[0]]))

        secrets = parse_gitleaks_findings(str(findings_file))
        assert len(secrets) == 1

        s = secrets[0]
        assert s.rule_id == "aws-access-key-id"
        assert s.secret_type == "aws"
        assert s.file == "config.py"
        assert s.line == 10
        assert s.match == "AKIAIOSFODNN7EXAMPLE"
        assert s.commit == "abc123"

    def test_handles_single_object_input(self, tmp_path):
        findings_file = tmp_path / "gitleaks.json"
        findings_file.write_text(json.dumps(SAMPLE_GITLEAKS_OUTPUT[0]))

        secrets = parse_gitleaks_findings(str(findings_file))
        assert len(secrets) == 1

    def test_empty_file(self, tmp_path):
        findings_file = tmp_path / "gitleaks.json"
        findings_file.write_text("[]")

        secrets = parse_gitleaks_findings(str(findings_file))
        assert len(secrets) == 0


class TestBuildEnvVarName:
    def test_aws_key(self):
        s = _secret(rule_id="aws-access-key-id")
        assert _build_env_var_name(s) == "AWS_ACCESS_KEY_ID"

    def test_github_pat(self):
        s = _secret(rule_id="github-pat")
        assert _build_env_var_name(s) == "GITHUB_PAT"

    def test_gitlab_pat(self):
        s = _secret(rule_id="gitlab-pat")
        assert _build_env_var_name(s) == "GITLAB_PAT"


class TestAWSKeyProvider:
    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_rotates_key_successfully(self, mock_run):
        list_resp = MagicMock(returncode=0, stdout=json.dumps({
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "UserName": "deploy-bot", "Status": "Active"},
            ],
        }))
        create_resp = MagicMock(returncode=0, stdout=json.dumps({
            "AccessKey": {
                "AccessKeyId": "AKIANEWKEY12345678",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEWSECRET",
                "UserName": "deploy-bot",
            },
        }))
        deactivate_resp = MagicMock(returncode=0)
        mock_run.side_effect = [list_resp, create_resp, deactivate_resp]

        provider = AWSKeyProvider()
        result = provider.rotate("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id")

        assert result["new_value"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEWSECRET"
        assert result["revoked"] is True
        assert "AKIANEWKEY12345678" in result["details"]
        assert mock_run.call_count == 3

    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_handles_aws_cli_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="Access denied", stdout="")

        provider = AWSKeyProvider()
        result = provider.rotate("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id")

        assert result["new_value"] == ""
        assert result["revoked"] is False
        assert "AWS CLI error" in result["details"]

    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_handles_timeout(self, mock_run):
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired("aws", 30)

        provider = AWSKeyProvider()
        result = provider.rotate("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id")

        assert result["new_value"] == ""
        assert "timed out" in result["details"]

    def test_can_rotate_supported_rules(self):
        provider = AWSKeyProvider()
        assert provider.can_rotate("aws-access-key-id") is True
        assert provider.can_rotate("aws-secret-access-key") is True
        assert provider.can_rotate("github-pat") is False


class TestGitHubPATProvider:
    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_revokes_token(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="ghp_current_token", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        provider = GitHubPATProvider()
        result = provider.rotate("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "github-pat")

        assert result["revoked"] is True
        assert "new PAT manually" in result["details"]

    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_handles_revoke_failure(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=1, stdout="", stderr="not found"),
        ]

        provider = GitHubPATProvider()
        result = provider.rotate("ghp_xxx", "github-pat")

        assert result["revoked"] is False

    def test_can_rotate_supported_rules(self):
        provider = GitHubPATProvider()
        assert provider.can_rotate("github-pat") is True
        assert provider.can_rotate("github-fine-grained-pat") is True
        assert provider.can_rotate("aws-access-key-id") is False


class TestGitLabPATProvider:
    def test_revokes_token(self):
        mock_requests = MagicMock()
        mock_self_resp = MagicMock(status_code=200)
        mock_self_resp.json.return_value = {"id": 1}
        mock_list_resp = MagicMock(status_code=200)
        mock_list_resp.json.return_value = [
            {"id": 42, "token": "glpa", "name": "deploy"},
        ]
        mock_revoke_resp = MagicMock(status_code=204)

        mock_requests.get.side_effect = [mock_self_resp, mock_list_resp]
        mock_requests.delete.return_value = mock_revoke_resp

        provider = GitLabPATProvider()
        with patch.dict(os.environ, {"GITLAB_ACCESS_TOKEN": "glpat-admin-token"}):
            with patch.dict("sys.modules", {"requests": mock_requests}):
                result = provider.rotate("glpat-xxxxxxxxxxxxxxxxxxxx", "gitlab-pat")

        assert result["revoked"] is True
        assert "token" in result["details"].lower()

    def test_can_rotate_supported_rules(self):
        provider = GitLabPATProvider()
        assert provider.can_rotate("gitlab-pat") is True
        assert provider.can_rotate("gitlab-ptt") is True
        assert provider.can_rotate("github-pat") is False

    def test_requires_gitlab_token(self):
        provider = GitLabPATProvider()
        with patch.dict(os.environ, {}, clear=True):
            env_backup = {k: v for k, v in os.environ.items()
                          if k in ("GITLAB_ACCESS_TOKEN", "GITLAB_TOKEN")}
            os.environ.pop("GITLAB_ACCESS_TOKEN", None)
            os.environ.pop("GITLAB_TOKEN", None)
            try:
                result = provider.rotate("glpat-xxx", "gitlab-pat")
                assert result["revoked"] is False
                assert "GITLAB_ACCESS_TOKEN" in result["details"]
            finally:
                os.environ.update(env_backup)


class TestRotateSecrets:
    def test_dry_run_skips_rotation(self):
        secrets = [_secret()]
        results = rotate_secrets(secrets, dry_run=True)

        assert len(results) == 1
        assert results[0].rotated is False
        assert results[0].env_var_name == "AWS_ACCESS_KEY_ID"
        assert results[0].error is None

    def test_unknown_rule_id_produces_error(self):
        s = _secret(rule_id="unknown-rule")
        s.secret_type = "unknown"
        results = rotate_secrets([s])

        assert len(results) == 1
        assert results[0].rotated is False
        assert "No provider" in results[0].error

    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_successful_rotation_with_store(self, mock_run):
        list_resp = MagicMock(returncode=0, stdout=json.dumps({
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "UserName": "bot", "Status": "Active"},
            ],
        }))
        create_resp = MagicMock(returncode=0, stdout=json.dumps({
            "AccessKey": {
                "AccessKeyId": "AKIANEW",
                "SecretAccessKey": "newsecret",
                "UserName": "bot",
            },
        }))
        deactivate_resp = MagicMock(returncode=0)
        store_resp = MagicMock(returncode=0)
        mock_run.side_effect = [list_resp, create_resp, deactivate_resp, store_resp]

        store = GitHubActionsSecretStore("owner/repo", token="fake")
        results = rotate_secrets([_secret()], store=store)

        assert len(results) == 1
        assert results[0].rotated is True
        assert results[0].old_revoked is True
        assert results[0].new_secret_stored is True

    def test_multiple_secrets_mixed_results(self):
        secrets = [
            _secret(rule_id="aws-access-key-id"),
            _secret(rule_id="unknown-rule", match="xxx", file="b.py"),
        ]
        secrets[1].secret_type = "unknown"
        results = rotate_secrets(secrets, dry_run=True)

        assert len(results) == 2
        rotatable = [r for r in results if r.error is None]
        errored = [r for r in results if r.error is not None]
        assert len(rotatable) == 1
        assert len(errored) == 1


class TestReplaceHardcodedSecret:
    def test_python_file(self, tmp_path):
        src = tmp_path / "config.py"
        src.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        s = _secret(file="config.py", match="AKIAIOSFODNN7EXAMPLE")
        result = replace_hardcoded_secret(str(src), s, "AWS_ACCESS_KEY_ID")

        assert result is True
        content = src.read_text()
        assert 'os.environ.get("AWS_ACCESS_KEY_ID")' in content
        assert "AKIAIOSFODNN7EXAMPLE" not in content

    def test_javascript_file(self, tmp_path):
        src = tmp_path / "config.js"
        src.write_text("const token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';\n")

        s = _secret(rule_id="github-pat", match="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                     file="config.js")
        result = replace_hardcoded_secret(str(src), s, "GITHUB_PAT")

        assert result is True
        content = src.read_text()
        assert "process.env.GITHUB_PAT" in content

    def test_ruby_file(self, tmp_path):
        src = tmp_path / "config.rb"
        src.write_text('TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"\n')

        s = _secret(rule_id="gitlab-pat", match="glpat-xxxxxxxxxxxxxxxxxxxx", file="config.rb")
        result = replace_hardcoded_secret(str(src), s, "GITLAB_PAT")

        assert result is True
        assert "ENV['GITLAB_PAT']" in src.read_text()

    def test_go_file(self, tmp_path):
        src = tmp_path / "main.go"
        src.write_text('var key = "AKIAIOSFODNN7EXAMPLE"\n')

        s = _secret(file="main.go")
        result = replace_hardcoded_secret(str(src), s, "AWS_ACCESS_KEY_ID")

        assert result is True
        assert 'os.Getenv("AWS_ACCESS_KEY_ID")' in src.read_text()

    def test_java_file(self, tmp_path):
        src = tmp_path / "Config.java"
        src.write_text('String key = "AKIAIOSFODNN7EXAMPLE";\n')

        s = _secret(file="Config.java")
        result = replace_hardcoded_secret(str(src), s, "AWS_ACCESS_KEY_ID")

        assert result is True
        assert 'System.getenv("AWS_ACCESS_KEY_ID")' in src.read_text()

    def test_php_file(self, tmp_path):
        src = tmp_path / "config.php"
        src.write_text("$key = 'AKIAIOSFODNN7EXAMPLE';\n")

        s = _secret(file="config.php")
        result = replace_hardcoded_secret(str(src), s, "AWS_ACCESS_KEY_ID")

        assert result is True
        assert "getenv('AWS_ACCESS_KEY_ID')" in src.read_text()

    def test_yaml_file(self, tmp_path):
        src = tmp_path / "config.yaml"
        src.write_text('api_key: "AKIAIOSFODNN7EXAMPLE"\n')

        s = _secret(file="config.yaml")
        result = replace_hardcoded_secret(str(src), s, "AWS_ACCESS_KEY_ID")

        assert result is True
        assert "${AWS_ACCESS_KEY_ID}" in src.read_text()

    def test_nonexistent_file(self, tmp_path):
        s = _secret(file="missing.py")
        result = replace_hardcoded_secret(str(tmp_path / "missing.py"), s, "VAR")
        assert result is False

    def test_secret_not_in_file(self, tmp_path):
        src = tmp_path / "clean.py"
        src.write_text('x = "not a secret"\n')

        s = _secret(file="clean.py")
        result = replace_hardcoded_secret(str(src), s, "VAR")
        assert result is False


class TestBuildRotationPrBody:
    def test_includes_table(self):
        results = [
            RotationResult(
                secret=_secret(),
                rotated=True,
                env_var_name="AWS_ACCESS_KEY_ID",
                old_revoked=True,
                new_secret_stored=True,
                store_target="GitHubActionsSecretStore",
            ),
        ]
        body = build_rotation_pr_body(results)
        assert "Automated Secret Rotation" in body
        assert "AWS_ACCESS_KEY_ID" in body
        assert "aws-access-key-id" in body
        assert "config.py:10" in body

    def test_includes_manual_action_items(self):
        results = [
            RotationResult(
                secret=_secret(),
                rotated=True,
                env_var_name="AWS_ACCESS_KEY_ID",
                old_revoked=True,
                new_secret_stored=False,
            ),
        ]
        body = build_rotation_pr_body(results)
        assert "Action Required" in body
        assert "manually" in body

    def test_includes_error_details(self):
        results = [
            RotationResult(
                secret=_secret(rule_id="unknown-rule"),
                rotated=False,
                env_var_name="UNKNOWN_RULE",
                error="No provider for rule_id: unknown-rule",
            ),
        ]
        body = build_rotation_pr_body(results)
        assert "could not be rotated" in body
        assert "No provider" in body


class TestBuildRotationBranchName:
    def test_single_type(self):
        results = [
            RotationResult(secret=_secret(), rotated=True, env_var_name="X"),
        ]
        name = build_rotation_branch_name(results)
        assert name == "ez-appsec/rotate-aws-1-secrets"

    def test_multiple_types(self):
        results = [
            RotationResult(secret=_secret(rule_id="aws-access-key-id"), rotated=True, env_var_name="X"),
            RotationResult(
                secret=_secret(rule_id="github-pat", match="ghp_xxx", file="b.py"),
                rotated=True, env_var_name="Y",
            ),
        ]
        name = build_rotation_branch_name(results)
        assert "aws" in name
        assert "github_pat" in name
        assert "2-secrets" in name


class TestBuildRotationPrTitle:
    def test_format(self):
        results = [
            RotationResult(secret=_secret(), rotated=True, env_var_name="X"),
        ]
        title = build_rotation_pr_title(results)
        assert "rotate" in title
        assert "1" in title
        assert "aws" in title


class TestCreateRotationPr:
    @patch("ez_appsec.secret_rotator.subprocess.run")
    @patch("ez_appsec.secret_rotator.replace_hardcoded_secret")
    @patch("ez_appsec.fix_pr.subprocess.run")
    def test_creates_github_pr(self, mock_git_run, mock_replace, mock_sub_run):
        mock_replace.return_value = True
        mock_git_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        mock_sub_run.return_value = MagicMock(
            returncode=0, stdout="https://github.com/owner/repo/pull/99\n", stderr=""
        )

        results = [
            RotationResult(secret=_secret(), rotated=True, env_var_name="AWS_ACCESS_KEY_ID"),
        ]

        result = create_rotation_pr("owner/repo", "/tmp/repo", results,
                                    platform="github", token="fake")

        assert result["pr_url"] == "https://github.com/owner/repo/pull/99"
        assert result["files_modified"] == ["config.py"]

    @patch("ez_appsec.secret_rotator.replace_hardcoded_secret")
    def test_dry_run_skips_git(self, mock_replace):
        mock_replace.return_value = True

        results = [
            RotationResult(secret=_secret(), rotated=True, env_var_name="AWS_ACCESS_KEY_ID"),
        ]

        result = create_rotation_pr("owner/repo", "/tmp/repo", results, dry_run=True)

        assert result["dry_run"] is True
        assert result["pr_url"] is None
        assert result["files_modified"] == ["config.py"]

    @patch("ez_appsec.secret_rotator.replace_hardcoded_secret")
    def test_no_modifications_returns_error(self, mock_replace):
        mock_replace.return_value = False

        results = [
            RotationResult(secret=_secret(), rotated=True, env_var_name="AWS_ACCESS_KEY_ID"),
        ]

        result = create_rotation_pr("owner/repo", "/tmp/repo", results)
        assert result.get("error")
        assert result["pr_url"] is None

    @patch("ez_appsec.secret_rotator.subprocess.run")
    @patch("ez_appsec.secret_rotator.replace_hardcoded_secret")
    @patch("ez_appsec.fix_pr.subprocess.run")
    def test_creates_gitlab_mr(self, mock_git_run, mock_replace, mock_sub_run):
        mock_replace.return_value = True
        mock_git_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        mock_sub_run.return_value = MagicMock(
            returncode=0, stdout="https://gitlab.com/group/repo/-/merge_requests/5\n", stderr=""
        )

        results = [
            RotationResult(secret=_secret(), rotated=True, env_var_name="AWS_ACCESS_KEY_ID"),
        ]

        result = create_rotation_pr("12345", "/tmp/repo", results,
                                    platform="gitlab", token="glpat-xxx")

        assert result["mr_url"] == "https://gitlab.com/group/repo/-/merge_requests/5"


class TestSecretStores:
    def test_create_github_store(self):
        store = create_secret_store("github", repo="owner/repo", token="t")
        assert isinstance(store, GitHubActionsSecretStore)

    def test_create_gitlab_store(self):
        store = create_secret_store("gitlab", project_id="123", token="t")
        assert isinstance(store, GitLabCIVariableStore)

    def test_create_vault_store(self):
        store = create_secret_store("vault")
        assert isinstance(store, VaultSecretStore)

    def test_github_store_requires_repo(self):
        with pytest.raises(ValueError, match="--repo"):
            create_secret_store("github")

    def test_gitlab_store_requires_project_id(self):
        with pytest.raises(ValueError, match="--repo"):
            create_secret_store("gitlab")

    def test_unknown_store_raises(self):
        with pytest.raises(ValueError, match="Unknown"):
            create_secret_store("s3")

    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_github_store_write(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        store = GitHubActionsSecretStore("owner/repo", token="t")

        assert store.write("MY_SECRET", "value123") is True

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "gh" in args
        assert "secret" in args
        assert "set" in args
        assert "MY_SECRET" in args

    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_vault_store_write(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        store = VaultSecretStore(vault_addr="https://vault.example.com")

        assert store.write("my-secret", "value123") is True

        args = mock_run.call_args[0][0]
        assert "vault" in args
        assert "kv" in args
        assert "put" in args

    @patch("ez_appsec.secret_rotator.subprocess.run")
    def test_vault_store_no_addr(self, mock_run):
        store = VaultSecretStore(vault_addr="")
        assert store.write("x", "y") is False
        mock_run.assert_not_called()


class TestEndToEnd:
    """Integration-style tests with real files, mocked providers/git."""

    @patch("ez_appsec.secret_rotator.subprocess.run")
    @patch("ez_appsec.fix_pr.subprocess.run")
    def test_gitleaks_to_rotation_pr(self, mock_git_run, mock_sub_run, tmp_path):
        mock_git_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        mock_sub_run.return_value = MagicMock(
            returncode=0, stdout="https://github.com/owner/repo/pull/1\n", stderr=""
        )

        findings_file = tmp_path / "gitleaks.json"
        findings_file.write_text(json.dumps([
            {
                "RuleID": "aws-access-key-id",
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "File": "config.py",
                "StartLine": 3,
            },
        ]))

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "config.py").write_text(
            'import os\n\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )

        secrets = parse_gitleaks_findings(str(findings_file))
        assert len(secrets) == 1

        results = rotate_secrets(secrets, dry_run=True)
        assert len(results) == 1
        assert results[0].env_var_name == "AWS_ACCESS_KEY_ID"

        result = create_rotation_pr("owner/repo", str(repo_dir), results,
                                    platform="github", token="t")

        assert result["files_modified"] == ["config.py"]
        content = (repo_dir / "config.py").read_text()
        assert 'os.environ.get("AWS_ACCESS_KEY_ID")' in content
        assert "AKIAIOSFODNN7EXAMPLE" not in content

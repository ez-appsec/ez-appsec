"""Unit tests for PR/MR commenter functionality"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
from tempfile import NamedTemporaryFile

from ez_appsec.pr_commenter import (
    GitHubPRCommenter,
    GitLabMRCommenter,
    PRDiffParser,
    PRDiff,
    load_findings_from_json,
    _sarif_level_to_severity
)


class TestPRDiffParser:
    """Test diff parsing functionality"""

    def test_parse_unified_diff_basic(self):
        """Test parsing a basic unified diff"""
        diff_text = """diff --git a/file.py b/file.py
index 1234567..abcdef 100644
--- a/file.py
+++ b/file.py
@@ -1,3 +1,4 @@
 def old():
-    return "old"
+    return "new"
+    print("added")
"""
        result = PRDiffParser._parse_unified_diff(diff_text)

        assert 'file.py' in result
        assert len(result['file.py']) > 0

    def test_parse_unified_diff_multiple_files(self):
        """Test parsing diff with multiple files"""
        diff_text = """diff --git a/file1.py b/file1.py
index 1234567..abcdef 100644
--- a/file1.py
+++ b/file1.py
@@ -1,2 +1,3 @@
 line1
+added line
 line2
diff --git a/file2.py b/file2.py
index 1234567..abcdef 100644
--- a/file2.py
+++ b/file2.py
@@ -1,2 +1,3 @@
 def foo():
-    return "bar"
+    return "baz"
"""
        result = PRDiffParser._parse_unified_diff(diff_text)

        assert 'file1.py' in result
        assert 'file2.py' in result

    def test_parse_github_pr_diff_with_mock(self):
        """Test GitHub PR diff parsing with mocked subprocess"""
        diff_output = """diff --git a/test.py b/test.py
@@ -1,2 +1,3 @@
 x
+y
 z"""

        with patch('ez_appsec.pr_commenter.subprocess.run') as mock_run:
            # Mock the gh pr diff --json files command
            mock_run.side_effect = [
                MagicMock(stdout='[{"path": "test.py"}]', returncode=0),  # files command
                MagicMock(stdout=diff_output, returncode=0)  # diff command
            ]

            result = PRDiffParser.parse_github_pr_diff('owner/repo', 123, 'fake-token')

            assert isinstance(result, PRDiff)
            assert 'test.py' in result.files


class TestGitHubPRCommenter:
    """Test GitHub PR commenting functionality"""

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing"""
        return [
            {
                'title': 'Hardcoded secret',
                'description': 'Potential secret found',
                'file': 'config.py',
                'line': 10,
                'severity': 'critical',
                'scanner': 'gitleaks',
                'solution': 'Rotate the secret'
            },
            {
                'title': 'SQL injection',
                'description': 'Unsanitized user input',
                'file': 'database.py',
                'line': 25,
                'severity': 'high',
                'scanner': 'semgrep',
                'solution': 'Use parameterized queries'
            },
            {
                'title': 'Another issue in config.py',
                'description': 'Config issue',
                'file': 'config.py',
                'line': 15,
                'severity': 'medium',
                'scanner': 'gitleaks',
                'solution': 'Fix config'
            }
        ]

    def test_init_commenter(self):
        """Test GitHubPRCommenter initialization"""
        commenter = GitHubPRCommenter('owner/repo', 123, 'token')
        assert commenter.repo == 'owner/repo'
        assert commenter.pr_number == 123
        assert commenter.token == 'token'

    @patch('ez_appsec.pr_commenter.subprocess.run')
    def test_post_findings_filters_by_diff(self, mock_run, sample_findings):
        """Test that only findings on changed lines are posted"""
        # Mock diff to only include line 10 in config.py
        diff = PRDiff({'config.py': {10}, 'database.py': set()})

        # Mock successful comment posting
        mock_run.return_value = MagicMock(
            stdout='{"headRefOid": "abc123"}',
            returncode=0
        )

        with patch('ez_appsec.pr_commenter.urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"id": 12345}'
            mock_urlopen.return_value.__enter__.return_value = mock_response

            commenter = GitHubPRCommenter('owner/repo', 123, 'token')
            results = commenter.post_findings(sample_findings, diff)

            # Only the finding on line 10 should be posted
            assert results['posted'] == 1
            assert results['skipped'] == 2
            assert 'config.py' in results['files_commented']

    @patch('ez_appsec.pr_commenter.subprocess.run')
    def test_post_findings_groups_multiple_per_file(self, mock_run, sample_findings):
        """Test that multiple findings on the same file are grouped"""
        # Mock diff to include both lines in config.py
        diff = PRDiff({'config.py': {10, 15}, 'database.py': {25}})

        mock_run.return_value = MagicMock(
            stdout='{"headRefOid": "abc123"}',
            returncode=0
        )

        with patch('ez_appsec.pr_commenter.urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"id": 12345}'
            mock_urlopen.return_value.__enter__.return_value = mock_response

            commenter = GitHubPRCommenter('owner/repo', 123, 'token')
            results = commenter.post_findings(sample_findings, diff)

            # All findings should be posted
            assert results['posted'] == 3
            assert results['skipped'] == 0

    def test_build_comment_body(self):
        """Test comment body formatting"""
        commenter = GitHubPRCommenter('owner/repo', 123, 'token')

        findings = [
            {
                'title': 'Critical issue',
                'description': 'This is bad',
                'line': 10,
                'severity': 'critical',
                'scanner': 'test',
                'solution': 'Fix it'
            }
        ]

        body = commenter._build_comment_body(findings)

        assert '## Security Findings' in body
        assert '### CRITICAL' in body
        assert 'Critical issue' in body
        assert 'line 10' in body
        assert 'test' in body
        assert 'Fix it' in body
        assert 'ez-appsec' in body

    @patch('ez_appsec.pr_commenter.subprocess.run')
    @patch('ez_appsec.pr_commenter.urllib.request.urlopen')
    def test_post_inline_comment_api_call(self, mock_urlopen, mock_run):
        """Test that correct API endpoint is called"""
        mock_run.return_value = MagicMock(
            stdout='{"headRefOid": "abc123"}',
            returncode=0
        )

        mock_response = MagicMock()
        mock_response.read.return_value = b'{"id": 12345}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        commenter = GitHubPRCommenter('owner/repo', 123, 'token')
        comment_id = commenter._post_inline_comment('test.py', 10, 'Test comment')

        assert comment_id == 12345

        # Verify the request was made to the correct URL
        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert 'pulls/123/comments' in request.full_url
        assert request.headers['Authorization'] == 'token token'


class TestGitLabMRCommenter:
    """Test GitLab MR commenting functionality"""

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing"""
        return [
            {
                'title': 'Hardcoded secret',
                'description': 'Potential secret found',
                'file': 'config.py',
                'line': 10,
                'severity': 'critical',
                'scanner': 'gitleaks',
                'solution': 'Rotate the secret'
            },
            {
                'title': 'SQL injection',
                'description': 'Unsanitized user input',
                'file': 'database.py',
                'line': 25,
                'severity': 'high',
                'scanner': 'semgrep',
                'solution': 'Use parameterized queries'
            }
        ]

    def test_init_commenter(self):
        """Test GitLabMRCommenter initialization"""
        commenter = GitLabMRCommenter('123', 456, 'token', 'https://gitlab.com')
        assert commenter.project_id == '123'
        assert commenter.mr_iid == 456
        assert commenter.token == 'token'
        assert commenter.gitlab_url == 'https://gitlab.com'

    def test_post_findings_filters_by_diff(self, sample_findings):
        """Test that only findings on changed lines are posted"""
        # Mock diff to only include line 10
        diff = PRDiff({'config.py': {10}, 'database.py': set()})

        with patch('ez_appsec.pr_commenter.urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"id": 789, "notes": [{"id": 790}]}'
            mock_urlopen.return_value.__enter__.return_value = mock_response

            commenter = GitLabMRCommenter('123', 456, 'token')
            results = commenter.post_findings(sample_findings, diff)

            assert results['posted'] == 1
            assert results['skipped'] == 1

    @patch('ez_appsec.pr_commenter.urllib.request.urlopen')
    def test_post_diff_note_api_call(self, mock_urlopen):
        """Test that correct API endpoint is called"""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"id": 789, "notes": [{"id": 790}]}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        commenter = GitLabMRCommenter('123', 456, 'token')
        note_id = commenter._post_diff_note('test.py', 10, 'Test note')

        assert note_id == 790

        # Verify the request was made to the correct URL
        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert '/projects/123/merge_requests/456/discussions' in request.full_url
        assert request.get_header('Private-token') == 'token'

    def test_build_comment_body(self):
        """Test comment body formatting"""
        commenter = GitLabMRCommenter('123', 456, 'token')

        findings = [
            {
                'title': 'High severity issue',
                'description': 'This is bad',
                'line': 20,
                'severity': 'high',
                'scanner': 'semgrep',
                'solution': 'Fix it'
            }
        ]

        body = commenter._build_comment_body(findings)

        assert '## Security Findings' in body
        assert '### HIGH' in body
        assert 'High severity issue' in body
        assert 'line 20' in body
        assert 'semgrep' in body


class TestLoadFindings:
    """Test findings loading from JSON files"""

    def test_load_gitlab_format(self):
        """Test loading findings from GitLab format"""
        gitlab_data = {
            "version": "15.0.0",
            "vulnerabilities": [
                {
                    "id": "1",
                    "name": "Secret found",
                    "description": "AWS key exposed",
                    "severity": "critical",
                    "location": {
                        "file": "config.py",
                        "start_line": 10
                    },
                    "scanner": {
                        "id": "gitleaks",
                        "name": "Gitleaks"
                    },
                    "solution": "Rotate the key"
                }
            ]
        }

        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(gitlab_data, f)
            temp_path = f.name

        try:
            findings = load_findings_from_json(temp_path)

            assert len(findings) == 1
            assert findings[0]['title'] == 'Secret found'
            assert findings[0]['file'] == 'config.py'
            assert findings[0]['line'] == 10
            assert findings[0]['severity'] == 'critical'
        finally:
            os.unlink(temp_path)

    def test_load_sarif_format(self):
        """Test loading findings from SARIF format"""
        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test"}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection found"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "database.py"},
                                        "region": {"startLine": 25}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sarif_data, f)
            temp_path = f.name

        try:
            findings = load_findings_from_json(temp_path)

            assert len(findings) == 1
            assert findings[0]['title'] == 'sql-injection'
            assert findings[0]['file'] == 'database.py'
            assert findings[0]['line'] == 25
            assert findings[0]['severity'] == 'high'  # 'error' maps to 'high'
        finally:
            os.unlink(temp_path)

    def test_load_direct_list_format(self):
        """Test loading findings from direct list format"""
        findings_data = [
            {
                "title": "Issue 1",
                "description": "Test",
                "file": "test.py",
                "line": 5,
                "severity": "medium",
                "scanner": "test"
            }
        ]

        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(findings_data, f)
            temp_path = f.name

        try:
            findings = load_findings_from_json(temp_path)

            assert len(findings) == 1
            assert findings[0]['title'] == 'Issue 1'
        finally:
            os.unlink(temp_path)

    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file returns empty list"""
        findings = load_findings_from_json('/nonexistent/file.json')
        assert findings == []

    def test_load_invalid_json(self):
        """Test loading invalid JSON returns empty list"""
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json")
            temp_path = f.name

        try:
            findings = load_findings_from_json(temp_path)
            assert findings == []
        finally:
            os.unlink(temp_path)


class TestSarifLevelMapping:
    """Test SARIF level to severity conversion"""

    def test_sarif_error_to_high(self):
        """Test SARIF 'error' maps to 'high'"""
        assert _sarif_level_to_severity('error') == 'high'

    def test_sarif_warning_to_medium(self):
        """Test SARIF 'warning' maps to 'medium'"""
        assert _sarif_level_to_severity('warning') == 'medium'

    def test_sarif_note_to_low(self):
        """Test SARIF 'note' maps to 'low'"""
        assert _sarif_level_to_severity('note') == 'low'

    def test_sarif_unknown_to_medium(self):
        """Test unknown SARIF level maps to 'medium'"""
        assert _sarif_level_to_severity('unknown') == 'medium'

    def test_sarif_case_insensitive(self):
        """Test mapping is case insensitive"""
        assert _sarif_level_to_severity('ERROR') == 'high'
        assert _sarif_level_to_severity('Warning') == 'medium'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

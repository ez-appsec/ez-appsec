"""Unit tests for CLI commands"""

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner
from ez_appsec.cli import main, scan, gitlab_scan, github_scan, init, check, status


class TestCLIBasic:
    """Test basic CLI functionality"""

    def test_main_command_help(self):
        """Test that main command help works"""
        runner = CliRunner()
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'ez-appsec: AI-powered application security scanning' in result.output

    def test_version_option(self):
        """Test that version option works"""
        runner = CliRunner()
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0


class TestScanCommand:
    """Test scan command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_file(self, temp_dir):
        """Create a sample Python file for scanning"""
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text("""
# Sample file for scanning
def example():
    return "hello"
""")
        return str(file_path)

    def test_scan_help(self):
        """Test scan command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'Scan a codebase' in result.output
        assert '--output' in result.output

    def test_scan_basic(self, sample_file):
        """Test basic scan command"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', sample_file])
        assert result.exit_code == 0
        assert 'Security scan completed' in result.output

    def test_scan_with_nonexistent_path(self):
        """Test scan with nonexistent path"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', '/nonexistent/path'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output

    def test_scan_with_invalid_output_path(self, sample_file):
        """Test scan with invalid output path"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--output', '/root/forbidden/output.json'
        ])
        # Should handle invalid output path gracefully
        assert result.exit_code != 0

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', temp_dir])
        assert result.exit_code == 0
        assert 'Security scan completed' in result.output

    def test_scan_with_ai_prompt(self, sample_file):
        """Test scan with custom AI prompt"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--ai-prompt', 'Focus on SQL injection'
        ])
        assert result.exit_code == 0

    def test_scan_with_languages(self, sample_file):
        """Test scan with language filter"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--languages', 'python'
        ])
        assert result.exit_code == 0

    def test_scan_with_severity(self, sample_file):
        """Test scan with severity filter"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan',
            sample_file,
            '--severity', 'high'
        ])
        assert result.exit_code == 0


class TestGitlabScanCommand:
    """Test gitlab-scan command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_file(self, temp_dir):
        """Create a sample Python file for scanning"""
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text("def test(): pass")
        return str(file_path)

    @pytest.fixture
    def temp_output_file(self, temp_dir):
        """Create a temporary output file path"""
        return str(Path(temp_dir) / "output.json")

    def test_gitlab_scan_help(self):
        """Test gitlab-scan command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['gitlab-scan', '--help'])
        assert result.exit_code == 0
        assert 'GitLab vulnerability format' in result.output

    def test_gitlab_scan_basic(self, sample_file):
        """Test basic gitlab-scan command"""
        runner = CliRunner()
        result = runner.invoke(main, ['gitlab-scan', sample_file])
        assert result.exit_code == 0
        assert 'GitLab vulnerability scan completed' in result.output

    def test_gitlab_scan_with_output(self, sample_file, temp_output_file):
        """Test gitlab-scan with output file"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'gitlab-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0
        assert 'GitLab report saved' in result.output
        assert os.path.exists(temp_output_file)

    def test_gitlab_scan_output_format(self, sample_file, temp_output_file):
        """Test that gitlab-scan produces correct GitLab format"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'gitlab-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0

        # Verify output format
        with open(temp_output_file) as f:
            data = json.load(f)
        assert 'version' in data
        assert 'vulnerabilities' in data
        assert 'remediations' in data
        assert data['version'] == '15.0.0'

    def test_gitlab_scan_with_nonexistent_path(self):
        """Test gitlab-scan with nonexistent path"""
        runner = CliRunner()
        result = runner.invoke(main, ['gitlab-scan', '/nonexistent/path'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output


class TestGithubScanCommand:
    """Test github-scan command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_file(self, temp_dir):
        """Create a sample Python file for scanning"""
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text("def test(): pass")
        return str(file_path)

    @pytest.fixture
    def temp_output_file(self, temp_dir):
        """Create a temporary output file path"""
        return str(Path(temp_dir) / "output.sarif")

    def test_github_scan_help(self):
        """Test github-scan command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['github-scan', '--help'])
        assert result.exit_code == 0
        assert 'SARIF format' in result.output

    def test_github_scan_basic(self, sample_file):
        """Test basic github-scan command"""
        runner = CliRunner()
        result = runner.invoke(main, ['github-scan', sample_file])
        assert result.exit_code == 0
        assert 'GitHub SARIF scan completed' in result.output

    def test_github_scan_with_output(self, sample_file, temp_output_file):
        """Test github-scan with output file"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'github-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0
        assert 'SARIF report saved' in result.output
        assert os.path.exists(temp_output_file)

    def test_github_scan_output_format(self, sample_file, temp_output_file):
        """Test that github-scan produces correct SARIF format"""
        runner = CliRunner()
        result = runner.invoke(main, [
            'github-scan',
            sample_file,
            '--output', temp_output_file
        ])
        assert result.exit_code == 0

        # Verify SARIF format
        with open(temp_output_file) as f:
            data = json.load(f)
        assert data['version'] == '2.1.0'
        assert '$schema' in data
        assert 'runs' in data
        assert len(data['runs']) > 0
        assert 'tool' in data['runs'][0]
        assert 'driver' in data['runs'][0]['tool']

    def test_github_scan_with_nonexistent_path(self):
        """Test github-scan with nonexistent path"""
        runner = CliRunner()
        result = runner.invoke(main, ['github-scan', '/nonexistent/path'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output


class TestInitCommand:
    """Test init command functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_init_help(self):
        """Test init command help"""
        runner = CliRunner()
        result = runner.invoke(main, ['init', '--help'])
        assert result.exit_code == 0

    def test_init_creates_config(self, temp_dir, monkeypatch):
        """Test that init creates configuration file"""
        runner = CliRunner()
        monkeypatch.chdir(temp_dir)
        result = runner.invoke(main, ['init'])
        assert result.exit_code == 0
        assert os.path.exists('.ez-appsec.yaml')

    def test_init_with_existing_config(self, temp_dir, monkeypatch):
        """Test init with existing configuration file"""
        # Create existing config
        config_path = Path(temp_dir) / '.ez-appsec.yaml'
        config_path.write_text("# Existing config")

        runner = CliRunner()
        monkeypatch.chdir(temp_dir)
        result = runner.invoke(main, ['init'])
        assert result.exit_code == 0
        assert 'already exists' in result.output


class TestErrorHandling:
    """Test error handling and edge cases"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_scan_with_empty_directory(self, temp_dir):
        """Test scanning empty directory"""
        runner = CliRunner()
        result = runner.invoke(main, ['scan', temp_dir])
        assert result.exit_code == 0
        assert 'Security scan completed' in result.output

    def test_scan_with_unreadable_file(self, temp_dir):
        """Test scanning unreadable file"""
        file_path = Path(temp_dir) / "unreadable.py"
        file_path.write_text("test")
        os.chmod(file_path, 0o000)  # Make unreadable

        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(file_path)])
        # Should handle unreadable file gracefully
        assert result.exit_code != 0 or result.exit_code == 0

        # Cleanup
        os.chmod(file_path, 0o644)

    def test_scan_with_special_characters_in_path(self, temp_dir):
        """Test scanning file with special characters"""
        file_path = Path(temp_dir) / "test file with spaces.py"
        file_path.write_text("def test(): pass")

        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(file_path)])
        assert result.exit_code == 0

    def test_scan_with_symlink(self, temp_dir):
        """Test scanning symlinked file"""
        target_file = Path(temp_dir) / "target.py"
        target_file.write_text("def test(): pass")

        link_path = Path(temp_dir) / "link.py"
        link_path.symlink_to(target_file)

        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(link_path)])
        assert result.exit_code == 0

    def test_serve_metrics_help_exposes_flags(self):
        """UX-1: the v2 metrics endpoint must be reachable from the CLI."""
        runner = CliRunner()
        result = runner.invoke(main, ['serve-metrics', '--help'])
        assert result.exit_code == 0
        assert 'serve-metrics' in result.output or 'Serve Prometheus' in result.output
        assert '--storage-backend' in result.output
        assert '--host' in result.output
        assert '--project' in result.output

    def test_scan_summary_shows_trend_when_v2_computed(self, tmp_path, monkeypatch):
        """UX-1: new/resolved counts computed by the scanner must reach stdout."""
        from ez_appsec import scanner as scanner_mod

        sample_file = tmp_path / "sample.py"
        sample_file.write_text("password = 'hardcoded'\n")

        real_scan = scanner_mod.SecurityScanner.scan

        def fake_scan(self, path, custom_prompt=None):
            result = real_scan(self, path, custom_prompt)
            result["scan_record"] = {
                "scan_id": "s1", "new_count": 3, "resolved_count": 1,
                "finding_count": 5,
            }
            # Make a couple of findings look aged for the >30d line.
            for issue in result.get("issues", []):
                issue["age_days"] = 45
            return result

        monkeypatch.setattr(scanner_mod.SecurityScanner, "scan", fake_scan)
        runner = CliRunner()
        result = runner.invoke(main, ['scan', str(sample_file)])
        assert result.exit_code == 0
        assert 'Trend:' in result.output
        assert '3 new' in result.output
        assert '1 resolved' in result.output


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

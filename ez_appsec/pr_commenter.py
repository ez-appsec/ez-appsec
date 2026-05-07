"""PR/MR inline comment poster for GitHub and GitLab

Posts security findings as inline review comments on pull requests and merge requests
so developers see findings during code review without context switching.
"""

import json
import os
import subprocess
import logging
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class PRDiff:
    """Represents a parsed PR/MR diff with changed files and line ranges"""
    files: Dict[str, Set[int]]  # file_path -> set of changed line numbers


class PRDiffParser:
    """Parses PR/MR diffs to identify which lines were changed"""

    @staticmethod
    def parse_github_pr_diff(repo: str, pr_number: int, github_token: str) -> PRDiff:
        """Parse GitHub PR diff to get changed lines

        Args:
            repo: Repository in format 'owner/repo'
            pr_number: Pull request number
            github_token: GitHub access token

        Returns:
            PRDiff with changed files and line numbers
        """
        files = defaultdict(set)

        try:
            # Use gh CLI to get the PR diff
            cmd = [
                "gh", "pr", "diff", str(pr_number),
                "--repo", repo,
                "--json", "files"  # Get file list first
            ]

            result = subprocess.run(
                cmd,
                env={**os.environ, "GH_TOKEN": github_token},
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.warning(f"Failed to get PR files: {result.stderr}")
                return PRDiff(dict(files))

            files_data = json.loads(result.stdout) if result.stdout.strip() else []
            changed_files = [f["path"] for f in files_data if f.get("path")]

            # Now get the actual diff to parse line numbers
            cmd = [
                "gh", "pr", "diff", str(pr_number),
                "--repo", repo
            ]

            result = subprocess.run(
                cmd,
                env={**os.environ, "GH_TOKEN": github_token},
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                files.update(PRDiffParser._parse_unified_diff(result.stdout))

        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Error parsing GitHub PR diff: {e}")

        return PRDiff(dict(files))

    @staticmethod
    def parse_gitlab_mr_diff(project_id: str, mr_iid: int, gitlab_token: str, gitlab_url: str = "https://gitlab.com") -> PRDiff:
        """Parse GitLab MR diff to get changed lines

        Args:
            project_id: Project ID (numeric)
            mr_iid: Merge request IID
            gitlab_token: GitLab access token
            gitlab_url: GitLab base URL

        Returns:
            PRDiff with changed files and line numbers
        """
        files = defaultdict(set)

        try:
            # Use glab CLI or curl to get MR diff
            # Try glab first
            cmd = [
                "glab", "mr", "diff", str(mr_iid),
                "--project", project_id,
                "--web", gitlab_url
            ]

            result = subprocess.run(
                cmd,
                env={**os.environ, "GITLAB_TOKEN": gitlab_token},
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout:
                files.update(PRDiffParser._parse_unified_diff(result.stdout))

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Error parsing GitLab MR diff: {e}")

        return PRDiff(dict(files))

    @staticmethod
    def _parse_unified_diff(diff_text: str) -> Dict[str, Set[int]]:
        """Parse unified diff format to extract changed line numbers per file

        Args:
            diff_text: Unified diff output

        Returns:
            Dictionary mapping file paths to sets of changed line numbers
        """
        files = defaultdict(set)
        current_file = None
        current_hunk_start = 0
        current_hunk_lines_added = 0

        for line in diff_text.split('\n'):
            # File header
            if line.startswith('diff --git'):
                parts = line.split()
                if len(parts) >= 4:
                    # Get the new file path (b/ prefix)
                    file_path = parts[3][2:] if parts[3].startswith('b/') else parts[3]
                    current_file = file_path

            # Hunk header
            elif line.startswith('@@') and current_file:
                # Parse: @@ -old_start,old_count +new_start,new_count @@
                try:
                    hunk_part = line.split('@@')[1].strip()
                    new_part = hunk_part.split('+')[1].split('@@')[0] if '+' in hunk_part else '1,0'
                    if ',' in new_part:
                        current_hunk_start = int(new_part.split(',')[0])
                        current_hunk_lines_added = int(new_part.split(',')[1])
                    else:
                        current_hunk_start = int(new_part)
                        current_hunk_lines_added = 0
                except (IndexError, ValueError):
                    current_hunk_start = 1
                    current_hunk_lines_added = 0

            # Added lines
            elif line.startswith('+') and not line.startswith('++') and current_file:
                # Calculate which line number this corresponds to
                # In the new file, line numbers start at hunk_start and increment
                # We need to count how many '+' lines we've seen in this hunk
                lines_before = sum(1 for l in line.split('\n')[:line.split('\n').index(line)] if l.startswith('+') and not l.startswith('++')) if '\n' in line else 0
                line_num = current_hunk_start + len(files[current_file]) % current_hunk_lines_added
                files[current_file].add(line_num)

        return dict(files)


class GitHubPRCommenter:
    """Posts inline comments on GitHub pull requests"""

    def __init__(self, repo: str, pr_number: int, github_token: str):
        """Initialize GitHub PR commenter

        Args:
            repo: Repository in format 'owner/repo'
            pr_number: Pull request number
            github_token: GitHub access token
        """
        self.repo = repo
        self.pr_number = pr_number
        self.token = github_token

    def post_findings(self, findings: List[Dict[str, Any]], diff: Optional[PRDiff] = None) -> Dict[str, Any]:
        """Post findings as inline review comments

        Only comments on lines that are changed in the diff.

        Args:
            findings: List of finding dictionaries from scan
            diff: PRDiff with changed lines (if None, will fetch)

        Returns:
            Dict with posted comment info
        """
        if diff is None:
            diff = PRDiffParser.parse_github_pr_diff(self.repo, self.pr_number, self.token)

        # Group findings by file
        findings_by_file = defaultdict(list)
        for finding in findings:
            file_path = finding.get('file', finding.get('file_name', ''))
            if file_path:
                findings_by_file[file_path].append(finding)

        # Post one comment thread per file with multiple findings
        results = {
            "posted": 0,
            "skipped": 0,
            "files_commented": []
        }

        for file_path, file_findings in findings_by_file.items():
            # Filter findings to only those on changed lines
            changed_lines = diff.files.get(file_path, set())

            if not changed_lines:
                results["skipped"] += len(file_findings)
                continue

            # Find findings that are on changed lines
            relevant_findings = [
                f for f in file_findings
                if int(f.get('line', f.get('start_line', 0))) in changed_lines
            ]
            skipped_in_file = len(file_findings) - len(relevant_findings)

            if not relevant_findings:
                results["skipped"] += len(file_findings)
                continue

            results["skipped"] += skipped_in_file

            # Get the first changed line for the comment position
            first_line = min(int(f.get('line', f.get('start_line', 1))) for f in relevant_findings)

            # Build comment body with all findings
            comment_body = self._build_comment_body(relevant_findings)

            # Post the comment
            comment_id = self._post_inline_comment(file_path, first_line, comment_body)

            if comment_id:
                results["posted"] += len(relevant_findings)
                results["files_commented"].append(file_path)
            else:
                results["skipped"] += len(relevant_findings)

        return results

    def _build_comment_body(self, findings: List[Dict[str, Any]]) -> str:
        """Build markdown comment body from findings

        Args:
            findings: List of finding dictionaries

        Returns:
            Markdown formatted comment body
        """
        lines = ["## Security Findings", ""]

        # Group by severity
        by_severity = defaultdict(list)
        for f in findings:
            severity = f.get('severity', 'unknown').upper()
            by_severity[severity].append(f)

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity not in by_severity:
                continue

            lines.append(f"### {severity}")
            lines.append("")

            for f in by_severity[severity]:
                title = f.get('title', f.get('type', 'Security Issue'))
                description = f.get('description', 'No description')
                line_num = f.get('line', f.get('start_line', '?'))
                scanner = f.get('scanner', 'unknown')
                solution = f.get('solution', '')

                lines.append(f"**{title}** (line {line_num})")
                lines.append(f"- *Scanner*: {scanner}")
                lines.append(f"- *Description*: {description}")
                if solution:
                    lines.append(f"- *Fix*: {solution}")
                lines.append("")

        lines.append("---")
        lines.append("*Posted by ez-appsec*")

        return "\n".join(lines)

    def _post_inline_comment(self, file_path: str, line: int, body: str) -> Optional[str]:
        """Post an inline review comment

        Args:
            file_path: Path to the file in the repo
            line: Line number to comment on
            body: Comment body (markdown)

        Returns:
            Comment ID if successful, None otherwise
        """
        try:
            # Use gh CLI to create a review comment
            # We'll use the API directly for more control
            # Get the PR's latest commit SHA
            cmd = [
                "gh", "pr", "view", str(self.pr_number),
                "--repo", self.repo,
                "--json", "headRefOid"
            ]
            result = subprocess.run(
                cmd,
                env={**os.environ, "GH_TOKEN": self.token},
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.error(f"Failed to get PR head SHA: {result.stderr}")
                return None

            pr_data = json.loads(result.stdout)
            commit_sha = pr_data.get('headRefOid')

            if not commit_sha:
                logger.error("No commit SHA found for PR")
                return None

            # Create the review comment via API
            api_url = f"https://api.github.com/repos/{self.repo}/pulls/{self.pr_number}/comments"

            comment_data = {
                "body": body,
                "commit_id": commit_sha,
                "path": file_path,
                "position": line,
                "line": line
            }

            req = urllib.request.Request(
                api_url,
                data=json.dumps(comment_data).encode('utf-8'),
                headers={
                    'Authorization': f'token {self.token}',
                    'Accept': 'application/vnd.github.v3+json',
                    'Content-Type': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                return response_data.get('id')

        except Exception as e:
            logger.error(f"Failed to post inline comment: {e}")
            return None


class GitLabMRCommenter:
    """Posts inline comments on GitLab merge requests"""

    def __init__(self, project_id: str, mr_iid: int, gitlab_token: str, gitlab_url: str = "https://gitlab.com"):
        """Initialize GitLab MR commenter

        Args:
            project_id: Project ID (numeric or encoded path)
            mr_iid: Merge request IID
            gitlab_token: GitLab access token
            gitlab_url: GitLab base URL
        """
        self.project_id = project_id
        self.mr_iid = mr_iid
        self.token = gitlab_token
        self.gitlab_url = gitlab_url.rstrip('/')

    def post_findings(self, findings: List[Dict[str, Any]], diff: Optional[PRDiff] = None) -> Dict[str, Any]:
        """Post findings as inline diff notes

        Only comments on lines that are changed in the diff.

        Args:
            findings: List of finding dictionaries from scan
            diff: PRDiff with changed lines (if None, will fetch)

        Returns:
            Dict with posted comment info
        """
        if diff is None:
            diff = PRDiffParser.parse_gitlab_mr_diff(
                self.project_id, self.mr_iid, self.token, self.gitlab_url
            )

        # Group findings by file
        findings_by_file = defaultdict(list)
        for finding in findings:
            file_path = finding.get('file', finding.get('file_name', ''))
            if file_path:
                findings_by_file[file_path].append(finding)

        # Post one comment thread per file with multiple findings
        results = {
            "posted": 0,
            "skipped": 0,
            "files_commented": []
        }

        for file_path, file_findings in findings_by_file.items():
            # Filter findings to only those on changed lines
            changed_lines = diff.files.get(file_path, set())

            if not changed_lines:
                results["skipped"] += len(file_findings)
                continue

            # Find findings that are on changed lines
            relevant_findings = [
                f for f in file_findings
                if int(f.get('line', f.get('start_line', 0))) in changed_lines
            ]

            if not relevant_findings:
                results["skipped"] += len(file_findings)
                continue

            # Get the first changed line for the comment position
            first_line = min(int(f.get('line', f.get('start_line', 1))) for f in relevant_findings)

            # Build comment body with all findings
            comment_body = self._build_comment_body(relevant_findings)

            # Post the comment
            note_id = self._post_diff_note(file_path, first_line, comment_body)

            if note_id:
                results["posted"] += len(relevant_findings)
                results["files_commented"].append(file_path)
            else:
                results["skipped"] += len(relevant_findings)

        return results

    def _build_comment_body(self, findings: List[Dict[str, Any]]) -> str:
        """Build markdown comment body from findings

        Args:
            findings: List of finding dictionaries

        Returns:
            Markdown formatted comment body
        """
        lines = ["## Security Findings", ""]

        # Group by severity
        by_severity = defaultdict(list)
        for f in findings:
            severity = f.get('severity', 'unknown').upper()
            by_severity[severity].append(f)

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity not in by_severity:
                continue

            lines.append(f"### {severity}")
            lines.append("")

            for f in by_severity[severity]:
                title = f.get('title', f.get('type', 'Security Issue'))
                description = f.get('description', 'No description')
                line_num = f.get('line', f.get('start_line', '?'))
                scanner = f.get('scanner', 'unknown')
                solution = f.get('solution', '')

                lines.append(f"**{title}** (line {line_num})")
                lines.append(f"- *Scanner*: {scanner}")
                lines.append(f"- *Description*: {description}")
                if solution:
                    lines.append(f"- *Fix*: {solution}")
                lines.append("")

        lines.append("---")
        lines.append("*Posted by ez-appsec*")

        return "\n".join(lines)

    def _post_diff_note(self, file_path: str, line: int, body: str) -> Optional[int]:
        """Post a diff note on the merge request

        Args:
            file_path: Path to the file in the repo
            line: Line number to comment on
            body: Comment body (markdown)

        Returns:
            Note ID if successful, None otherwise
        """
        try:
            # URL-encode the project ID (may contain slashes)
            encoded_project_id = urllib.parse.quote(self.project_id, safe='')

            api_url = f"{self.gitlab_url}/api/v4/projects/{encoded_project_id}/merge_requests/{self.mr_iid}/discussions"

            comment_data = {
                "body": body,
                "position": {
                    "position_type": "text",
                    "base_sha": "HEAD",  # Will be set by GitLab
                    "head_sha": "HEAD",  # Will be set by GitLab
                    "start_sha": "HEAD",  # Will be set by GitLab
                    "new_path": file_path,
                    "new_line": line
                }
            }

            req = urllib.request.Request(
                api_url,
                data=json.dumps(comment_data).encode('utf-8'),
                headers={
                    'PRIVATE-TOKEN': self.token,
                    'Content-Type': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                # Return the ID of the first note in the discussion
                notes = response_data.get('notes', [])
                if notes:
                    return int(notes[0].get('id', 0))
                # Discussion ID as fallback
                return int(response_data.get('id', 0))

        except Exception as e:
            logger.error(f"Failed to post GitLab diff note: {e}")
            return None


def load_findings_from_json(findings_path: str) -> List[Dict[str, Any]]:
    """Load findings from a vulnerabilities.json file

    Args:
        findings_path: Path to the JSON file

    Returns:
        List of finding dictionaries
    """
    try:
        with open(findings_path, 'r') as f:
            data = json.load(f)

        # Handle different output formats
        if 'vulnerabilities' in data:
            # GitLab format
            vulns = data['vulnerabilities']
            findings = []
            for vuln in vulns:
                location = vuln.get('location', {})
                findings.append({
                    'title': vuln.get('name', 'Unknown'),
                    'description': vuln.get('description', vuln.get('message', '')),
                    'file': location.get('file', 'unknown'),
                    'line': location.get('start_line', 1),
                    'severity': vuln.get('severity', 'medium'),
                    'scanner': vuln.get('scanner', {}).get('name', 'unknown'),
                    'solution': vuln.get('solution', ''),
                })
            return findings
        elif 'runs' in data:
            # SARIF format
            findings = []
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    locations = result.get('locations', [])
                    if locations:
                        phys_loc = locations[0].get('physicalLocation', {})
                        file_path = phys_loc.get('artifactLocation', {}).get('uri', 'unknown')
                        region = phys_loc.get('region', {})
                        line = region.get('startLine', 1)

                        findings.append({
                            'title': result.get('ruleId', 'Unknown'),
                            'description': result.get('message', {}).get('text', ''),
                            'file': file_path,
                            'line': line,
                            'severity': _sarif_level_to_severity(result.get('level', 'warning')),
                            'scanner': 'sarif',
                            'solution': '',
                        })
            return findings
        else:
            # Direct issues list
            return data if isinstance(data, list) else []

    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error loading findings from {findings_path}: {e}")
        return []


def _sarif_level_to_severity(level: str) -> str:
    """Convert SARIF level to severity string"""
    mapping = {
        'error': 'high',
        'warning': 'medium',
        'note': 'low'
    }
    return mapping.get(level.lower(), 'medium')

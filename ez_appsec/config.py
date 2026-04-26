"""Configuration management for ez-appsec"""

from datetime import datetime
from fnmatch import fnmatch
from typing import List, Optional, Union
from pathlib import Path
from pydantic import BaseModel, Field, field_validator

import yaml


class IgnoreRule(BaseModel):
    """Single ignore rule for suppressing findings"""

    rule_id: Optional[str] = None
    file_path: Optional[str] = None
    message: Optional[str] = None
    cve_id: Optional[str] = None
    permanent: bool = False
    until: Optional[str] = None
    reason: str = ""

    @field_validator("until")
    @classmethod
    def validate_date_format(cls, v):
        """Validate ISO date format for until field"""
        if v is None:
            return v
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError(f"'until' must be in ISO format (YYYY-MM-DD), got: {v}")
        return v

    class Config:
        arbitrary_types_allowed = True

    def is_active(self) -> bool:
        """Check if this ignore rule is currently active"""
        if self.permanent:
            return True
        if self.until:
            until_date = datetime.fromisoformat(self.until)
            return datetime.now() < until_date
        return False

    def matches(self, finding: dict) -> bool:
        """Check if this ignore rule matches a finding"""
        if not self.is_active():
            return False

        # Match by rule ID
        if self.rule_id:
            finding_rule_id = finding.get("rule_id") or finding.get("id") or ""
            if self.rule_id == finding_rule_id:
                return True

        # Match by CVE ID
        if self.cve_id:
            finding_cve = finding.get("cve_id") or ""
            if self.cve_id == finding_cve:
                return True

        # Match by file path (glob pattern)
        if self.file_path:
            finding_file = finding.get("file") or finding.get("location", {}).get("file", "")
            if finding_file and fnmatch(finding_file, self.file_path):
                return True

        # Match by message substring
        if self.message:
            finding_msg = finding.get("message") or finding.get("description") or ""
            if self.message.lower() in finding_msg.lower():
                return True

        return False


class Config(BaseModel):
    """Configuration for security scanning"""

    languages: Optional[List[str]] = None
    severity: str = "all"
    output_file: Optional[str] = None
    ai_model: str = "gpt-4"
    ai_temperature: float = 0.5
    ignore_rules: List[IgnoreRule] = Field(default_factory=list)

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_file(cls, path: str = ".ez-appsec.yaml") -> "Config":
        """Load configuration from YAML file"""
        config_path = Path(path)

        if not config_path.exists():
            return cls()

        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        # Parse ignore rules if present
        ignore_data = data.pop("ignore", [])
        if isinstance(ignore_data, list):
            ignore_rules = []
            for item in ignore_data:
                if isinstance(item, dict):
                    ignore_rules.append(IgnoreRule(**item))
            data["ignore_rules"] = ignore_rules

        return cls(**data)

    def to_dict(self) -> dict:
        """Convert configuration to dictionary"""
        return self.model_dump(exclude_none=True)

    def get_matching_ignore_rule(self, finding: dict) -> Optional[IgnoreRule]:
        """Find an ignore rule that matches the given finding"""
        for rule in self.ignore_rules:
            if rule.matches(finding):
                return rule
        return None

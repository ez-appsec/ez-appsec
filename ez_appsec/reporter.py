"""Integration with reporting formats"""

import json
from pathlib import Path
from typing import Dict, List, Any


class Reporter:
    """Generate reports in various formats"""
    
    @staticmethod
    def to_json(results: Dict[str, Any], file_path: str) -> None:
        """Export results to JSON"""
        with open(file_path, "w") as f:
            json.dump(results, f, indent=2)
    
    @staticmethod
    def to_sarif(results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert to SARIF format (GitHub/GitLab compatible)"""
        runs = []
        
        for issue in results.get("issues", []):
            runs.append({
                "ruleId": issue.get("type", "UNKNOWN"),
                "message": {
                    "text": issue.get("title", "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": issue.get("file", "")
                            },
                            "region": {
                                "startLine": issue.get("line", 1)
                            }
                        }
                    }
                ],
                "level": issue.get("severity", "note").lower()
            })
        
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ez-appsec",
                            "version": "0.1.0"
                        }
                    },
                    "results": runs
                }
            ]
        }

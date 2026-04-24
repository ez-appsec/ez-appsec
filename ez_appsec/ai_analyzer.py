"""AI-powered security analysis using LLMs"""

import os
from typing import Dict, List, Any
from pathlib import Path
from ez_appsec.config import Config


class AIAnalyzer:
    """Analyze security issues using AI and provide remediation suggestions"""
    
    def __init__(self, config: Config):
        self.config = config
        self.model = config.ai_model
        self.temperature = config.ai_temperature
        
        # Check for API key
        self.api_key = os.getenv("OPENAI_API_KEY")
    
    def analyze(
        self,
        issues: List[Dict[str, Any]],
        path: Path,
        custom_prompt: str = None
    ) -> Dict[str, Any]:
        """Analyze detected issues using AI and enhance with remediation"""
        
        if not self.api_key:
            return {
                "enhanced_issues": issues,
                "message": "OPENAI_API_KEY not set. Install OpenAI provider for AI analysis."
            }
        
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            
            enhanced_issues = []
            
            for issue in issues:
                prompt = custom_prompt or self._build_prompt(issue, path)
                
                response = client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    timeout=30,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a security expert. Analyze the security issue and provide remediation guidance."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )
                
                analysis = response.choices[0].message.content
                enhanced_issue = issue.copy()
                enhanced_issue["ai_analysis"] = analysis
                enhanced_issue["remediation"] = self._extract_remediation(analysis)
                
                enhanced_issues.append(enhanced_issue)
            
            return {"enhanced_issues": enhanced_issues}
            
        except ImportError:
            return {
                "enhanced_issues": issues,
                "message": "OpenAI library not installed. Install with: pip install openai"
            }
        except Exception as e:
            return {
                "enhanced_issues": issues,
                "error": str(e)
            }
    
    def _build_prompt(self, issue: Dict[str, Any], path: Path) -> str:
        """Build AI prompt for issue analysis"""
        return f"""
Security Issue Found:
Type: {issue.get('type')}
Title: {issue.get('title')}
Description: {issue.get('description')}
File: {issue.get('file')}
Severity: {issue.get('severity')}

Please provide:
1. A brief explanation of why this is a security risk
2. Step-by-step remediation guidance
3. Code example fix (if applicable)
"""
    
    def _extract_remediation(self, analysis: str) -> str:
        """Extract remediation steps from AI analysis"""
        lines = analysis.split("\n")
        remediation = []
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ["step", "fix", "remediation", "change"]):
                remediation.append(line.strip())
        
        return "\n".join(remediation[:3]) if remediation else "See AI analysis above"

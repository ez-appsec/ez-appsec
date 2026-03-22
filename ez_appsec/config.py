"""Configuration management for ez-appsec"""

from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
import yaml


class Config(BaseModel):
    """Configuration for security scanning"""
    
    languages: Optional[List[str]] = None
    severity: str = "all"
    output_file: Optional[str] = None
    ai_model: str = "gpt-4"
    ai_temperature: float = 0.5
    
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
        
        return cls(**data)
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary"""
        return self.model_dump(exclude_none=True)

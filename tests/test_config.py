"""Tests for configuration"""

import pytest
from ez_appsec.config import Config


def test_default_config():
    config = Config()
    assert config.severity == "all"
    assert config.ai_model == "gpt-4"
    assert config.ai_temperature == 0.5


def test_config_with_languages():
    config = Config(languages=["python", "javascript"])
    assert config.languages == ["python", "javascript"]


def test_config_severity():
    config = Config(severity="high")
    assert config.severity == "high"

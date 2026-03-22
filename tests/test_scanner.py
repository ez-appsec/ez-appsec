"""Tests for the security scanner"""

import pytest
from pathlib import Path
from ez_appsec.scanner import SecurityScanner
from ez_appsec.config import Config


@pytest.fixture
def test_config():
    return Config(severity="all")


@pytest.fixture
def scanner(test_config):
    return SecurityScanner(test_config)


def test_scanner_initialization(scanner):
    """Test scanner initializes correctly"""
    assert scanner is not None
    assert scanner.sast is not None
    assert scanner.secrets is not None
    assert scanner.dependencies is not None

"""Tests for detectors"""

import pytest
from pathlib import Path
from ez_appsec.detectors import SastDetector, SecretsDetector, DependencyDetector


def test_sast_detector_initialization():
    detector = SastDetector()
    assert detector is not None
    assert len(detector.PATTERNS) > 0


def test_secrets_detector_patterns():
    detector = SecretsDetector()
    assert "api_key" in detector.PATTERNS
    assert "private_key" in detector.PATTERNS
    assert "aws_key" in detector.PATTERNS


def test_dependency_detector_initialization():
    detector = DependencyDetector()
    assert detector is not None

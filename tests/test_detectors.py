"""Tests for detectors"""

import pytest
from pathlib import Path
from ez_appsec.detectors import SastDetector, SecretsDetector, DependencyDetector


def test_sast_detector_initialization():
    detector = SastDetector()
    assert detector is not None
    assert hasattr(detector, "detect")


def test_secrets_detector_patterns():
    detector = SecretsDetector()
    assert detector is not None
    assert hasattr(detector, "detect")


def test_dependency_detector_initialization():
    detector = DependencyDetector()
    assert detector is not None

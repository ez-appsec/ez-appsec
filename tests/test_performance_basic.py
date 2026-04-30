"""Basic performance testing for ez-appsec scanner (no external dependencies)

Measures scan time and scalability across codebase sizes.
"""

import pytest
import time
import tempfile
from pathlib import Path
from ez_appsec.config import Config
from ez_appsec.scanner import SecurityScanner


@pytest.fixture
def test_config():
    """Test configuration optimized for performance tests"""
    config = Config()
    config.severity = "medium"
    return config


def _create_test_files(base_dir: str, file_count: int, lines_per_file: int):
    """Helper to create test codebase files"""
    base_path = Path(base_dir)

    for i in range(file_count):
        file_path = base_path / f"test_file_{i}.py"
        with open(file_path, 'w') as f:
            f.write(f"# Test file {i}\n")
            f.write("def test_function():\n")
            f.write('    """Test function"""\n')
            for j in range(lines_per_file - 5):
                f.write(f"    x_{j} = {j}\n")


@pytest.mark.performance
class TestScanPerformanceBasic:
    """Basic performance tests without external dependencies"""

    def _create_test_files(self, base_dir: str, file_count: int, lines_per_file: int):
        """Helper to create test codebase files"""
        base_path = Path(base_dir)
        for i in range(file_count):
            file_path = base_path / f"test_file_{i}.py"
            with open(file_path, 'w') as f:
                f.write(f"# Test file {i}\n")
                f.write("def test_function():\n")
                f.write('    """Test function"""\n')
                for j in range(lines_per_file - 5):
                    f.write(f"    x_{j} = {j}\n")

    def test_small_codebase_scan_time(self, test_config):
        """8.2: Scan time scales linearly with codebase size - small codebase (<100 files)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            _create_test_files(tmpdir, file_count=50, lines_per_file=100)

            start_time = time.time()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            duration = time.time() - start_time

        # Small codebase should scan quickly (<10 seconds without external scanners)
        assert duration < 10, f"Small codebase scan took {duration:.2f}s, expected <10s"

    def test_medium_codebase_scan_time(self, test_config):
        """8.2: Scan time scales linearly - medium codebase (100-500 files)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            _create_test_files(tmpdir, file_count=200, lines_per_file=200)

            start_time = time.time()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            duration = time.time() - start_time

        # Medium codebase should still be reasonable (<30 seconds)
        assert duration < 30, f"Medium codebase scan took {duration:.2f}s, expected <30s"

    def test_large_codebase_scan_time(self, test_config):
        """8.2: Scan time scales linearly - large codebase (500-2000 files)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            _create_test_files(tmpdir, file_count=1000, lines_per_file=100)

            start_time = time.time()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            duration = time.time() - start_time

        # Large codebase scan should complete (<120 seconds)
        assert duration < 120, f"Large codebase scan took {duration:.2f}s, expected <120s"

@pytest.mark.performance
class TestScalingCharacteristicsBasic:
    """Tests for understanding scaling behavior (no external dependencies)"""

    def test_scan_time_scaling(self, test_config):
        """8.2: Verify scan time scales approximately linearly with codebase size"""
        sizes = [50, 100, 200, 400]
        durations = []

        for size in sizes:
            with tempfile.TemporaryDirectory() as tmpdir:
                _create_test_files(tmpdir, file_count=size, lines_per_file=100)

                start_time = time.time()
                scanner = SecurityScanner(test_config, use_external_scanners=False)
                results = scanner.scan(tmpdir)
                duration = time.time() - start_time
                durations.append(duration)

        # Check that doubling size approximately doubles time (within reasonable bounds)
        # Allow up to 3x for larger sizes (may have overhead)
        for i in range(1, len(sizes)):
            # Skip ratio check when durations are too small to measure reliably
            if durations[i-1] < 0.01:
                continue
            ratio = durations[i] / durations[i-1]
            size_ratio = sizes[i] / sizes[i-1]
            # Time ratio should be between 0.5x and 3x of size ratio
            assert 0.5 * size_ratio <= ratio <= 3 * size_ratio, \
                f"Non-linear scaling detected: size {sizes[i-1]}->{sizes[i]}, time {durations[i-1]:.2f}->{durations[i]:.2f}s"

    def test_ci_cd_limits(self, test_config):
        """8.3: Scanner should work within typical CI/CD time limits"""
        with tempfile.TemporaryDirectory() as tmpdir:
            _create_test_files(tmpdir, file_count=500, lines_per_file=150)

            start_time = time.time()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            duration = time.time() - start_time

        # Should complete within typical CI/CD timeout (5 minutes)
        assert duration < 300, f"CI/CD: scan took {duration:.2f}s (>5 min limit)"

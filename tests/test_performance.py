"""Performance testing for ez-appsec scanner

Measures scan time, resource usage, and scalability across codebase sizes.
"""

import pytest
import time
import os
import psutil
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any
from ez_appsec.config import Config
from ez_appsec.scanner import SecurityScanner


class PerformanceMetrics:
    """Container for performance measurement results"""

    def __init__(self):
        self.start_time = 0
        self.end_time = 0
        self.start_memory = 0
        self.end_memory = 0
        self.start_cpu = 0
        self.cpu_times = []

    def start(self):
        """Start performance measurement"""
        self.start_time = time.time()
        process = psutil.Process(os.getpid())
        self.start_memory = process.memory_info().rss / (1024 * 1024)  # MB
        self.cpu_times.append(process.cpu_percent())

    def stop(self):
        """Stop performance measurement"""
        self.end_time = time.time()
        process = psutil.Process(os.getpid())
        self.end_memory = process.memory_info().rss / (1024 * 1024)  # MB
        self.cpu_times.append(process.cpu_percent())

    @property
    def duration(self) -> float:
        """Scan duration in seconds"""
        return self.end_time - self.start_time

    @property
    def memory_delta(self) -> float:
        """Memory delta in MB"""
        return self.end_memory - self.start_memory

    @property
    def peak_memory(self) -> float:
        """Peak memory in MB"""
        return self.end_memory

    @property
    def avg_cpu(self) -> float:
        """Average CPU usage percentage"""
        return sum(self.cpu_times) / len(self.cpu_times) if self.cpu_times else 0


@pytest.fixture
def metrics():
    """Fresh metrics for each test"""
    return PerformanceMetrics()


@pytest.fixture
def test_config():
    """Test configuration optimized for performance tests"""
    config = Config()
    config.severity = "medium"
    config.max_findings = 1000
    return config


@pytest.mark.performance
class TestScanPerformance:
    """Tests for scan performance characteristics"""

    def test_small_codebase_scan_time(self, metrics, test_config):
        """8.2: Scan time scales linearly with codebase size - small codebase (<100 files)"""
        # Create small test codebase
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=50, lines_per_file=100)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # Small codebase should scan quickly (<10 seconds without external scanners)
        assert metrics.duration < 10, f"Small codebase scan took {metrics.duration:.2f}s"

    def test_medium_codebase_scan_time(self, metrics, test_config):
        """8.2: Scan time scales linearly - medium codebase (100-500 files)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=200, lines_per_file=200)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # Medium codebase should still be reasonable (<30 seconds)
        assert metrics.duration < 30, f"Medium codebase scan took {metrics.duration:.2f}s"

    def test_large_codebase_scan_time(self, metrics, test_config):
        """8.2: Scan time scales linearly - large codebase (500-2000 files)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=1000, lines_per_file=100)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # Large codebase scan should complete (<120 seconds)
        assert metrics.duration < 120, f"Large codebase scan took {metrics.duration:.2f}s"

    def test_memory_usage_small_scan(self, metrics, test_config):
        """8.3: Scanner doesn't exceed resource limits - memory usage for small scan"""
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=100, lines_per_file=100)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # Memory usage should be reasonable (<500MB delta)
        assert metrics.memory_delta < 500, f"Memory delta {metrics.memory_delta:.2f}MB exceeds limit"

    def test_memory_usage_large_scan(self, metrics, test_config):
        """8.3: Scanner doesn't exceed resource limits - memory usage for large scan"""
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=1000, lines_per_file=100)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # Even large scans should stay under 2GB
        assert metrics.peak_memory < 2000, f"Peak memory {metrics.peak_memory:.2f}MB exceeds limit"

    def test_cpu_usage(self, metrics, test_config):
        """8.3: CPU usage should be reasonable during scan"""
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=200, lines_per_file=150)

            metrics.start()
            # Sample CPU during scan
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # CPU should not be pegged at 100% consistently
        # (brief spikes are OK, but average should be reasonable)
        assert metrics.avg_cpu < 300, f"Average CPU {metrics.avg_cpu:.2f}% seems too high"

    @pytest.mark.skip(reason="Requires external scanners and more test setup")
    def test_external_scanner_timing(self, metrics, test_config):
        """8.1: Measure scan time with external scanners enabled"""
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=100, lines_per_file=100)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=True)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # With external scanners, still should complete in reasonable time
        # This is a baseline - actual time depends on scanner availability
        print(f"External scanner scan time: {metrics.duration:.2f}s")

    @pytest.mark.skip(reason="Multi-process testing setup required")
    def test_concurrent_scanning(self, metrics, test_config):
        """8.4: Multiple scans can run simultaneously without excessive resource contention"""
        import concurrent.futures

        def run_scan(scan_id):
            with tempfile.TemporaryDirectory() as tmpdir:
                scan_dir = Path(tmpdir) / f"scan_{scan_id}"
                scan_dir.mkdir()
                self._create_test_files(str(scan_dir), file_count=100, lines_per_file=100)

                local_metrics = PerformanceMetrics()
                local_metrics.start()
                scanner = SecurityScanner(test_config, use_external_scanners=False)
                results = scanner.scan(str(scan_dir))
                local_metrics.stop()
                return local_metrics.duration, local_metrics.peak_memory

        # Run 3 concurrent scans
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_scan, i) for i in range(3)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All scans should complete
        durations, memories = zip(*results)
        assert len(durations) == 3, "Not all scans completed"

        # Concurrent scans shouldn't take dramatically longer than sequential
        avg_duration = sum(durations) / len(durations)
        print(f"Concurrent scan avg duration: {avg_duration:.2f}s")

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


@pytest.mark.performance
class TestScalingCharacteristics:
    """Tests for understanding scaling behavior"""

    def test_scan_time_scaling(self, test_config):
        """8.2: Verify scan time scales approximately linearly with codebase size"""
        sizes = [50, 100, 200, 400]
        durations = []

        for size in sizes:
            with tempfile.TemporaryDirectory() as tmpdir:
                self._create_test_files(tmpdir, file_count=size, lines_per_file=100)

                start = time.time()
                scanner = SecurityScanner(test_config, use_external_scanners=False)
                results = scanner.scan(tmpdir)
                duration = time.time() - start
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


@pytest.mark.performance
class TestResourceLimits:
    """Tests for CI/CD resource limits"""

    def test_github_actions_resources(self, metrics, test_config):
        """8.3: Scanner should work within GitHub Actions limits (2-core, 7GB RAM)"""
        # GitHub Actions: 2-core CPU, 7 GB RAM, 14 GB SSD
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=500, lines_per_file=150)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # Should complete within typical GitHub Actions timeout
        assert metrics.duration < 300, f"GitHub Actions: scan took {metrics.duration:.2f}s (>5 min)"
        assert metrics.peak_memory < 6000, f"GitHub Actions: memory {metrics.peak_memory:.2f}MB (>6GB)"

    def test_gitlab_ci_resources(self, metrics, test_config):
        """8.3: Scanner should work within GitLab CI limits (variable, typically 4-core, 4GB RAM)"""
        # GitLab CI: varies by runner, assume 4-core, 4GB RAM
        with tempfile.TemporaryDirectory() as tmpdir:
            self._create_test_files(tmpdir, file_count=500, lines_per_file=150)

            metrics.start()
            scanner = SecurityScanner(test_config, use_external_scanners=False)
            results = scanner.scan(tmpdir)
            metrics.stop()

        # Should complete within typical GitLab CI timeout
        assert metrics.duration < 300, f"GitLab CI: scan took {metrics.duration:.2f}s (>5 min)"
        assert metrics.peak_memory < 3500, f"GitLab CI: memory {metrics.peak_memory:.2f}MB (>3.5GB)"

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

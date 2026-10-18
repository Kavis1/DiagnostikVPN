import os
import shutil
import sys
import unittest


class TestEnvironment(unittest.TestCase):
    def test_python_version(self):
        """Check Python version is >= 3.10."""
        self.assertGreaterEqual(
            sys.version_info[:2],
            (3, 10),
            f"Python version {sys.version} is below required 3.10",
        )

    def test_ram(self):
        """Check total RAM is >= 2GB."""
        ram_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        ram_gb = ram_bytes / (1024**3)
        self.assertGreaterEqual(
            ram_gb,
            2.0,
            f"Total RAM ({ram_gb:.2f} GB) is less than required 2 GB",
        )

    def test_disk_space(self):
        """Check available disk space is >= 5GB."""
        disk_usage = shutil.disk_usage(".")
        free_gb = disk_usage.free / (1024**3)
        self.assertGreaterEqual(
            free_gb,
            5.0,
            f"Free disk space ({free_gb:.2f} GB) is less than required 5 GB",
        )


if __name__ == "__main__":
    unittest.main()

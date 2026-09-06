import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.selftest import run_selftest


class TestSelftest(unittest.TestCase):
    def test_full_selftest_passes_fast(self):
        root = os.path.join("/tmp", "edr_test_selftest_%d" % os.getpid())
        start = time.monotonic()
        code, checks, report, score, elapsed = run_selftest(fixture_root=root)
        self.assertEqual(code, 0, "self-test must exit 0")
        failed = [name for name, ok, _d in checks if not ok]
        self.assertEqual(failed, [])
        self.assertLess(elapsed, 15.0)
        total = score["total"] if isinstance(score, dict) else score
        self.assertGreaterEqual(total, 0.0)
        self.assertLess(total, 100.0)


if __name__ == "__main__":
    unittest.main()
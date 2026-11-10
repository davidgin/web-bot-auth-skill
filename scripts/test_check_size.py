# SPDX-License-Identifier: Apache-2.0
"""Tests for check_size.py. Run: python -m unittest -v test_check_size (from scripts/)."""
import tempfile
import unittest
from pathlib import Path

import check_size


def func(name, body_lines):
    """A function whose total length (def line + body) is body_lines + 1."""
    return f"def {name}():\n" + "".join("    x = 1\n" for _ in range(body_lines))


def padded(total_lines, tail=""):
    """A file of exactly total_lines lines made of short functions."""
    lines = ["# pad\n"] * (total_lines - tail.count("\n"))
    return "".join(lines) + tail


class SizeGate(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def write(self, name, text):
        (self.root / name).write_text(text)

    def run_check(self, baseline=None):
        return check_size.check(self.root, baseline or {})

    def test_empty_directory_passes(self):
        self.assertEqual(self.run_check(), [])

    def test_over_limit_file_fails(self):
        self.write("big.py", padded(1001))
        self.assertTrue(any("big.py" in v and "1001" in v for v in self.run_check()))

    def test_file_at_limit_passes(self):
        self.write("ok.py", padded(1000))
        self.assertEqual(self.run_check(), [])

    def test_vendored_file_1050_passes(self):
        self.write("web_bot_auth.py", padded(1050))
        self.assertEqual(self.run_check(), [])

    def test_vendored_file_1100_passes(self):
        self.write("web_bot_auth.py", padded(1100))
        self.assertEqual(self.run_check(), [])

    def test_vendored_file_1101_fails(self):
        self.write("web_bot_auth.py", padded(1101))
        self.assertTrue(any("web_bot_auth.py" in v for v in self.run_check()))

    def test_other_file_does_not_get_vendored_limit(self):
        self.write("other.py", padded(1050))
        self.assertEqual(len(self.run_check()), 1)

    def test_test_files_are_skipped(self):
        self.write("test_x.py", padded(2000) + func("t", 80))
        self.assertEqual(self.run_check(), [])

    def test_new_51_line_function_fails(self):
        self.write("m.py", func("long_one", 50))  # 51 lines
        self.assertTrue(any("long_one" in v for v in self.run_check()))

    def test_50_line_function_passes(self):
        self.write("m.py", func("fits", 49))
        self.assertEqual(self.run_check(), [])

    def test_method_is_checked_with_qualified_name(self):
        body = "class C:\n" + "".join(
            "    " + l + "\n" for l in func("meth", 60).splitlines()
        )
        self.write("m.py", body)
        self.assertTrue(any("C.meth" in v for v in self.run_check()))

    def test_baselined_function_that_grew_fails(self):
        self.write("m.py", func("f", 60))  # 61 lines
        self.assertTrue(self.run_check({"m.py::f": 60}))

    def test_baselined_function_at_baseline_passes(self):
        self.write("m.py", func("f", 60))  # 61 lines
        self.assertEqual(self.run_check({"m.py::f": 61}), [])

    def test_baselined_function_below_baseline_passes(self):
        self.write("m.py", func("f", 60))
        self.assertEqual(self.run_check({"m.py::f": 100}), [])

    def test_syntax_error_fails(self):
        self.write("bad.py", "def (:\n")
        self.assertTrue(any("bad.py" in v for v in self.run_check()))


if __name__ == "__main__":
    unittest.main()

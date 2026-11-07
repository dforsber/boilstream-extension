"""Regression controls for CI's mandatory native SQL inventory."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("native_sql", Path(__file__).with_name("test-native-sql.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def event(**changes):
    return "[TEST_EVENT] " + json.dumps(dict(event="end", name="test/sql/example.test", status="ok",
                                             passes=2, fails=0, **{"skip-mode": 0}) | changes)


class InventoryTests(unittest.TestCase):
    expected = {"test/sql/example.test"}

    def test_complete(self):
        self.assertEqual(module.verify(event(), self.expected), 2)

    def test_missing_duplicate_or_unexpected_events(self):
        for output in ["", event() + "\n" + event(), event(name="unexpected")]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                module.verify(output, self.expected)

    def test_skip_failure_and_empty_are_not_success(self):
        for changes in [{"status": "skip-requirement"}, {"skip-mode": 1}, {"fails": 1}, {"passes": 0},
                        {"partial-skip-reasons": ["mode skip"]}, {"status": "error"}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.verify(event(**changes), self.expected)

    def test_malformed_event_is_not_ignored(self):
        with self.assertRaises(ValueError):
            module.verify("[TEST_EVENT] {broken}", self.expected)


if __name__ == "__main__":
    unittest.main()

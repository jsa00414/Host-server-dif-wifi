"""Unit tests for Elements upload path sanitization (TV folder trees)."""

from __future__ import annotations

import unittest

from server import _elements_sanitize_filename, _elements_sanitize_relpath


class ElementsUploadPathTests(unittest.TestCase):
    def test_basename(self):
        self.assertEqual(_elements_sanitize_filename("ep.mkv"), "ep.mkv")
        self.assertEqual(
            _elements_sanitize_filename("Show/Season 01/ep.mkv"), "ep.mkv"
        )

    def test_nested_tv_relpath(self):
        self.assertEqual(
            _elements_sanitize_relpath(
                "Show Name (2020)/Season 01/S01E01.mkv", allow_nested=True
            ),
            "Show Name (2020)/Season 01/S01E01.mkv",
        )
        self.assertEqual(
            _elements_sanitize_relpath(
                r"Show\Season 02\ep.mkv", allow_nested=True
            ),
            "Show/Season 02/ep.mkv",
        )

    def test_nested_disabled_strips_to_basename(self):
        self.assertEqual(
            _elements_sanitize_relpath(
                "Show/Season 01/ep.mkv", allow_nested=False
            ),
            "ep.mkv",
        )

    def test_rejects_traversal(self):
        with self.assertRaises(ValueError):
            _elements_sanitize_relpath("../etc/passwd", allow_nested=True)
        with self.assertRaises(ValueError):
            _elements_sanitize_relpath("Show/../secret/ep.mkv", allow_nested=True)
        with self.assertRaises(ValueError):
            _elements_sanitize_relpath("Show/./ep.mkv", allow_nested=True)


if __name__ == "__main__":
    unittest.main()

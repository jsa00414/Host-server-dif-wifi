#!/usr/bin/env python3
"""Unit tests for TMDB / Plex TV naming helpers (no live TMDB calls)."""
from __future__ import annotations

import unittest

import media_tmdb as tmdb


class TestPlexNaming(unittest.TestCase):
    def test_show_folder(self):
        self.assertEqual(tmdb.plex_show_folder_name("The Office", "2005"), "The Office (2005)")
        self.assertEqual(
            tmdb.plex_show_folder_name("The Office (2005)", "2005"), "The Office (2005)"
        )

    def test_episode_filename(self):
        name = tmdb.plex_episode_filename(
            show_name="The Office",
            year="2005",
            season=2,
            episode=3,
            episode_title="Office Olympics",
            ext="mkv",
        )
        self.assertEqual(
            name, "The Office (2005) - S02E03 - Office Olympics.mkv"
        )

    def test_relpath(self):
        rel = tmdb.plex_episode_relpath(
            show_name="Bluey",
            year="2018",
            season=1,
            episode=1,
            episode_title="Magic Xylophone",
            ext="mp4",
        )
        self.assertEqual(
            rel,
            "Bluey (2018)/Season 01/Bluey (2018) - S01E01 - Magic Xylophone.mp4",
        )

    def test_guess_season_episode(self):
        self.assertEqual(tmdb.guess_season_episode("Show.S01E05.mkv"), (1, 5))
        self.assertEqual(tmdb.guess_season_episode("Show.1x02.mkv"), (1, 2))
        self.assertEqual(tmdb.guess_season_episode("random.mkv"), (0, 0))

    def test_build_from_form(self):
        rel, base = tmdb.build_upload_name_from_form(
            "clip.mkv",
            show_name="Bluey",
            year="2018",
            season=1,
            episode=2,
            episode_title="Hospital",
        )
        self.assertTrue(rel.startswith("Bluey (2018)/Season 01/"))
        self.assertIn("S01E02", base)
        self.assertEqual(base, rel.rsplit("/", 1)[-1])

    def test_build_guesses_from_filename(self):
        rel, _ = tmdb.build_upload_name_from_form(
            "Bluey.S03E10.mkv",
            show_name="Bluey",
            year="2018",
        )
        self.assertIn("Season 03", rel)
        self.assertIn("S03E10", rel)

    def test_movie_filename(self):
        self.assertEqual(
            tmdb.plex_movie_filename("Inception", "2010", "mkv"),
            "Inception (2010).mkv",
        )

    def test_build_movie_from_form(self):
        rel, base = tmdb.build_movie_upload_name_from_form(
            "clip.mp4",
            title="Inception",
            year="2010",
        )
        self.assertEqual(rel, "Inception (2010).mp4")
        self.assertEqual(base, rel)

    def test_unsafe_chars_stripped(self):
        folder = tmdb.plex_show_folder_name('Foo/Bar:Baz', "2020")
        self.assertNotIn("/", folder)
        self.assertNotIn(":", folder)


if __name__ == "__main__":
    unittest.main()

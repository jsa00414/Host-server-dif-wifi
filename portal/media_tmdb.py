"""TMDB helpers for Plex TV / movie upload naming."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

TMDB_API_KEY = os.environ.get("TMDB_API_KEY", "").strip()
TMDB_ACCESS_TOKEN = os.environ.get("TMDB_ACCESS_TOKEN", "").strip()
TMDB_API_BASE = os.environ.get("TMDB_API_BASE", "https://api.themoviedb.org/3").rstrip("/")
TMDB_TIMEOUT = float(os.environ.get("TMDB_TIMEOUT", "12"))


def tmdb_configured() -> bool:
    return bool(TMDB_API_KEY or TMDB_ACCESS_TOKEN)


def _tmdb_request(path: str, params: dict[str, Any] | None = None) -> dict:
    if not tmdb_configured():
        raise RuntimeError(
            "TMDB is not configured. Set TMDB_API_KEY (or TMDB_ACCESS_TOKEN) "
            "in /opt/wireguard/port-forward-ui.env"
        )
    q = dict(params or {})
    headers = {
        "Accept": "application/json",
        "User-Agent": "ServerManager-PlexUpload/1.0",
    }
    if TMDB_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {TMDB_ACCESS_TOKEN}"
    elif TMDB_API_KEY:
        q["api_key"] = TMDB_API_KEY
    url = f"{TMDB_API_BASE}{path}"
    if q:
        url += "?" + urllib.parse.urlencode(q)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TMDB_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:240]
        raise RuntimeError(f"TMDB HTTP {exc.code}: {body or exc.reason}") from exc
    except Exception as exc:
        raise RuntimeError(f"TMDB request failed: {exc}") from exc


def search_tv(query: str, *, page: int = 1, include_adult: bool = False) -> dict:
    q = str(query or "").strip()
    if len(q) < 1:
        raise ValueError("Search query required")
    data = _tmdb_request(
        "/search/tv",
        {
            "query": q,
            "page": max(1, int(page or 1)),
            "include_adult": "true" if include_adult else "false",
            "language": "en-US",
        },
    )
    results = []
    for row in data.get("results") or []:
        if not isinstance(row, dict):
            continue
        year = ""
        first = str(row.get("first_air_date") or "")
        if len(first) >= 4 and first[:4].isdigit():
            year = first[:4]
        results.append(
            {
                "id": int(row.get("id") or 0),
                "name": str(row.get("name") or row.get("original_name") or "").strip(),
                "original_name": str(row.get("original_name") or "").strip(),
                "year": year,
                "first_air_date": first,
                "overview": str(row.get("overview") or "")[:400],
                "poster_path": str(row.get("poster_path") or ""),
                "popularity": float(row.get("popularity") or 0),
                "media_type": "tv",
            }
        )
    return {
        "ok": True,
        "configured": True,
        "media_type": "tv",
        "query": q,
        "page": int(data.get("page") or 1),
        "total_pages": int(data.get("total_pages") or 1),
        "total_results": int(data.get("total_results") or len(results)),
        "results": results,
    }


def search_movie(query: str, *, page: int = 1, include_adult: bool = False) -> dict:
    q = str(query or "").strip()
    if len(q) < 1:
        raise ValueError("Search query required")
    data = _tmdb_request(
        "/search/movie",
        {
            "query": q,
            "page": max(1, int(page or 1)),
            "include_adult": "true" if include_adult else "false",
            "language": "en-US",
        },
    )
    results = []
    for row in data.get("results") or []:
        if not isinstance(row, dict):
            continue
        year = ""
        release = str(row.get("release_date") or "")
        if len(release) >= 4 and release[:4].isdigit():
            year = release[:4]
        title = str(row.get("title") or row.get("original_title") or "").strip()
        results.append(
            {
                "id": int(row.get("id") or 0),
                "name": title,
                "title": title,
                "original_name": str(row.get("original_title") or "").strip(),
                "original_title": str(row.get("original_title") or "").strip(),
                "year": year,
                "release_date": release,
                "overview": str(row.get("overview") or "")[:400],
                "poster_path": str(row.get("poster_path") or ""),
                "popularity": float(row.get("popularity") or 0),
                "media_type": "movie",
                "filename": plex_movie_filename(title, year, "mkv") if title else "",
            }
        )
    return {
        "ok": True,
        "configured": True,
        "media_type": "movie",
        "query": q,
        "page": int(data.get("page") or 1),
        "total_pages": int(data.get("total_pages") or 1),
        "total_results": int(data.get("total_results") or len(results)),
        "results": results,
    }


def tv_details(tv_id: int) -> dict:
    tid = int(tv_id or 0)
    if tid <= 0:
        raise ValueError("tmdb id required")
    data = _tmdb_request(f"/tv/{tid}", {"language": "en-US"})
    year = ""
    first = str(data.get("first_air_date") or "")
    if len(first) >= 4 and first[:4].isdigit():
        year = first[:4]
    seasons = []
    for s in data.get("seasons") or []:
        if not isinstance(s, dict):
            continue
        sn = int(s.get("season_number") or 0)
        if sn < 0:
            continue
        seasons.append(
            {
                "season_number": sn,
                "name": str(s.get("name") or f"Season {sn}"),
                "episode_count": int(s.get("episode_count") or 0),
                "air_date": str(s.get("air_date") or ""),
            }
        )
    seasons.sort(key=lambda x: x["season_number"])
    return {
        "ok": True,
        "id": tid,
        "name": str(data.get("name") or data.get("original_name") or "").strip(),
        "original_name": str(data.get("original_name") or "").strip(),
        "year": year,
        "first_air_date": first,
        "overview": str(data.get("overview") or "")[:800],
        "poster_path": str(data.get("poster_path") or ""),
        "number_of_seasons": int(data.get("number_of_seasons") or 0),
        "number_of_episodes": int(data.get("number_of_episodes") or 0),
        "seasons": seasons,
        "folder_name": plex_show_folder_name(
            str(data.get("name") or data.get("original_name") or "").strip(), year
        ),
    }


def movie_details(movie_id: int) -> dict:
    mid = int(movie_id or 0)
    if mid <= 0:
        raise ValueError("tmdb id required")
    data = _tmdb_request(f"/movie/{mid}", {"language": "en-US"})
    year = ""
    release = str(data.get("release_date") or "")
    if len(release) >= 4 and release[:4].isdigit():
        year = release[:4]
    title = str(data.get("title") or data.get("original_title") or "").strip()
    return {
        "ok": True,
        "id": mid,
        "name": title,
        "title": title,
        "original_title": str(data.get("original_title") or "").strip(),
        "year": year,
        "release_date": release,
        "overview": str(data.get("overview") or "")[:800],
        "poster_path": str(data.get("poster_path") or ""),
        "filename": plex_movie_filename(title, year, "mkv"),
        "folder_name": plex_show_folder_name(title, year),
    }


def tv_season(tv_id: int, season_number: int) -> dict:
    tid = int(tv_id or 0)
    sn = int(season_number)
    if tid <= 0:
        raise ValueError("tmdb id required")
    if sn < 0:
        raise ValueError("season number required")
    data = _tmdb_request(f"/tv/{tid}/season/{sn}", {"language": "en-US"})
    show = tv_details(tid)
    episodes = []
    for ep in data.get("episodes") or []:
        if not isinstance(ep, dict):
            continue
        en = int(ep.get("episode_number") or 0)
        title = str(ep.get("name") or "").strip()
        episodes.append(
            {
                "episode_number": en,
                "name": title,
                "air_date": str(ep.get("air_date") or ""),
                "overview": str(ep.get("overview") or "")[:300],
                "filename": plex_episode_filename(
                    show_name=show["name"],
                    year=show["year"],
                    season=sn,
                    episode=en,
                    episode_title=title,
                    ext="mkv",
                ),
            }
        )
    return {
        "ok": True,
        "id": tid,
        "show": show,
        "season_number": sn,
        "name": str(data.get("name") or f"Season {sn}"),
        "episodes": episodes,
        "folder_name": show["folder_name"],
        "season_folder": f"Season {sn:02d}",
    }


_SAFE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def _clean_name(value: str) -> str:
    text = str(value or "").strip()
    text = _SAFE_CHARS.sub("", text)
    text = re.sub(r"\s+", " ", text).strip(" .")
    return text


def plex_show_folder_name(show_name: str, year: str = "") -> str:
    name = _clean_name(show_name)
    y = str(year or "").strip()
    if y.isdigit() and len(y) == 4 and f"({y})" not in name:
        return f"{name} ({y})"
    return name


def plex_movie_filename(title: str, year: str = "", ext: str = "mkv") -> str:
    folder = plex_show_folder_name(title, year)
    ext_n = str(ext or "mkv").lstrip(".").lower() or "mkv"
    return f"{folder}.{ext_n}"


def plex_episode_filename(
    *,
    show_name: str,
    year: str = "",
    season: int,
    episode: int,
    episode_title: str = "",
    ext: str = "mkv",
) -> str:
    folder = plex_show_folder_name(show_name, year)
    sn = max(0, int(season))
    en = max(0, int(episode))
    title = _clean_name(episode_title)
    base = f"{folder} - S{sn:02d}E{en:02d}"
    if title:
        base = f"{base} - {title}"
    ext_n = str(ext or "mkv").lstrip(".").lower() or "mkv"
    return f"{base}.{ext_n}"


def plex_episode_relpath(
    *,
    show_name: str,
    year: str = "",
    season: int,
    episode: int,
    episode_title: str = "",
    ext: str = "mkv",
) -> str:
    folder = plex_show_folder_name(show_name, year)
    sn = max(0, int(season))
    fname = plex_episode_filename(
        show_name=show_name,
        year=year,
        season=season,
        episode=episode,
        episode_title=episode_title,
        ext=ext,
    )
    return f"{folder}/Season {sn:02d}/{fname}"


def guess_season_episode(filename: str) -> tuple[int, int]:
    stem = PathName(filename).stem
    patterns = [
        r"[Ss](\d{1,2})[Ee](\d{1,3})",
        r"(\d{1,2})x(\d{1,3})",
        r"[Ss]eason[.\s_-]*(\d{1,2})[.\s_-]*[Ee]p(?:isode)?[.\s_-]*(\d{1,3})",
    ]
    for pat in patterns:
        m = re.search(pat, stem)
        if m:
            return int(m.group(1)), int(m.group(2))
    return 0, 0


class PathName:
    """Tiny Path-like for basename/stem without importing pathlib everywhere."""

    def __init__(self, name: str):
        self.name = str(name or "").replace("\\", "/").split("/")[-1]

    @property
    def stem(self) -> str:
        if "." in self.name:
            return self.name.rsplit(".", 1)[0]
        return self.name

    @property
    def suffix(self) -> str:
        if "." in self.name:
            return "." + self.name.rsplit(".", 1)[-1]
        return ""


def build_upload_name_from_form(
    original_filename: str,
    *,
    show_name: str,
    year: str = "",
    season: int | None = None,
    episode: int | None = None,
    episode_title: str = "",
) -> tuple[str, str]:
    """Return (relative_path_under_inbox, basename) for a plex-named episode."""
    ext = PathName(original_filename).suffix.lstrip(".") or "mkv"
    sn, en = 0, 0
    if season is not None and episode is not None:
        sn, en = int(season), int(episode)
    else:
        sn, en = guess_season_episode(original_filename)
    if sn <= 0 or en <= 0:
        raise ValueError(
            "Season and episode required (could not parse from filename)"
        )
    rel = plex_episode_relpath(
        show_name=show_name,
        year=year,
        season=sn,
        episode=en,
        episode_title=episode_title,
        ext=ext,
    )
    return rel, rel.rsplit("/", 1)[-1]


def build_movie_upload_name_from_form(
    original_filename: str,
    *,
    title: str,
    year: str = "",
) -> tuple[str, str]:
    """Return (relative_path_under_inbox, basename) for a plex-named movie."""
    name = _clean_name(title)
    if not name:
        raise ValueError("Movie title required for full movie form")
    ext = PathName(original_filename).suffix.lstrip(".") or "mkv"
    fname = plex_movie_filename(name, year, ext)
    return fname, fname

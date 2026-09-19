import os
import re
import math
import sqlite3
import time
import traceback
import ast
import base64
import hashlib
import hmac
import secrets
import string
import uuid
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, g, jsonify, redirect, render_template, request, session
from jinja2 import TemplateNotFound
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

load_dotenv()  # loads variables from a local .env file (if present) into
                # os.environ, so every os.environ.get(...) call below picks
                # them up automatically -- must run before those calls, so
                # it sits right here, before anything else reads env vars

app = Flask(__name__)
# Needed for login sessions (signed session cookies). Set a real SECRET_KEY
# env var in production -- this fallback is fine for local/dev use only.
app.secret_key = os.environ.get("SECRET_KEY", "aetherscan-dev-secret-change-me")


@app.after_request
def _add_no_cache_headers(response):
    """
    The desktop app's QWebEngineProfile below is configured with a
    PERSISTENT DISK HTTP cache (see HttpCacheType.DiskHttpCache further
    down this file). That's normally a good thing for a real browser --
    but during development it has a confusing side effect: editing a
    template and restarting `python app.py` can still show the OLD page,
    because the browser serves its own cached copy instead of re-fetching
    from the (freshly restarted) server. This app has no user-facing
    "clear cache" button, so instead of relying on the person to know to
    hard-refresh, every HTML response tells the browser outright not to
    cache it -- editing a file and restarting the server is then always
    enough on its own.
    """
    if response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

# ---------------------------------------------------------------------------
# ACCOUNTS: a real, local username/email/password system (hashed passwords,
# SQLite, signed session cookies) -- like "Create account" on Google, just
# self-hosted instead of federated. No 3rd-party OAuth here; this is your
# own AetherScan account, stored in a local SQLite file next to app.py.
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aetherscan_users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            query TEXT NOT NULL,
            mode TEXT NOT NULL,
            searched_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    # Migration: add per-user API key columns if this DB predates them --
    # ALTER TABLE has no "IF NOT EXISTS" in SQLite, so we just try each one
    # and swallow the "duplicate column" error on databases that already
    # have it (e.g. every run after the first one that creates them).
    for col in ("gemini_api_key", "anthropic_api_key", "tmdb_api_key", "groq_api_key"):
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    conn.close()
    print(f"[AetherScan] Accounts database: {DB_PATH}")


init_db()  # safe to call on every startup -- CREATE TABLE IF NOT EXISTS is a no-op once it exists


def save_search_history(user_id, query, mode):
    """Log a search for a signed-in user -- powers the 'Recent searches' list."""
    if not user_id or not query:
        return
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO search_history (user_id, query, mode, searched_at) VALUES (?, ?, ?, ?)",
            (user_id, query, mode, datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        traceback.print_exc()  # history is a nice-to-have -- never let it break a real search


def get_search_history(user_id, limit=10):
    """Most recent DISTINCT queries for this user, newest first."""
    if not user_id:
        return []
    try:
        conn = get_db()
        rows = conn.execute(
            """
            SELECT query, mode, MAX(searched_at) AS last_searched
            FROM search_history WHERE user_id = ?
            GROUP BY query, mode ORDER BY last_searched DESC LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        conn.close()
        return [{"query": r["query"], "mode": r["mode"]} for r in rows]
    except Exception:
        traceback.print_exc()
        return []


# ---------------------------------------------------------------------------
# PER-USER API KEYS: signed-in users can add their own Gemini/Anthropic/TMDb
# keys on the Settings page (reachable from the account menu) instead of
# editing environment variables. A user's own key always takes priority
# over the server's environment-variable key when both exist, resolved
# fresh on every request via flask.g (see _apply_user_ai_settings below) so
# concurrent requests from different signed-in users never bleed into
# each other's keys.
# ---------------------------------------------------------------------------
def get_user_settings(user_id):
    if not user_id:
        return {}
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT gemini_api_key, anthropic_api_key, tmdb_api_key, groq_api_key FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        conn.close()
        if not row:
            return {}
        return {
            "gemini_api_key": row["gemini_api_key"] or "",
            "anthropic_api_key": row["anthropic_api_key"] or "",
            "tmdb_api_key": row["tmdb_api_key"] or "",
            "groq_api_key": row["groq_api_key"] or "",
        }
    except Exception:
        traceback.print_exc()
        return {}


def save_user_settings(user_id, gemini_api_key, anthropic_api_key, tmdb_api_key, groq_api_key):
    try:
        conn = get_db()
        conn.execute(
            "UPDATE users SET gemini_api_key = ?, anthropic_api_key = ?, tmdb_api_key = ?, groq_api_key = ? WHERE id = ?",
            (gemini_api_key or None, anthropic_api_key or None, tmdb_api_key or None, groq_api_key or None, user_id),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        traceback.print_exc()
        return False


def _apply_user_ai_settings():
    """Call once near the top of any route that might use an AI or TMDb
    key (currently home() and api_chat()) -- stashes the signed-in user's
    own keys (if any) on flask.g for this request only, so the getters
    below can prefer them over the server's environment-variable keys."""
    user_id = session.get("user_id")
    settings = get_user_settings(user_id) if user_id else {}
    g.gemini_api_key = settings.get("gemini_api_key") or None
    g.anthropic_api_key = settings.get("anthropic_api_key") or None
    g.tmdb_api_key = settings.get("tmdb_api_key") or None
    g.groq_api_key = settings.get("groq_api_key") or None


def _effective_gemini_key():
    return getattr(g, "gemini_api_key", None) or GEMINI_API_KEY


def _effective_anthropic_key():
    return getattr(g, "anthropic_api_key", None) or ANTHROPIC_API_KEY


def _effective_tmdb_key():
    return getattr(g, "tmdb_api_key", None) or TMDB_API_KEY


def _effective_groq_key():
    return getattr(g, "groq_api_key", None) or GROQ_API_KEY

# ---------------------------------------------------------------------------
# OPTIONAL paid/keyed sources. Every source in this file works with NO key.
# ---------------------------------------------------------------------------
BRAVE_API_KEY = os.environ.get("BRAVE_API_KEY", "")
SERPAPI_API_KEY = os.environ.get("SERPAPI_API_KEY", "")
BING_API_KEY = os.environ.get("BING_API_KEY", "")
GOOGLE_CSE_API_KEY = os.environ.get("GOOGLE_CSE_API_KEY", "")
GOOGLE_CSE_ID = os.environ.get("GOOGLE_CSE_ID", "")
YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY", "")

# Movies tab -- free key at https://www.themoviedb.org/settings/api
# (instant approval, generous free tier, no card required). TMDb is the
# same data source most movie/TV apps and "where to watch" sites are
# built on, so this gives real posters, ratings, overviews, and release
# dates -- not a stand-in dataset.
TMDB_API_KEY = os.environ.get("TMDB_API_KEY", "")

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")

# Alternative to Gemini for both the AI Overview and the AI Chat tab below --
# whichever of these two you set gets used (Gemini is tried first if both
# are set). Free-tier note: unlike Gemini's free API tier, Anthropic's API
# is pay-as-you-go (no perpetual free tier at the time of writing), so
# Gemini is the "free" option and this is the "I already use Claude" option.
# Get a key at https://console.anthropic.com/settings/keys
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")

# A second genuinely-free option for AI Chat (no card, no trial clock --
# rate-limited rather than credit-limited), for the period where Google's
# Gemini API key rollout (Standard "AIza" keys -> Auth "AQ." keys) is
# causing new keys to fail direct REST calls. Get a free key at
# https://console.groq.com/keys -- OpenAI-compatible chat completions API,
# so the request/response shapes below look like the OpenAI format rather
# than Gemini's or Claude's.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

OPENVERSE_CLIENT_ID = os.environ.get("OPENVERSE_CLIENT_ID", "")
OPENVERSE_CLIENT_SECRET = os.environ.get("OPENVERSE_CLIENT_SECRET", "")

# Maps tab -- powers the 3D Cesium globe (satellite imagery + terrain) in
# place of the old flat Leaflet map. Free "ion" account, no card required
# -- sign up at https://cesium.com/ion/signup, then grab your default
# token at https://cesium.com/ion/tokens. Unlike the other keys in this
# file, this one runs entirely in the BROWSER (Cesium is client-side JS),
# so it necessarily ends up visible in the page's JavaScript -- not a
# secret the way GEMINI_API_KEY etc. are. Fine for a local personal app;
# just don't publish this app publicly with your token baked in.
CESIUM_ION_TOKEN = os.environ.get("CESIUM_ION_TOKEN", "")

# Movies tab -- free instant key at themoviedb.org/signup (Settings -> API
# -> "Request an API key" -> Developer). Real posters, ratings, overviews,
# and (via the watch-providers endpoint below) real "where to stream this"
# links -- not fake/simulated playback. TMDb's terms require attributing
# them as the data source when you display their data, which the movie
# cards below do (a small "Data from TMDb" credit).
TMDB_API_KEY = os.environ.get("TMDB_API_KEY", "")
TMDB_IMAGE_BASE = "https://image.tmdb.org/t/p/w342"

CLOSEST_PATTERN = re.compile(r"^\s*closest\s+(.+?)\s*(?:to me|near me)?\s*$", re.IGNORECASE)

HEADERS = {"User-Agent": "AetherScan/2.0 (contact: youremail@example.com)"}

ESPN_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://www.espn.com/",
    "Origin": "https://www.espn.com",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

_espn_session = requests.Session()
_espn_session.headers.update(ESPN_HEADERS)
_espn_warmed_up = False


def _espn_warm_up():
    global _espn_warmed_up
    if _espn_warmed_up:
        return
    try:
        _espn_session.get("https://www.espn.com/", timeout=8)
    except requests.RequestException:
        pass
    _espn_warmed_up = True


def _wikipedia_results(query, limit=8):
    res = requests.get(
        "https://en.wikipedia.org/w/api.php",
        params={"action": "query", "list": "search", "srsearch": query, "format": "json", "srlimit": limit},
        headers=HEADERS,
        timeout=8,
    )
    res.raise_for_status()
    results = []
    for item in res.json().get("query", {}).get("search", []):
        title = item.get("title", "")
        snippet = BeautifulSoup(item.get("snippet", ""), "html.parser").get_text()
        results.append(
            {
                "title": title,
                "url": f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}",
                "snippet": snippet + "...",
                "source": "Wikipedia",
            }
        )
    return results


def _unwrap_ddg_redirect(href):
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        real = parse_qs(parsed.query).get("uddg", [None])[0]
        if real:
            return unquote(real)
    return href


def _duckduckgo_results(query, limit=14):
    """Fetch general web results from DuckDuckGo HTML, with a Lite fallback."""
    urls = [
        "https://html.duckduckgo.com/html/",
        "https://lite.duckduckgo.com/lite/",
    ]
    last_error = None
    for endpoint in urls:
        try:
            res = requests.get(
                endpoint,
                params={"q": query},
                headers={**HEADERS, "User-Agent": ESPN_HEADERS["User-Agent"]},
                timeout=10,
            )
            res.raise_for_status()
            soup = BeautifulSoup(res.text, "html.parser")
            results = []
            # Normal DDG HTML layout.
            for row in soup.select("div.result"):
                link_el = row.select_one("a.result__a")
                if not link_el:
                    continue
                url = _unwrap_ddg_redirect(link_el.get("href", ""))
                title = link_el.get_text(" ", strip=True)
                snippet_el = row.select_one(".result__snippet")
                snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
                if title and url.startswith("http"):
                    results.append({"title": title, "url": url, "snippet": snippet, "source": urlparse(url).netloc})
                if len(results) >= limit:
                    break
            # Lite layout uses result-link/result-snippet classes.
            if not results:
                for link_el in soup.select("a.result-link"):
                    url = _unwrap_ddg_redirect(link_el.get("href", ""))
                    title = link_el.get_text(" ", strip=True)
                    if not title or not url.startswith("http"):
                        continue
                    parent = link_el.parent
                    snippet = ""
                    if parent:
                        sn = parent.find_next(class_=re.compile(r"result-snippet"))
                        if sn:
                            snippet = sn.get_text(" ", strip=True)
                    results.append({"title": title, "url": url, "snippet": snippet, "source": urlparse(url).netloc})
                    if len(results) >= limit:
                        break
            if results:
                return results
            last_error = RuntimeError(f"{endpoint} returned no parseable results")
        except Exception as e:
            last_error = e
    if last_error:
        raise last_error
    return []


def _yahoo_web_results(query, limit=10):
    """Independent general-web fallback when other HTML search pages block scraping."""
    try:
        res = requests.get(
            "https://search.yahoo.com/search",
            params={"p": query, "n": limit},
            headers={**HEADERS, "User-Agent": ESPN_HEADERS["User-Agent"]},
            timeout=10,
        )
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        results = []
        for item in soup.select("div#web ol.searchCenterMiddle li, div.dd.algo"):
            link = item.select_one("h3 a, a.ac-algo")
            if not link:
                continue
            url = link.get("href", "")
            title = link.get_text(" ", strip=True)
            snippet_el = item.select_one("p, div.compText")
            snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
            if title and url.startswith("http"):
                results.append({"title": title, "url": url, "snippet": snippet, "source": urlparse(url).netloc})
            if len(results) >= limit:
                break
        return results
    except Exception:
        traceback.print_exc()
        return []


def _duckduckgo_instant_answer(query):
    res = requests.get(
        "https://api.duckduckgo.com/",
        params={"q": query, "format": "json", "no_redirect": 1, "no_html": 1, "skip_disambig": 1},
        headers=HEADERS,
        timeout=6,
    )
    res.raise_for_status()
    data = res.json()
    if data.get("AbstractText") and data.get("AbstractURL"):
        return {
            "title": data.get("Heading") or query.title(),
            "url": data["AbstractURL"],
            "snippet": data["AbstractText"] + "...",
            "source": data.get("AbstractSource") or "DuckDuckGo",
        }
    return None


def _stackoverflow_results(query, limit=6):
    res = requests.get(
        "https://api.stackexchange.com/2.3/search/advanced",
        params={"order": "desc", "sort": "relevance", "q": query, "site": "stackoverflow", "pagesize": limit},
        headers=HEADERS,
        timeout=8,
    )
    res.raise_for_status()
    data = res.json()

    results = []
    for item in data.get("items", []):
        title, link = item.get("title"), item.get("link")
        if not title or not link:
            continue
        status = "answered" if item.get("is_answered") else "unanswered"
        score = item.get("score", 0)
        snippet = f"{score} votes \u2022 {status} \u2022 Stack Overflow question"
        results.append({"title": title, "url": link, "snippet": snippet, "source": "Stack Overflow"})
    return results


def _hackernews_results(query, limit=6):
    res = requests.get(
        "https://hn.algolia.com/api/v1/search",
        params={"query": query, "tags": "story", "hitsPerPage": limit},
        headers=HEADERS,
        timeout=8,
    )
    res.raise_for_status()
    data = res.json()

    results = []
    for hit in data.get("hits", []):
        title = hit.get("title")
        url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
        if not title:
            continue
        points = hit.get("points") or 0
        comments = hit.get("num_comments") or 0
        results.append(
            {
                "title": title,
                "url": url,
                "snippet": f"{points} points \u2022 {comments} comments \u2022 Hacker News discussion",
                "source": "Hacker News",
            }
        )
    return results


REDDIT_HEADERS = {
    "User-Agent": "AetherScan/2.0 (personal search app; by /u/aetherscan-app)",
}


def _reddit_results(query, limit=6):
    res = requests.get(
        "https://www.reddit.com/search.json",
        params={"q": query, "limit": limit, "sort": "relevance"},
        headers=REDDIT_HEADERS,
        timeout=8,
    )
    res.raise_for_status()
    data = res.json()
    results = []
    for child in data.get("data", {}).get("children", []):
        d = child.get("data", {})
        title, permalink = d.get("title"), d.get("permalink")
        if not title or not permalink:
            continue
        subreddit = d.get("subreddit_name_prefixed", "Reddit")
        score = d.get("score", 0)
        num_comments = d.get("num_comments", 0)
        results.append({
            "title": title,
            "url": f"https://www.reddit.com{permalink}",
            "snippet": f"{score} upvotes \u2022 {num_comments} comments \u2022 {subreddit}",
            "source": "Reddit",
        })
    return results


def _arxiv_results(query, limit=6):
    res = requests.get(
        "http://export.arxiv.org/api/query",
        params={"search_query": f"all:{query}", "start": 0, "max_results": limit},
        headers=HEADERS,
        timeout=8,
    )
    res.raise_for_status()
    root = ET.fromstring(res.content)
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    results = []
    for entry in root.findall("atom:entry", ns):
        title = (entry.findtext("atom:title", default="", namespaces=ns) or "").strip().replace("\n", " ")
        link = entry.findtext("atom:id", default="", namespaces=ns) or ""
        summary = (entry.findtext("atom:summary", default="", namespaces=ns) or "").strip().replace("\n", " ")
        if not title or not link:
            continue
        results.append({
            "title": title,
            "url": link,
            "snippet": (summary[:200] + "...") if summary else "arXiv paper.",
            "source": "arXiv",
        })
    return results


def get_news(query="", limit=12):
    if query:
        url = f"https://news.google.com/rss/search?q={quote(query)}&hl=en-US&gl=US&ceid=US:en"
    else:
        url = "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en"
    res = requests.get(url, headers=HEADERS, timeout=8)
    res.raise_for_status()

    root = ET.fromstring(res.content)
    articles = []
    for item in root.findall(".//item")[:limit]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        source = (item.findtext("source") or "Google News").strip()
        if title and link:
            articles.append({"title": title, "url": link, "source": source, "published": pub_date})
    return articles


def get_weather(lat, lon):
    res = requests.get(
        "https://api.open-meteo.com/v1/forecast",
        params={"latitude": lat, "longitude": lon, "current": "temperature_2m,weather_code,is_day", "timezone": "auto"},
        timeout=8,
    )
    res.raise_for_status()
    current = res.json().get("current", {})
    codes = {
        0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
        45: "Fog", 48: "Fog", 51: "Light drizzle", 53: "Drizzle", 55: "Heavy drizzle",
        61: "Light rain", 63: "Rain", 65: "Heavy rain", 71: "Light snow", 73: "Snow",
        75: "Heavy snow", 80: "Rain showers", 81: "Rain showers", 82: "Violent showers",
        95: "Thunderstorm", 96: "Thunderstorm", 99: "Thunderstorm",
    }
    return {
        "temp_c": current.get("temperature_2m"),
        "condition": codes.get(current.get("weather_code"), "Unknown"),
        "is_day": bool(current.get("is_day", 1)),
    }


def _wikipedia_related_results(query, limit=6):
    search_res = requests.get(
        "https://en.wikipedia.org/w/api.php",
        params={"action": "query", "list": "search", "srsearch": query, "format": "json", "srlimit": 1},
        headers=HEADERS,
        timeout=8,
    )
    search_res.raise_for_status()
    matches = search_res.json().get("query", {}).get("search", [])
    if not matches:
        return []
    top_title = matches[0]["title"]

    rel_res = requests.get(
        f"https://en.wikipedia.org/api/rest_v1/page/related/{quote(top_title.replace(' ', '_'))}",
        headers=HEADERS,
        timeout=8,
    )
    rel_res.raise_for_status()
    pages = rel_res.json().get("pages", [])

    results = []
    for page in pages[:limit]:
        title = page.get("title", "")
        extract = page.get("extract", "")
        if not title:
            continue
        results.append(
            {
                "title": title,
                "url": f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}",
                "snippet": (extract[:200] + "...") if extract else "Related Wikipedia article.",
                "source": "Wikipedia (related)",
            }
        )
    return results


def _brave_results(query, limit=10):
    res = requests.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": limit},
        headers={**HEADERS, "Accept": "application/json", "X-Subscription-Token": BRAVE_API_KEY},
        timeout=8,
    )
    res.raise_for_status()
    data = res.json()
    results = []
    for item in data.get("web", {}).get("results", [])[:limit]:
        title, url = item.get("title"), item.get("url")
        if not title or not url:
            continue
        domain = url.split("/")[2] if "//" in url else "Brave"
        results.append({"title": title, "url": url, "snippet": item.get("description", ""), "source": domain})
    return results


def _serpapi_results(query, limit=10):
    res = requests.get(
        "https://serpapi.com/search",
        params={"q": query, "api_key": SERPAPI_API_KEY, "num": limit},
        headers=HEADERS,
        timeout=10,
    )
    res.raise_for_status()
    data = res.json()
    results = []
    for item in data.get("organic_results", [])[:limit]:
        title, url = item.get("title"), item.get("link")
        if not title or not url:
            continue
        domain = url.split("/")[2] if "//" in url else "Google"
        results.append({"title": title, "url": url, "snippet": item.get("snippet", ""), "source": domain})
    return results


def _bing_results(query, limit=10):
    res = requests.get(
        "https://api.bing.microsoft.com/v7.0/search",
        params={"q": query, "count": limit, "responseFilter": "Webpages"},
        headers={**HEADERS, "Ocp-Apim-Subscription-Key": BING_API_KEY},
        timeout=10,
    )
    res.raise_for_status()
    results = []
    for item in res.json().get("webPages", {}).get("value", [])[:limit]:
        title, url = item.get("name"), item.get("url")
        if not title or not url:
            continue
        domain = url.split("/")[2] if "//" in url else "Bing"
        results.append({"title": title, "url": url, "snippet": item.get("snippet", ""), "source": domain})
    return results


def _google_cse_results(query, limit=10):
    res = requests.get(
        "https://www.googleapis.com/customsearch/v1",
        params={"key": GOOGLE_CSE_API_KEY, "cx": GOOGLE_CSE_ID, "q": query, "num": min(limit, 10)},
        headers=HEADERS,
        timeout=10,
    )
    res.raise_for_status()
    results = []
    for item in res.json().get("items", [])[:limit]:
        title, url = item.get("title"), item.get("link")
        if not title or not url:
            continue
        domain = url.split("/")[2] if "//" in url else "Google"
        results.append({"title": title, "url": url, "snippet": item.get("snippet", ""), "source": domain})
    return results


_SOURCE_WEIGHT = {
    "Wikipedia": 0.85,
    "Wikipedia (related)": 0.80,
    "Stack Overflow": 1.1,
    "Hacker News": 1.0,
    "Reddit": 1.0,
    "arXiv": 1.05,
}
_DEFAULT_SOURCE_WEIGHT = 1.0


def _rank_results(results, query):
    terms = [t for t in re.findall(r"\w+", query.lower()) if t]
    if not terms:
        return results

    def score(item):
        title = (item.get("title") or "").lower()
        snippet = (item.get("snippet") or "").lower()
        title_hits = sum(title.count(t) for t in terms)
        snippet_hits = sum(snippet.count(t) for t in terms)
        density = title_hits * 2 + snippet_hits
        weight = _SOURCE_WEIGHT.get(item.get("source"), _DEFAULT_SOURCE_WEIGHT)
        return density * weight

    ranked = sorted(results, key=score, reverse=True)
    for item in ranked:
        url = item.get("url") or ""
        parsed = urlparse(url)
        item["domain"] = parsed.netloc.removeprefix("www.") or item.get("source", "")
        item["favicon"] = f"https://www.google.com/s2/favicons?domain={quote(item['domain'])}&sz=32" if item["domain"] else ""
    return ranked


def _duckduckgo_instant_answer_as_list(query):
    answer = _duckduckgo_instant_answer(query)
    return [answer] if answer else []


def _google_web_scrape(query, limit=12):
    """Scrape Google search results directly to access entire internet"""
    try:
        res = requests.get(
            "https://www.google.com/search",
            params={"q": query, "num": limit},
            headers={**HEADERS, "User-Agent": ESPN_HEADERS["User-Agent"]},
            timeout=10,
        )
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        results = []
        
        for g in soup.find_all("div", class_="g"):
            try:
                link = g.find("a", href=True)
                if not link:
                    continue
                url = link["href"]
                if url.startswith("/url?q="):
                    url = url.split("/url?q=")[1].split("&")[0]
                
                title_elem = g.find("h3")
                title = title_elem.get_text(strip=True) if title_elem else ""
                
                snippet_elem = g.find("div", class_="VwiC3b")
                snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""
                
                if title and url and not url.startswith("http"):
                    url = "https://" + url if not url.startswith("//") else "https:" + url
                
                if title and url and ("http" in url):
                    domain = url.split("/")[2] if "//" in url else "Google"
                    results.append({"title": title, "url": url, "snippet": snippet, "source": domain})
                    if len(results) >= limit:
                        break
            except Exception:
                continue
        
        return results
    except Exception:
        traceback.print_exc()
        return []


def _bing_web_scrape(query, limit=12):
    """Scrape Bing search results for broader web coverage"""
    try:
        res = requests.get(
            "https://www.bing.com/search",
            params={"q": query, "count": limit},
            headers={**HEADERS, "User-Agent": ESPN_HEADERS["User-Agent"]},
            timeout=10,
        )
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        results = []
        
        for result in soup.find_all("li", class_="b_algo"):
            try:
                link = result.find("a", href=True)
                if not link:
                    continue
                url = link["href"]
                
                title_elem = link.find("h2")
                title = title_elem.get_text(strip=True) if title_elem else ""
                
                snippet_elem = result.find("p")
                snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""
                
                if title and url:
                    domain = url.split("/")[2] if "//" in url else "Bing"
                    results.append({"title": title, "url": url, "snippet": snippet, "source": domain})
                    if len(results) >= limit:
                        break
            except Exception:
                continue
        
        return results
    except Exception:
        traceback.print_exc()
        return []



# ---------------------------------------------------------------------------
# SHOPPING SEARCH
# ---------------------------------------------------------------------------
# AetherScan's shopping tab uses the same web-search infrastructure as the
# normal search, but ranks pages that look like product listings and removes
# merchants the user asked not to show.
SHOPPING_BLOCKED_DOMAINS = {
    "aliexpress.com",
    "www.aliexpress.com",
    "temu.com",
    "www.temu.com",
}


def _shopping_domain_blocked(url):
    try:
        host = (urlparse(url or "").hostname or "").lower().removeprefix("www.")
        return host == "aliexpress.com" or host.endswith(".aliexpress.com") or host == "temu.com" or host.endswith(".temu.com")
    except Exception:
        return False


def search_shopping(query, limit=24):
    """Search for products while excluding AliExpress and Temu results."""
    q = (query or "").strip()
    if not q:
        return [], None

    # Adding commercial intent terms helps general search providers return
    # product/listing pages instead of encyclopedic or informational pages.
    search_query = f"{q} buy online price"
    results, err = search_the_entire_internet(search_query, sort="relevance")

    product_words = re.compile(
        r"\b(buy|shop|price|sale|deal|product|order|add to cart|in stock|shipping)\b",
        re.IGNORECASE,
    )
    price_pattern = re.compile(r"(?:[$£€¥]|NZ\$|AU\$|US\$)\s?\d+(?:[.,]\d{1,2})?")

    cleaned = []
    seen = set()
    for item in results:
        url = item.get("url") or ""
        if not url or _shopping_domain_blocked(url):
            continue
        key = url.split("#", 1)[0].rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        title = _repair_mojibake(item.get("title") or "")
        snippet = _repair_mojibake(item.get("snippet") or "")
        combined = f"{title} {snippet} {url}"
        commercial = len(product_words.findall(combined))
        prices = price_pattern.findall(combined)
        if commercial == 0 and not prices:
            continue
        item = dict(item)
        item["title"] = title
        item["snippet"] = snippet
        item["price"] = prices[0] if prices else ""
        item["domain"] = (urlparse(url).hostname or "").removeprefix("www.")
        item["favicon"] = f"https://www.google.com/s2/favicons?domain={quote(item['domain'])}&sz=32" if item["domain"] else ""
        item["shopping_score"] = commercial * 3 + (3 if prices else 0)
        cleaned.append(item)

    cleaned.sort(key=lambda x: x.get("shopping_score", 0), reverse=True)
    return cleaned[:limit], err


def search_the_entire_internet(query, site_filter=None, sort="relevance"):
    """
    Enhanced search that scrapes Google and Bing directly for broader web coverage.
    Returns results from multiple sources including generic web crawlers to access entire internet.
    """
    sources = [
        ("Wikipedia search failed", _wikipedia_results, (query,)),
        ("DuckDuckGo search failed", _duckduckgo_results, (query,)),
        ("DuckDuckGo instant-answer failed", _duckduckgo_instant_answer_as_list, (query,)),
        ("Google Web Scrape failed", _google_web_scrape, (query,)),
        ("Bing Web Scrape failed", _bing_web_scrape, (query,)),
        ("Yahoo Web search failed", _yahoo_web_results, (query,)),
        ("Stack Overflow search failed", _stackoverflow_results, (query,)),
        ("Hacker News search failed", _hackernews_results, (query,)),
        ("Wikipedia related-pages failed", _wikipedia_related_results, (query,)),
        ("Reddit search failed", _reddit_results, (query,)),
        ("arXiv search failed", _arxiv_results, (query,)),
    ]
    if BRAVE_API_KEY:
        sources.append(("Brave search failed", _brave_results, (query,)))
    if SERPAPI_API_KEY:
        sources.append(("SerpAPI search failed", _serpapi_results, (query,)))
    if BING_API_KEY:
        sources.append(("Bing API search failed", _bing_results, (query,)))
    if GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID:
        sources.append(("Google Custom Search failed", _google_cse_results, (query,)))

    results, seen_urls, errors = [], set(), []

    def _is_raw_local_game_result(result):
        """Exclude physical game HTML files from search results.

        The canonical game URL is /games/<slug>; files such as
        /games/1v1%20Fighter.html are implementation files and should not
        appear as separate results. This is deliberately limited to the
        local AetherScan host so normal web results are never affected.
        """
        try:
            parsed = urlparse(result.get("url") or "")
            host = (parsed.hostname or "").lower()
            path = unquote(parsed.path or "")
            return (
                host in {"127.0.0.1", "localhost", "0.0.0.0"}
                and re.fullmatch(r"/games/[^/]+\.html?", path, flags=re.IGNORECASE)
                is not None
            )
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        future_to_label = {pool.submit(fn, *args): label for label, fn, args in sources}
        for future in as_completed(future_to_label):
            label = future_to_label[future]
            try:
                for r in future.result():
                    url = r.get("url") or ""
                    # Do not index/display the physical game HTML files.
                    # A canonical /games/<slug> result is retained.
                    if _is_raw_local_game_result(r):
                        continue
                    normalized_url = url.split("#", 1)[0].rstrip("/")
                    if normalized_url not in seen_urls:
                        seen_urls.add(normalized_url)
                        # Repair mojibake only on local game results.
                        parsed = urlparse(url)
                        if (parsed.hostname or "").lower() in {"127.0.0.1", "localhost", "0.0.0.0"} and unquote(parsed.path or "").startswith("/games/"):
                            r["title"] = _repair_mojibake(r.get("title") or "")
                            r["snippet"] = _repair_mojibake(r.get("snippet") or "")
                        results.append(r)
            except Exception as e:
                traceback.print_exc()
                errors.append(f"{label}: {e}")

    if site_filter:
        results = [r for r in results if site_filter.lower() in (r.get("source") or "").lower()]

    results = _rank_results(results, query)
    if sort == "newest":
        priority = {"Hacker News": 0, "Stack Overflow": 1}
        results = sorted(results, key=lambda r: priority.get(r.get("source"), 2))

    err = "; ".join(errors) if errors and not results else None
    return results, err


def get_on_this_day(limit=4):
    """
    Homepage widget: a few historical events that happened on today's
    calendar date, via Wikipedia's own REST feed API -- free, no key,
    changes automatically every day since it's keyed off the real date.
    """
    try:
        now = datetime.utcnow()
        res = requests.get(
            f"https://en.wikipedia.org/api/rest_v1/feed/onthisday/selected/{now.month:02d}/{now.day:02d}",
            headers=HEADERS,
            timeout=8,
        )
        res.raise_for_status()
        data = res.json()
        events = []
        for item in data.get("selected", [])[:limit]:
            year, text = item.get("year"), item.get("text")
            pages = item.get("pages") or []
            url = f"https://en.wikipedia.org/wiki/{quote(pages[0]['title'])}" if pages and pages[0].get("title") else "https://en.wikipedia.org/wiki/Main_Page"
            if year and text:
                events.append({"year": year, "text": text, "url": url})
        return events
    except Exception:
        traceback.print_exc()
        return []


def get_spelling_suggestion(query):
    try:
        res = requests.get(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action": "query", "list": "search", "srsearch": query,
                "format": "json", "srlimit": 1, "srinfo": "suggestion",
            },
            headers=HEADERS,
            timeout=6,
        )
        res.raise_for_status()
        suggestion = res.json().get("query", {}).get("searchinfo", {}).get("suggestion")
        return suggestion or None
    except Exception:
        return None


OPENVERSE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://openverse.org/",
    "Origin": "https://openverse.org",
}
_openverse_session = requests.Session()
_openverse_session.headers.update(OPENVERSE_HEADERS)
_openverse_token = None
_openverse_token_expiry = 0


def _openverse_get_token():
    global _openverse_token, _openverse_token_expiry
    if _openverse_token and time.time() < _openverse_token_expiry:
        return _openverse_token
    res = requests.post(
        "https://api.openverse.org/v1/auth_tokens/token/",
        data={
            "client_id": OPENVERSE_CLIENT_ID,
            "client_secret": OPENVERSE_CLIENT_SECRET,
            "grant_type": "client_credentials",
        },
        timeout=8,
    )
    res.raise_for_status()
    data = res.json()
    _openverse_token = data["access_token"]
    _openverse_token_expiry = time.time() + data.get("expires_in", 43200) - 120
    return _openverse_token


def _openverse_get(params):
    if OPENVERSE_CLIENT_ID and OPENVERSE_CLIENT_SECRET:
        token = _openverse_get_token()
        res = requests.get(
            "https://api.openverse.org/v1/images/",
            params=params,
            headers={**OPENVERSE_HEADERS, "Authorization": f"Bearer {token}"},
            timeout=8,
        )
    else:
        res = _openverse_session.get("https://api.openverse.org/v1/images/", params=params, timeout=8)
    res.raise_for_status()
    return res.json()


def get_live_images(query, pages=3, page_size=20):
    all_results = []
    try:
        for page in range(1, pages + 1):
            data = _openverse_get({"q": query, "page_size": page_size, "page": page})
            page_results = data.get("results", [])
            if not page_results:
                break
            all_results.extend(page_results)
    except Exception as e:
        traceback.print_exc()
        if not all_results:
            return [], f"Image search failed: {e}"

    all_results.sort(key=lambda item: item.get("indexed_on") or "", reverse=True)

    images, seen = [], set()
    for item in all_results:
        thumb = item.get("thumbnail") or item.get("url")
        if thumb and thumb not in seen:
            seen.add(thumb)
            images.append(thumb)
    return images, None


def get_live_videos(query):
    q = quote(query)
    videos = [
        {"title": f"Search YouTube for \u201c{query}\u201d", "url": f"https://www.youtube.com/results?search_query={q}", "source": "YouTube"},
        {"title": f"Search Vimeo for \u201c{query}\u201d", "url": f"https://vimeo.com/search?q={q}", "source": "Vimeo"},
        {"title": f"Search Dailymotion for \u201c{query}\u201d", "url": f"https://www.dailymotion.com/search/{q}", "source": "Dailymotion"},
    ]
    return videos, None


# ---------------------------------------------------------------------------
# MOVIES: real search results (posters, ratings, overviews) via TMDb, plus
# real "where to watch" links via TMDb's watch-providers endpoint.
#
# HONEST LIMIT, please read: this tab gets you real movie DATA and real
# links OUT to streaming services -- it does NOT make Netflix/Disney+/Max/
# etc. actually PLAY video inside this app's browser tabs. That's a
# separate, much harder problem: those services require Widevine DRM,
# and the open-source PyQt6-WebEngine build (what `pip install
# PyQt6-WebEngine` gives you) does not include Widevine at all -- that's
# a Qt licensing/build decision, not something fixable from this file's
# Python code. Clicking a streaming link below will open that service
# normally in a tab; whether VIDEO PLAYS depends on Qt/Chromium's DRM
# support in your installed build, not on anything here.
# ---------------------------------------------------------------------------
_tmdb_session = requests.Session()


def _tmdb_get(path, params=None):
    p = dict(params or {})
    p["api_key"] = _effective_tmdb_key()
    res = _tmdb_session.get(f"https://api.themoviedb.org/3/{path}", params=p, timeout=8)
    res.raise_for_status()
    return res.json()


def _tmdb_watch_links(movie_id, region="US"):
    """
    Real 'where to stream this' links via TMDb's watch-providers endpoint
    -- genuine current availability (subscription/rent/buy), not guessed.
    Falls back to an empty list (not an error) if a title just isn't
    streaming anywhere tracked for that region, which is common and normal.
    """
    try:
        data = _tmdb_get(f"movie/{movie_id}/watch/providers")
        region_data = data.get("results", {}).get(region, {})
        # TMDb doesn't give deep-linkable per-provider URLs on the free
        # tier -- `link` below is their own aggregator page for this
        # title/region, which reliably lists every option; that's what
        # each provider chip opens.
        watch_page = region_data.get("link")
        providers = []
        seen = set()
        for bucket in ("flatrate", "free", "ads", "rent", "buy"):
            for p in region_data.get(bucket, []):
                name = p.get("provider_name")
                if name and name not in seen:
                    seen.add(name)
                    providers.append(name)
        return providers[:6], watch_page
    except Exception:
        return [], None


def get_live_movies(query, limit=16):
    if not _effective_tmdb_key():
        return [], (
            "Movies needs a free TMDb API key. Get one at "
            "https://www.themoviedb.org/signup (Settings -> API -> "
            "Request an API key -> Developer), then set it as the "
            "TMDB_API_KEY environment variable and restart the app."
        )
    try:
        data = _tmdb_get("search/movie", {"query": query, "include_adult": "false"})
    except Exception as e:
        traceback.print_exc()
        return [], f"Movie search failed: {e}"

    results = data.get("results", [])[:limit]

    # Watch-provider links are a separate request PER movie -- fetch them
    # concurrently rather than one at a time, same reasoning as the main
    # web search sources above.
    movies = []
    with ThreadPoolExecutor(max_workers=min(len(results), 8) or 1) as pool:
        future_to_movie = {pool.submit(_tmdb_watch_links, m["id"]): m for m in results if m.get("id")}
        watch_by_id = {}
        for future in as_completed(future_to_movie):
            m = future_to_movie[future]
            try:
                watch_by_id[m["id"]] = future.result()
            except Exception:
                watch_by_id[m["id"]] = ([], None)

    for m in results:
        title = m.get("title") or m.get("original_title")
        if not title:
            continue
        poster_path = m.get("poster_path")
        year = (m.get("release_date") or "")[:4]
        providers, watch_page = watch_by_id.get(m.get("id"), ([], None))
        movies.append(
            {
                "title": title,
                "year": year,
                "overview": m.get("overview", ""),
                "rating": round(m.get("vote_average", 0), 1) if m.get("vote_average") else None,
                "poster": f"{TMDB_IMAGE_BASE}{poster_path}" if poster_path else "",
                "tmdb_url": f"https://www.themoviedb.org/movie/{m['id']}",
                "watch_providers": providers,
                "watch_url": watch_page or f"https://www.themoviedb.org/movie/{m['id']}/watch",
            }
        )
    return movies, None




SITE_ALIASES = {
    "canva": "https://www.canva.com",
    "gmail": "https://mail.google.com",
    "grok": "https://grok.com",
    "claude": "https://claude.ai",
    "chatgpt": "https://chat.openai.com",
    "tvnz": "https://www.tvnz.co.nz",
    "makeplay": "https://makeplay.ai",
    "youtube": "https://www.youtube.com",
    "netflix": "https://www.netflix.com",
    "reddit": "https://www.reddit.com",
    "amazon": "https://www.amazon.com",
    "twitter": "https://x.com",
    "x": "https://x.com",
    "facebook": "https://www.facebook.com",
    "instagram": "https://www.instagram.com",
    "spotify": "https://open.spotify.com",
    "github": "https://github.com",
    "outlook": "https://outlook.com",
    # -- Movie/streaming site shortcuts, added on request.
    "disney": "https://www.disneyplus.com",
    "disneyplus": "https://www.disneyplus.com",
    "disney+": "https://www.disneyplus.com",
    "hulu": "https://www.hulu.com",
    "max": "https://www.max.com",
    "hbomax": "https://www.max.com",
    "primevideo": "https://www.primevideo.com",
    "prime video": "https://www.primevideo.com",
    "appletv": "https://tv.apple.com",
    "apple tv": "https://tv.apple.com",
    "paramount": "https://www.paramountplus.com",
    "paramountplus": "https://www.paramountplus.com",
    "peacock": "https://www.peacocktv.com",
    "imdb": "https://www.imdb.com",
    "tmdb": "https://www.themoviedb.org",
    "letterboxd": "https://letterboxd.com",
}

WEBSITE_INFO = {
    "canva": ("Canva", "Visual design and publishing platform", "Create presentations, posters, social graphics, videos, and other visual content online."),
    "tvnz": ("TVNZ", "New Zealand television and streaming service", "Watch TVNZ news, shows, sport, and on-demand programming online."),
    "youtube": ("YouTube", "Video-sharing and streaming platform", "Watch, upload, and share videos, live streams, music, and educational content."),
    "github": ("GitHub", "Software development platform", "Host code, collaborate on projects, review changes, and manage software development workflows."),
    "spotify": ("Spotify", "Music and audio streaming service", "Stream music, podcasts, and other audio from a large online catalog."),
    "reddit": ("Reddit", "Community discussion platform", "Discover communities where people share links, questions, news, and conversations."),
    "instagram": ("Instagram", "Photo and video sharing platform", "Share photos, videos, stories, and messages with people and communities."),
    "netflix": ("Netflix", "Subscription video streaming service", "Watch films, television series, documentaries, and original productions online."),
    "amazon": ("Amazon", "Online shopping and services company", "Shop for products online and access Amazon's broader digital and delivery services."),
    "gmail": ("Gmail", "Email service by Google", "Send, receive, organize, and search email through Google's webmail service."),
    "github": ("GitHub", "Software development platform", "Host code, collaborate on projects, review changes, and manage software development workflows."),
}


_DOMAIN_PATTERN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", re.IGNORECASE)


def _resolve_direct_site(query):
    q = query.strip()
    ql = q.lower()

    if ql in SITE_ALIASES:
        return SITE_ALIASES[ql]
    if q.startswith("http://") or q.startswith("https://"):
        return q
    if " " not in q and _DOMAIN_PATTERN.match(q):
        return f"https://{q}"
    return None


def _website_overview(query):
    """Return a useful branded card for a known website search."""
    normalized = query.strip().lower()
    if normalized in WEBSITE_INFO:
        title, subtitle, description = WEBSITE_INFO[normalized]
        url = SITE_ALIASES[normalized]
        return (
            f"{title} is a {subtitle.lower()}. {description}",
            {
                "title": title,
                "subtitle": subtitle,
                "desc": description,
                "link": url,
                "link_label": f"Open {title}",
            },
        )
    if normalized in SITE_ALIASES:
        url = SITE_ALIASES[normalized]
        title = normalized.replace("+", " ").replace("-", " ").title()
        return (
            f"{title} is an online website available at {url}.",
            {
                "title": title,
                "subtitle": "Website",
                "desc": f"Visit {title} directly using the link below.",
                "link": url,
                "link_label": f"Open {title}",
            },
        )
    return None


def _normalize_for_about(text):
    text = text.lower().strip().replace("\u00e6", "ae")
    return re.sub(r"[^a-z0-9]", "", text)


# Queries that trigger the "about AetherScan" answer instead of a normal
# search -- normalized the same way _normalize_for_about() normalizes the
# user's query, so e.g. "Who made AetherScan?" and "who made aetherscan"
# both match.
ABOUT_TRIGGERS = {
    _normalize_for_about(t) for t in (
        "aetherscan",
        "about aetherscan",
        "what is aetherscan",
        "who made aetherscan",
        "who made this",
        "who created aetherscan",
        "who built aetherscan",
        "about this app",
        "about this website",
    )
}


def get_about_aetherscan():
    ai_overview = (
        "AetherScan is a personal search app created by Oscar Hou, first built on "
        "September 1, 2026. It's a from-scratch search engine and browser: real "
        "web results pulled live from Wikipedia and DuckDuckGo, image search via "
        "Openverse, sports scores/news via ESPN, interactive maps via OpenStreetMap, "
        "and its own tabbed in-app browser -- built with Python, Flask, and PyQt6."
    )
    infobox = {
        "title": "AetherScan",
        "subtitle": "Personal search app \u2022 created by Oscar Hou \u2022 2026-09-01",
        "desc": (
            "A search engine and desktop browser built from scratch: web, image, "
            "video, sports, and map search combined into one native app, with "
            "genuine live data pulled from free, key-free public APIs rather than "
            "any single search provider."
        ),
    }
    return ai_overview, infobox


_MATH_EXPR_PATTERN = re.compile(r"^[\d\s.\+\-\*/()%^]+$")
_MATH_ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod,
    ast.FloorDiv, ast.USub, ast.UAdd,
)


def _try_calculate(query):
    q = query.strip()
    if not q or not any(ch.isdigit() for ch in q) or not _MATH_EXPR_PATTERN.match(q):
        return None
    try:
        tree = ast.parse(q.replace("^", "**"), mode="eval")
        for node in ast.walk(tree):
            if not isinstance(node, _MATH_ALLOWED_NODES):
                return None
        return eval(compile(tree, "<calc>", "eval"))
    except Exception:
        return None


_UNIT_ALIASES = {
    "km": "km", "kilometer": "km", "kilometre": "km", "kilometers": "km", "kilometres": "km",
    "mi": "mi", "mile": "mi", "miles": "mi",
    "kg": "kg", "kilogram": "kg", "kilograms": "kg", "kgs": "kg",
    "lb": "lb", "lbs": "lb", "pound": "lb", "pounds": "lb",
    "c": "c", "celsius": "c",
    "f": "f", "fahrenheit": "f",
    "m": "m", "meter": "m", "meters": "m", "metre": "m", "metres": "m",
    "ft": "ft", "foot": "ft", "feet": "ft",
    "cm": "cm", "centimeter": "cm", "centimeters": "cm", "centimetre": "cm", "centimetres": "cm",
    "in": "in", "inch": "in", "inches": "in",
    "l": "l", "liter": "l", "liters": "l", "litre": "l", "litres": "l",
    "gal": "gal", "gallon": "gal", "gallons": "gal",
}
_CONVERSIONS = {
    ("km", "mi"): lambda x: x * 0.621371, ("mi", "km"): lambda x: x * 1.60934,
    ("kg", "lb"): lambda x: x * 2.20462, ("lb", "kg"): lambda x: x * 0.453592,
    ("c", "f"): lambda x: x * 9 / 5 + 32, ("f", "c"): lambda x: (x - 32) * 5 / 9,
    ("m", "ft"): lambda x: x * 3.28084, ("ft", "m"): lambda x: x / 3.28084,
    ("cm", "in"): lambda x: x / 2.54, ("in", "cm"): lambda x: x * 2.54,
    ("l", "gal"): lambda x: x * 0.264172, ("gal", "l"): lambda x: x / 0.264172,
}
_CONVERT_PATTERN = re.compile(r"^([\d.]+)\s*([a-zA-Z]+)\s+(?:to|in)\s+([a-zA-Z]+)$", re.IGNORECASE)


def _try_convert(query):
    m = _CONVERT_PATTERN.match(query.strip())
    if not m:
        return None
    value_s, from_raw, to_raw = m.groups()
    from_u, to_u = _UNIT_ALIASES.get(from_raw.lower()), _UNIT_ALIASES.get(to_raw.lower())
    convert_fn = _CONVERSIONS.get((from_u, to_u)) if from_u and to_u else None
    if not convert_fn:
        return None
    try:
        value = float(value_s)
    except ValueError:
        return None
    return value, from_raw, convert_fn(value), to_raw


_DEFINE_PATTERN = re.compile(r"^(?:define|definition of|what does)\s+([a-zA-Z\- ]+?)(?:\s+mean)?\??$", re.IGNORECASE)


_CURRENCY_CODES = {
    "usd", "eur", "gbp", "nzd", "aud", "cad", "jpy", "cny", "inr", "chf",
    "sgd", "hkd", "krw", "mxn", "brl", "zar", "sek", "nok", "dkk", "pln",
    "thb", "idr", "myr", "php", "vnd", "try", "rub", "aed", "sar", "ils",
}


def _try_convert_currency(query):
    """
    Same regex shape as _try_convert() above ("20 usd to nzd") but for
    currency pairs instead of physical units -- kept as a separate
    function/codepath since the conversion factor isn't a fixed constant,
    it has to be fetched live. open.er-api.com is free, no key required,
    updates daily.
    """
    m = _CONVERT_PATTERN.match(query.strip())
    if not m:
        return None
    value_s, from_raw, to_raw = m.groups()
    from_c, to_c = from_raw.lower(), to_raw.lower()
    if from_c not in _CURRENCY_CODES or to_c not in _CURRENCY_CODES:
        return None
    try:
        value = float(value_s)
    except ValueError:
        return None
    try:
        res = requests.get(f"https://open.er-api.com/v6/latest/{from_c.upper()}", timeout=6)
        res.raise_for_status()
        data = res.json()
        rate = data.get("rates", {}).get(to_c.upper())
        if not rate:
            return None
        return value, from_c.upper(), value * rate, to_c.upper()
    except Exception:
        traceback.print_exc()
        return None


_TIME_QUERY_PATTERN = re.compile(
    r"^(?:what(?:'s| is)?\s+)?(?:the\s+)?(?:current\s+)?time\s+(?:is\s+it\s+)?in\s+(.+?)\??$",
    re.IGNORECASE,
)


def _try_time_query(query):
    """
    'what time is it in X' / 'time in X' -- geocodes X via Nominatim (the
    same geocoder the Maps tab already uses), then asks Open-Meteo's
    forecast endpoint for that lat/lon with timezone=auto. Open-Meteo
    already returns the current LOCAL time and IANA timezone name
    directly in that response (it's what get_weather() above quietly
    relies on too) -- no separate timezone-lookup API or library needed.
    """
    m = _TIME_QUERY_PATTERN.match(query.strip())
    if not m:
        return None
    place = m.group(1).strip()
    if not place:
        return None
    try:
        raw, err = _nominatim_search({"q": place, "format": "jsonv2", "limit": 1})
        if err or not raw:
            return None
        lat, lon = float(raw[0]["lat"]), float(raw[0]["lon"])
        display_name = (raw[0].get("display_name") or place).split(",")[0]

        res = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params={"latitude": lat, "longitude": lon, "current": "temperature_2m", "timezone": "auto"},
            timeout=8,
        )
        res.raise_for_status()
        data = res.json()
        local_time = data.get("current", {}).get("time")
        tz_name = data.get("timezone", "")
        if not local_time:
            return None
        dt = datetime.fromisoformat(local_time)
        formatted = dt.strftime("%I:%M %p").lstrip("0") + f" on {dt.strftime('%A, %B %-d, %Y')}"
        return display_name, formatted, tz_name
    except Exception:
        traceback.print_exc()
        return None


_QR_PATTERN = re.compile(r"^qr(?:\s*code)?\s*[:\-]?\s+(.+)$", re.IGNORECASE)


def _try_qr(query):
    m = _QR_PATTERN.match(query.strip())
    if not m:
        return None
    text = m.group(1).strip()
    return text or None


_PASSWORD_PATTERN = re.compile(r"^(?:generate|create|make)\s+(?:a\s+|me\s+a\s+)?(?:random\s+)?password$", re.IGNORECASE)


def _try_password(query):
    if not _PASSWORD_PATTERN.match(query.strip()):
        return None
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(16))


def _try_define(query):
    m = _DEFINE_PATTERN.match(query.strip())
    if not m:
        return None
    word = m.group(1).strip()
    if not word:
        return None
    res = requests.get(f"https://api.dictionaryapi.dev/api/v2/entries/en/{quote(word)}", headers=HEADERS, timeout=6)
    if res.status_code != 200:
        return None
    data = res.json()
    if not data or not isinstance(data, list):
        return None
    meanings = data[0].get("meanings", [])
    parts = []
    for meaning in meanings[:3]:
        pos = meaning.get("partOfSpeech", "")
        defs = meaning.get("definitions", [])
        if defs and defs[0].get("definition"):
            parts.append(f"({pos}) {defs[0]['definition']}")
    return (word, parts) if parts else None


def get_smart_overview(query):
    website = _website_overview(query)
    if website is not None:
        return website[0], website[1], None, []

    if _normalize_for_about(query) in ABOUT_TRIGGERS:
        ai_overview, infobox = get_about_aetherscan()
        return ai_overview, infobox, None, []

    calc_result = _try_calculate(query)
    if calc_result is not None:
        display = f"{calc_result:g}" if isinstance(calc_result, float) else str(calc_result)
        ai_overview = f"{query.strip()} = {display}"
        infobox = {"title": display, "subtitle": "Calculator", "desc": f"{query.strip()} = {display}"}
        return ai_overview, infobox, None, []

    try:
        conversion = _try_convert(query)
    except Exception:
        conversion = None
    if conversion is not None:
        value, from_u, result, to_u = conversion
        ai_overview = f"{value:g} {from_u} = {result:.4g} {to_u}"
        infobox = {"title": f"{value:g} {from_u}", "subtitle": "Unit conversion", "desc": f"= {result:.4g} {to_u}"}
        return ai_overview, infobox, None, []

    try:
        currency = _try_convert_currency(query)
    except Exception:
        traceback.print_exc()
        currency = None
    if currency is not None:
        value, from_c, result, to_c = currency
        ai_overview = f"{value:,.2f} {from_c} = {result:,.2f} {to_c}"
        infobox = {"title": f"{result:,.2f} {to_c}", "subtitle": "Currency conversion (live rate)", "desc": f"{value:,.2f} {from_c} = {result:,.2f} {to_c}"}
        return ai_overview, infobox, None, []

    try:
        time_result = _try_time_query(query)
    except Exception:
        traceback.print_exc()
        time_result = None
    if time_result is not None:
        display_name, formatted, tz_name = time_result
        ai_overview = f"The current time in {display_name} is {formatted} ({tz_name})."
        infobox = {"title": formatted.split(" on ")[0], "subtitle": f"{display_name} \u2014 {tz_name}", "desc": formatted}
        return ai_overview, infobox, None, []

    qr_text = _try_qr(query)
    if qr_text is not None:
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=260x260&data={quote(qr_text)}"
        ai_overview = f"QR code for \u201c{qr_text}\u201d \u2014 scan with your phone's camera."
        infobox = {"title": "QR Code", "subtitle": qr_text[:60], "desc": "Scan with your phone's camera.", "image": qr_url}
        return ai_overview, infobox, None, []

    password_result = _try_password(query)
    if password_result is not None:
        ai_overview = f"Generated password: {password_result}"
        infobox = {"title": password_result, "subtitle": "Random 16-character password", "desc": "Generated locally, not stored anywhere. Use once and don't reuse across sites."}
        return ai_overview, infobox, None, []

    try:
        definition = _try_define(query)
    except Exception:
        traceback.print_exc()
        definition = None
    if definition is not None:
        word, parts = definition
        ai_overview = f"{word.title()}: " + " \u2014 ".join(parts)
        infobox = {"title": word.title(), "subtitle": "Definition", "desc": " ".join(parts)}
        return ai_overview, infobox, None, []

    return get_ai_overview_and_wiki(query)


def _overview_context(base_overview, web_results):
    """Format compact, labelled evidence for an answer model."""
    context_lines = []
    if base_overview:
        context_lines.append(f"[Wikipedia summary] {base_overview}")
    for index, result in enumerate(web_results[:10], 1):
        source = result.get("source", "web")
        title = result.get("title", "Untitled result")
        snippet = result.get("snippet", "").strip()
        url = result.get("url", "")
        context_lines.append(f"[Source {index} | {source}] {title}\n{snippet}\nURL: {url}")
    return "\n\n".join(context_lines)[:10000]


def _overview_prompt(query, base_overview, web_results):
    context = _overview_context(base_overview, web_results)
    return (
        "You are the answer engine inside AetherScan. Answer the user's actual question, "
        "not merely the topic suggested by the first search result. Use the evidence below "
        "as your primary source.\n"
        "Rules:\n"
        "- Lead with the direct answer in the first sentence.\n"
        "- Explain the key reasoning or context in 2-5 concise sentences.\n"
        "- Use exact names, dates, quantities, and steps when the evidence supports them.\n"
        "- Cite supporting claims inline as [Source 1], [Source 2], etc. using the labels below.\n"
        "- Do not invent facts, fill gaps with confident guesses, or treat a search snippet as proof.\n"
        "- If the evidence does not answer the question, say what is missing and give the most useful "
        "qualified answer you can.\n"
        "- If sources disagree, describe the disagreement and prefer the more current or authoritative source.\n"
        "- Plain text only: no heading, markdown table, or preamble like 'based on the sources'.\n\n"
        f"Question: {query}\n\nEvidence:\n{context or '[No usable search evidence was returned.]'}"
    )


_QUESTION_STOPWORDS = {
    "a", "an", "and", "are", "be", "can", "could", "did", "do", "does", "for", "from",
    "how", "i", "in", "is", "it", "me", "of", "on", "or", "the", "to", "was", "what",
    "when", "where", "which", "who", "why", "with", "would", "list", "most",
}


def _topic_terms(text):
    return {
        term.rstrip("s")
        for term in re.findall(r"[a-z]{3,}", text.lower())
        if term not in _QUESTION_STOPWORDS
    }


def _is_relevant_wikipedia_match(query, title):
    query_terms = _topic_terms(query)
    title_terms = _topic_terms(title)
    if not query_terms or not title_terms:
        return False
    overlap = query_terms & title_terms
    return bool(overlap)


def enhance_overview_with_gemini(query, base_overview, web_results):
    """
    Optional: if GEMINI_API_KEY is set, ask Gemini to write a better,
    more natural AI Overview -- grounded in the Wikipedia extract and top
    web results already fetched, so it's summarizing real content rather
    than answering purely from its own training data (lower hallucination
    risk, and it can say "the sources don't really answer this" instead
    of guessing). On any failure -- bad key, rate limit, model renamed --
    this quietly falls back to the plain overview rather than breaking
    the page.

    STILL EXACTLY ONE API CALL per search (same as before) -- the quality
    improvement here comes from feeding it more of the real results we
    already fetched for the page anyway (free -- no extra network cost)
    and a more deliberate prompt, not from calling Gemini more often. That
    matters for staying inside a free-tier rate/quota limit: this function
    is called at most once per search regardless of how rich the answer is.
    """
    if not _effective_gemini_key():
        return base_overview

    prompt = _overview_prompt(query, base_overview, web_results)
    try:
        text = _gemini_generate_text(prompt)
        return text or base_overview
    except Exception:
        traceback.print_exc()
        return base_overview


def get_ai_overview_and_wiki(query):
    try:
        res = requests.get(
            "https://en.wikipedia.org/w/api.php",
            params={"action": "query", "list": "search", "srsearch": query, "format": "json", "srlimit": 5},
            headers=HEADERS,
            timeout=8,
        )
        res.raise_for_status()
        matches = res.json().get("query", {}).get("search", [])
        match = next(
            (item for item in matches if _is_relevant_wikipedia_match(query, item.get("title", ""))),
            None,
        )
        if not match:
            return (
                f"I couldn't find a reliable summary for \u201c{query}\u201d. "
                "Try the web results below, or add an AI API key for a synthesized answer.",
                None,
                None,
                [],
            )

        matched_title = match["title"]
        summary_res = requests.get(
            f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(matched_title.replace(' ', '_'))}",
            headers=HEADERS,
            timeout=8,
        )
        summary_res.raise_for_status()
        data = summary_res.json()
        desc_text = data.get("extract", "")
        description = data.get("description", "topic")
        ai_overview = f"{matched_title} \u2014 {description}. {desc_text}"
        related = []
        try:
            rel_res = requests.get(
                f"https://en.wikipedia.org/api/rest_v1/page/related/{quote(matched_title.replace(' ', '_'))}",
                headers=HEADERS,
                timeout=6,
            )
            rel_res.raise_for_status()
            for page in rel_res.json().get("pages", [])[:5]:
                title = page.get("title")
                if title:
                    related.append({"title": title, "url": f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"})
        except Exception:
            pass

        wiki_card = {
            "title": data.get("title", matched_title),
            "subtitle": description,
            "desc": desc_text,
        }
        return ai_overview, wiki_card, None, related
    except Exception as e:
        traceback.print_exc()
        return f"No summary found for \u201c{query}\u201d.", None, f"AI overview failed: {e}", []


_COMPARE_PATTERN = re.compile(r"^(.+?)\s+(?:vs\.?|versus)\s+(.+)$", re.IGNORECASE)


def _try_compare(query):
    m = _COMPARE_PATTERN.match(query.strip())
    if not m:
        return None
    item_a, item_b = m.group(1).strip(), m.group(2).strip()
    if not item_a or not item_b:
        return None
    return item_a, item_b


def get_comparison(item_a, item_b, web_results):
    """
    'X vs Y' searches: asks whichever AI provider is available (same
    priority order as chat -- Gemini, then Claude, then Groq) to return a
    strict-JSON side-by-side comparison, grounded in the same web results
    already fetched for the normal search results list. Returns None
    (falls back to a normal search page) if no provider is configured or
    the AI's response doesn't parse as the expected shape -- this is a
    bonus rendering on top of the normal results, never a replacement
    that could break the page if it fails.
    """
    provider = _ai_chat_provider()
    if not provider:
        return None

    context_lines = [f"[{r.get('source', 'web')}] {r.get('title', '')}: {r.get('snippet', '')}" for r in web_results[:8]]
    context = "\n".join(context_lines)[:6000]
    prompt = (
        f'Compare "{item_a}" vs "{item_b}". Use the context below where it\'s relevant; you may '
        "supplement with your own well-established knowledge, but never invent specific numbers "
        "or facts you're not confident about. Respond with STRICT JSON ONLY -- no markdown code "
        "fences, no commentary before or after -- in exactly this shape:\n"
        '{"categories": [{"label": "short category name", "a": "value for item A", "b": "value for item B"}], '
        '"verdict": "one or two sentence overall takeaway"}\n'
        "Include 4 to 7 categories genuinely relevant to comparing these two specific things. "
        "Keep each cell under 12 words.\n\n"
        f"Context:\n{context}"
    )

    try:
        if provider == "gemini":
            text = _gemini_generate_text(prompt)
        elif provider == "claude":
            res = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": _effective_anthropic_key(),
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={"model": ANTHROPIC_MODEL, "max_tokens": 800, "messages": [{"role": "user", "content": prompt}]},
                timeout=20,
            )
            res.raise_for_status()
            text = "".join(b.get("text", "") for b in res.json().get("content", []) if b.get("type") == "text")
        else:
            res = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {_effective_groq_key()}", "Content-Type": "application/json"},
                json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}]},
                timeout=20,
            )
            res.raise_for_status()
            text = res.json()["choices"][0]["message"]["content"]

        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
            text = text.strip()

        data = json.loads(text)
        categories = data.get("categories") or []
        if not categories:
            return None
        return {
            "item_a": item_a,
            "item_b": item_b,
            "categories": categories[:8],
            "verdict": data.get("verdict", ""),
        }
    except Exception:
        traceback.print_exc()
        return None


def _ai_chat_provider():
    """Which AI provider is usable right now, if any -- Gemini preferred
    (it's the free-tier option), then Claude, then Groq (also free,
    no card required -- the fallback for when Gemini's AQ. keys are
    broken and Claude isn't an option). Checks the signed-in user's own
    key (Settings page) before the server's environment-variable key."""
    if _effective_gemini_key():
        return "gemini"
    if _effective_anthropic_key():
        return "claude"
    if _effective_groq_key():
        return "groq"
    return None


def _get_grounding_context(query, limit=4):
    """
    Quick, live web context for the chat to ground its answer in -- reuses
    the same real sources the search tabs use (Wikipedia, DuckDuckGo,
    etc.), so the assistant can actually look things up ("research") rather
    than answer purely from its training data. Best-effort: if this fails
    for any reason, the chat still works, just without fresh grounding.
    """
    try:
        results, _ = search_the_entire_internet(query)
        return results[:limit]
    except Exception:
        traceback.print_exc()
        return []


def _raise_with_api_error_detail(res, provider_name):
    """
    res.raise_for_status() alone only gives a generic message like
    "400 Client Error: Bad Request for url: ..." -- it throws away the
    actual JSON error body the API sent back, which is where the REAL
    reason lives (e.g. "API key not valid", "model not found", "quota
    exceeded"). This reads that body first and raises a RuntimeError
    with it included, so failures are actually diagnosable instead of
    just "Bad Request".
    """
    if res.ok:
        return
    detail = None
    try:
        body = res.json()
        detail = (
            body.get("error", {}).get("message")  # Gemini's shape
            or (body.get("error") if isinstance(body.get("error"), str) else None)  # Claude's shape sometimes
            or body.get("error", {}).get("type")
        )
    except Exception:
        detail = (res.text or "")[:300]
    raise RuntimeError(f"{provider_name} API error {res.status_code}: {detail or 'no further detail returned'}")


def _gemini_generate_text(contents):
    """Call Gemini through Google's current GenAI SDK and return plain text."""
    if not _effective_gemini_key():
        raise RuntimeError("GEMINI_API_KEY is not configured")
    try:
        from google import genai
    except ImportError as exc:
        raise RuntimeError("Install the current Gemini client with: python -m pip install -U google-genai") from exc

    client = genai.Client(api_key=_effective_gemini_key())
    response = client.models.generate_content(model=GEMINI_MODEL, contents=contents)
    text = getattr(response, "text", None)
    if not text:
        raise RuntimeError("Gemini returned no text")
    return text.strip()


def _call_gemini_chat(history, grounding):
    """history is a list of {'role': 'user'|'assistant', 'content': str},
    oldest first. Gemini's API calls the assistant role 'model'."""
    contents = []
    if grounding:
        ctx = "\n".join(
            f"[Source {i}] {r.get('title', '')}: {r.get('snippet', '')} URL: {r.get('url', '')}"
            for i, r in enumerate(grounding, 1)
        )[:5000]
        contents.append({
            "role": "user",
            "parts": [{"text": (
                "For context, here are some current, real web search results that might be relevant "
                "to this conversation. Use them if they're actually helpful; ignore them if they're not, "
                "answer the question directly, and cite useful evidence as [Source 1], [Source 2], etc. "
                "Never pretend a fact came from search if it didn't:\n" + ctx
            )}],
        })
        contents.append({"role": "model", "parts": [{"text": "Understood, I'll use those if relevant."}]})
    for turn in history:
        contents.append({"role": "model" if turn["role"] == "assistant" else "user", "parts": [{"text": turn["content"]}]})

    return _gemini_generate_text(contents)


def _call_groq_chat(history, grounding):
    """
    Groq's API is OpenAI-compatible chat completions -- different request
    AND response shape than Gemini/Claude (messages list with a leading
    'system' role message, reply lives at choices[0].message.content).
    Free tier, no card required -- the fallback for when Gemini's AQ.
    keys are broken and Anthropic's paid tier isn't an option.
    """
    messages = [{
        "role": "system",
        "content": "You are a helpful research assistant embedded in a search engine called AetherScan.",
    }]
    if grounding:
        ctx = "\n".join(
            f"[Source {i}] {r.get('title', '')}: {r.get('snippet', '')} URL: {r.get('url', '')}"
            for i, r in enumerate(grounding, 1)
        )[:5000]
        messages.append({
            "role": "system",
            "content": (
                "Here are some current, real web search results that might be relevant to this "
                "conversation -- use them if helpful, answer the actual question directly, and "
                "never claim a fact came from search if it didn't. Cite useful evidence as [Source 1], "
                "[Source 2], etc.:\n" + ctx
            ),
        })
    for turn in history:
        messages.append({"role": turn["role"], "content": turn["content"]})

    res = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {_effective_groq_key()}",
            "Content-Type": "application/json",
        },
        json={"model": GROQ_MODEL, "messages": messages},
        timeout=25,
    )
    _raise_with_api_error_detail(res, "Groq")
    data = res.json()
    return data["choices"][0]["message"]["content"].strip()


def enhance_overview_with_groq(query, base_overview, web_results):
    """
    Groq equivalent of enhance_overview_with_gemini() -- same idea (write
    a better AI Overview grounded in real search results already
    fetched), used only when there's no usable Gemini key. Same
    fail-quiet behavior: any error just falls back to the plain overview.
    """
    if not _effective_groq_key():
        return base_overview

    prompt = _overview_prompt(query, base_overview, web_results)
    try:
        res = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {_effective_groq_key()}",
                "Content-Type": "application/json",
            },
            json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}]},
            timeout=15,
        )
        res.raise_for_status()
        data = res.json()
        text = data["choices"][0]["message"]["content"].strip()
        return text or base_overview
    except Exception:
        traceback.print_exc()
        return base_overview


def enhance_overview_with_claude(query, base_overview, web_results):
    """Generate a grounded overview with Claude when it is the active provider."""
    if not _effective_anthropic_key():
        return base_overview

    try:
        res = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": _effective_anthropic_key(),
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 900,
                "system": "Answer questions accurately from the supplied evidence. Never invent missing facts.",
                "messages": [{"role": "user", "content": _overview_prompt(query, base_overview, web_results)}],
            },
            timeout=15,
        )
        _raise_with_api_error_detail(res, "Claude")
        text = "".join(
            block.get("text", "")
            for block in res.json().get("content", [])
            if block.get("type") == "text"
        ).strip()
        return text or base_overview
    except Exception:
        traceback.print_exc()
        return base_overview


def _call_claude_chat(history, grounding):
    messages = list(history)
    system = (
        "You are the research assistant embedded in AetherScan. Answer the user's actual question "
        "directly, lead with the answer, separate sourced facts from uncertainty, and never invent "
        "details that are not supported by the evidence or your clearly stated general knowledge."
    )
    if grounding:
        ctx = "\n".join(
            f"[Source {i}] {r.get('title', '')}: {r.get('snippet', '')} URL: {r.get('url', '')}"
            for i, r in enumerate(grounding, 1)
        )[:5000]
        system += (
            " Here are some current, real web search results that might be relevant to this "
            "conversation -- use them if helpful, ignore them if not, and never claim a fact came "
            "from search if it didn't. Cite them as [Source 1], [Source 2], etc. when used:\n" + ctx
        )
    res = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": _effective_anthropic_key(),
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": ANTHROPIC_MODEL,
            "max_tokens": 1024,
            "system": system,
            "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
        },
        timeout=25,
    )
    _raise_with_api_error_detail(res, "Claude")
    data = res.json()
    return "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text").strip()


@app.route("/api/chat", methods=["POST"])
def api_chat():
    _apply_user_ai_settings()
    provider = _ai_chat_provider()
    if not provider:
        return jsonify({
            "error": (
                "AI Chat needs a free API key. Get one at https://console.groq.com/keys "
                "(genuinely free, no card) and set it as the GROQ_API_KEY environment variable "
                "-- or GEMINI_API_KEY / ANTHROPIC_API_KEY if you'd rather use Gemini or Claude "
                "instead -- then restart the app. Or, if you're signed in, add your own key on "
                "your Settings page instead."
            )
        }), 400

    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip()
    history = payload.get("history") or []
    if not message:
        return jsonify({"error": "Empty message."}), 400
    if not isinstance(history, list):
        history = []
    # keep the payload bounded -- last 12 turns is plenty of context for a search-engine sidebar chat
    history = [h for h in history if isinstance(h, dict) and h.get("role") in ("user", "assistant") and h.get("content")][-12:]
    history.append({"role": "user", "content": message})

    grounding = _get_grounding_context(message)

    try:
        if provider == "gemini":
            reply = _call_gemini_chat(history, grounding)
        elif provider == "claude":
            reply = _call_claude_chat(history, grounding)
        else:
            reply = _call_groq_chat(history, grounding)
        sources = [{"title": r.get("title"), "url": r.get("url")} for r in grounding]
        return jsonify({"reply": reply, "sources": sources, "provider": provider})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"{provider.title()} request failed: {e}"}), 502


LEAGUES = {
    "eng.1":  ("soccer", "eng.1", "Premier League"),
    "esp.1":  ("soccer", "esp.1", "La Liga"),
    "ger.1":  ("soccer", "ger.1", "Bundesliga"),
    "ita.1":  ("soccer", "ita.1", "Serie A"),
    "fra.1":  ("soccer", "fra.1", "Ligue 1"),
    "usa.1":  ("soccer", "usa.1", "MLS"),
    "uefa.champions": ("soccer", "uefa.champions", "Champions League"),
    "nfl":    ("football", "nfl", "NFL"),
    "college-football": ("football", "college-football", "NCAA Football"),
    "nba":    ("basketball", "nba", "NBA"),
    "wnba":   ("basketball", "wnba", "WNBA"),
    "mens-college-basketball": ("basketball", "mens-college-basketball", "NCAA Men's Basketball"),
    "womens-college-basketball": ("basketball", "womens-college-basketball", "NCAA Women's Basketball"),
    "mlb":    ("baseball", "mlb", "MLB"),
    "nhl":    ("hockey", "nhl", "NHL"),
    "aus.1":  ("soccer", "aus.1", "A-League (Australia)"),
    "sco.1":  ("soccer", "sco.1", "Scottish Premiership"),
    "ned.1":  ("soccer", "ned.1", "Eredivisie"),
    "bra.1":  ("soccer", "bra.1", "Brasileir\u00e3o"),
    "por.1":  ("soccer", "por.1", "Primeira Liga"),
    "netball": ("thesportsdb", "Netball", "Netball (ANZ Premiership)"),
    "mtb":     ("thesportsdb", "Cycling", "Mountain Biking (UCI MTB)"),
}


def _espn_get(path, params=None):
    _espn_warm_up()
    url = f"https://site.api.espn.com/apis/site/v2/sports/{path}"
    res = _espn_session.get(url, params=params, timeout=8)

    if res.status_code == 403:
        global _espn_warmed_up
        _espn_warmed_up = False
        _espn_warm_up()
        res = _espn_session.get(url, params=params, timeout=8)

    if res.status_code == 403:
        raise requests.HTTPError(
            "ESPN is blocking this server's requests (403) even with a full "
            "browser-like session. This usually means the network you're "
            "running on is a datacenter/VPS IP that ESPN's bot protection "
            "blocks outright, regardless of headers -- it's less likely to "
            "happen on a home internet connection."
        )
    res.raise_for_status()
    return res.json()


def find_team(league_key, team_query):
    sport, league, _ = LEAGUES[league_key]
    data = _espn_get(f"{sport}/{league}/teams", params={"limit": 1000})

    teams = []
    for s in data.get("sports", []):
        for lg in s.get("leagues", []):
            teams.extend(lg.get("teams", []))

    q = team_query.strip().lower()
    best = None
    for entry in teams:
        team = entry.get("team", entry)
        names = [
            team.get("displayName", ""),
            team.get("name", ""),
            team.get("shortDisplayName", ""),
            team.get("location", ""),
            team.get("abbreviation", ""),
        ]
        names_lower = [n.lower() for n in names if n]
        if q in names_lower:
            return team
        if any(q in n for n in names_lower) and best is None:
            best = team
    return best


def get_team_games(sport, league, team_id):
    previous, upcoming = [], []
    data = _espn_get(f"{sport}/{league}/teams/{team_id}/schedule")
    for event in data.get("events", []):
        date = event.get("date", "")
        name = event.get("name") or event.get("shortName", "Match")
        competition = (event.get("competitions") or [{}])[0]
        status = competition.get("status", {}).get("type", {})
        completed = status.get("completed", False)

        home_score = away_score = None
        for comp in competition.get("competitors", []):
            score = comp.get("score")
            if isinstance(score, dict):
                score = score.get("value") or score.get("displayValue")
            if comp.get("homeAway") == "home":
                home_score = score
            else:
                away_score = score

        game = {
            "date": date[:10] if date else "",
            "name": name,
            "status": status.get("shortDetail") or status.get("description", ""),
            "score": f"{away_score}\u2013{home_score}" if completed and home_score is not None else None,
        }
        (previous if completed else upcoming).append(game)

    previous.sort(key=lambda g: g["date"], reverse=True)
    upcoming.sort(key=lambda g: g["date"])
    return previous[:8], upcoming[:8]


def get_team_transactions(sport, league, team_id):
    try:
        data = _espn_get(f"{sport}/{league}/teams/{team_id}/transactions")
    except Exception:
        return []
    items = data.get("transactions") or data.get("items") or []
    out = []
    for t in items[:10]:
        out.append(
            {
                "date": (t.get("date") or "")[:10],
                "text": t.get("description") or t.get("text") or str(t),
            }
        )
    return out


def get_team_news(sport, league, team_id):
    try:
        data = _espn_get(f"{sport}/{league}/news", params={"team": team_id})
    except Exception:
        return []
    out = []
    for a in data.get("articles", [])[:8]:
        out.append(
            {
                "headline": a.get("headline", ""),
                "description": a.get("description", ""),
                "url": (a.get("links", {}).get("web", {}) or {}).get("href", ""),
                "published": (a.get("published") or "")[:10],
            }
        )
    return out


THESPORTSDB_KEY = os.environ.get("THESPORTSDB_KEY", "123")
_thesportsdb_league_cache = {}


def _thesportsdb_get(path, params=None):
    res = requests.get(
        f"https://www.thesportsdb.com/api/v1/json/{THESPORTSDB_KEY}/{path}",
        params=params, headers=HEADERS, timeout=8,
    )
    res.raise_for_status()
    return res.json()


def _thesportsdb_find_league(sport_name, name_contains=None):
    cache_key = sport_name.lower()
    if cache_key not in _thesportsdb_league_cache:
        data = _thesportsdb_get("search_all_leagues.php", params={"s": sport_name})
        _thesportsdb_league_cache[cache_key] = data.get("countries") or []
    leagues = _thesportsdb_league_cache[cache_key]
    if not leagues:
        return None
    if name_contains:
        nc = name_contains.lower()
        for lg in leagues:
            if nc in (lg.get("strLeague") or "").lower():
                return lg
    return leagues[0]


def _thesportsdb_game(ev, completed):
    def _num(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    home_score, away_score = _num(ev.get("intHomeScore")), _num(ev.get("intAwayScore"))
    return {
        "date": ev.get("dateEvent") or "",
        "detail": ev.get("strStatus") or ("Final" if completed else "Scheduled"),
        "venue": ev.get("strVenue") or "",
        "home": {"name": ev.get("strHomeTeam", "Home"), "logo": "", "score": home_score,
                 "winner": bool(completed and home_score is not None and away_score is not None and home_score > away_score)},
        "away": {"name": ev.get("strAwayTeam", "Away"), "logo": "", "score": away_score,
                 "winner": bool(completed and home_score is not None and away_score is not None and away_score > home_score)},
    }


def _thesportsdb_league_events(league_id):
    recent = (_thesportsdb_get("eventspastleague.php", params={"id": league_id}).get("events") or [])
    upcoming_data = _thesportsdb_get("eventsnextleague.php", params={"id": league_id})
    upcoming = upcoming_data.get("events") or []
    return recent, upcoming


def get_thesportsdb_scoreboard(sport_name, league_hint, league_display_name):
    league = _thesportsdb_find_league(sport_name, league_hint)
    if not league:
        return None, f"No {league_display_name} league found on TheSportsDB (free community-sourced data -- coverage varies)."
    try:
        recent_raw, upcoming_raw = _thesportsdb_league_events(league["idLeague"])
    except Exception as e:
        traceback.print_exc()
        return None, f"{league_display_name} fetch failed: {e}"

    recent = sorted((_thesportsdb_game(e, True) for e in recent_raw), key=lambda g: g["date"], reverse=True)
    upcoming = sorted((_thesportsdb_game(e, False) for e in upcoming_raw), key=lambda g: g["date"])
    return {"league_name": league.get("strLeague", league_display_name), "live": [], "recent": recent[:20], "upcoming": upcoming[:20]}, None


def get_thesportsdb_team_report(sport_name, league_hint, league_display_name, team_query):
    league = _thesportsdb_find_league(sport_name, league_hint)
    if not league:
        return None, f"No {league_display_name} league found on TheSportsDB."
    try:
        recent_raw, upcoming_raw = _thesportsdb_league_events(league["idLeague"])
    except Exception as e:
        traceback.print_exc()
        return None, f"{league_display_name} fetch failed: {e}"

    q = team_query.strip().lower()

    def matches(ev):
        return q in (ev.get("strHomeTeam") or "").lower() or q in (ev.get("strAwayTeam") or "").lower()

    recent_hits = [e for e in recent_raw if matches(e)]
    upcoming_hits = [e for e in upcoming_raw if matches(e)]
    if not recent_hits and not upcoming_hits:
        return None, f"No team matching \u201c{team_query}\u201d found in {league_display_name} on TheSportsDB."

    team_name = team_query
    for ev in recent_hits + upcoming_hits:
        for side in ("strHomeTeam", "strAwayTeam"):
            if q in (ev.get(side) or "").lower():
                team_name = ev[side]
                break
        break

    recent = sorted((_thesportsdb_game(e, True) for e in recent_hits), key=lambda g: g["date"], reverse=True)
    upcoming = sorted((_thesportsdb_game(e, False) for e in upcoming_hits), key=lambda g: g["date"])
    return {
        "team_name": team_name, "logo": "", "league_name": league.get("strLeague", league_display_name),
        "previous": recent[:8], "upcoming": upcoming[:8], "transactions": [], "news": [],
    }, None


def get_league_scoreboard(league_key, days_back=4, days_ahead=10):
    if league_key not in LEAGUES:
        return None, f"Unknown league '{league_key}'."
    sport, league, league_name = LEAGUES[league_key]

    if sport == "thesportsdb":
        return get_thesportsdb_scoreboard(league, None, league_name)

    from datetime import datetime, timedelta

    today = datetime.utcnow()
    start = (today - timedelta(days=days_back)).strftime("%Y%m%d")
    end = (today + timedelta(days=days_ahead)).strftime("%Y%m%d")

    try:
        data = _espn_get(f"{sport}/{league}/scoreboard", params={"dates": f"{start}-{end}", "limit": 200})
    except Exception as e:
        traceback.print_exc()
        return None, f"Scoreboard fetch failed: {e}"

    def _team_side(competitors, side):
        for c in competitors:
            if c.get("homeAway") == side:
                team = c.get("team", {})
                score = c.get("score")
                if isinstance(score, dict):
                    score = score.get("value") or score.get("displayValue")
                return {
                    "name": team.get("shortDisplayName") or team.get("displayName", "?"),
                    "logo": team.get("logo") or (team.get("logos") or [{}])[0].get("href", ""),
                    "score": score,
                    "winner": c.get("winner", False),
                }
        return {"name": "?", "logo": "", "score": None, "winner": False}

    live, recent, upcoming = [], [], []
    for event in data.get("events", []):
        competition = (event.get("competitions") or [{}])[0]
        status = (event.get("status") or competition.get("status") or {}).get("type", {})
        state = status.get("state", "pre")
        competitors = competition.get("competitors", [])

        game = {
            "date": (event.get("date") or "")[:10],
            "detail": status.get("shortDetail") or status.get("detail", ""),
            "venue": (competition.get("venue") or {}).get("fullName", ""),
            "home": _team_side(competitors, "home"),
            "away": _team_side(competitors, "away"),
        }

        if state == "in":
            live.append(game)
        elif state == "post":
            recent.append(game)
        else:
            upcoming.append(game)

    recent.sort(key=lambda g: g["date"], reverse=True)
    upcoming.sort(key=lambda g: g["date"])

    return {
        "league_name": league_name,
        "live": live[:20],
        "recent": recent[:20],
        "upcoming": upcoming[:20],
    }, None


def get_team_report(league_key, team_query):
    if league_key not in LEAGUES:
        return None, f"Unknown league '{league_key}'."
    sport, league, league_name = LEAGUES[league_key]

    if sport == "thesportsdb":
        return get_thesportsdb_team_report(league, None, league_name, team_query)

    try:
        team = find_team(league_key, team_query)
    except Exception as e:
        traceback.print_exc()
        return None, f"Team lookup failed: {e}"
    if not team:
        return None, f"No team matching \u201c{team_query}\u201d found in {league_name}."

    team_id = team.get("id")
    try:
        previous, upcoming = get_team_games(sport, league, team_id)
    except Exception as e:
        traceback.print_exc()
        previous, upcoming = [], []
        prev_err = f"Schedule fetch failed: {e}"
    else:
        prev_err = None

    transactions = get_team_transactions(sport, league, team_id)
    news = get_team_news(sport, league, team_id)

    report = {
        "team_name": team.get("displayName", team_query),
        "logo": (team.get("logos") or [{}])[0].get("href", ""),
        "league_name": league_name,
        "previous": previous,
        "upcoming": upcoming,
        "transactions": transactions,
        "news": news,
    }
    return report, prev_err


def _haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


NOMINATIM_HEADERS = {
    "User-Agent": "AetherScan-DesktopApp/1.0 (personal project by Oscar Hou; github.com/)",
    "Accept-Language": "en-US,en;q=0.9",
}


def _nominatim_search(params, attempts=2):
    last_error = None
    for attempt in range(attempts):
        try:
            res = requests.get(
                "https://nominatim.openstreetmap.org/search",
                params=params,
                headers=NOMINATIM_HEADERS,
                timeout=8,
            )
            if res.status_code == 429 and attempt < attempts - 1:
                time.sleep(1.2)
                continue
            res.raise_for_status()
            return res.json(), None
        except Exception as e:
            last_error = e
    traceback.print_exc()
    return None, str(last_error)


def find_nearby_places(place_type, lat, lon, radius_km=6):
    d = radius_km / 111.0
    viewbox = f"{lon - d},{lat + d},{lon + d},{lat - d}"
    raw, err = _nominatim_search({"q": place_type, "format": "jsonv2", "limit": 12, "bounded": 1, "viewbox": viewbox})
    if err:
        return [], f"Nearby-places search failed: {err}"

    places = []
    for item in raw:
        try:
            plat, plon = float(item["lat"]), float(item["lon"])
        except (KeyError, ValueError, TypeError):
            continue
        name = (item.get("display_name") or "").split(",")[0] or place_type.title()
        places.append(
            {
                "name": name,
                "address": item.get("display_name", ""),
                "lat": plat,
                "lon": plon,
                "distance_km": round(_haversine_km(lat, lon, plat, plon), 2),
            }
        )
    places.sort(key=lambda p: p["distance_km"])
    return places[:10], None


def search_places_general(query, limit=10):
    raw, err = _nominatim_search({"q": query, "format": "jsonv2", "limit": limit})
    if err:
        return [], None, None, f"Map search failed: {err}"

    places = []
    for item in raw:
        try:
            plat, plon = float(item["lat"]), float(item["lon"])
        except (KeyError, ValueError, TypeError):
            continue
        name = (item.get("display_name") or "").split(",")[0] or query.title()
        places.append({"name": name, "address": item.get("display_name", ""), "lat": plat, "lon": plon})

    if not places:
        return [], None, None, None

    center_lat = sum(p["lat"] for p in places) / len(places)
    center_lon = sum(p["lon"] for p in places) / len(places)
    return places, center_lat, center_lon, None


SOURCE_FILTERS = ["All", "Wikipedia", "Stack Overflow", "Hacker News", "DuckDuckGo", "Reddit", "arXiv"]


@app.route("/api/weather", methods=["GET"])
def api_weather():
    lat, lon = request.args.get("lat", type=float), request.args.get("lon", type=float)
    if lat is None or lon is None:
        return jsonify(None)
    try:
        return jsonify(get_weather(lat, lon))
    except Exception:
        traceback.print_exc()
        return jsonify(None)


@app.route("/api/suggest", methods=["GET"])
def api_suggest():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])
    try:
        res = requests.get(
            "https://en.wikipedia.org/w/api.php",
            params={"action": "opensearch", "search": q, "limit": 8, "namespace": 0, "format": "json"},
            headers=HEADERS,
            timeout=5,
        )
        res.raise_for_status()
        data = res.json()
        suggestions = data[1] if len(data) > 1 else []
        return jsonify(suggestions)
    except Exception:
        return jsonify([])


@app.route("/api/more_images", methods=["GET"])
def api_more_images():
    query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    if not query:
        return jsonify({"images": []})
    try:
        data = _openverse_get({"q": query, "page_size": 20, "page": max(page, 1)})
        items = data.get("results", [])
        images = [item.get("thumbnail") or item.get("url") for item in items if item.get("thumbnail") or item.get("url")]
        return jsonify({"images": images})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"images": [], "error": str(e)})


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not username or not email or not password:
            error = "Please fill in every field."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Those passwords don't match."
        else:
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password), datetime.utcnow().isoformat()),
                )
                conn.commit()
                user = conn.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect("/")
            except sqlite3.IntegrityError:
                error = "That username or email is already taken."
            finally:
                conn.close()
    return render_template("account.html", form_mode="signup", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier.lower())
        ).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/")
        error = "Incorrect username/email or password."
    return render_template("account.html", form_mode="login", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    """
    A signed-in user's own AI (Gemini/Anthropic) and TMDb API keys --
    reachable from the account menu next to the username. A saved key
    here always takes priority over the server's environment-variable
    key (see _apply_user_ai_settings/_effective_*_key above), so each
    person using this app can bring their own key without ever touching
    the environment variables or restarting the app.

    FIX (2026-09): save_user_settings() takes 5 args (user_id, gemini,
    anthropic, tmdb, groq) but this route used to call it with only 4 --
    a missing 'groq_api_key' TypeError on every single save, meaning no
    key entered here (Gemini included) ever actually persisted. There's
    no Groq field in settings.html yet, so we preserve whatever Groq key
    is already on the account (env-var-only for now) instead of wiping it.
    """
    if not session.get("user_id"):
        return redirect("/login")

    user_id = session["user_id"]
    saved = False

    if request.method == "POST":
        gemini_key = request.form.get("gemini_api_key", "").strip()
        anthropic_key = request.form.get("anthropic_api_key", "").strip()
        tmdb_key = request.form.get("tmdb_api_key", "").strip()
        groq_key = request.form.get("groq_api_key", "").strip()
        saved = save_user_settings(user_id, gemini_key, anthropic_key, tmdb_key, groq_key)

    current = get_user_settings(user_id)
    return render_template(
        "settings.html",
        username=session.get("username"),
        saved=saved,
        gemini_api_key=current.get("gemini_api_key", ""),
        anthropic_api_key=current.get("anthropic_api_key", ""),
        tmdb_api_key=current.get("tmdb_api_key", ""),
        groq_api_key=current.get("groq_api_key", ""),
    )


@app.route("/game", methods=["GET"])
def game_legacy_redirect():
    """Old direct link to the one-and-only game -- now that there's a
    picker, send anyone who still has this URL bookmarked to the hub."""
    return redirect("/games")


# ---------------------------------------------------------------------------
# GAMES HUB: a small built-in arcade, reachable from the desktop app's
# History and Restore Session dialogs as "\u2728 Special: Aether Game". Add a
# new game by (1) dropping its self-contained HTML file in
# templates/games/<slug>.html and (2) adding one entry below -- the hub
# page and the /games/<slug> route both pick it up automatically.
# ---------------------------------------------------------------------------
GAMES_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "templates", "games"
)


def _repair_mojibake(text):
    """'ðŸ’¥' -> '💥' (UTF-8 bytes that were decoded as cp1252)."""
    if not text or not any(ch in text for ch in "ÃÂðŸ¥"):
        return text
    try:
        return text.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text


def _slugify_game(raw):
    """'2dFighter.html' / '1v1 Fighter.html' -> '2d-fighter' / '1v1-fighter'."""
    s = re.sub(r"\.html?$", "", str(raw or "").strip(), flags=re.IGNORECASE)
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", s)   # camelCase -> camel-Case
    s = re.sub(r"[^a-z0-9]+", "-", s.lower())
    return s.strip("-")


def _normalize_games(raw_games):
    """Repair encoding, fix slugs, and drop duplicates -- last clean entry wins."""
    by_slug = {}
    for entry in raw_games:
        slug = _slugify_game(entry.get("slug") or entry.get("title"))
        if not slug:
            continue
        title = _repair_mojibake((entry.get("title") or "").strip())
        title = re.sub(r"\.html?$", "", title, flags=re.IGNORECASE).strip()
        game = {
            "slug": slug,
            "title": title or slug.replace("-", " ").title(),
            "tagline": _repair_mojibake(entry.get("tagline") or ""),
            "icon": _repair_mojibake(entry.get("icon") or "\U0001F3AE"),
        }
        # prefer the entry that didn't come from a raw filename
        if slug not in by_slug or not str(entry.get("slug", "")).lower().endswith(".html"):
            by_slug[slug] = game
    return list(by_slug.values())


def _game_template_for(slug):
    """Find the real file on disk whose NAME slugifies to this slug."""
    try:
        for name in sorted(os.listdir(GAMES_TEMPLATE_DIR)):
            if name.lower().endswith((".html", ".htm")) and _slugify_game(name) == slug:
                return f"games/{name}"
    except OSError:
        pass
    return None
GAMES = [
    {
        "slug": "2d-fighter",
        "title": "2D Fighter",
        "tagline": "A fast-paced one-on-one fighting game.",
        "icon": "🥊",
    },
    {
        "slug": "1v1-fighter",
        "title": "1v1 Fighter",
        "tagline": "A fast-paced one-on-one shooting game.",
        "icon": "💥",
    },
    {
        "slug": "quantum-forge",
        "title": "Quantum Forge: Cosmic Harvest",
        "tagline": "Idle clicker \u2014 harvest energy shards, automate the grid, and ascend.",
        "icon": "\u269b\ufe0f",
    },
    {
        "slug": "nebula-swarm",
        "title": "Nebula Swarm",
        "tagline": "Twin-stick shooter \u2014 defend your ship against relentless swarm drones.",
        "icon": "\U0001F680",
    },
    {
        "slug": "siege-forge",
        "title": "Siege Forge: Castle Shatter",
        "tagline": "Slingshot physics \u2014 shatter 15 castles before you run out of shots.",
        "icon": "\U0001F3F0",
    },
    {
        "slug": "basket-random",
        "title": "Basketball Free Throw Pro",
        "tagline": "Free-throw shooting \u2014 nail your shots, chain streaks, unlock harder difficulty.",
        "icon": "\U0001F3C0",
    },
    {
        "slug": "moto-tracks",
        "title": "Moto Tracks",
        "tagline": "Side-scrolling dirt bike physics \u2014 race whoops and gap jumps, unlock bikes in the garage.",
        "icon": "\U0001F3CD\uFE0F",
    },
    {
        "slug": "word-guess",
        "title": "Word Guess Game",
        "tagline": "Wordle-style daily word puzzle \u2014 advanced mode with hints.",
        "icon": "\U0001F524",
    },
    {
        "slug": "fc-manager",
        "title": "FC 26: Ultra Manager Pro",
        "tagline": "Football management sim \u2014 squad, fitness, transfers, and matchdays.",
        "icon": "\u26bd",
    },
]


@app.route("/games", methods=["GET"])
def games_hub():
    try:
        return render_template("games_hub.html", games=GAMES)
    except TemplateNotFound as e:
        traceback.print_exc()
        return (
            "Couldn't find templates/games_hub.html. Make sure it's saved directly "
            f"inside your templates/ folder (missing: {e.name}).",
            500,
        )


@app.route("/games/<path:slug>", methods=["GET"])
def play_game(slug):
    slug = _slugify_game(unquote(slug))
    if not any(g["slug"] == slug for g in GAMES):
        return redirect("/games")
    template = _game_template_for(slug)
    if not template:
        available = ", ".join(sorted(os.listdir(GAMES_TEMPLATE_DIR))) or "(folder is empty)"
        return (
            f"No template found for '{slug}' in templates/games/. Files there: {available}",
            404,
        )
    try:
        return render_template(template)
    except TemplateNotFound as e:
        traceback.print_exc()
        return f"Couldn't render {template} (missing: {e.name}).", 500
        


@app.route("/", methods=["GET"])
def home():
    _apply_user_ai_settings()
    query = request.args.get("q", "").strip()
    mode = request.args.get("mode", "all")
    league = request.args.get("league", "eng.1")
    site_filter = request.args.get("site", "").strip()
    sort = request.args.get("sort", "relevance")

    if mode == "all" and query:
        direct_url = _resolve_direct_site(query)
        if direct_url and (query.lower().startswith(("http://", "https://")) or _DOMAIN_PATTERN.match(query)):
            return redirect(direct_url)
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    web_results, images, videos, infobox_data, ai_text, team_report, scoreboard = [], [], [], None, "", None, None
    nearby_places, nearby_query = None, None
    map_places, map_center_lat, map_center_lon = None, None, None
    related_searches, spelling_suggestion = [], None
    news_articles = []
    movie_results = []
    shopping_results = []
    compare_data = None
    on_this_day = []
    errors = []

    closest_match = CLOSEST_PATTERN.match(query) if (query and mode == "all") else None

    if mode == "all" and not query:
        on_this_day = get_on_this_day()

    if query and mode in ("all", "images", "videos", "news", "movies", "shopping"):
        save_search_history(session.get("user_id"), query, mode)

    if mode == "sports":
        if query:
            team_report, err = get_team_report(league, query)
        else:
            scoreboard, err = get_league_scoreboard(league)
        if err:
            errors.append(err)
    elif mode == "news":
        try:
            news_articles = get_news(query)
        except Exception as e:
            traceback.print_exc()
            errors.append(f"News fetch failed: {e}")
    elif mode == "movies":
        if query:
            movie_results, err = get_live_movies(query)
            if err:
                errors.append(err)
    elif mode == "shopping":
        if query:
            shopping_results, err = search_shopping(query)
            if err:
                errors.append(err)
    elif mode == "maps":
        if query:
            map_places, map_center_lat, map_center_lon, err = search_places_general(query)
            if err:
                errors.append(err)
    elif mode == "chat":
        pass  # AI Chat is fully client-side/AJAX via /api/chat -- nothing to fetch for the page itself
    elif closest_match and lat is not None and lon is not None:
        nearby_query = closest_match.group(1).strip()
        nearby_places, err = find_nearby_places(nearby_query, lat, lon)
        if err:
            errors.append(err)
    elif query:
        if mode == "images":
            images, err = get_live_images(query)
            if err:
                errors.append(err)
        elif mode == "videos":
            videos, err = get_live_videos(query)
            if err:
                errors.append(err)
        else:
            with ThreadPoolExecutor(max_workers=3) as pool:
                web_future = pool.submit(search_the_entire_internet, query, site_filter or None, sort)
                overview_future = pool.submit(get_smart_overview, query)
                spell_future = pool.submit(get_spelling_suggestion, query)

                web_results, err1 = web_future.result()
                ai_text, infobox_data, err2, related_searches = overview_future.result()
                try:
                    spelling_suggestion = spell_future.result()
                except Exception:
                    spelling_suggestion = None
            if spelling_suggestion and spelling_suggestion.lower() == query.lower():
                spelling_suggestion = None
            errors = [e for e in (err1, err2) if e]

            if _normalize_for_about(query) not in ABOUT_TRIGGERS:
                if _effective_gemini_key():
                    ai_text = enhance_overview_with_gemini(query, ai_text, web_results)
                elif _effective_anthropic_key():
                    ai_text = enhance_overview_with_claude(query, ai_text, web_results)
                elif _effective_groq_key():
                    ai_text = enhance_overview_with_groq(query, ai_text, web_results)

            compare_match = _try_compare(query)
            if compare_match:
                compare_data = get_comparison(compare_match[0], compare_match[1], web_results)

    return render_template(
        "search.html",
        query=query,
        mode=mode,
        league=league,
        leagues=LEAGUES,
        username=session.get("username"),
        web_results=web_results,
        images=images,
        videos=videos,
        infobox=infobox_data,
        ai_overview=ai_text,
        related_searches=related_searches,
        spelling_suggestion=spelling_suggestion,
        source_filters=SOURCE_FILTERS,
        site_filter=site_filter,
        sort=sort,
        team_report=team_report,
        scoreboard=scoreboard,
        nearby_places=nearby_places,
        nearby_query=nearby_query,
        map_places=map_places,
        map_center_lat=map_center_lat,
        map_center_lon=map_center_lon,
        news_articles=news_articles,
        movie_results=movie_results,
        shopping_results=shopping_results,
        tmdb_configured=bool(_effective_tmdb_key()),
        cesium_configured=bool(CESIUM_ION_TOKEN),
        cesium_token=CESIUM_ION_TOKEN,
        compare=compare_data,
        on_this_day=on_this_day,
        recent_searches=get_search_history(session.get("user_id")),
        ai_chat_provider=_ai_chat_provider(),
        lat=lat,
        lon=lon,
        errors=errors,
    )


if __name__ == "__main__":
    PORT = 5006
    HOME_URL = f"http://127.0.0.1:{PORT}/"
    GAMES_URL = f"http://127.0.0.1:{PORT}/games"

    # Must be set before PyQt6's WebEngine modules are imported (Chromium
    # reads this env var during its own startup, which can be triggered as
    # early as import time) -- see the fuller explanation further below,
    # right before QApplication is constructed.
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--autoplay-policy=no-user-gesture-required")

    try:
        from PyQt6.QtCore import Qt, QStandardPaths, QUrl, QFileInfo, QDir, QTimer
        from PyQt6.QtGui import QIcon, QColor
        from PyQt6.QtWidgets import (
            QApplication, QLineEdit, QMainWindow, QPushButton, QTabWidget,
            QToolBar, QFileDialog, QMessageBox, QInputDialog, QDialog,
            QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem, QLabel, QMenu
        )
        from PyQt6.QtWebEngineCore import (
            QWebEnginePage, QWebEngineProfile, QWebEngineSettings,
            QWebEngineDownloadRequest
        )
        from PyQt6.QtWebEngineWidgets import QWebEngineView

        try:
            from PyQt6.QtWebEngineCore import QWebEngineExtensionManager, QWebEngineExtensionInfo
            HAS_EXTENSIONS = True
        except ImportError:
            HAS_EXTENSIONS = False
    except ImportError:
        print("(Tip: run `py -m pip install PyQt6 PyQt6-WebEngine` for a real app window instead of a browser tab.)")
        print(f"Starting AetherScan on http://127.0.0.1:{PORT}")
        app.run(debug=True, port=PORT, use_reloader=False)
    else:
        import sys
        import threading
        import time

        def _run_flask():
            app.run(port=PORT, use_reloader=False, debug=False)

        threading.Thread(target=_run_flask, daemon=True).start()
        time.sleep(1)

        # --- Autoplay / playback compatibility for video & movie sites ------
        # Chromium's default autoplay policy blocks audio+video from playing
        # without a user gesture on many sites -- the per-page
        # PlaybackRequiresUserGesture=False setting below handles this at
        # the Qt API level; the QTWEBENGINE_CHROMIUM_FLAGS env var set at
        # the very top of this block (before PyQt6 was even imported)
        # closes the same gap at Chromium's own internal policy level.
        # HONEST LIMIT: this improves playback on ordinary video sites
        # (YouTube, Vimeo, most news/blog embeds, etc.). It does NOT enable
        # DRM-protected streaming (Netflix, Disney+, Max, Prime Video, Hulu,
        # Paramount+, Peacock, Apple TV+) -- those require the proprietary
        # Widevine CDM component, which the open-source `pip install
        # PyQt6-WebEngine` build does not ship at all (a Qt licensing
        # decision, not a bug). Those sites will open fine as pages -- the
        # video itself just won't play, typically showing their own "your
        # browser doesn't support the required content protection" message.
        # There is no supported way to add Widevine to this build from
        # Python code; it requires Qt's separate commercial WebEngine
        # Widevine package.
        #
        # --- FIX #1 for "clicking any link closes the whole app" ------------
        # This MUST run before QApplication is constructed. Qt's own docs
        # require Qt.ApplicationAttribute.AA_ShareOpenGLContexts to be set
        # before QApplication() whenever an app creates MORE THAN ONE
        # QWebEngineView -- which is exactly what happens the instant you
        # click any link, since every link that opens "a new tab" (handled
        # via the newWindowRequested signal below) constructs a second
        # QWebEngineView. Without this attribute, creating that second view
        # can bring down the whole process at the OpenGL/graphics-driver
        # level -- a native crash, not a Python exception, so no try/except
        # anywhere else in this file could ever catch it on its own.
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)

        # --- FIX #2 for the SAME crash, from a different angle --------------
        # sys.excepthook (below) catches Python-level exceptions in Qt
        # callbacks, but it cannot catch a native crash either. Doing heavy
        # UI work (creating a whole new tab widget, switching focus)
        # SYNCHRONOUSLY inside createWindow() is a second, independent
        # known trigger for native crashes in PyQt6/PySide6 WebEngine apps,
        # because createWindow() is called by Chromium while it is still in
        # the middle of its own internal navigation logic. So createWindow()
        # below creates and returns a bare QWebEnginePage synchronously
        # (Chromium needs a page back immediately, to have somewhere to
        # load the target URL), and defers EVERYTHING else -- building the
        # actual tab widget, adding it to the tab bar, switching focus -- to
        # the next event-loop tick via QTimer.singleShot(0, ...). By the
        # time that runs, Chromium's nested call into createWindow() has
        # already returned, so it's safe to touch the UI. These two fixes
        # are independent and complementary -- both address real, separate
        # documented crash triggers for the same user-visible symptom.
        def _qt_exception_hook(exc_type, exc_value, exc_tb):
            print("\n[AetherScan] Caught an error that would previously have crashed the whole app:")
            traceback.print_exception(exc_type, exc_value, exc_tb)

        sys.excepthook = _qt_exception_hook

        class BrowserPage(QWebEnginePage):
            """
            Custom page whose only extra job is: if the tab is currently
            showing AetherScan itself (127.0.0.1) and a navigation is about
            to take it somewhere else entirely, open that destination in a
            NEW TAB instead of navigating away in place. That's the actual
            fix for "open websites but stay in a tab so I can exit it and
            look at another" -- your search results/home tab is never
            replaced; you just close the new external-site tab to land
            right back where you were, instead of having to hit Back.

            This applies uniformly to every way a navigation can happen --
            clicking a plain (non target="_blank") link, typing an address
            in the toolbar, or AetherScan's own site-nickname redirects
            (e.g. typing "gmail" in the search box) -- since they all pass
            through this same interception point. Once you're ALREADY on
            an external site, further navigation there behaves like a
            normal browser tab again (no new tab spawned for every click)
            -- only the moment of LEAVING AetherScan is special-cased.
            """

            def __init__(self, profile, view):
                super().__init__(profile, view)
                self._view = view

            def acceptNavigationRequest(self, url, nav_type, is_main_frame):
                try:
                    if is_main_frame:
                        current_host = self.url().host()
                        target_host = url.host()
                        leaving_aetherscan = (
                            current_host == "127.0.0.1"
                            and target_host
                            and target_host != "127.0.0.1"
                        )
                        if leaving_aetherscan:
                            self._view.window.add_tab(url.toString(), focus=True)
                            return False
                except Exception:
                    traceback.print_exc()
                return super().acceptNavigationRequest(url, nav_type, is_main_frame)

        class BrowserTab(QWebEngineView):
            """
            A single tab. Any link that would normally open a new browser
            window/tab (target="_blank", window.open(), a video card, a
            search result, etc.) is intercepted here via the page's
            newWindowRequested signal and opened as a NEW TAB inside this
            app instead of an external browser. See BrowserPage above for
            the separate "leaving AetherScan opens a new tab too" behavior.
            """

            def __init__(self, window, profile, page=None):
                super().__init__()
                self.window = window
                # `page` lets a caller hand us an ALREADY-CREATED
                # QWebEnginePage instead of making a fresh one -- used by
                # add_tab_with_page()/_handle_new_window_request() below.
                page = page or BrowserPage(profile, self)
                self.setPage(page)
                self.loadFinished.connect(self._on_load_finished)
                s = self.settings()
                s.setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, False)
                s.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
                s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, True)
                s.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
                s.setAttribute(QWebEngineSettings.WebAttribute.ScreenCaptureEnabled, True)
                self.page().featurePermissionRequested.connect(self._grant_permission)
                self.page().newWindowRequested.connect(self._handle_new_window_request)

            def _grant_permission(self, url, feature):
                try:
                    grantable = {
                        QWebEnginePage.Feature.Geolocation,
                        QWebEnginePage.Feature.MediaAudioCapture,
                        QWebEnginePage.Feature.MediaVideoCapture,
                        QWebEnginePage.Feature.MediaAudioVideoCapture,
                    }
                    policy = (
                        QWebEnginePage.PermissionPolicy.PermissionGrantedByUser
                        if feature in grantable
                        else QWebEnginePage.PermissionPolicy.PermissionDeniedByUser
                    )
                    self.page().setFeaturePermission(url, feature, policy)
                except Exception:
                    traceback.print_exc()

            def _handle_new_window_request(self, request):
                # THE ACTUAL FIX for "opens a blank white New Tab": the
                # previous approach overrode QWebEngineView.createWindow()
                # and returned a QWebEnginePage, relying on Chromium to
                # implicitly pick that page up and navigate it -- which
                # this Qt build apparently doesn't do reliably (a tab got
                # created, but nothing ever loaded into it). This signal +
                # request.openIn(page) is the newer (Qt 6.2+), explicit
                # replacement API: it directly and synchronously BINDS the
                # pending navigation to the page we give it, rather than
                # hoping a return value gets picked up correctly. Per Qt's
                # own docs, this signal simply won't fire at all if a
                # createWindow() override handled the request first -- so
                # that override had to be removed entirely, not just left
                # alongside this (the two are alternatives, not layers).
                try:
                    new_tab = self.window.add_tab_with_page(None, focus=True)
                    request.openIn(new_tab.page())
                except Exception:
                    traceback.print_exc()

            def _on_load_finished(self, ok):
                """Logs a completed page load to History -- fires once per
                navigation (unlike titleChanged/urlChanged, which can fire
                several times mid-load), so this is the reliable point to
                record a real visit with its final URL and title."""
                if not ok:
                    return
                try:
                    url = self.url().toString()
                    if url.startswith("http://") or url.startswith("https://"):
                        self.window._log_history(url, self.title() or url)
                except Exception:
                    traceback.print_exc()

        class BrowserWindow(QMainWindow):
            def __init__(self, profile):
                super().__init__()
                self.profile = profile
                self.setWindowTitle("AetherScan")
                self.resize(1280, 850)

                self.profile.downloadRequested.connect(self._on_download_requested)

                self.tabs = QTabWidget()
                self.tabs.setTabsClosable(True)
                self.tabs.setMovable(True)
                self.tabs.tabCloseRequested.connect(self.close_tab)
                self.tabs.currentChanged.connect(self._sync_url_bar)
                self._tab_state = {}
                self._collapsed_groups = set()
                self._closed_tabs = []
                tab_bar = self.tabs.tabBar()
                tab_bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                tab_bar.customContextMenuRequested.connect(self._show_tab_menu)
                tab_bar.setToolTip("Right-click a tab to pin it or place it in a group")

                toolbar = QToolBar()
                toolbar.setMovable(False)
                self.addToolBar(toolbar)

                for label, handler in [
                    ("\u2190", lambda: self.current_tab().back()),
                    ("\u2192", lambda: self.current_tab().forward()),
                    ("\u21bb", lambda: self.current_tab().reload()),
                    ("\u2302", lambda: self.current_tab().setUrl(QUrl(HOME_URL))),
                ]:
                    btn = QPushButton(label)
                    btn.setFixedWidth(34)
                    btn.clicked.connect(handler)
                    toolbar.addWidget(btn)

                self.url_bar = QLineEdit()
                self.url_bar.setPlaceholderText("Type a web address and press Enter -- opens right here, in this tab")
                self.url_bar.returnPressed.connect(self.navigate_to_url_bar)
                toolbar.addWidget(self.url_bar)

                new_tab_btn = QPushButton("+ New Tab")
                new_tab_btn.clicked.connect(lambda: self.add_tab(HOME_URL, focus=True))
                toolbar.addWidget(new_tab_btn)

                if HAS_EXTENSIONS:
                    ext_btn = QPushButton("\U0001F9E9 Extensions")
                    ext_btn.setToolTip("Load / install a Chrome (Manifest V3) extension")
                    ext_btn.clicked.connect(self._manage_extensions)
                    toolbar.addWidget(ext_btn)

                restore_btn = QPushButton("\U0001F5C2\uFE0F Restore Session")
                restore_btn.setToolTip("Reopen the tabs that were open the last time this app was closed")
                restore_btn.clicked.connect(self._restore_session)
                toolbar.addWidget(restore_btn)

                history_btn = QPushButton("\U0001F553 History")
                history_btn.setToolTip("Every page you've visited in this app, most recent first")
                history_btn.clicked.connect(self._show_history)
                toolbar.addWidget(history_btn)

                bookmark_btn = QPushButton("☆ Bookmark")
                bookmark_btn.setToolTip("Save the current page to bookmarks")
                bookmark_btn.clicked.connect(self._bookmark_current)
                toolbar.addWidget(bookmark_btn)

                bookmarks_btn = QPushButton("Bookmarks")
                bookmarks_btn.setToolTip("Open a saved bookmark")
                bookmarks_btn.clicked.connect(self._show_bookmarks)
                toolbar.addWidget(bookmarks_btn)

                self.setCentralWidget(self.tabs)
                self.add_tab(HOME_URL, focus=True)

            def _tab_info(self, tab):
                return self._tab_state.setdefault(
                    id(tab), {"pinned": False, "group": "", "title": "New Tab"}
                )

            def _refresh_tab_label(self, tab, title=None):
                index = self.tabs.indexOf(tab)
                if index < 0:
                    return
                info = self._tab_info(tab)
                if title is not None:
                    info["title"] = title or "New Tab"
                raw_title = info.get("title") or "New Tab"
                if info.get("pinned"):
                    is_games = tab.url().toString().startswith(GAMES_URL) or "Aether Games" in raw_title
                    self.tabs.setTabText(index, "✦" if is_games else "•")
                    self.tabs.setTabToolTip(index, "Aether Games" if is_games else raw_title)
                    return
                short_title = (raw_title[:20] + "...") if len(raw_title) > 20 else raw_title
                prefix = "PIN / " if info.get("pinned") else ""
                if info.get("group"):
                    group = info["group"]
                    group_tabs = self._group_tabs(group)
                    is_representative = group_tabs and group_tabs[0] is tab
                    if group in self._collapsed_groups and is_representative:
                        prefix += f"{group} ({len(group_tabs)}) / "
                    else:
                        prefix += f"{group} / "
                self.tabs.setTabText(index, prefix + short_title)
                tooltip = raw_title
                if info.get("pinned"):
                    tooltip = "Pinned tab\n" + tooltip
                if info.get("group"):
                    tooltip = f"Group: {info['group']}\n" + tooltip
                self.tabs.setTabToolTip(index, tooltip)

            def _update_tab_icon(self, tab, icon):
                index = self.tabs.indexOf(tab)
                if index < 0 or icon.isNull():
                    return
                self.tabs.setTabIcon(index, icon)
                if self._tab_info(tab).get("pinned"):
                    self._refresh_tab_label(tab)

            def _group_tabs(self, group):
                return [
                    self.tabs.widget(i)
                    for i in range(self.tabs.count())
                    if self._tab_info(self.tabs.widget(i)).get("group") == group
                ]

            def _apply_group_visibility(self):
                current = self.current_tab()
                for i in range(self.tabs.count()):
                    tab = self.tabs.widget(i)
                    group = self._tab_info(tab).get("group")
                    visible = not group or group not in self._collapsed_groups
                    if group in self._collapsed_groups:
                        visible = bool(self._group_tabs(group) and self._group_tabs(group)[0] is tab)
                    self.tabs.tabBar().setTabVisible(i, visible)
                if current is not None and not self.tabs.tabBar().isTabVisible(self.tabs.indexOf(current)):
                    group = self._tab_info(current).get("group")
                    group_tabs = self._group_tabs(group) if group else []
                    if group_tabs:
                        self.tabs.setCurrentWidget(group_tabs[0])
                for i in range(self.tabs.count()):
                    self._refresh_tab_label(self.tabs.widget(i))

            def _toggle_group(self, group):
                if not group:
                    return
                if group in self._collapsed_groups:
                    self._collapsed_groups.remove(group)
                else:
                    self._collapsed_groups.add(group)
                self._apply_group_visibility()
                self._schedule_session_save()

            def _move_tabs_into_order(self):
                current = self.current_tab()
                tabs = [self.tabs.widget(i) for i in range(self.tabs.count())]
                ordered = sorted(
                    enumerate(tabs),
                    key=lambda pair: (
                        0 if self._tab_info(pair[1]).get("pinned") else 1,
                        self._tab_info(pair[1]).get("group") or "~",
                        pair[0],
                    ),
                )
                if [tab for _, tab in ordered] != tabs:
                    self.tabs.blockSignals(True)
                    try:
                        for target_index, (_, tab) in enumerate(ordered):
                            old_index = self.tabs.indexOf(tab)
                            if old_index != target_index:
                                self.tabs.removeTab(old_index)
                                self.tabs.insertTab(target_index, tab, "New Tab")
                    finally:
                        self.tabs.blockSignals(False)
                for i in range(self.tabs.count()):
                    self._refresh_tab_label(self.tabs.widget(i))
                if current is not None:
                    self.tabs.setCurrentWidget(current)

            def _set_tab_pinned(self, tab, pinned):
                self._tab_info(tab)["pinned"] = pinned
                self._move_tabs_into_order()
                self._apply_group_visibility()
                self._schedule_session_save()

            def _set_tab_group(self, tab, group):
                old_group = self._tab_info(tab).get("group", "")
                new_group = group.strip()
                self._tab_info(tab)["group"] = new_group
                if old_group and not self._group_tabs(old_group):
                    self._collapsed_groups.discard(old_group)
                self._move_tabs_into_order()
                self._apply_group_visibility()
                self._schedule_session_save()

            def _show_tab_menu(self, position):
                index = self.tabs.tabBar().tabAt(position)
                if index < 0:
                    return
                tab = self.tabs.widget(index)
                info = self._tab_info(tab)
                menu = QMenu(self)
                bookmark_action = menu.addAction("Bookmark tab")
                pin_action = menu.addAction("Unpin tab" if info.get("pinned") else "Pin tab")
                menu.addSeparator()
                groups_menu = menu.addMenu("Tab group")
                new_group_action = groups_menu.addAction("New group...")
                groups_menu.addSeparator()
                existing_groups = sorted({
                    self._tab_info(self.tabs.widget(i)).get("group")
                    for i in range(self.tabs.count())
                    if self._tab_info(self.tabs.widget(i)).get("group")
                })
                group_actions = {}
                for group in existing_groups:
                    group_actions[groups_menu.addAction(group)] = group
                remove_group_action = groups_menu.addAction("Remove from group")
                collapse_action = None
                if info.get("group"):
                    collapse_action = menu.addAction(
                        "Expand group" if info["group"] in self._collapsed_groups else "Collapse group"
                    )
                menu.addSeparator()
                close_action = menu.addAction("Close tab")
                reopen_action = menu.addAction("Reopen closed tab") if self._closed_tabs else None
                chosen = menu.exec(self.tabs.tabBar().mapToGlobal(position))
                if chosen is bookmark_action:
                    self.tabs.setCurrentWidget(tab)
                    self._bookmark_current()
                elif chosen is pin_action:
                    self._set_tab_pinned(tab, not info.get("pinned"))
                elif chosen is new_group_action:
                    name, ok = QInputDialog.getText(self, "New tab group", "Group name:")
                    if ok and name.strip():
                        self._set_tab_group(tab, name)
                elif chosen in group_actions:
                    self._set_tab_group(tab, group_actions[chosen])
                elif chosen is remove_group_action:
                    self._set_tab_group(tab, "")
                elif chosen is collapse_action:
                    self._toggle_group(info["group"])
                elif chosen is close_action:
                    self.close_tab(index)
                elif chosen is reopen_action:
                    self._reopen_closed_tab()

            def _on_download_requested(self, download: QWebEngineDownloadRequest):
                try:
                    suggested = download.downloadFileName() or download.suggestedFileName() or "download"
                    default_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
                    default_path = QDir(default_dir).filePath(suggested)

                    path, _ = QFileDialog.getSaveFileName(
                        self,
                        "Save file",
                        default_path,
                        "All files (*.*)"
                    )
                    if not path:
                        download.cancel()
                        return

                    info = QFileInfo(path)
                    download.setDownloadDirectory(info.absolutePath())
                    download.setDownloadFileName(info.fileName())
                    download.accept()

                    def _on_finished():
                        try:
                            if download.isFinished():
                                QMessageBox.information(
                                    self, "Download finished",
                                    f"Saved to:\n{download.downloadDirectory()}/{download.downloadFileName()}"
                                )
                        except Exception:
                            traceback.print_exc()
                    download.isFinishedChanged.connect(_on_finished)
                except Exception:
                    traceback.print_exc()

            def _manage_extensions(self):
                try:
                    self._manage_extensions_inner()
                except Exception:
                    traceback.print_exc()

            def _manage_extensions_inner(self):
                if not HAS_EXTENSIONS:
                    QMessageBox.information(
                        self, "Extensions",
                        "Chrome extension support requires Qt 6.10+ / a recent PyQt6-WebEngine.\n"
                        "Update with:\n  py -m pip install -U PyQt6 PyQt6-WebEngine"
                    )
                    return

                # SEPARATE, IMPORTANT CAVEAT: Qt 6.10.1 has a CONFIRMED
                # upstream crash bug in QWebEngineExtensionManager itself --
                # a hard native SIGTRAP (not a Python exception, so this
                # try/except cannot always save you if it fires deep inside
                # the C++ call). See
                # https://github.com/qutebrowser/qutebrowser/issues/8785
                # (filed Nov 2025, "priority: 0 - high"). If extensions
                # still crash or misbehave after everything here, run
                # `pip show PyQt6-WebEngine` -- if it's 6.10.1 specifically,
                # that upstream bug is the likely cause. Try
                # `pip install PyQt6-WebEngine==6.10.0`, or the newest patch
                # release once Qt ships a fix. This is a bug in Qt itself,
                # not something fixable from this app's Python code.
                try:
                    manager = self.profile.extensionManager()
                except Exception:
                    traceback.print_exc()
                    QMessageBox.warning(
                        self, "Extensions",
                        "This build of PyQt6-WebEngine doesn't fully support the extension API yet "
                        "(profile.extensionManager() failed). Try:\n  py -m pip install -U PyQt6 PyQt6-WebEngine"
                    )
                    return
                if manager is None:
                    QMessageBox.warning(self, "Extensions", "No extension manager available on this profile.")
                    return

                choice, ok = QInputDialog.getItem(
                    self, "Chrome Extensions",
                    "What do you want to do?",
                    [
                        "Install from Chrome Web Store (ID or link)",
                        "Load unpacked extension (folder)",
                        "Install extension (.crx / .zip / folder)",
                        "List loaded extensions",
                        "Enable / disable an extension",
                    ],
                    0, False
                )
                if not ok:
                    return

                if choice.startswith("List"):
                    exts = manager.extensions()
                    if not exts:
                        QMessageBox.information(self, "Extensions", "No extensions currently loaded.")
                        return
                    lines = []
                    for e in exts:
                        status = "enabled" if e.isEnabled() else "disabled"
                        lines.append(f"\u2022 {e.name()}  [{status}]\n  {e.path()}")
                    QMessageBox.information(self, "Loaded extensions", "\n\n".join(lines))
                    return

                if choice.startswith("Enable"):
                    exts = manager.extensions()
                    if not exts:
                        QMessageBox.information(self, "Extensions", "No extensions loaded yet -- load or install one first.")
                        return
                    labels = [f"{e.name()} ({'enabled' if e.isEnabled() else 'disabled'})" for e in exts]
                    label, ok2 = QInputDialog.getItem(self, "Enable / disable", "Which extension?", labels, 0, False)
                    if not ok2:
                        return
                    target = exts[labels.index(label)]
                    manager.setExtensionEnabled(target, not target.isEnabled())
                    QMessageBox.information(
                        self, "Extensions",
                        f"{target.name()} is now {'enabled' if not target.isEnabled() else 'disabled'}.\n"
                        "You may need to open a new tab for the change to take effect."
                    )
                    return

                if choice.startswith("Install from Chrome Web Store"):
                    id_or_url, ok3 = QInputDialog.getText(
                        self, "Install from Chrome Web Store",
                        "Paste the extension's ID, or its full Web Store URL\n"
                        "(e.g. https://chromewebstore.google.com/detail/<name>/<32-letter-id>):"
                    )
                    if not ok3 or not id_or_url.strip():
                        return
                    try:
                        path = _install_from_webstore(manager, id_or_url.strip())
                        _enable_by_path(manager, path)
                        QMessageBox.information(
                            self, "Extension installed",
                            "Downloaded and installed -- it's enabled and will keep loading automatically on "
                            "every future launch. Open a new tab for it to take effect."
                        )
                    except Exception as e:
                        QMessageBox.warning(
                            self, "Install failed",
                            f"Couldn't install that extension:\n{e}\n\n"
                            "This can happen if the ID is wrong, the extension is Manifest V2-only "
                            "(unsupported here), or it's region/account-restricted on the Web Store."
                        )
                    return

                if "unpacked" in choice.lower():
                    path = QFileDialog.getExistingDirectory(self, "Select unpacked extension folder")
                    if not path:
                        return
                    manager.loadExtension(path)
                    _enable_by_path(manager, path)
                    _remember_extension(path, "unpacked")
                    QMessageBox.information(
                        self, "Extension",
                        f"Loaded and enabled:\n{path}\n\n"
                        "It'll automatically load again on every future launch -- no need to redo this."
                    )
                else:
                    path, _ = QFileDialog.getOpenFileName(
                        self, "Select extension (.crx / .zip) or cancel to pick a folder",
                        "", "Chrome extensions (*.crx *.zip);;All files (*.*)"
                    )
                    if not path:
                        path = QFileDialog.getExistingDirectory(self, "Or select an unpacked extension folder")
                    if not path:
                        return
                    manager.installExtension(path)
                    _enable_by_path(manager, path)
                    _remember_extension(path, "crx")
                    QMessageBox.information(
                        self, "Extension",
                        f"Installed and enabled:\n{path}\n\n"
                        "It'll automatically load again on every future launch -- no need to redo this."
                    )

            def add_tab(self, url, focus=False):
                try:
                    tab = BrowserTab(self, self.profile)
                    self._tab_info(tab)["title"] = "New Tab"
                    tab.setUrl(QUrl(url))
                    tab.titleChanged.connect(lambda title, t=tab: self._update_tab_title(t, title))
                    tab.iconChanged.connect(lambda icon, t=tab: self._update_tab_icon(t, icon))
                    tab.urlChanged.connect(lambda qurl, t=tab: self._update_url_bar(t, qurl))
                    tab.urlChanged.connect(lambda _qurl: self._schedule_session_save())
                    index = self.tabs.addTab(tab, "New Tab")
                    if focus:
                        self.tabs.setCurrentIndex(index)
                    self._schedule_session_save()
                    return tab
                except Exception:
                    traceback.print_exc()
                    return self.current_tab()

            def add_tab_with_page(self, page=None, focus=False):
                """
                Like add_tab(), but wraps an ALREADY-CREATED QWebEnginePage
                instead of making a fresh one and navigating it to HOME_URL
                -- or, if `page` is None, lets BrowserTab create a fresh,
                blank page that's immediately owned by a live view (used by
                createWindow() above, so Chromium has somewhere real to
                render the popup navigation into from the very first frame).
                Either way, we must NOT call setUrl() here: for a page
                Chromium handed us via createWindow(), it's about to
                navigate that page itself (to the link that was actually
                clicked) -- calling setUrl() would race with, and likely
                clobber, that navigation.
                """
                try:
                    tab = BrowserTab(self, self.profile, page=page)
                    self._tab_info(tab)["title"] = "New Tab"
                    tab.titleChanged.connect(lambda title, t=tab: self._update_tab_title(t, title))
                    tab.iconChanged.connect(lambda icon, t=tab: self._update_tab_icon(t, icon))
                    tab.urlChanged.connect(lambda qurl, t=tab: self._update_url_bar(t, qurl))
                    tab.urlChanged.connect(lambda _qurl: self._schedule_session_save())
                    index = self.tabs.addTab(tab, "New Tab")
                    if focus:
                        self.tabs.setCurrentIndex(index)
                    self._schedule_session_save()
                    return tab
                except Exception:
                    traceback.print_exc()
                    return self.current_tab()

            def _schedule_session_save(self):
                """
                Debounced session save: a single page load can fire
                urlChanged several times in quick succession (redirects,
                fragment changes, etc.). Writing to disk synchronously on
                the GUI thread for EACH of those -- which the earlier
                version of this did -- is a real source of stutter/flicker
                right at the moment a link is clicked and a new tab is
                being created, since it blocks the same thread that's
                trying to render the new tab. Coalescing rapid-fire saves
                into one, ~400ms after things settle, keeps the session
                file accurate without doing disk I/O in the middle of a
                navigation/tab-creation burst.
                """
                if not hasattr(self, "_session_save_timer"):
                    self._session_save_timer = QTimer(self)
                    self._session_save_timer.setSingleShot(True)
                    self._session_save_timer.timeout.connect(lambda: _save_session(self))
                self._session_save_timer.start(400)

            def close_tab(self, index):
                try:
                    if self.tabs.count() > 1:
                        tab = self.tabs.widget(index)
                        group = self._tab_info(tab).get("group", "")
                        self._closed_tabs.append({
                            "url": tab.url().toString(),
                            "title": self._tab_info(tab).get("title", "New Tab"),
                        })
                        self._closed_tabs = self._closed_tabs[-10:]
                        self.tabs.removeTab(index)
                        self._tab_state.pop(id(tab), None)
                        if group and not self._group_tabs(group):
                            self._collapsed_groups.discard(group)
                        self._apply_group_visibility()
                        _save_session(self)
                    else:
                        self.close()
                except Exception:
                    traceback.print_exc()

            def _reopen_closed_tab(self):
                if not self._closed_tabs:
                    return
                record = self._closed_tabs.pop()
                tab = self.add_tab(record["url"], focus=True)
                self._tab_info(tab)["title"] = record.get("title", "New Tab")
                self._refresh_tab_label(tab)

            def closeEvent(self, event):
                try:
                    _save_session(self)
                except Exception:
                    traceback.print_exc()
                super().closeEvent(event)

            def _restore_session(self):
                try:
                    urls = _load_session()
                    if not urls:
                        box = QMessageBox(self)
                        box.setIcon(QMessageBox.Icon.Information)
                        box.setWindowTitle("Restore session")
                        box.setText(
                            "No saved session found yet. Open a few tabs, close the app normally, "
                            "and it'll be saved for next time -- or just try this button again after that."
                        )
                        game_btn = box.addButton("\u2728 Play Aether Game", QMessageBox.ButtonRole.ActionRole)
                        box.addButton(QMessageBox.StandardButton.Ok)
                        box.exec()
                        if box.clickedButton() is game_btn:
                            self.add_tab(GAMES_URL, focus=True)
                        return
                    restore = QMessageBox.question(
                        self, "Restore previous session",
                        f"Reopen {len(urls)} saved tab{'s' if len(urls) != 1 else ''}?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.Yes,
                    )
                    if restore == QMessageBox.StandardButton.Yes:
                        for i, record in enumerate(urls):
                            tab = self.add_tab(record["url"], focus=(i == 0))
                            self._tab_info(tab)["pinned"] = record.get("pinned", False)
                            self._tab_info(tab)["group"] = record.get("group", "")
                            if record.get("collapsed") and record.get("group"):
                                self._collapsed_groups.add(record["group"])
                        self._move_tabs_into_order()
                        self._apply_group_visibility()
                except Exception:
                    traceback.print_exc()

            def _log_history(self, url, title):
                try:
                    _append_history(url, title)
                except Exception:
                    traceback.print_exc()

            def _show_history(self):
                try:
                    self._show_history_inner()
                except Exception:
                    traceback.print_exc()

            def _show_history_inner(self):
                entries = _load_history_raw()

                dialog = QDialog(self)
                dialog.setWindowTitle("History")
                dialog.resize(560, 480)
                layout = QVBoxLayout(dialog)

                if entries:
                    layout.addWidget(QLabel(f"{len(entries)} page{'s' if len(entries) != 1 else ''} \u2014 double-click to reopen:"))
                else:
                    layout.addWidget(QLabel("No history yet -- pages you visit will show up here, most recent first."))

                list_widget = QListWidget()

                # Pinned shortcut, always shown first regardless of history --
                # not a visited page, just a fun way in to the built-in game.
                special_item = QListWidgetItem("\u2728 Special: Aether Games \u2014 double-click to play")
                special_font = special_item.font()
                special_font.setBold(True)
                special_item.setFont(special_font)
                special_item.setForeground(QColor("#a78bfa"))
                special_item.setData(Qt.ItemDataRole.UserRole, GAMES_URL)
                list_widget.addItem(special_item)

                for entry in entries:
                    title = entry.get("title") or entry.get("url", "")
                    when = (entry.get("visited_at") or "")[:16].replace("T", " ")
                    item = QListWidgetItem(f"{title}\n{entry.get('url', '')}   \u00b7   {when}")
                    item.setData(Qt.ItemDataRole.UserRole, entry.get("url"))
                    list_widget.addItem(item)

                def _open_selected():
                    item = list_widget.currentItem()
                    if item:
                        self.add_tab(item.data(Qt.ItemDataRole.UserRole), focus=True)
                        dialog.close()

                list_widget.itemDoubleClicked.connect(lambda _item: _open_selected())
                layout.addWidget(list_widget)

                button_row = QHBoxLayout()
                if entries:
                    clear_btn = QPushButton("Clear History")

                    def _do_clear():
                        confirm = QMessageBox.question(
                            dialog, "Clear history", "Delete all browsing history? This can't be undone.",
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                            QMessageBox.StandardButton.No,
                        )
                        if confirm == QMessageBox.StandardButton.Yes:
                            _clear_history()
                            dialog.close()

                    clear_btn.clicked.connect(_do_clear)
                    button_row.addWidget(clear_btn)
                button_row.addStretch()
                close_btn = QPushButton("Close")
                close_btn.clicked.connect(dialog.close)
                button_row.addWidget(close_btn)
                layout.addLayout(button_row)

                dialog.exec()

            def _bookmark_current(self):
                tab = self.current_tab()
                if tab is None:
                    return
                url = tab.url().toString()
                if not (url.startswith("http://") or url.startswith("https://")):
                    QMessageBox.information(self, "Bookmark", "Only web pages can be bookmarked.")
                    return
                existing = next((b for b in _load_bookmarks() if b.get("url") == url), None)
                default_title = tab.title() or url
                title, ok = QInputDialog.getText(self, "Add bookmark", "Name:", text=default_title)
                if not ok or not title.strip():
                    return
                bookmarks = _load_bookmarks()
                if existing:
                    existing["title"] = title.strip()
                else:
                    bookmarks.insert(0, {"title": title.strip(), "url": url})
                _save_bookmarks(bookmarks)

            def keyPressEvent(self, event):
                if event.modifiers() & Qt.KeyboardModifier.ControlModifier and event.key() == Qt.Key.Key_D:
                    self._bookmark_current()
                    event.accept()
                    return
                super().keyPressEvent(event)

            def _show_bookmarks(self):
                bookmarks = _load_bookmarks()
                dialog = QDialog(self)
                dialog.setWindowTitle("Bookmarks")
                dialog.resize(620, 460)
                layout = QVBoxLayout(dialog)
                layout.addWidget(QLabel("Saved pages -- double-click one to open it."))
                list_widget = QListWidget()
                for bookmark in bookmarks:
                    item = QListWidgetItem(f"{bookmark.get('title') or bookmark.get('url')}\n{bookmark.get('url')}")
                    item.setData(Qt.ItemDataRole.UserRole, bookmark.get("url"))
                    list_widget.addItem(item)
                layout.addWidget(list_widget)

                def open_selected():
                    item = list_widget.currentItem()
                    if item:
                        self.add_tab(item.data(Qt.ItemDataRole.UserRole), focus=True)
                        dialog.close()

                list_widget.itemDoubleClicked.connect(lambda _item: open_selected())
                buttons = QHBoxLayout()
                remove_btn = QPushButton("Remove selected")

                def remove_selected():
                    item = list_widget.currentItem()
                    if not item:
                        return
                    url = item.data(Qt.ItemDataRole.UserRole)
                    _save_bookmarks([b for b in _load_bookmarks() if b.get("url") != url])
                    list_widget.takeItem(list_widget.row(item))

                remove_btn.clicked.connect(remove_selected)
                buttons.addWidget(remove_btn)
                buttons.addStretch()
                close_btn = QPushButton("Close")
                close_btn.clicked.connect(dialog.close)
                buttons.addWidget(close_btn)
                layout.addLayout(buttons)
                dialog.exec()

            def current_tab(self):
                return self.tabs.currentWidget()

            def _update_tab_title(self, tab, title):
                try:
                    self._refresh_tab_label(tab, title)
                except Exception:
                    traceback.print_exc()

            def _update_url_bar(self, tab, qurl):
                try:
                    if tab is self.current_tab():
                        self.url_bar.setText(qurl.toString())
                except Exception:
                    traceback.print_exc()

            def _sync_url_bar(self, index):
                try:
                    tab = self.tabs.widget(index)
                    if tab is not None:
                        self.url_bar.setText(tab.url().toString())
                except Exception:
                    traceback.print_exc()

            def navigate_to_url_bar(self):
                try:
                    text = self.url_bar.text().strip()
                    if not text:
                        return
                    if text.startswith("http://") or text.startswith("https://"):
                        target = text
                    elif "." in text and " " not in text:
                        target = "https://" + text
                    else:
                        target = f"{HOME_URL}?q={quote(text)}&mode=all"
                    self.current_tab().setUrl(QUrl(target))
                except Exception:
                    traceback.print_exc()

        qt_app = QApplication(sys.argv)

        data_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
        profile = QWebEngineProfile("AetherScanProfile", qt_app)
        profile.setPersistentStoragePath(f"{data_dir}/webprofile")
        profile.setCachePath(f"{data_dir}/webcache")
        profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
        profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)

        profile.setDownloadPath(
            QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        )

        EXTENSIONS_DIR = os.path.join(data_dir, "webstore_extensions")
        EXTENSIONS_MANIFEST_PATH = os.path.join(data_dir, "extensions_manifest.json")
        SESSION_FILE = os.path.join(data_dir, "last_session.json")
        HISTORY_FILE = os.path.join(data_dir, "browsing_history.json")
        BOOKMARKS_FILE = os.path.join(data_dir, "bookmarks.json")
        HISTORY_MAX_ENTRIES = 1000  # oldest entries drop off past this, same idea as a real browser's history cap

        def _append_history(url, title):
            try:
                entries = _load_history_raw()
                # Move a re-visited URL to the top instead of duplicating it,
                # same as most real browsers' history behavior.
                entries = [e for e in entries if e.get("url") != url]
                entries.insert(0, {"url": url, "title": title, "visited_at": datetime.utcnow().isoformat()})
                entries = entries[:HISTORY_MAX_ENTRIES]
                with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                    json.dump(entries, f)
            except Exception:
                traceback.print_exc()

        def _load_history_raw():
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    entries = json.load(f)
                return [e for e in entries if isinstance(e, dict) and e.get("url")]
            except (FileNotFoundError, json.JSONDecodeError):
                return []

        def _clear_history():
            try:
                with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                    json.dump([], f)
            except Exception:
                traceback.print_exc()

        def _load_bookmarks():
            try:
                with open(BOOKMARKS_FILE, "r", encoding="utf-8") as f:
                    bookmarks = json.load(f)
                return [
                    b for b in bookmarks
                    if isinstance(b, dict) and b.get("url", "").startswith(("http://", "https://"))
                ]
            except (FileNotFoundError, json.JSONDecodeError):
                return []

        def _save_bookmarks(bookmarks):
            try:
                seen = set()
                cleaned = []
                for bookmark in bookmarks:
                    url = bookmark.get("url", "")
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    cleaned.append({"title": bookmark.get("title") or url, "url": url})
                with open(BOOKMARKS_FILE, "w", encoding="utf-8") as f:
                    json.dump(cleaned, f, indent=2)
            except Exception:
                traceback.print_exc()

        def _save_session(window):
            try:
                tabs = [
                    {
                        "url": window.tabs.widget(i).url().toString(),
                        "pinned": window._tab_info(window.tabs.widget(i)).get("pinned", False),
                        "group": window._tab_info(window.tabs.widget(i)).get("group", ""),
                        "collapsed": window._tab_info(window.tabs.widget(i)).get("group", "") in window._collapsed_groups,
                    }
                    for i in range(window.tabs.count())
                    if window.tabs.widget(i).url().toString()
                ]
                with open(SESSION_FILE, "w", encoding="utf-8") as f:
                    json.dump(tabs, f)
            except Exception:
                traceback.print_exc()

        def _load_session():
            try:
                with open(SESSION_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if not isinstance(saved, list):
                    return []
                records = []
                for item in saved:
                    if isinstance(item, str) and item:
                        records.append({"url": item, "pinned": False, "group": "", "collapsed": False})
                    elif isinstance(item, dict) and item.get("url"):
                        records.append({
                            "url": item["url"],
                            "pinned": bool(item.get("pinned")),
                            "group": str(item.get("group") or ""),
                            "collapsed": bool(item.get("collapsed")),
                        })
                return records
            except (FileNotFoundError, json.JSONDecodeError):
                return []

        os.makedirs(EXTENSIONS_DIR, exist_ok=True)

        def _load_ext_manifest():
            try:
                with open(EXTENSIONS_MANIFEST_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                return []

        def _save_ext_manifest(entries):
            with open(EXTENSIONS_MANIFEST_PATH, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)

        def _remember_extension(path, kind):
            entries = _load_ext_manifest()
            if not any(e.get("path") == path for e in entries):
                entries.append({"path": path, "kind": kind})
                _save_ext_manifest(entries)

        def _enable_by_path(manager, path):
            for ext in manager.extensions():
                try:
                    if ext.path() == path and not ext.isEnabled():
                        manager.setExtensionEnabled(ext, True)
                except Exception:
                    pass

        def _install_from_webstore(manager, id_or_url):
            ext_id_match = re.search(r"[a-p]{32}", id_or_url)
            if not ext_id_match:
                raise ValueError("That doesn't look like a valid extension ID or Chrome Web Store URL.")
            ext_id = ext_id_match.group()

            crx_url = (
                "https://clients2.google.com/service/update2/crx"
                f"?response=redirect&acceptformat=crx3&prodversion=124.0.0.0&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
            )
            res = requests.get(crx_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
            res.raise_for_status()
            if len(res.content) < 1000:
                raise ValueError("The Web Store didn't return a valid extension package for that ID (it may not exist, or may be Manifest V2-only).")

            crx_path = os.path.join(EXTENSIONS_DIR, f"{ext_id}.crx")
            with open(crx_path, "wb") as f:
                f.write(res.content)

            manager.installExtension(crx_path)
            _remember_extension(crx_path, "crx")
            return crx_path

        def _autoload_saved_extensions(manager):
            for entry in _load_ext_manifest():
                path = entry.get("path")
                if not path or not os.path.exists(path):
                    continue
                try:
                    if entry.get("kind") == "crx":
                        manager.installExtension(path)
                    else:
                        manager.loadExtension(path)
                    _enable_by_path(manager, path)
                except Exception:
                    traceback.print_exc()

        profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )

        window = BrowserWindow(profile)

        try:
            if _load_session():
                window.tabs.removeTab(0)
                window._restore_session()
                if window.tabs.count() == 0:
                    window.add_tab(HOME_URL, focus=True)
        except Exception:
            traceback.print_exc()

        try:
            if HAS_EXTENSIONS:
                _ext_manager = profile.extensionManager()
                if _ext_manager is not None:
                    _autoload_saved_extensions(_ext_manager)
        except Exception:
            traceback.print_exc()

        window.show()
        sys.exit(qt_app.exec())
"""Fetches release notes for a version range."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests

GITHUB_API = "https://api.github.com"
_DISCOURSE_REPO = "discourse/discourse"
_DISCOURSE_RELEASES_FEED = "https://releases.discourse.org/feed.xml"
_DISCOURSE_RELEASES_INDEX = "https://releases.discourse.org/"
_TEAMSPEAK_CHANGELOG_URL = "https://www.teamspeak.com/en/changelog/"
_TEAMSPEAK_COMMUNITY_SEARCH = "https://community.teamspeak.com/search.json"
_DISCOURSE_BACKPORT_TAG_RE = re.compile(r"\[backport ([\w.]+)\]")
_DISCOURSE_COMMITS_DEFAULT_WINDOW_DAYS = 60
_DISCOURSE_COMMITS_MAX_PAGES = 5

_CHANGELOG_ASSET_RE = re.compile(r"https://\S+/releases/download/\S+?\.md")
_MAX_FETCHED_CHANGELOG_CHARS = 40_000

_RELEASES_PAGE_SIZE = 100
_RELEASES_MAX_PAGES = 3


@dataclass
class ReleaseSource:
    type: str
    repo: str = ""
    host: str = ""


def fetch_release_notes(
    source: ReleaseSource,
    current_version: str,
    new_version: str,
    *,
    max_releases: int = 10,
    since_timestamp: str | None = None,
    deployed_commit: str | None = None,
) -> tuple[str, str]:
    if source.type == "discourse_commits":
        return _fetch_discourse_commits(since_timestamp, deployed_commit)

    if source.type == "discourse_releases":
        return _fetch_discourse_releases(max_releases)

    if source.type == "teamspeak_changelog":
        return _fetch_teamspeak_changelog(new_version)

    if source.type == "github":
        api_base = GITHUB_API
    elif source.type == "forgejo":
        if not source.host:
            raise ValueError("forgejo release source requires 'host'")
        api_base = f"{source.host.rstrip('/')}/api/v1"
    else:
        raise ValueError(f"unknown release source type: {source.type!r}")

    norm_current = current_version.lstrip("vV")
    norm_new = new_version.lstrip("vV")

    if norm_current == norm_new:
        url = ""
        try:
            resp = requests.get(
                f"{api_base}/repos/{source.repo}/releases",
                params={"per_page": _RELEASES_PAGE_SIZE, "page": 1},
                timeout=15,
            )
            resp.raise_for_status()
            for rel in resp.json():
                if rel.get("tag_name", "").lstrip("vV") == norm_new:
                    url = rel.get("html_url", "")
                    break
        except Exception:
            pass
        return (
            f"VERIFIED-NO-CHANGES: {new_version} is already the current version -- "
            f"this event is an upstream image rebuild (digest changed) under the same "
            f"published tag, not a new release. No new release exists for this delta "
            f"because there isn't one."
        ), url

    releases: list[dict] = []
    found_current = norm_current == ""
    for page in range(1, _RELEASES_MAX_PAGES + 1):
        resp = requests.get(
            f"{api_base}/repos/{source.repo}/releases",
            params={"per_page": _RELEASES_PAGE_SIZE, "page": page},
            timeout=15,
        )
        resp.raise_for_status()
        page_releases = resp.json()
        releases.extend(page_releases)
        if any(r.get("tag_name", "").lstrip("vV") == norm_current for r in page_releases):
            found_current = True
            break
        if len(page_releases) < _RELEASES_PAGE_SIZE:
            break

    notes = []
    new_version_url = ""
    collecting = False
    for rel in releases:
        tag = rel.get("tag_name", "")
        norm_tag = tag.lstrip("vV")
        if norm_tag == norm_new:
            new_version_url = rel.get("html_url", "")
            collecting = True
        if norm_tag == norm_current:
            break
        if not collecting:
            continue
        if rel.get("prerelease"):
            continue
        if len(notes) >= max_releases:
            continue
        body = rel.get("body") or ""
        body = _resolve_changelog_placeholder(body)
        if body:
            notes.append(f"## {tag}\n\n{body}")

    if not found_current and notes:
        notes.insert(0, (
            f"NOTE: could not find a release tagged {current_version!r} within "
            f"{len(releases)} releases searched -- the notes below cover the most "
            f"recent releases down to that search limit, but may be missing "
            f"earlier ones between the real current version and here."
        ))

    return "\n\n".join(notes), new_version_url


def _resolve_changelog_placeholder(body: str) -> str:
    if len(body) > 500:
        return body
    match = _CHANGELOG_ASSET_RE.search(body)
    if not match:
        return body
    try:
        resp = requests.get(match.group(0), timeout=15)
        resp.raise_for_status()
    except Exception:
        return body
    return resp.text[:_MAX_FETCHED_CHANGELOG_CHARS]


def _fetch_teamspeak_community_announcement(new_version: str) -> tuple[str, str]:
    try:
        resp = requests.get(
            _TEAMSPEAK_COMMUNITY_SEARCH,
            params={"q": f"{new_version} #announcements"},
            timeout=15,
        )
        resp.raise_for_status()
        posts = resp.json().get("posts", [])
        if not posts:
            return "", ""
        topic_id = posts[0]["topic_id"]
        post_number = posts[0]["post_number"]
        topic_resp = requests.get(
            f"https://community.teamspeak.com/t/{topic_id}.json", timeout=15,
        )
        topic_resp.raise_for_status()
        topic = topic_resp.json()
        slug = topic.get("slug", str(topic_id))
        for p in topic.get("post_stream", {}).get("posts", []):
            if p.get("post_number") == post_number:
                text = re.sub(r"<[^>]+>", " ", p.get("cooked", "")).strip()
                return text, f"https://community.teamspeak.com/t/{slug}/{topic_id}"
    except Exception:
        pass
    return "", ""


def _fetch_teamspeak_changelog(new_version: str) -> tuple[str, str]:
    community_text, community_url = _fetch_teamspeak_community_announcement(new_version)
    if community_text:
        return community_text, community_url
    try:
        resp = requests.get(_TEAMSPEAK_CHANGELOG_URL, timeout=15)
        resp.raise_for_status()
        if new_version in resp.text:
            idx = resp.text.index(new_version)
            snippet = re.sub(r"<[^>]+>", " ", resp.text[idx:idx + 2000])
            return snippet.strip(), _TEAMSPEAK_CHANGELOG_URL
    except Exception:
        pass
    return "", _TEAMSPEAK_CHANGELOG_URL


def _fetch_discourse_releases(max_releases: int) -> tuple[str, str]:
    resp = requests.get(_DISCOURSE_RELEASES_FEED, timeout=15)
    resp.raise_for_status()
    root = ET.fromstring(resp.text)

    notes: list[str] = []
    newest_url = ""
    for item in root.findall("./channel/item"):
        title = (item.findtext("title") or "").strip()
        if "released" not in title:
            continue
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        if not newest_url:
            newest_url = link
        notes.append(f"- {title} ({pub_date}): {link}")
        if len(notes) >= max_releases:
            break

    return "\n".join(notes), newest_url


_DISCOURSE_SECURITY_PREFIX_RE = re.compile(r"^\s*security\s*:", re.IGNORECASE)


def _resolve_discourse_release_branch(deployed_commit: str) -> str:
    resp = requests.get(f"{GITHUB_API}/repos/{_DISCOURSE_REPO}/commits/{deployed_commit}", timeout=15)
    resp.raise_for_status()
    message = resp.json()["commit"]["message"]
    m = _DISCOURSE_BACKPORT_TAG_RE.search(message)
    if m:
        return f"release/{m.group(1)}"

    branches_resp = requests.get(
        f"{GITHUB_API}/repos/{_DISCOURSE_REPO}/branches",
        params={"per_page": 100},
        timeout=15,
    )
    branches_resp.raise_for_status()
    release_branches = sorted(
        (b["name"] for b in branches_resp.json() if b["name"].startswith("release/")),
        reverse=True,
    )
    for branch in release_branches:
        cmp_resp = requests.get(
            f"{GITHUB_API}/repos/{_DISCOURSE_REPO}/compare/{deployed_commit}...{branch}",
            timeout=15,
        )
        cmp_resp.raise_for_status()
        if cmp_resp.json().get("status") in ("identical", "ahead"):
            return branch
    raise ValueError(f"commit {deployed_commit} isn't an ancestor of any real release/* branch")


def _discourse_commits_since_param(since_iso: str | None) -> str:
    if since_iso:
        dt = datetime.fromisoformat(since_iso)
    else:
        dt = datetime.now(timezone.utc) - timedelta(days=_DISCOURSE_COMMITS_DEFAULT_WINDOW_DAYS)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fetch_discourse_commits_from_branch(branch: str, since_iso: str | None) -> tuple[str, str]:
    commits: list[dict] = []
    page = 1
    while page <= _DISCOURSE_COMMITS_MAX_PAGES:
        resp = requests.get(
            f"{GITHUB_API}/repos/{_DISCOURSE_REPO}/commits",
            params={"sha": branch, "since": _discourse_commits_since_param(since_iso), "per_page": 100, "page": page},
            timeout=20,
        )
        resp.raise_for_status()
        page_commits = resp.json()
        commits.extend(page_commits)
        if len(page_commits) < 100:
            break
        page += 1

    if not commits:
        since_display = since_iso or f"the last {_DISCOURSE_COMMITS_DEFAULT_WINDOW_DAYS} days (no prior successful update on record)"
        return (
            f"VERIFIED-NO-CHANGES: checked the real commit history on {branch} "
            f"directly against GitHub, since {since_display} -- zero commits found. "
            "Nothing has shipped on the branch this image actually tracks since the "
            "last successful update.",
            "",
        )

    commits.reverse()

    lines = []
    for commit in commits:
        message = commit["commit"]["message"]
        subject, _, rest = message.partition("\n")
        lines.append(f"- {subject}")
        if _DISCOURSE_SECURITY_PREFIX_RE.match(subject) and rest.strip():
            lines.append(f"  {rest.strip()}")

    text = "\n".join(lines)
    if len(text) > _MAX_FETCHED_CHANGELOG_CHARS:
        text = text[:_MAX_FETCHED_CHANGELOG_CHARS] + "\n[... truncated, too many commits to include in full ...]"

    newest_hash = commits[-1]["sha"]
    newest_url = f"https://github.com/{_DISCOURSE_REPO}/commit/{newest_hash}"
    return text, newest_url


def _fetch_discourse_commits(since_iso: str | None, deployed_commit: str | None) -> tuple[str, str]:
    try:
        if not deployed_commit:
            raise ValueError("no deployed commit hash available to resolve the release branch from")
        branch = _resolve_discourse_release_branch(deployed_commit)
        return _fetch_discourse_commits_from_branch(branch, since_iso)
    except Exception as exc:
        notes, url = _fetch_discourse_releases(max_releases=10)
        return (
            f"[Note: real commit history was unavailable ({exc}), falling back to a bare version list.]\n"
            + notes,
            url,
        )

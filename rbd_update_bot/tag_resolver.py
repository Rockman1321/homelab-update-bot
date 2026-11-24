'Resolves a floating major-version tag (e.g. "v3") to the release tag sharing its digest.'
from __future__ import annotations

import re
from dataclasses import dataclass

import requests

_DOCKERHUB_TAGS_API = "https://hub.docker.com/v2/repositories"
_GHCR_AUTH = "https://ghcr.io/token"
_GHCR_API = "https://ghcr.io"


@dataclass
class RegistryConfig:
    type: str
    repo: str


def _major_from_tag(tag: str) -> str:
    return tag[1:] if tag.lower().startswith("v") else tag


def resolve_tag(
    registry: RegistryConfig,
    floating_tag: str,
    target_digest: str,
    *,
    github_releases_repo: str | None = None,
) -> str | None:
    major = _major_from_tag(floating_tag)
    if registry.type == "dockerhub":
        return _resolve_dockerhub(registry.repo, major, target_digest)
    if registry.type == "ghcr":
        if not github_releases_repo:
            raise ValueError("ghcr resolution requires github_releases_repo")
        return _resolve_ghcr(registry.repo, github_releases_repo, major, target_digest)
    raise ValueError(f"unknown registry type: {registry.type!r}")


def _resolve_dockerhub(repo: str, major: str, target_digest: str, max_pages: int = 5) -> str | None:
    pattern = re.compile(rf"^{re.escape(major)}\.\d+\.\d+$")
    url = f"{_DOCKERHUB_TAGS_API}/{repo}/tags"
    params: dict | None = {"page_size": 100, "name": f"{major}."}

    for _ in range(max_pages):
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        for result in data.get("results", []):
            name = result.get("name", "")
            if pattern.match(name) and result.get("digest") == target_digest:
                return name
        next_url = data.get("next")
        if not next_url:
            return None
        url, params = next_url, None
    return None


def _ghcr_manifest_digest(repo: str, tag: str, token: str) -> str | None:
    resp = requests.head(
        f"{_GHCR_API}/v2/{repo}/manifests/{tag}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.oci.image.index.v1+json,"
                      "application/vnd.docker.distribution.manifest.list.v2+json,"
                      "application/vnd.docker.distribution.manifest.v2+json",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        return None
    return resp.headers.get("Docker-Content-Digest")


def _resolve_ghcr(
    ghcr_repo: str, github_releases_repo: str, major: str, target_digest: str, max_candidates: int = 20
) -> str | None:
    token_resp = requests.get(
        _GHCR_AUTH, params={"service": "ghcr.io", "scope": f"repository:{ghcr_repo}:pull"}, timeout=15
    )
    token_resp.raise_for_status()
    token = token_resp.json()["token"]

    releases_resp = requests.get(
        f"https://api.github.com/repos/{github_releases_repo}/releases",
        params={"per_page": max_candidates},
        timeout=15,
    )
    releases_resp.raise_for_status()

    pattern = re.compile(rf"^v?{re.escape(major)}\.\d+\.\d+$") if major.isdigit() else None
    for rel in releases_resp.json():
        tag = rel.get("tag_name", "")
        if pattern and not pattern.match(tag):
            continue
        if _ghcr_manifest_digest(ghcr_repo, tag, token) == target_digest:
            return tag
    return None

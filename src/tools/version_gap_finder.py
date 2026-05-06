"""
VersionGapFinder
================
Compares the current Ubuntu noble release version against the latest upstream
version and reports the version gap.

Data source priority:
  1. Pre-computed JSON (data/output/*.json) — millisecond response
  2. crates.io API (librust-* packages)
  3. Launchpad REST API (all packages)

Public interface: find_gap(pkg_name) → dict
"""

import re
import os
import json
import logging
from functools import lru_cache
from typing import Optional

import requests
from packaging.version import Version, InvalidVersion

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import config as cfg

log = logging.getLogger(__name__)

_CRATES_HEADERS = {
    "User-Agent": "linux-sec-theater/1.0 (security research)"
}
_TIMEOUT = 12


# ── Hard-coded upstream repo mapping ─────────────────────────────────────────
# Handles classic C/C++ packages whose upstream repo cannot be inferred from
# the package name alone.
# key: Ubuntu source/binary package name, value: GitHub repository URL
KNOWN_UPSTREAM_REPOS: dict[str, str] = {
    # libxml2
    "libxml2":                    "https://github.com/GNOME/libxml2",
    "libxml2-dev":                "https://github.com/GNOME/libxml2",
    "libxml2-utils":              "https://github.com/GNOME/libxml2",
    # FFmpeg
    "ffmpeg":                     "https://github.com/FFmpeg/FFmpeg",
    "libavcodec-dev":             "https://github.com/FFmpeg/FFmpeg",
    "libavformat-dev":            "https://github.com/FFmpeg/FFmpeg",
    "libavutil-dev":              "https://github.com/FFmpeg/FFmpeg",
    # ImageMagick
    # Ubuntu ships the 6.x series; all 6.x tags live in the ImageMagick6 repo.
    # The main ImageMagick repo only contains 7.x tags.
    "imagemagick":                "https://github.com/ImageMagick/ImageMagick6",
    "imagemagick-6.q16":          "https://github.com/ImageMagick/ImageMagick6",
    "libmagickcore-dev":          "https://github.com/ImageMagick/ImageMagick6",
    # curl / libcurl
    "curl":                       "https://github.com/curl/curl",
    "libcurl4":                   "https://github.com/curl/curl",
    "libcurl4-openssl-dev":       "https://github.com/curl/curl",
    # OpenSSL
    "openssl":                    "https://github.com/openssl/openssl",
    "libssl-dev":                 "https://github.com/openssl/openssl",
    "libssl3":                    "https://github.com/openssl/openssl",
    # zlib
    "zlib1g":                     "https://github.com/madler/zlib",
    "zlib1g-dev":                 "https://github.com/madler/zlib",
    # expat
    "libexpat1":                  "https://github.com/libexpat/libexpat",
    "libexpat1-dev":              "https://github.com/libexpat/libexpat",
    # SQLite
    "libsqlite3-0":               "https://github.com/sqlite/sqlite",
    "libsqlite3-dev":             "https://github.com/sqlite/sqlite",
    # libjpeg-turbo
    "libjpeg-turbo8":             "https://github.com/libjpeg-turbo/libjpeg-turbo",
    "libjpeg-dev":                "https://github.com/libjpeg-turbo/libjpeg-turbo",
    "libjpeg-turbo8-dev":         "https://github.com/libjpeg-turbo/libjpeg-turbo",
    # libpng
    "libpng16-16":                "https://github.com/pnggroup/libpng",
    "libpng-dev":                 "https://github.com/pnggroup/libpng",
    # libwebp
    "libwebp7":                   "https://github.com/webmproject/libwebp",
    "libwebp-dev":                "https://github.com/webmproject/libwebp",
    # GLib / GObject
    "libglib2.0-0":               "https://github.com/GNOME/glib",
    "libglib2.0-dev":             "https://github.com/GNOME/glib",
    # libssh / libssh2
    "libssh2-1":                  "https://github.com/libssh2/libssh2",
    "libssh2-1-dev":              "https://github.com/libssh2/libssh2",
    # nghttp2
    "libnghttp2-14":              "https://github.com/nghttp2/nghttp2",
    "libnghttp2-dev":             "https://github.com/nghttp2/nghttp2",
    # pcre2
    "libpcre2-8-0":               "https://github.com/PCRE2Project/pcre2",
    "libpcre2-dev":               "https://github.com/PCRE2Project/pcre2",

    "golang-github-containers-image-dev":         "https://github.com/containers/image",
    "golang-github-emersion-go-smtp-dev":         "https://github.com/emersion/go-smtp",
    "golang-github-kevinburke-ssh-config-dev":    "https://github.com/kevinburke/ssh_config",
    "golang-webpki-org-jsoncanonicalizer-dev":     "https://github.com/cyberphone/json-canonicalization",
    "golang-sslmate-src-go-pkcs12-dev":           "https://github.com/SSLMate/go-pkcs12",
    # Rust crates
    "librust-actix-rt-dev":                       "https://github.com/actix/actix-net",
    "librust-ansi-to-tui-dev":                    "https://github.com/ratatui/ansi-to-tui",
    "librust-anstyle-query-dev":                  "https://github.com/rust-cli/anstyle",
    "librust-asn1-derive-dev":                    "https://github.com/alex/rust-asn1",
    "librust-async-fs-dev":                       "https://github.com/smol-rs/async-fs",
    "librust-async-global-executor-dev":          "https://github.com/async-rs/async-global-executor",
    "librust-async-process-dev":                  "https://github.com/smol-rs/async-process",
    "librust-base64ct-dev":                       "https://github.com/RustCrypto/formats",
    "librust-bitflags-dev":                       "https://github.com/bitflags/bitflags",
    "librust-bitstream-io-dev":                   "https://github.com/tuffy/bitstream-io",
    "librust-os-info-dev":                        "https://github.com/stanislav-tkach/os_info",
    "sqlite3":     "https://github.com/sqlite/sqlite",
    "libarchive":  "https://github.com/libarchive/libarchive",
    "libjpeg-turbo": "https://github.com/libjpeg-turbo/libjpeg-turbo",
    "libpng":        "https://github.com/pnggroup/libpng",
    "nghttp2":       "https://github.com/nghttp2/nghttp2",
    "librust-bitstream-io-dev":                   "https://github.com/tuffy/bitstream-io"
}


# ── Version string normalization ──────────────────────────────────────────────

def _clean_ver(raw: str) -> str:
    """
    '8:6.9.12.98+dfsg1-5.2build2' → '6.9.12.98'
    '0.21.0-2'                    → '0.21.0'
    """
    raw = re.sub(r"^\d+:", "", raw)       # strip epoch
    raw = re.sub(r"[+~].*$", "", raw)     # strip +dfsg / ~beta suffix
    raw = re.sub(r"-[^-]+$", "", raw)     # strip Debian revision
    return raw.strip()


def _parse(v: str) -> Optional[Version]:
    try:
        return Version(v)
    except InvalidVersion:
        return None


# ── Pre-computed cache ────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _ligrust_cache() -> dict:
    if cfg.LIGRUST_GAP_FILE.exists():
        return json.loads(cfg.LIGRUST_GAP_FILE.read_text())
    return {}


@lru_cache(maxsize=1)
def _golang_cache() -> dict:
    if cfg.GOLANG_GAP_FILE.exists():
        return json.loads(cfg.GOLANG_GAP_FILE.read_text())
    return {}


# ── crates.io lookup ──────────────────────────────────────────────────────────

def _pkg_to_crate(pkg: str) -> Optional[str]:
    """'librust-addr2line-dev' → 'addr2line'"""
    m = re.match(r"^librust-(.+?)(?:\+.+)?-dev$", pkg)
    return m.group(1) if m else None


def _crates_info(crate: str) -> dict:
    url = cfg.CRATES_IO_API.format(crate=crate)
    try:
        r = requests.get(url, headers=_CRATES_HEADERS, timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json().get("crate", {})
        return {
            "latest_version": data.get("newest_version", ""),
            "repository":     data.get("repository", ""),
        }
    except Exception as e:
        log.warning("[VersionGapFinder] crates.io query failed %s: %s", crate, e)
        return {"latest_version": "", "repository": ""}


# ── Go module info lookup (pkg.go.dev proxy) ──────────────────────────────────

def _golang_pkg_to_module(pkg: str) -> Optional[str]:
    """
    Convert a golang Ubuntu package name to a Go module path.
    golang-github-foo-bar-dev → github.com/foo/bar
    golang-cfssl              → github.com/cloudflare/cfssl  (via known map)
    """
    # Special mapping for well-known golang packages without a github- prefix
    _KNOWN = {
        "golang-cfssl":          "github.com/cloudflare/cfssl",
        "golang-k8s-client-dev": "k8s.io/client-go",
    }
    if pkg in _KNOWN:
        return _KNOWN[pkg]

    # golang-github-OWNER-REPO[-dev] format
    m = re.match(r"^golang-github-([^-]+)-(.+?)(?:-dev)?$", pkg)
    if m:
        return f"github.com/{m.group(1)}/{m.group(2)}"

    # golang-PROVIDER-OWNER-REPO[-dev] (e.g. golang-gopkg-ini-v1-dev)
    m2 = re.match(r"^golang-([a-z]+)-([^-]+)-(.+?)(?:-dev)?$", pkg)
    if m2:
        provider, owner, repo = m2.group(1), m2.group(2), m2.group(3)
        if provider == "gopkg":
            return f"gopkg.in/{owner}/{repo}"
        return f"github.com/{owner}/{repo}"

    return None


def _golang_latest_version(module_path: str) -> tuple[str, str]:
    """
    Query the latest Go module version and source URL via proxy.golang.org.
    Returns (latest_version, repo_url).
    """
    try:
        url = f"https://proxy.golang.org/{module_path}/@latest"
        r = requests.get(url, timeout=_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            version = data.get("Version", "").lstrip("v")
            # Derive repo URL from module path or pkg.go.dev
            if module_path.startswith("github.com/"):
                parts = module_path.split("/")
                repo_url = "https://" + "/".join(parts[:3])
            else:
                repo_url = "https://" + module_path
            return version, repo_url
    except Exception as e:
        log.debug("[VersionGapFinder] golang proxy query failed %s: %s", module_path, e)
    return "", ""


# ── GitHub repo URL resolution ────────────────────────────────────────────────

def resolve_repo_url(pkg: str) -> Optional[str]:
    if pkg.startswith("librust-"):
        crate = _pkg_to_crate(pkg)
        if crate:
            info = _crates_info(crate)
            repo = info.get("repository", "")
            if "github.com" in repo:
                return re.sub(r"\.git$", "", repo.rstrip("/"))
    if pkg.startswith("golang-"):
        module = _golang_pkg_to_module(pkg)
        if module and module.startswith("github.com/"):
            parts = module.split("/")
            return "https://" + "/".join(parts[:3])
    return None


# ── GitHub tags latest version lookup ────────────────────────────────────────

def _github_latest_tag(repo_url: str) -> str:
    """
    Extract the latest semantic version from the GitHub Tags API.
    Only supports github.com URLs; returns empty string for others.
    """
    m = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url)
    if not m:
        return ""
    owner, repo = m.group(1), m.group(2)
    url = cfg.GITHUB_TAGS_API.format(owner=owner, repo=repo)
    headers: dict[str, str] = {"User-Agent": "linux-sec-theater/1.0 (security research)"}
    if cfg.GITHUB_TOKEN:
        headers["Authorization"] = f"token {cfg.GITHUB_TOKEN}"
    try:
        r = requests.get(url, headers=headers, timeout=_TIMEOUT)
        r.raise_for_status()
        for tag in r.json():
            name = tag.get("name", "").lstrip("v").lstrip("V")
            # Skip pre-release tags (rc/alpha/beta/dev)
            if re.search(r"(rc|alpha|beta|dev|pre)", name, re.IGNORECASE):
                continue
            if _parse(name):
                return name
    except Exception as e:
        log.warning("[VersionGapFinder] GitHub tags query failed %s/%s: %s", owner, repo, e)
    return ""


# ── Launchpad online lookup (fallback) ───────────────────────────────────────

def _launchpad_version(pkg: str) -> Optional[str]:
    url = (
        "https://api.launchpad.net/1.0/ubuntu/+archive/primary"
        f"?ws.op=getPublishedSources&source_name={pkg}"
        f"&distro_series={cfg.UBUNTU_SERIES_LP}&order_by_date=true"
    )
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        entries = r.json().get("entries", [])
        if entries:
            return entries[0].get("source_package_version")
    except Exception as e:
        log.warning("[VersionGapFinder] Launchpad query failed %s: %s", pkg, e)
    return None


# ── Public interface ──────────────────────────────────────────────────────────

def find_gap(pkg_name: str) -> dict:
    """
    Returns a version gap description dict:

    {
      "package":          "libxml2",
      "ubuntu_version":   "2.9.14",
      "upstream_version": "2.12.6",
      "gap":              True,
      "repo_url":         "https://github.com/GNOME/libxml2",
      "source":           "known_map+live",
      "error":            None           # error string on failure
    }

    If repo_url or upstream_version cannot be resolved, the "error" field is
    set to a "Tool_Error: ..." string; callers should pass this directly to the
    LLM rather than returning gap: false.
    """
    result: dict = {
        "package":          pkg_name,
        "ubuntu_version":   "",
        "upstream_version": "",
        "gap":              False,
        "repo_url":         None,
        "source":           "unknown",
        "error":            None,
    }

    # ① Check hard-coded mapping first (handles classic C/C++ packages)
    if pkg_name in KNOWN_UPSTREAM_REPOS:
        result["repo_url"] = KNOWN_UPSTREAM_REPOS[pkg_name]
        result["source"]   = "known_map"
        log.info("[VersionGapFinder] %s → known_map %s", pkg_name, result["repo_url"])

    # ② Pre-computed fast path
    precomp: dict = {}
    if pkg_name.startswith("librust-"):
        precomp = _ligrust_cache().get(pkg_name, {})
    elif pkg_name.startswith("golang-"):
        precomp = _golang_cache().get(pkg_name, {})

    if precomp:
        result["ubuntu_version"]   = _clean_ver(precomp.get("ubuntu_full_version", ""))
        result["upstream_version"] = precomp.get("upstream_version", "")
        result["source"] = (
            "known_map+precomputed" if result["source"] == "known_map" else "precomputed"
        )
    else:
        # ③ Live Ubuntu version lookup (Launchpad)
        raw = _launchpad_version(pkg_name) or ""
        result["ubuntu_version"] = _clean_ver(raw)
        if result["source"] == "unknown":
            result["source"] = "live"
        else:
            result["source"] = "known_map+live"

        if pkg_name.startswith("librust-"):
            crate = _pkg_to_crate(pkg_name)
            if crate:
                info = _crates_info(crate)
                result["upstream_version"] = info.get("latest_version", "")
                repo = info.get("repository", "")
                if "github.com" in repo and not result["repo_url"]:
                    result["repo_url"] = re.sub(r"\.git$", "", repo.rstrip("/"))
        elif pkg_name.startswith("golang-"):
            module = _golang_pkg_to_module(pkg_name)
            if module:
                ver, repo_url = _golang_latest_version(module)
                result["upstream_version"] = ver
                if repo_url and not result["repo_url"]:
                    result["repo_url"] = repo_url

    # ④ repo_url fallback (crates.io / Go module generic method)
    if not result["repo_url"]:
        result["repo_url"] = resolve_repo_url(pkg_name)

    # ⑤ If repo_url is known but upstream_version is still empty, fetch from GitHub Tags API
    if result["repo_url"] and not result["upstream_version"]:
        tag_ver = _github_latest_tag(result["repo_url"])
        if tag_ver:
            result["upstream_version"] = tag_ver
            log.info(
                "[VersionGapFinder] %s upstream (GitHub tags): %s",
                pkg_name, tag_ver,
            )

    # ⑥ Determine whether a gap exists
    v_ub = _parse(result["ubuntu_version"])
    v_up = _parse(result["upstream_version"])
    if v_ub and v_up:
        result["gap"] = v_up > v_ub

    # ⑦ Fail-safe: mark error on missing critical info; prevent Fail-Open returning gap: false
    if not result["repo_url"] or not result["upstream_version"]:
        result["error"] = (
            f"Tool_Error: Cannot resolve upstream GitHub repository or tags "
            f"for package '{pkg_name}'. "
            f"(repo_url={result['repo_url']!r}, "
            f"upstream_version={result['upstream_version']!r})"
        )
        log.warning("[VersionGapFinder] %s resolution failed → %s", pkg_name, result["error"])

    log.info(
        "[VersionGapFinder] %s  ubuntu=%s  upstream=%s  gap=%s  source=%s  error=%s",
        pkg_name,
        result["ubuntu_version"],
        result["upstream_version"],
        result["gap"],
        result["source"],
        result["error"],
    )
    return result

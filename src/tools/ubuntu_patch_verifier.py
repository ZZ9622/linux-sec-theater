"""
UbuntuPatchVerifier
===================
Strictly verifies whether an upstream security patch has been backported by
the Ubuntu team into noble.

Four verification channels:
  ① ubuntu.com/security/cves.json  — full-text SHA search + per-package CVEs
  ② changelogs.ubuntu.com          — Debian changelog text search
  ③ Launchpad source diff          — Launchpad patch text search
  ④ Launchpad web changelog        — fallback: scrape +changelog HTML page

Verdict:
  "Unpatched"          — at least one channel ran successfully and did not find the commit
  "Already-Backported" — at least one channel found the patch
  "Verify_Error"       — all channels failed due to network errors (422/timeout); result unreliable
  "Unknown"            — other cases

Public interface: verify(pkg_name, commit_sha, ubuntu_ver) → dict
"""

import re
import gzip
import logging
import subprocess
from io import BytesIO
from typing import Optional

import requests
from bs4 import BeautifulSoup

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import config as cfg

log = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": "linux-sec-theater/1.0 (security research)",
    "Accept":     "text/html,application/xhtml+xml,application/json",
}
_TIMEOUT = 15


# ── Helper functions ──────────────────────────────────────────────────────────

def _source_pkg_name(pkg_name: str) -> str:
    """
    Derive the source package name from a binary package name.
    librust-addr2line-dev → rust-addr2line
    golang-github-foo-bar-dev → golang-github-foo-bar
    """
    name = pkg_name
    if name.startswith("lib"):
        name = name[3:]
    if name.endswith("-dev"):
        name = name[:-4]
    return name


def _is_network_error(exc: Exception) -> bool:
    """Return True if the exception represents a network/server error (422 / timeout / connection)."""
    s = str(exc)
    return (
        "422" in s
        or "timed out" in s.lower()
        or "timeout" in s.lower()
        or "ConnectionError" in type(exc).__name__
        or "ConnectTimeout" in type(exc).__name__
    )


# ── Channel ①: ubuntu.com CVE JSON API ───────────────────────────────────────

_CVE_PAGE_SIZE = 20   # maximum limit value allowed by the Ubuntu API


def _query_cve_tracker(pkg_name: str) -> tuple[list[dict], Optional[str]]:
    """
    Query the per-package CVE list using pagination (limit=20, offset).
    Returns (entries, error_type): error_type is None on success, otherwise an error description.
    """
    entries: list[dict] = []
    offset = 0

    while True:
        params: dict = {
            "package": pkg_name,
            "version": cfg.UBUNTU_RELEASE,
            "limit":   _CVE_PAGE_SIZE,
            "offset":  offset,
        }
        try:
            r = requests.get(
                cfg.UBUNTU_CVE_JSON,
                headers=_HEADERS,
                params=params,
                timeout=_TIMEOUT,
            )
            if not r.ok:
                # Log the server response body (especially useful for 422), then raise
                log.warning(
                    "[Verifier①] CVE API returned %d (offset=%d): %s",
                    r.status_code, offset, r.text[:500],
                )
                r.raise_for_status()

            page_items = r.json().get("cves", [])
            for item in page_items:
                pkg_status = "unknown"
                for pe in item.get("packages", []):
                    if pe.get("name") == pkg_name:
                        for rs in pe.get("statuses", []):
                            if rs.get("release_codename") == cfg.UBUNTU_RELEASE:
                                pkg_status = rs.get("status", "unknown")
                entries.append({
                    "cve_id":      item.get("id", ""),
                    "description": item.get("description", "")[:300],
                    "status":      pkg_status,
                })

            # If this page returned fewer items than the page size, we've reached the end
            if len(page_items) < _CVE_PAGE_SIZE:
                break
            offset += _CVE_PAGE_SIZE

        except Exception as e:
            log.warning("[Verifier①] CVE JSON query failed %s (offset=%d): %s",
                        pkg_name, offset, e)
            err = "network_error" if _is_network_error(e) else str(e)
            # If the first page failed we have nothing; if mid-pagination, return partial results
            if not entries:
                return [], err
            log.warning("[Verifier①] Pagination interrupted (collected %d entries), returning partial results", len(entries))
            return entries, None

    return entries, None


def _sha_in_cve_tracker(commit_sha: str) -> tuple[list[str], Optional[str]]:
    """Full-text search for commit SHA; returns (matched CVE list, error_type)."""
    found = []
    last_err = None
    for q in [commit_sha[:8], commit_sha[:12]]:
        try:
            r = requests.get(
                "https://ubuntu.com/security/cves",
                headers=_HEADERS,
                params={"q": q},
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "lxml")
            for a in soup.select("a[href*='/security/CVE-']"):
                m = re.search(r"CVE-\d{4}-\d+", a["href"])
                if m:
                    found.append(m.group(0))
            last_err = None  # at least one successful request
        except Exception as e:
            log.warning("[Verifier①] SHA full-text search failed q=%s: %s", q, e)
            if last_err is None:
                last_err = "network_error" if _is_network_error(e) else str(e)
    return list(set(found)), last_err


# ── Channel ②: changelogs.ubuntu.com ─────────────────────────────────────────

def _pkg_section(pkg_name: str) -> str:
    if pkg_name.startswith("librust-") or pkg_name.startswith("golang-"):
        return "universe"
    return "main"


def _fetch_changelog(pkg_name: str, ubuntu_ver: str) -> tuple[Optional[str], Optional[str]]:
    """
    Fetch changelog text from changelogs.ubuntu.com.
    Returns (text, error_type).
    """
    section = _pkg_section(pkg_name)
    first   = pkg_name[0]
    base_url = (
        f"https://changelogs.ubuntu.com/changelogs/pool"
        f"/{section}/{first}/{pkg_name}/{pkg_name}_{ubuntu_ver}"
    )
    last_err = "not_found"
    for suffix in ["/changelog", "/changelog.gz"]:
        url = base_url + suffix
        try:
            r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
            if r.status_code == 200:
                if suffix.endswith(".gz"):
                    return gzip.decompress(r.content).decode("utf-8", errors="replace"), None
                return r.text, None
            if _is_network_error(Exception(str(r.status_code))):
                last_err = "network_error"
        except Exception as e:
            log.debug("[Verifier②] %s fetch failed: %s", url, e)
            if _is_network_error(e):
                last_err = "network_error"
    return None, last_err


def _sha_in_text(text: str, commit_sha: str) -> bool:
    """Search for a commit SHA (7/8/12/40 chars) in text."""
    for length in [7, 8, 12, 40]:
        if re.search(re.escape(commit_sha[:length]), text, re.IGNORECASE):
            return True
    return False


# ── Channel ③: Launchpad source diff ─────────────────────────────────────────

def _launchpad_patch_text(pkg_name: str, ubuntu_ver: str) -> tuple[Optional[str], Optional[str]]:
    """Fetch source diff text via the Launchpad REST API."""
    lp_url = (
        "https://api.launchpad.net/1.0/ubuntu/+archive/primary"
        f"?ws.op=getPublishedSources&source_name={pkg_name}"
        f"&distro_series={cfg.UBUNTU_SERIES_LP}&order_by_date=true"
    )
    try:
        r = requests.get(lp_url, timeout=_TIMEOUT)
        r.raise_for_status()
        entries = r.json().get("entries", [])
        if not entries:
            return None, "not_found"
        full_ver = entries[0].get("source_package_version", ubuntu_ver)
        diff_url = f"https://launchpad.net/ubuntu/+source/{pkg_name}/+diff/{full_ver}"
        dr = requests.get(diff_url, headers=_HEADERS, timeout=_TIMEOUT)
        if dr.status_code == 200:
            soup = BeautifulSoup(dr.text, "lxml")
            pre = soup.find("pre")
            return (pre.get_text() if pre else dr.text[:20000]), None
        return None, "not_found"
    except Exception as e:
        log.debug("[Verifier③] Launchpad diff query failed %s: %s", pkg_name, e)
        err = "network_error" if _is_network_error(e) else str(e)
        return None, err


# ── Channel ④: Launchpad web changelog (fallback) ────────────────────────────

def _launchpad_web_changelog(pkg_name: str) -> tuple[Optional[str], Optional[str]]:
    """
    Scrape the Launchpad +changelog page (HTML) and extract changelog text.
    Tries both the source package name and the original package name.
    URL format: https://launchpad.net/ubuntu/+source/rust-addr2line/+changelog
    """
    candidates = list({pkg_name, _source_pkg_name(pkg_name)})
    last_err = "not_found"
    for src in candidates:
        url = f"https://launchpad.net/ubuntu/+source/{src}/+changelog"
        try:
            r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                # Changelog content is in <div class="changelog"> or <pre>
                block = soup.find("div", class_="changelog") or soup.find("pre")
                text = block.get_text() if block else r.text
                if len(text) > 100:
                    log.info("[Verifier④] Launchpad web changelog retrieved: %s", src)
                    return text, None
            last_err = "not_found"
        except Exception as e:
            log.debug("[Verifier④] Launchpad web changelog failed %s: %s", src, e)
            if _is_network_error(e):
                last_err = "network_error"
    return None, last_err


# ── Main entry point ──────────────────────────────────────────────────────────

def verify(pkg_name: str, commit_sha: str, ubuntu_ver: str) -> dict:
    """
    Run four-channel verification for a given commit and return:
    {
      "verdict":   "Unpatched"|"Already-Backported"|"Verify_Error"|"Unknown",
      "channel":   str | None,
      "evidence":  str,
      "pkg_cves":  list,
      "errors":    list,   # per-channel error records
    }

    Verify_Error: all channels failed due to 422/timeout; conclusion unreliable.
    Unpatched:    at least one channel ran successfully and did not find the commit.
    """
    short = commit_sha[:8]
    log.info("[Verifier] Verifying %s  commit=%s  ubuntu_ver=%s", pkg_name, short, ubuntu_ver)

    result: dict = {
        "verdict":  "Unknown",
        "channel":  None,
        "evidence": "",
        "pkg_cves": [],
        "errors":   [],
    }

    # channels_searched: channel ran successfully and actively searched the SHA (regardless of result)
    # channels_errored:  channel failed with a hard error (network/422), could not run
    channels_searched = 0
    channels_errored  = 0

    # ── Internal helpers to record channel outcomes ───────────────────────────
    def _record_error(label: str, err: str) -> None:
        nonlocal channels_errored
        result["errors"].append(f"{label}: {err}")
        channels_errored += 1
        log.warning("[Verifier%s] Hard error (not counted as search): %s", label, err)

    def _record_searched(label: str) -> None:
        nonlocal channels_searched
        channels_searched += 1
        log.info("[Verifier%s] Search complete (no hit)", label)

    # ① CVE Tracker SHA full-text search ──────────────────────────────────────
    cve_hits, err1 = _sha_in_cve_tracker(commit_sha)
    if err1:
        _record_error("①", err1)
    else:
        _record_searched("①")
        if cve_hits:
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "cve_tracker",
                "evidence": f"commit {short} referenced in CVE Tracker: {', '.join(cve_hits)}",
            })
            log.info("[Verifier①] Already backported: %s", result["evidence"])
            pkg_cves, _ = _query_cve_tracker(pkg_name)
            result["pkg_cves"] = pkg_cves
            return result

    # ① Per-package CVE list (auxiliary context; failure does not affect verdict count)
    pkg_cves, _ = _query_cve_tracker(pkg_name)
    result["pkg_cves"] = pkg_cves

    # ② changelogs.ubuntu.com ─────────────────────────────────────────────────
    changelog, err2 = _fetch_changelog(pkg_name, ubuntu_ver)
    if err2 == "network_error":
        _record_error("②", err2)
    elif changelog:
        _record_searched("②")
        if _sha_in_text(changelog, commit_sha):
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "changelog",
                "evidence": f"commit {short} referenced in Debian changelog",
            })
            log.info("[Verifier②] Already backported (changelog)")
            return result
    else:
        # not_found or other: resource absent, not a hard error and not a valid search
        log.info("[Verifier②] Changelog absent or unavailable, skipping")

    # ③ Launchpad source diff ─────────────────────────────────────────────────
    patch_text, err3 = _launchpad_patch_text(pkg_name, ubuntu_ver)
    if err3 == "network_error":
        _record_error("③", err3)
    elif patch_text:
        _record_searched("③")
        if _sha_in_text(patch_text, commit_sha):
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "launchpad_diff",
                "evidence": f"commit {short} referenced in Launchpad source diff",
            })
            log.info("[Verifier③] Already backported (launchpad_diff)")
            return result
    else:
        log.info("[Verifier③] Launchpad diff absent or unavailable, skipping")

    # ④ Launchpad web changelog (fallback) ────────────────────────────────────
    web_cl, err4 = _launchpad_web_changelog(pkg_name)
    if err4 == "network_error":
        _record_error("④", err4)
    elif web_cl:
        _record_searched("④")
        if _sha_in_text(web_cl, commit_sha):
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "launchpad_web_changelog",
                "evidence": f"commit {short} referenced in Launchpad web changelog",
            })
            log.info("[Verifier④] Already backported (launchpad_web_changelog)")
            return result
    else:
        log.info("[Verifier④] Launchpad web changelog absent or unavailable, skipping")

    # ── Final determination ───────────────────────────────────────────────────
    if channels_searched > 0:
        # At least one channel ran and found nothing → Unpatched (evidence-based conclusion)
        result["verdict"]  = "Unpatched"
        result["evidence"] = (
            f"commit {short} not found in {channels_searched} valid channel(s)"
            + (f" ({channels_errored} channel(s) failed with network errors)"
               if channels_errored else "")
        )
        log.info("[Verifier] Unpatched (%d channel(s) confirmed): %s  %s",
                 channels_searched, pkg_name, short)
    else:
        # No channel completed a valid search → cannot conclude
        result["verdict"]  = "Verification_Failed"
        result["evidence"] = (
            f"No channel completed a valid search ({channels_errored} hard error(s))"
            + (f": {'; '.join(result['errors'])}" if result["errors"] else "")
        )
        log.warning("[Verifier] Verification_Failed: %s  %s  errors=%s",
                    pkg_name, short, result["errors"])

    return result


def format_verdict(v: dict) -> str:
    """Human-readable summary for Agent Observation output."""
    lines = [
        f"Verdict: {v['verdict']}",
        f"Channel: {v['channel'] or 'none'}",
        f"Evidence: {v['evidence']}",
    ]
    if v.get("errors"):
        lines.append(f"Channel errors: {'; '.join(v['errors'])}")
    if v.get("pkg_cves"):
        open_cves = [c for c in v["pkg_cves"] if c["status"] in ("needed", "open", "unknown")]
        lines.append(f"Package CVEs: {len(v['pkg_cves'])} total, {len(open_cves)} open/needed")
    return "\n".join(lines)

"""
ubuntu_patch_verifier.py  –  Rule-based + apt-source patch presence checker.

verify()          – fast git line-match heuristic against the 24.04 upstream tag.
format_verdict()  – human-readable summary of a verify() result.
check_apt_source() – ground-truth check via Docker (ubuntu:24.04 container) or
                     Launchpad source download; falls back gracefully on macOS
                     when Docker is absent.
"""

import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from .version_gap_finder import resolve_source_package_name

log = logging.getLogger(__name__)


def _requests_get_with_retry(requests_mod, url: str, *, params: dict | None = None,
                             timeout: int = 15, retry_once: bool = True):
    """
    HTTP GET helper with a single retry for network errors.
    Returns (response_or_none, error_or_none).
    """
    attempts = 2 if retry_once else 1
    last_err: Optional[str] = None
    for i in range(attempts):
        try:
            resp = requests_mod.get(url, params=params, timeout=timeout)
            return resp, None
        except Exception as exc:
            name = exc.__class__.__name__.lower()
            msg = str(exc).lower()
            is_timeout = "timeout" in name or "timed out" in msg
            is_network = is_timeout or "connection" in name or "connection" in msg
            if is_timeout:
                last_err = "network timeout"
            elif is_network:
                last_err = "endpoint_unreachable"
            else:
                last_err = f"unknown_exception:{exc.__class__.__name__}"
            if not is_network or i == attempts - 1:
                break
    return None, last_err


def verify(repo, commit: dict, start_tag_name: str) -> dict:
    """
    Heuristic: are the lines *added* by this commit already present in the
    Ubuntu 24.04 source at ``start_tag_name``?

    Returns a verdict dict:
      patch_present_in_2404  bool   True  → already backported (not a gap)
                                   False → patch is missing from 24.04
      matched_lines          int    count of added lines found verbatim in 24.04
      total_new_lines        int    total non-trivial added lines in the diff
      coverage_ratio         float  matched / total  (0.0 – 1.0)
      files_checked          list   upstream file paths that were readable at the tag
    """
    diff   = commit.get("diff", "")
    stage1 = commit.get("stage1", {})

    affected_files: list[str] = stage1.get("affected_files", [])
    if not affected_files:
        affected_files = re.findall(
            r"^diff --git a/\S+ b/(\S+)", diff, re.MULTILINE
        )[:3]

    # Collect non-trivial added lines (skip blank, '{', '}', pure-comment lines)
    _trivial = re.compile(r"^[\s{}();,/*]*$")
    added_lines = [
        line[1:].strip()
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
        and not _trivial.match(line[1:].strip())
        and len(line) > 12
    ]

    empty_result = {
        "patch_present_in_2404": False,
        "matched_lines": 0,
        "total_new_lines": 0,
        "coverage_ratio": 0.0,
        "files_checked": [],
    }

    if not added_lines or not affected_files:
        return empty_result

    matched       = 0
    files_checked: list[str] = []

    for filepath in affected_files[:3]:
        try:
            content = repo.git.show(f"{start_tag_name}:{filepath}")
        except Exception:
            continue
        files_checked.append(filepath)
        for added in added_lines:
            if added in content:
                matched += 1

    total = len(added_lines)
    ratio = matched / total if total else 0.0

    # >50 % of the fix's non-trivial lines are already in 24.04 → patch present
    return {
        "patch_present_in_2404": ratio > 0.5,
        "matched_lines":         matched,
        "total_new_lines":       total,
        "coverage_ratio":        round(ratio, 3),
        "files_checked":         files_checked,
    }


def format_verdict(result: dict[str, Any]) -> str:
    """Compact human-readable summary of a verify() result dict."""
    present = result.get("patch_present_in_2404", False)
    ratio   = result.get("coverage_ratio", 0.0)
    matched = result.get("matched_lines", 0)
    total   = result.get("total_new_lines", 0)
    files   = ", ".join(result.get("files_checked", [])) or "—"
    status  = "PRESENT (already backported)" if present else "ABSENT  (patch gap confirmed)"
    return (
        f"Patch status : {status}\n"
        f"Lines matched: {matched}/{total} ({ratio:.0%})\n"
        f"Files checked: {files}"
    )


_MARKER_UPPER = re.compile(r'\b([A-Z][A-Z0-9_]{5,})\b')         # MACRO_NAMES ≥6
_MARKER_LONG  = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]{9,})\b') # anyName ≥10
_MARKER_STOP  = {
    "NULL", "TRUE", "FALSE", "SIZE_MAX", "INT_MAX", "UINT_MAX",
    "LONG_MAX", "ULONG_MAX", "INT_MIN", "LONG_MIN",
    "return", "struct", "static", "const", "include", "define",
    "ifdef", "endif", "ifndef", "printf", "sizeof", "typedef",
    "extern", "unsigned", "signed", "inline", "volatile", "assert",
    "error", "warning", "pragma",
}


def _extract_patch_markers(diff: str) -> list[str]:
    """
    Extract high-specificity identifiers introduced by the patch.

    Only accepts:
      • ALLCAPS identifiers ≥ 6 chars  (macro / error-code names like VALID_ERR2P)
      • Mixed-case / snake_case ≥ 10 chars  (function names like xmlBuildRelativeURISafe)

    Identifiers must appear on '+' lines (additions) but NOT on '-' lines (removals),
    ensuring they are truly new symbols the patch introduces.

    The high length threshold avoids false positives from common short symbols
    (nbslash, len, pos) appearing as context lines in unrelated debian patches.
    """
    added, removed = set(), set()
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.update(_MARKER_UPPER.findall(line[1:]))
            added.update(_MARKER_LONG.findall(line[1:]))
        elif line.startswith("-") and not line.startswith("---"):
            removed.update(_MARKER_UPPER.findall(line[1:]))
            removed.update(_MARKER_LONG.findall(line[1:]))
    new_only = (added - removed) - _MARKER_STOP
    return sorted(new_only, key=len, reverse=True)[:8]


def _extract_markers_with_quality(diff: str) -> tuple[list[str], str]:
    """
    Extract patch markers and classify their quality.

    Separately collects identifiers from:
      - pre_fix_ids  : '-' lines only (not in '+' lines) — code removed by the fix
      - post_fix_only_ids : '+' lines only (not in '-' lines) — new symbols introduced
      - shared_ids   : in BOTH '+' and '-' lines — context identifiers

    Quality priority:
      "pre_fix_code"   — prefer pre-fix identifiers (≥8 chars); searching for their
                         REMOVAL in backport patches is the most accurate signal.
      "shared_context" — identifiers present in both add and remove lines.
      "post_fix_only"  — only post-fix identifiers available; least reliable because
                         common function names may exist in unrelated patch context lines.

    Returns (markers, quality).
    """
    added_ids:   set[str] = set()
    removed_ids: set[str] = set()

    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added_ids.update(_MARKER_UPPER.findall(line[1:]))
            added_ids.update(_MARKER_LONG.findall(line[1:]))
        elif line.startswith("-") and not line.startswith("---"):
            removed_ids.update(_MARKER_UPPER.findall(line[1:]))
            removed_ids.update(_MARKER_LONG.findall(line[1:]))

    pre_fix_ids      = (removed_ids - added_ids) - _MARKER_STOP
    post_fix_only_ids = (added_ids - removed_ids) - _MARKER_STOP
    shared_ids       = (added_ids & removed_ids) - _MARKER_STOP

    # Filter pre_fix_ids to ≥8 chars (high specificity)
    pre_fix_long = {m for m in pre_fix_ids if len(m) >= 8}

    if pre_fix_long:
        markers = sorted(pre_fix_long, key=len, reverse=True)[:8]
        quality = "pre_fix_code"
    elif shared_ids:
        markers = sorted(shared_ids, key=len, reverse=True)[:8]
        quality = "shared_context"
    elif post_fix_only_ids:
        markers = sorted(post_fix_only_ids, key=len, reverse=True)[:8]
        quality = "post_fix_only"
    else:
        markers = []
        quality = "post_fix_only"

    return markers, quality


def _extract_long_line_marker(diff: str) -> Optional[str]:
    """
    Return the first substantive line ≥ 30 chars from the diff, preferring
    '-' lines (pre-fix / deleted code) over '+' lines (newly added code).
    Pre-fix code is more reliable as a grep marker because it uniquely
    identifies the vulnerable code that a backport would remove.
    Skips comment/header lines and trivially generic content.
    """
    _skip_prefix = ("//", "/*", "*", "#!", "#define", "diff --git", "index ", "@@", "+++", "---")
    _trivial_re  = re.compile(
        r'^(return\b.*|\bNULL\b|\btrue\b|\bfalse\b|break;|continue;|goto\s+\w+;|'
        r'\s*[\d]+\s*;?|\s*\{\s*|\s*\}\s*)$',
        re.IGNORECASE,
    )
    pre_fix = post_fix = None
    for line in diff.splitlines():
        if pre_fix and post_fix:
            break
        if not pre_fix and line.startswith("-") and not line.startswith("---"):
            s = line[1:].strip()
            if (len(s) >= 30
                    and not any(s.startswith(p) for p in _skip_prefix)
                    and not _trivial_re.match(s)):
                pre_fix = s[:100]
        if not post_fix and line.startswith("+") and not line.startswith("+++"):
            s = line[1:].strip()
            if (len(s) >= 30
                    and not any(s.startswith(p) for p in _skip_prefix)
                    and not _trivial_re.match(s)):
                post_fix = s[:100]
    return pre_fix or post_fix


def _apply_long_marker(result: dict, diff: str) -> dict:
    """Post-process: replace patch_marker_grep_query with a ≥30-char specific snippet."""
    if diff:
        long_m = _extract_long_line_marker(diff)
        if long_m and len(long_m) >= 30:
            result["patch_marker_grep_query"] = long_m
    return result


# ══════════════════════════════════════════════════════════════════════════════
# apt-get source ground-truth verification
# ══════════════════════════════════════════════════════════════════════════════

def _docker_available() -> bool:
    try:
        subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5, check=True
        )
        return True
    except Exception:
        return False


def _docker_apt_source(
    pkg_name: str,
    commit_sha: str,
    markers: list[str] | None = None,
    marker_quality: str = "post_fix_only",
) -> Optional[dict]:
    """
    Spin up an ubuntu:24.04 container, pull source from the noble-security /
    noble-updates pocket, and grep debian/patches/ for the commit SHA and
    patch-specific marker identifiers.

    For pre_fix_code quality markers, searches '-' lines (removals in patches) because
    pre-fix identifiers are REMOVED by the backport, not added.
    For post_fix_only / shared_context markers, searches '+' lines as before.

    Returns dict with method, found, and evidence list — or None if Docker failed.
    """
    short_sha = commit_sha[:12]
    src_pkg   = resolve_source_package_name(pkg_name)

    # SHA: anywhere in debian/patches/*.patch headers (upstream commits are often cited)
    sha_patch_cmd = (
        f"if find /src -path '*/debian/patches/*.patch' 2>/dev/null "
        f"| xargs -r grep -q '{short_sha}' 2>/dev/null; "
        f"then echo SHA_IN_PATCH; fi"
    )
    # SHA in debian/changelog (security team mentions upstream commit)
    sha_log_cmd = (
        f"if find /src -name 'changelog' 2>/dev/null "
        f"| xargs -r grep -q '{short_sha}' 2>/dev/null; "
        f"then echo SHA_IN_CHANGELOG; fi"
    )

    # Marker grep direction depends on quality:
    #   pre_fix_code   → search '-' lines (pre-fix code is removed by the backport)
    #   others         → search '+' lines (post-fix code is added by the backport)
    if marker_quality == "pre_fix_code":
        marker_grep_prefix = r'^-[^-]'
    else:
        marker_grep_prefix = r'^\+[^+]'

    marker_cmds = "; ".join(
        f"if find /src -path '*/debian/patches/*.patch' 2>/dev/null "
        f"| xargs -r grep -qE '{marker_grep_prefix}.*{m}' 2>/dev/null; "
        f"then echo 'MARKER:{m}'; fi"
        for m in (markers or [])[:5]
    )
    all_greps = "; ".join(filter(None, [sha_patch_cmd, sha_log_cmd, marker_cmds or ""]))

    script = (
        "set -e; "
        "export DEBIAN_FRONTEND=noninteractive; "
        "echo 'deb-src http://security.ubuntu.com/ubuntu noble-security main universe'"
        "  >> /etc/apt/sources.list; "
        "echo 'deb-src http://archive.ubuntu.com/ubuntu noble-updates main universe'"
        "  >> /etc/apt/sources.list; "
        "apt-get update -qq 2>/dev/null; "
        "apt-get install -y dpkg-dev 2>/dev/null; "
        f"mkdir /src && cd /src && "
        f"(apt-get source -q -t noble-security {src_pkg} 2>/dev/null || "
        f" apt-get source -q -t noble-updates {src_pkg} 2>/dev/null || "
        f" apt-get source -q {src_pkg} 2>/dev/null || true); "
        f"echo '---SEARCH---'; "
        f"{all_greps}; "
        f"echo '---END---'"
    )
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "ubuntu:24.04", "bash", "-c", script],
            capture_output=True, text=True, timeout=180,
        )
    except Exception as exc:
        log.warning("[apt_source] Docker run failed: %s", exc)
        return None

    output = r.stdout.split("---SEARCH---")[-1].split("---END---")[0]
    lines  = output.splitlines()
    sha_in_patch     = any("SHA_IN_PATCH" in l for l in lines)
    sha_in_changelog = any("SHA_IN_CHANGELOG" in l for l in lines)
    markers_found    = [l.split(":", 1)[1] for l in lines if l.startswith("MARKER:")]
    marker_count     = len(markers_found)

    review_flags: list[str] = []

    if sha_in_patch or sha_in_changelog:
        found  = True
        method = "backport" if sha_in_changelog else "quilt_patch"
    elif marker_count >= 2 and marker_quality != "post_fix_only":
        # Only trust ≥2-marker hits for pre_fix_code / shared_context quality.
        # post_fix_only markers are too easily found in unrelated patches.
        found  = True
        method = "quilt_patch"
    elif marker_quality == "post_fix_only":
        # post_fix-only markers cannot confirm a backport regardless of count.
        found  = None
        method = "marker_unreliable"
        review_flags.append(
            "MARKER_POST_FIX_ONLY: markers are post-fix identifiers only; "
            "search result is inconclusive — manual review required"
        )
    else:
        found  = False
        method = "not_present"

    evidence = (
        (["sha_in_patch"] if sha_in_patch else []) +
        (["sha_in_changelog"] if sha_in_changelog else []) +
        [f"marker:{m}" for m in markers_found]
    )
    result = {
        "ubuntu_2404_actually_patched": found,
        "ubuntu_2404_patch_method":     method,
        "_apt_source_evidence":         evidence[:5],
        "_apt_source_method":           "docker_apt_source",
        "_marker_quality":              marker_quality,
        "patch_marker_grep_query":      "|".join((markers or [])[:3]) or short_sha,
        "patch_marker_found":           bool(found),
    }
    if review_flags:
        result["_review_flags"] = review_flags
    return result


def _launchpad_patch_search(
    pkg_name: str,
    commit_sha: str,
    markers: list[str] | None = None,
    marker_quality: str = "post_fix_only",
) -> dict:
    """
    Fallback when Docker is unavailable: download the source package's
    debian.tar.xz from Launchpad (Security pocket first) and grep
    debian/patches/*.patch for the commit SHA and patch-specific markers.

    Marker search direction depends on quality:
      pre_fix_code    → search '-' lines (removed_in_patches): pre-fix code is
                        removed by the backport → its PRESENCE in '-' lines confirms fix.
      others          → search '+' lines (added_in_patches): post-fix identifiers
                        are added by the backport.

    A marker found in a quilt patch file confirms a backport; a marker found
    only after quilt-applying requires the Docker path.  For this path we also
    check debian/changelog for the commit SHA as a secondary signal.
    """
    try:
        import requests
        import tarfile
        import io as _io
    except ImportError:
        return {
            "ubuntu_2404_actually_patched": None,
            "ubuntu_2404_patch_method":     None,
            "_apt_source_method":           "no_requests_lib",
            "_apt_fetch_error":             "endpoint_unreachable",
            "_status":                      "skipped_due_to_apt_failure",
        }

    short_sha = commit_sha[:12]
    src_pkg   = resolve_source_package_name(pkg_name)
    markers   = markers or []

    # ── 1. Find source publication — Security pocket first ─────────────────────
    pub_entry   = None
    pocket_used = "Release"
    apt_fetch_error: Optional[str] = None
    for pocket in ("Security", "Updates", "Release"):
        r, err = _requests_get_with_retry(
            requests,
            "https://api.launchpad.net/1.0/ubuntu/+archive/primary",
            params={
                "ws.op":         "getPublishedSources",
                "source_name":   src_pkg,
                "status":        "Published",
                "distro_series": "/ubuntu/noble",
                "pocket":        pocket,
            },
            timeout=15,
            retry_once=True,
        )
        if r is None:
            apt_fetch_error = err or "endpoint_unreachable"
            log.debug("[launchpad] source lookup (%s pocket): %s", pocket, apt_fetch_error)
            continue
        if r.status_code == 404:
            apt_fetch_error = "launchpad 404"
            continue
        if 400 <= r.status_code < 500:
            apt_fetch_error = "http_4xx"
            continue
        if 500 <= r.status_code < 600:
            apt_fetch_error = "http_5xx"
            continue
        try:
            entries = r.json().get("entries", [])
        except Exception:
            apt_fetch_error = "json_decode_error"
            continue
        if entries:
            pub_entry   = entries[0]
            pocket_used = pocket
            break

    if not pub_entry:
        return {
            "ubuntu_2404_actually_patched": None,
            "ubuntu_2404_patch_method":     None,
            "_apt_source_method":           "launchpad_no_entry",
            "_apt_fetch_error":             apt_fetch_error or "package not in noble pocket",
            "_status":                      "skipped_due_to_apt_failure",
        }

    current_ver = pub_entry.get("source_package_version", "")

    # ── 2. Get source file URLs via Launchpad API ──────────────────────────────
    debian_tar_url = None
    self_link      = pub_entry.get("self_link", "")
    if self_link:
        r2, err2 = _requests_get_with_retry(
            requests,
            f"{self_link}?ws.op=sourceFileUrls",
            timeout=15,
            retry_once=True,
        )
        if r2 is None:
            apt_fetch_error = err2 or "endpoint_unreachable"
            log.debug("[launchpad] sourceFileUrls failed: %s", apt_fetch_error)
        elif not r2.ok:
            apt_fetch_error = "launchpad 404" if r2.status_code == 404 else (
                "http_5xx" if r2.status_code >= 500 else "http_4xx"
            )
        else:
            try:
                urls = r2.json()
                if isinstance(urls, list):
                    debian_tar_url = next(
                        (u for u in urls if isinstance(u, str) and ".debian.tar." in u),
                        None,
                    )
            except Exception:
                apt_fetch_error = "json_decode_error"
        if debian_tar_url is None and apt_fetch_error is None:
            apt_fetch_error = "sourceFileUrls returned empty"

    # ── 3. Download debian.tar.xz and grep debian/patches/ ────────────────────
    if debian_tar_url:
        try:
            r3 = requests.get(debian_tar_url, timeout=90)
            r3.raise_for_status()
            patches_text   = ""
            changelog_text = ""
            with tarfile.open(fileobj=_io.BytesIO(r3.content), mode="r:*") as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    name = member.name
                    f    = tar.extractfile(member)
                    if not f:
                        continue
                    content = f.read().decode("utf-8", errors="replace")
                    if "patches/" in name and name.endswith(".patch"):
                        patches_text += content + "\n"
                    elif name.endswith("/changelog") or name == "debian/changelog":
                        changelog_text = content

            # For pre_fix_code quality: search '-' lines (removed code) — the pre-fix
            # identifier is REMOVED by the backport patch, confirming the fix is present.
            # For all other qualities: search '+' lines (added code) as before.
            added_in_patches = "\n".join(
                line for line in patches_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            )
            removed_in_patches = "\n".join(
                line for line in patches_text.splitlines()
                if line.startswith("-") and not line.startswith("---")
            )

            if marker_quality == "pre_fix_code":
                marker_search_text = removed_in_patches
            else:
                marker_search_text = added_in_patches

            evidence: list[str] = []
            if short_sha in patches_text:
                evidence.append(f"sha_in_patch:{short_sha}")
            if short_sha in changelog_text:
                evidence.append(f"sha_in_changelog:{short_sha}")
            for m in markers:
                if m in marker_search_text:
                    evidence.append(f"marker:{m}")

            sha_found    = any(e.startswith("sha") for e in evidence)
            marker_count = sum(1 for e in evidence if e.startswith("marker:"))

            review_flags: list[str] = []

            # Require SHA confirmation OR ≥2 independent marker matches.
            # A single marker hit is not sufficient: common function names from the
            # affected file can appear in any related security patch.
            if sha_found:
                found  = True
                method = "backport" if any("changelog" in e for e in evidence) else "quilt_patch"
            elif marker_count >= 2 and marker_quality != "post_fix_only":
                # Only trust ≥2-marker hits for pre_fix_code / shared_context quality.
                found  = True
                method = "quilt_patch"
            elif marker_quality == "post_fix_only":
                # post_fix-only markers cannot confirm a backport regardless of count.
                found  = None
                method = "marker_unreliable"
                review_flags.append(
                    "MARKER_POST_FIX_ONLY: markers are post-fix identifiers only; "
                    "search result is inconclusive — manual review required"
                )
            else:
                found  = False
                method = "not_present"

            result = {
                "ubuntu_2404_actually_patched": found,
                "ubuntu_2404_patch_method":     method,
                "ubuntu_2404_current_version":  current_ver,
                "_apt_source_evidence":         evidence[:5],
                "_apt_source_method":           f"launchpad_debian_tar/{pocket_used}",
                "_apt_fetch_error":             None,
                "_marker_quality":              marker_quality,
                "patch_marker_grep_query":      "|".join(markers[:3]) or short_sha,
                "patch_marker_found":           bool(found),
                "_status":                      "ok",
            }
            if review_flags:
                result["_review_flags"] = review_flags
            return result
        except Exception as exc:
            log.debug("[launchpad] debian tar download/parse failed: %s", exc)
            apt_fetch_error = f"debian.tar parse failed: {exc.__class__.__name__}"

    # ── 4. Last-resort: .changes file SHA search ──────────────────────────────
    try:
        changes_url = (
            f"https://launchpad.net/ubuntu/+archive/primary/+files/"
            f"{src_pkg}_{current_ver}_source.changes"
        )
        r4, err4 = _requests_get_with_retry(
            requests,
            changes_url,
            timeout=15,
            retry_once=True,
        )
        if r4 is None:
            apt_fetch_error = err4 or "endpoint_unreachable"
            text = ""
        elif not r4.ok:
            apt_fetch_error = "launchpad 404" if r4.status_code == 404 else (
                "http_5xx" if r4.status_code >= 500 else "http_4xx"
            )
            text = ""
        else:
            text = r4.text
    except Exception as exc:
        apt_fetch_error = f"unknown_exception:{exc.__class__.__name__}"
        text = ""

    found_in_changes = short_sha in text
    return {
        "ubuntu_2404_actually_patched": found_in_changes if text else None,
        "ubuntu_2404_patch_method":     "backport" if found_in_changes else ("not_present" if text else None),
        "ubuntu_2404_current_version":  current_ver,
        "_apt_source_method":           "launchpad_changes_file",
        "_apt_fetch_error":             (None if text else (apt_fetch_error or "launchpad changes unavailable")),
        "patch_marker_grep_query":      short_sha,
        "patch_marker_found":           found_in_changes,
        "_status":                      "ok" if text else "skipped_due_to_apt_failure",
    }


def check_apt_source(pkg_name: str, commit_sha: str, ver_2404: str, diff: str = "") -> dict:
    """
    Ground-truth check: is the fix present in the current Ubuntu 24.04 source?

    Extracts patch-specific marker identifiers from ``diff`` and greps
    debian/patches/ in the Noble source package (Security pocket first).
    A confirmed gap requires: no CVE, no USN, AND no marker found in patches.

    Execution order:
      1. Docker ubuntu:24.04 → apt-get source -t noble-security → grep patches + markers
      2. Launchpad debian.tar.xz download → grep debian/patches/*.patch for markers
      3. Launchpad .changes file SHA search (lowest recall, last resort)

    Returned keys:
      ubuntu_2404_actually_patched  bool | None
      ubuntu_2404_patch_method      "backport" | "quilt_patch" | "not_present" | "unknown"
      _apt_source_method            provenance label
    """
    if diff:
        markers, marker_quality = _extract_markers_with_quality(diff)
    else:
        markers, marker_quality = [], "post_fix_only"
    log.debug("[apt_source] %s — %d patch markers (quality=%s): %s",
              pkg_name, len(markers), marker_quality, markers[:4])

    if _docker_available():
        log.info("[apt_source] Docker available — running ubuntu:24.04 container for %s", pkg_name)
        result = _docker_apt_source(pkg_name, commit_sha, markers, marker_quality=marker_quality)
        if result is not None:
            result.setdefault("_apt_fetch_error", None)
            return _apply_long_marker(result, diff)
        log.warning("[apt_source] Docker run returned no result, falling back to Launchpad")

    log.info("[apt_source] Using Launchpad fallback for %s", pkg_name)
    return _apply_long_marker(
        _launchpad_patch_search(pkg_name, commit_sha, markers, marker_quality=marker_quality),
        diff,
    )

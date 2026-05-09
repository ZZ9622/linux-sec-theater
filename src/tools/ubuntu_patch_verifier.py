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

log = logging.getLogger(__name__)


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
    _upper = re.compile(r'\b([A-Z][A-Z0-9_]{5,})\b')            # MACRO_NAMES ≥6
    _long  = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]{9,})\b')    # anyName ≥10
    _stop  = {
        "NULL", "TRUE", "FALSE", "SIZE_MAX", "INT_MAX", "UINT_MAX",
        "LONG_MAX", "ULONG_MAX", "INT_MIN", "LONG_MIN",
        "return", "struct", "static", "const", "include", "define",
        "ifdef", "endif", "ifndef", "printf", "sizeof", "typedef",
        "extern", "unsigned", "signed", "inline", "volatile", "assert",
        "error", "warning", "pragma",
    }
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.update(_upper.findall(line[1:]))
            added.update(_long.findall(line[1:]))
        elif line.startswith("-") and not line.startswith("---"):
            removed.update(_upper.findall(line[1:]))
            removed.update(_long.findall(line[1:]))
    new_only = (added - removed) - _stop
    return sorted(new_only, key=len, reverse=True)[:8]


def _extract_long_line_marker(diff: str) -> Optional[str]:
    """
    Return the first substantive added line ≥ 30 chars from the diff.
    Used as patch_marker_grep_query so reviewers can Ctrl+F for a unique,
    specific string — longer and more precise than a single identifier token.
    Skips comment/header lines and trivially generic content.
    """
    _skip_prefix = ("//", "/*", "*", "#!", "#define", "diff --git", "index ", "@@", "+++")
    _trivial_re  = re.compile(
        r'^(return\b.*|\bNULL\b|\btrue\b|\bfalse\b|break;|continue;|goto\s+\w+;|'
        r'\s*[\d]+\s*;?|\s*\{\s*|\s*\}\s*)$',
        re.IGNORECASE,
    )
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            s = line[1:].strip()
            if (len(s) >= 30
                    and not any(s.startswith(p) for p in _skip_prefix)
                    and not _trivial_re.match(s)):
                return s[:100]
    return None


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


def _docker_apt_source(pkg_name: str, commit_sha: str, markers: list[str] | None = None) -> Optional[dict]:
    """
    Spin up an ubuntu:24.04 container, pull source from the noble-security /
    noble-updates pocket, and grep debian/patches/ for the commit SHA and
    patch-specific marker identifiers.

    Returns dict with method, found, and evidence list — or None if Docker failed.
    """
    short_sha = commit_sha[:12]
    src_pkg   = re.sub(r"-dev$|-devel$|-doc$|-dbg$|-bin$", "", pkg_name)

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
    # Markers: require them on '+' lines (actual additions) inside debian/patches/*.patch.
    # This prevents false positives from context lines of unrelated patches that
    # happen to reference the same function in surrounding unchanged code.
    marker_cmds = "; ".join(
        f"if find /src -path '*/debian/patches/*.patch' 2>/dev/null "
        f"| xargs -r grep -qE '^\\+[^+].*{m}' 2>/dev/null; "
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

    if sha_in_patch or sha_in_changelog:
        found  = True
        method = "backport" if sha_in_changelog else "quilt_patch"
    elif marker_count >= 2:
        found  = True
        method = "quilt_patch"
    else:
        found  = False
        method = "not_present"

    evidence = (
        (["sha_in_patch"] if sha_in_patch else []) +
        (["sha_in_changelog"] if sha_in_changelog else []) +
        [f"marker:{m}" for m in markers_found]
    )
    return {
        "ubuntu_2404_actually_patched": found,
        "ubuntu_2404_patch_method":     method,
        "_apt_source_evidence":         evidence[:5],
        "_apt_source_method":           "docker_apt_source",
        "patch_marker_grep_query":      "|".join((markers or [])[:3]) or short_sha,
        "patch_marker_found":           found,
    }


def _launchpad_patch_search(pkg_name: str, commit_sha: str, markers: list[str] | None = None) -> dict:
    """
    Fallback when Docker is unavailable: download the source package's
    debian.tar.xz from Launchpad (Security pocket first) and grep
    debian/patches/*.patch for the commit SHA and patch-specific markers.

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
            "ubuntu_2404_patch_method":     "unknown",
            "_apt_source_method":           "no_requests_lib",
        }

    short_sha = commit_sha[:12]
    src_pkg   = re.sub(r"-dev$|-devel$|-doc$|-dbg$|-bin$", "", pkg_name)
    markers   = markers or []

    # ── 1. Find source publication — Security pocket first ─────────────────────
    pub_entry   = None
    pocket_used = "Release"
    for pocket in ("Security", "Updates", "Release"):
        try:
            r = requests.get(
                "https://api.launchpad.net/1.0/ubuntu/+archive/primary",
                params={
                    "ws.op":         "getPublishedSources",
                    "source_name":   src_pkg,
                    "status":        "Published",
                    "distro_series": "/ubuntu/noble",
                    "pocket":        pocket,
                },
                timeout=15,
            )
            r.raise_for_status()
            entries = r.json().get("entries", [])
            if entries:
                pub_entry   = entries[0]
                pocket_used = pocket
                break
        except Exception as exc:
            log.debug("[launchpad] source lookup (%s pocket): %s", pocket, exc)

    if not pub_entry:
        return {
            "ubuntu_2404_actually_patched": None,
            "ubuntu_2404_patch_method":     "unknown",
            "_apt_source_method":           "launchpad_no_entry",
        }

    current_ver = pub_entry.get("source_package_version", "")

    # ── 2. Get source file URLs via Launchpad API ──────────────────────────────
    debian_tar_url = None
    self_link      = pub_entry.get("self_link", "")
    if self_link:
        try:
            r2 = requests.get(f"{self_link}?ws.op=sourceFileUrls", timeout=15)
            if r2.ok:
                urls = r2.json()
                if isinstance(urls, list):
                    debian_tar_url = next(
                        (u for u in urls if isinstance(u, str) and ".debian.tar." in u),
                        None,
                    )
        except Exception as exc:
            log.debug("[launchpad] sourceFileUrls failed: %s", exc)

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

            # Only check markers on '+' lines (actual additions in each patch file).
            # Checking the full patches_text causes false positives: an unrelated patch
            # touching nearby code will have the function name as a context line (' '),
            # which is indistinguishable from the function actually being added by the fix.
            added_in_patches = "\n".join(
                line for line in patches_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            )

            evidence: list[str] = []
            if short_sha in patches_text:
                evidence.append(f"sha_in_patch:{short_sha}")
            if short_sha in changelog_text:
                evidence.append(f"sha_in_changelog:{short_sha}")
            for m in markers:
                if m in added_in_patches:
                    evidence.append(f"marker:{m}")

            sha_found    = any(e.startswith("sha") for e in evidence)
            marker_count = sum(1 for e in evidence if e.startswith("marker:"))

            # Require SHA confirmation OR ≥2 independent marker matches on '+' lines.
            # A single marker hit is not sufficient: common function names from the
            # affected file can appear in any related security patch.
            found = sha_found or marker_count >= 2
            if sha_found:
                method = "backport" if any("changelog" in e for e in evidence) else "quilt_patch"
            elif marker_count >= 2:
                method = "quilt_patch"
            else:
                method = "not_present"

            return {
                "ubuntu_2404_actually_patched": found,
                "ubuntu_2404_patch_method":     method,
                "ubuntu_2404_current_version":  current_ver,
                "_apt_source_evidence":         evidence[:5],
                "_apt_source_method":           f"launchpad_debian_tar/{pocket_used}",
                "patch_marker_grep_query":      "|".join(markers[:3]) or short_sha,
                "patch_marker_found":           found,
            }
        except Exception as exc:
            log.debug("[launchpad] debian tar download/parse failed: %s", exc)

    # ── 4. Last-resort: .changes file SHA search ──────────────────────────────
    try:
        changes_url = (
            f"https://launchpad.net/ubuntu/+archive/primary/+files/"
            f"{src_pkg}_{current_ver}_source.changes"
        )
        r4   = requests.get(changes_url, timeout=15)
        text = r4.text if r4.ok else ""
    except Exception:
        text = ""

    found_in_changes = short_sha in text
    return {
        "ubuntu_2404_actually_patched": found_in_changes if text else None,
        "ubuntu_2404_patch_method":     "backport" if found_in_changes else ("not_present" if text else "unknown"),
        "ubuntu_2404_current_version":  current_ver,
        "_apt_source_method":           "launchpad_changes_file",
        "patch_marker_grep_query":      short_sha,
        "patch_marker_found":           found_in_changes,
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
    markers = _extract_patch_markers(diff) if diff else []
    log.debug("[apt_source] %s — %d patch markers: %s", pkg_name, len(markers), markers[:4])

    if _docker_available():
        log.info("[apt_source] Docker available — running ubuntu:24.04 container for %s", pkg_name)
        result = _docker_apt_source(pkg_name, commit_sha, markers)
        if result is not None:
            return _apply_long_marker(result, diff)
        log.warning("[apt_source] Docker run returned no result, falling back to Launchpad")

    log.info("[apt_source] Using Launchpad fallback for %s", pkg_name)
    return _apply_long_marker(_launchpad_patch_search(pkg_name, commit_sha, markers), diff)

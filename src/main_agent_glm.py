#!/usr/bin/env python3
"""
main_agent_glm.py  –  Ubuntu 24.04 → 26.04 Patch Gap Analyzer (GLM Edition)

Pipeline
--------
  Step 1  Data Module:     Compare 24.04 vs 26.04 package versions → GitHub commit list
  Step 2  GLM Stage 1:     Filter — no-CVE memory corruption / logic vulnerability fixes
  Step 3  Source Analysis: Locate affected functions in Ubuntu 24.04 source
  Step 4  GLM Stage 2:     Confirm 24.04 vulnerability + backport difficulty assessment
  Step 5  Output:          Patch Gap report

Usage
-----
  export ZAI_API_KEY=<your-key>

  # Single package:
  python src/main_agent_glm.py --package libxml2

  # Package list file:
  python src/main_agent_glm.py --file data/target_pkgs/target_test_20.txt

  # Auto-scan all packages with known repos and a version gap:
  python src/main_agent_glm.py --auto --top 10
"""

import argparse
import csv
import json
import logging
import os
import re
import subprocess
import sys
import urllib.parse
from datetime import date as _date, datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
import config as cfg

from tools.diff_harvester import (
    harvest,
    _find_tag_fuzzy,
    _clone_or_update,
    _local_dir,
    _normalize_repo_url,
)
from tools.version_gap_finder import find_gap, KNOWN_UPSTREAM_REPOS
from tools.version_gap_finder import resolve_source_package_name
from tools.cve_tracker import lookup_cve_for_commit, check_ubuntu_patch_status, get_ubuntu_component
from tools.ubuntu_patch_verifier import check_apt_source

from openai import OpenAI
from packaging.version import Version, InvalidVersion

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)-28s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("patch_gap_glm")

# ── Data paths ────────────────────────────────────────────────────────────────
_UBUNTU_2404_DETAIL = cfg.DATA_DIR / "output" / "ubuntu_24.04" / "ubuntu_24.04_packages_detail.json"
_UBUNTU_2604_DETAIL = cfg.DATA_DIR / "output" / "ubuntu_26.04" / "ubuntu_26.04_packages_detail.json"
_REPORT_FILE        = cfg.FINDINGS_DIR / "patch_gap_report.json"
_REPORT_CSV_FILE    = cfg.FINDINGS_DIR / "patch_gap_report.csv"

_MAX_COMMITS_STAGE1 = 20   # max commits sent to Stage 1 GLM filter
_MAX_COMMITS_STAGE2 = 5    # max commits sent to Stage 2 deep audit

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# In-memory caches for API calls that are not persisted across runs
_MERGE_PR_CACHE:  dict[str, tuple] = {}   # "github/owner/repo/PR#" → (content, url)
_FORGE_DATE_CACHE: dict[str, Optional[str]] = {}  # "lp_pkg:sha12" → "YYYY-MM-DD"


# ── CDSFA-Audit helpers ───────────────────────────────────────────────────────

def _has_cve(message: str) -> bool:
    return bool(_CVE_RE.search(message))


def _classify_repo_component(pkg_name: str, detail_file: Path) -> str:
    """Determine Ubuntu component (main/universe/restricted/multiverse) from package detail JSON."""
    try:
        data = json.loads(detail_file.read_text())
        for pkg_list in data.values():
            for pkg in pkg_list:
                if pkg.get("Package", "") == pkg_name:
                    section = pkg.get("Section", "").lower()
                    for component in ("universe", "multiverse", "restricted"):
                        if component in section:
                            return component
                    if section:
                        return "main"
    except Exception:
        pass
    return "unknown"


def _determine_inheritance_mode(repo, commit_sha: str, end_tag_name: str) -> str:
    """
    Classify how a fix arrived in Ubuntu 26.04 (Resolute).

    Natural_Import  — commit is in the upstream ancestry of the 26.04 version tag,
                      meaning it simply arrived with the upstream version bump.
    Manual_Backport — commit is NOT in that ancestry (Debian-specific patch), OR it
                      carries Canonical/Ubuntu authorship / cherry-pick markers.
    """
    try:
        # git merge-base --is-ancestor exits 0 if ancestor, raises otherwise
        repo.git.merge_base("--is-ancestor", commit_sha, end_tag_name)
        # Commit IS in upstream ancestry → check for Canonical backport signals
        try:
            obj   = repo.commit(commit_sha)
            msg   = (obj.message or "").lower()
            email = (obj.author.email or "").lower()
            if ("cherry picked from" in msg or "ubuntu.com" in email
                    or "canonical.com" in email):
                return "Manual_Backport"
        except Exception:
            pass
        return "Natural_Import"
    except Exception:
        # Not reachable from end tag → must be a Debian-layer patch
        return "Manual_Backport"


def _get_commit_date(repo, sha: str) -> str:
    """Return ISO date (YYYY-MM-DD) of a git commit, or empty string on failure."""
    try:
        return repo.commit(sha).committed_datetime.strftime("%Y-%m-%d")
    except Exception:
        return ""


def _get_resolute_evidence(repo, commit_sha: str, end_tag_name: str, inherit_mode: str) -> str:
    """One-line provenance string: how the commit arrived in Ubuntu 26.04."""
    try:
        obj      = repo.commit(commit_sha)
        msg_head = (obj.message or "").splitlines()[0][:80]
        if inherit_mode == "Natural_Import":
            return (
                f"Reachable from upstream tag {end_tag_name}; "
                f"arrived via natural version import. upstream: {msg_head}"
            )
        email = obj.author.email or ""
        return (
            f"Manual backport / Debian-layer patch (author: {email}). "
            f"upstream: {msg_head}"
        )
    except Exception:
        return ""


def _maintenance_gap_type(silent_at_commit: bool, cve_assigned: bool, priority: str) -> str:
    """
    Trigger_Gap  — no CVE at commit time AND none found in external databases.
    Priority_Gap — CVE exists (either at commit time or assigned later) but low priority.
    Resolved     — CVE assigned and ubuntu 24.04 patch confirmed.
    """
    if cve_assigned:
        return "Priority_Gap" if priority.lower() in ("low", "informational") else "Trigger_Gap"
    if silent_at_commit:
        return "Trigger_Gap"
    return "Priority_Gap"


# ══════════════════════════════════════════════════════════════════════════════
# GLM client helpers
# ══════════════════════════════════════════════════════════════════════════════

def _build_client() -> OpenAI:
    if not cfg.ZAI_API_KEY:
        raise RuntimeError("ZAI_API_KEY not set. Run: export ZAI_API_KEY=<your-key>")
    return OpenAI(api_key=cfg.ZAI_API_KEY, base_url=cfg.ZAI_BASE_URL)


def _call_glm(client: OpenAI, system: str, user: str) -> dict:
    resp = client.chat.completions.create(
        model=cfg.ZAI_MODEL,
        temperature=0.05,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    )
    raw = resp.choices[0].message.content or "{}"
    return json.loads(raw.strip())


# ══════════════════════════════════════════════════════════════════════════════
# Step 1: Data Module — compare Ubuntu 24.04 vs 26.04 package versions
# ══════════════════════════════════════════════════════════════════════════════

def _load_pkg_versions(detail_file: Path) -> dict[str, str]:
    """Load {package_name: version} from ubuntu detail JSON."""
    data = json.loads(detail_file.read_text())
    packages: dict[str, str] = {}
    for pkg_list in data.values():
        for pkg in pkg_list:
            name = pkg.get("Package", "")
            ver  = pkg.get("Version", "")
            if name and ver:
                packages[name] = ver
    return packages


def _normalize_ver(raw: str) -> str:
    v = raw.strip().lstrip("v")
    v = re.sub(r"^\d+:", "", v)     # strip epoch (3:)
    v = re.sub(r"[+~].*$", "", v)   # strip +dfsg / ~beta
    v = re.sub(r"-.*$", "", v)      # strip Debian revision
    return v.strip()


# Package name variants across Ubuntu versions (e.g., libxml2 → libxml2-16 in 26.04)
_PACKAGE_VARIANTS: dict[str, list[str]] = {
    "libxml2": ["libxml2", "libxml2-16"],  # 24.04 vs 26.04
    "libssh": ["libssh", "libssh-4", "libssh-dev"],
    "pcre2": ["pcre2", "libpcre2-8-0", "libpcre2-dev"],
}


def _package_preference_score(pkg_name: str, base_name: str) -> tuple[int, int, int]:
    """Lower score is better when choosing a representative binary package."""
    p = pkg_name.lower()
    penalties = 0
    if p.endswith("-dev"):
        penalties += 3
    if p.endswith("-doc") or p.endswith("-docs"):
        penalties += 3
    if p.endswith("-dbg") or p.endswith("-debug"):
        penalties += 3
    if p.endswith("-tools") or p.endswith("-utils") or p.endswith("-common"):
        penalties += 1
    if p.endswith("-bin"):
        penalties += 1

    prefix_bias = 0 if p.startswith(base_name.lower()) else 1
    return (penalties, prefix_bias, len(pkg_name))


def _find_package_in_dicts(base_name: str, pkgs_2404: dict, pkgs_2604: dict) -> tuple[str, str]:
    """
    Find matching package names in both Ubuntu versions, handling variants.
    Returns (name_in_2404, name_in_2604) or ("", "") if not found.
    """
    # First try exact match
    if base_name in pkgs_2404 and base_name in pkgs_2604:
        return (base_name, base_name)

    source_name = resolve_source_package_name(base_name)

    # Try explicit variant mapping first (covers known rename patterns)
    variants = list(dict.fromkeys(
        _PACKAGE_VARIANTS.get(base_name, []) +
        _PACKAGE_VARIANTS.get(source_name, []) +
        [base_name, source_name]
    ))
    for v24 in variants:
        if v24 not in pkgs_2404:
            continue
        for v26 in variants:
            if v26 in pkgs_2604:
                return (v24, v26)

    # Generic fallback: map source package name to matching binary package names.
    # Example: pcre2 -> libpcre2-8-0, libpcre2-dev; libssh -> libssh-4, libssh-dev
    matches_2404 = [
        name for name in pkgs_2404
        if resolve_source_package_name(name) == source_name
    ]
    matches_2604 = [
        name for name in pkgs_2604
        if resolve_source_package_name(name) == source_name
    ]

    if not matches_2404 or not matches_2604:
        return ("", "")

    common = set(matches_2404) & set(matches_2604)
    if common:
        best = min(common, key=lambda n: _package_preference_score(n, base_name))
        return (best, best)

    best_2404 = min(matches_2404, key=lambda n: _package_preference_score(n, base_name))
    best_2604 = min(matches_2604, key=lambda n: _package_preference_score(n, base_name))
    return (best_2404, best_2604)

    # If no variants found, return empty
    return ("", "")


def find_version_gaps(pkg_filter: Optional[list[str]] = None) -> list[dict]:
    """
    Compare Ubuntu 24.04 vs 26.04 packages.
    Returns packages where 26.04 is newer AND a known upstream repo exists.
    """
    log.info("[Data] Loading Ubuntu 24.04 package list …")
    pkgs_2404 = _load_pkg_versions(_UBUNTU_2404_DETAIL)
    log.info("[Data] Loading Ubuntu 26.04 package list …")
    pkgs_2604 = _load_pkg_versions(_UBUNTU_2604_DETAIL)

    gaps: list[dict] = []
    for pkg_name, ver_2604 in pkgs_2604.items():
        if pkg_filter and pkg_name not in pkg_filter:
            continue
        if pkg_name not in pkgs_2404:
            continue
        ver_2404 = pkgs_2404[pkg_name]
        try:
            if Version(_normalize_ver(ver_2604)) > Version(_normalize_ver(ver_2404)):
                repo_url = KNOWN_UPSTREAM_REPOS.get(pkg_name, "")
                gaps.append({
                    "package":  pkg_name,
                    "ver_2404": ver_2404,
                    "ver_2604": ver_2604,
                    "repo_url": repo_url,
                })
        except InvalidVersion:
            pass

    with_repo = [g for g in gaps if g["repo_url"]]
    log.info("[Data] %d packages with version gaps, %d with known upstream repos",
             len(gaps), len(with_repo))
    return with_repo


# ══════════════════════════════════════════════════════════════════════════════
# Step 2: GLM Stage 1 — filter commits (no-CVE memory/logic vulnerability fixes)
# ══════════════════════════════════════════════════════════════════════════════

_STAGE1_SYSTEM = (
    "You are a senior security researcher reviewing Linux package commits. "
    "Identify commits that fix memory corruption or logic vulnerabilities "
    "WITHOUT an associated CVE number. "
    "Apply Ubuntu Security Priority Definitions when scoring: "
    "Critical=network-exploitable, no auth, severe impact; "
    "High=hard-to-exploit but severe, or easy with significant impact; "
    "Medium=real vuln but requires local access or specific conditions; "
    "Low=theoretical, very difficult, minimal real-world impact. "
    "Respond ONLY with a single valid JSON object. No markdown, no prose."
)

_STAGE1_TEMPLATE = """\
Analyze this git commit. Determine if it fixes a memory corruption or logic \
vulnerability WITHOUT an associated CVE identifier.

Target criteria:
  • Memory safety: use-after-free, double-free, out-of-bounds read/write, buffer
    overflow, integer overflow/underflow, null-pointer dereference, heap corruption
  • Logic vulnerabilities: incorrect state transitions, authentication bypass,
    race conditions, improper validation of untrusted input
  • NO CVE number in the message or comments
  • NOT a pure refactor, doc update, test, style, or dependency bump

Package: {package}
Ubuntu 24.04 version: {ver_2404}
Ubuntu 26.04 version: {ver_2604}
Commit SHA: {sha}

Commit message:
{message}

Code diff (truncated):
{diff}

Respond with this JSON only:
{{
  "keep": true,
  "vuln_class": "memory_corruption|logic_vuln|none",
  "affected_functions": ["func1", "func2"],
  "affected_files": ["path/to/file.c"],
  "confidence": "high|medium|low",
  "canonical_priority": "Critical|High|Medium|Low",
  "brief_reason": "one-sentence rationale"
}}"""


def _funcs_in_diff(diff: str) -> list[str]:
    """
    Extract function names that are genuinely present in the diff:
    1. Context labels from @@ ... @@ headers  (most reliable)
    2. Identifiers appearing in a call/definition position on + lines
    De-duplicates, preserves order, caps at 10 entries.
    """
    funcs: list[str] = []
    seen:  set[str]  = set()

    def _add(name: str) -> None:
        if name not in seen and len(name) > 4:
            funcs.append(name)
            seen.add(name)

    for m in re.finditer(r'^@@[^@]*@@\s+(?:\w+\s+)*([a-zA-Z_]\w+)\s*\(', diff, re.MULTILINE):
        _add(m.group(1))
    for m in re.finditer(r'^\+[^+].*\b([a-zA-Z_][a-zA-Z0-9_]{4,})\s*\(', diff, re.MULTILINE):
        _add(m.group(1))
    return funcs[:10]


def glm_stage1_filter(
    pkg_name: str,
    ver_2404: str,
    ver_2604: str,
    commits: list[dict],
    client: OpenAI,
) -> list[dict]:
    """Stage 1: keep only no-CVE memory/logic vulnerability fix commits."""
    kept: list[dict] = []

    for commit in commits[:_MAX_COMMITS_STAGE1]:
        sha8   = commit.get("short_sha", commit.get("sha", "")[:8])
        prompt = _STAGE1_TEMPLATE.format(
            package  = pkg_name,
            ver_2404 = ver_2404,
            ver_2604 = ver_2604,
            sha      = commit.get("sha", ""),
            message  = commit.get("message", "")[:400],
            diff     = commit.get("diff", "")[:2000],
        )
        try:
            result = _call_glm(client, _STAGE1_SYSTEM, prompt)
        except Exception as exc:
            log.warning("[Stage1] SHA=%s call failed: %s — keeping", sha8, exc)
            commit["stage1"] = {"error": str(exc), "keep": True}
            kept.append(commit)
            continue

        keep       = bool(result.get("keep", False))
        vuln_class = result.get("vuln_class", "none")
        confidence = result.get("confidence", "low")
        reason     = result.get("brief_reason", "")
        # Ground-truth filter: keep only functions that appear in the diff's @@ headers
        # or + lines.  Removes hallucinated names that the GLM added from context alone.
        _diff_funcs = _funcs_in_diff(commit.get("diff", ""))
        if _diff_funcs:
            _glm_funcs = result.get("affected_functions", [])
            _verified  = [f for f in _glm_funcs if f in _diff_funcs]
            result["affected_functions"] = _verified if _verified else _diff_funcs[:3]
            if _verified != _glm_funcs:
                log.debug("[Stage1] SHA=%s funcs: GLM=%s → verified=%s",
                          sha8, _glm_funcs, result["affected_functions"])
        commit["stage1"] = result

        if keep:
            log.info("[Stage1] KEEP SHA=%s  class=%-20s  conf=%-6s  %s",
                     sha8, vuln_class, confidence, reason[:60])
            kept.append(commit)
        else:
            log.info("[Stage1] DROP SHA=%s  conf=%-6s  %s", sha8, confidence, reason[:60])

    log.info("[Stage1] %d / %d commits retained", len(kept), min(len(commits), _MAX_COMMITS_STAGE1))
    return kept


# ══════════════════════════════════════════════════════════════════════════════
# Step 3: Source Analysis — extract Ubuntu 24.04 function source from git
# ══════════════════════════════════════════════════════════════════════════════

def _extract_function_source(content: str, func_name: str, context_lines: int = 60) -> str:
    """Find func_name in file content and return surrounding lines."""
    lines = content.splitlines()
    func_re = re.compile(rf'\b{re.escape(func_name)}\s*\(')
    for i, line in enumerate(lines):
        if func_re.search(line):
            start = max(0, i - 2)
            end   = min(len(lines), i + context_lines)
            return "\n".join(f"{start + j + 1:4d}  {l}"
                             for j, l in enumerate(lines[start:end]))
    return ""


def extract_source_analysis(repo, start_tag_name: str, commit: dict) -> str:
    """
    Return Ubuntu 24.04 source code for functions affected by the commit.
    Falls back to the first 2 000 chars of each file when functions aren't found.
    """
    stage1         = commit.get("stage1", {})
    affected_files = stage1.get("affected_files", [])
    affected_funcs = stage1.get("affected_functions", [])

    if not affected_files:
        diff = commit.get("diff", "")
        affected_files = re.findall(r"^diff --git a/\S+ b/(\S+)", diff, re.MULTILINE)[:3]

    parts: list[str] = []
    for filepath in affected_files[:3]:
        try:
            content = repo.git.show(f"{start_tag_name}:{filepath}")
        except Exception:
            continue

        parts.append(f"// === {filepath}  @  {start_tag_name} ===")

        found_any = False
        for func_name in affected_funcs:
            snippet = _extract_function_source(content, func_name)
            if snippet:
                parts.append(f"// Function: {func_name}\n{snippet}")
                found_any = True

        if not found_any:
            parts.append(content[:2000])

    return "\n\n".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# Step 4: GLM Stage 2 — confirm 24.04 vulnerability + backport assessment
# ══════════════════════════════════════════════════════════════════════════════

_STAGE2_SYSTEM = (
    "You are an elite vulnerability researcher and patch analyst. "
    "Given Ubuntu 24.04 function source and the upstream fix patch, confirm "
    "whether the vulnerability still exists in 24.04, assess backport difficulty, "
    "and evaluate the 'logical survival' of vulnerable code — whether it is common "
    "core code unlikely to have changed, and whether the patch is decoupled from "
    "version-specific features. "
    "Also provide a concrete proof-of-concept reproduction outline: describe the triggering "
    "input/API call, the vulnerable code path, and the observable crash/behaviour, so a "
    "researcher can verify exploitability without writing full exploit code. "
    "Respond ONLY with a single valid JSON object. No markdown, no prose."
)

_STAGE2_TEMPLATE = """\
Analyze a potential unpatched vulnerability in Ubuntu 24.04.

Package: {package}
Ubuntu 24.04 version: {ver_2404}
Ubuntu 26.04 version: {ver_2604}
Commit SHA (upstream fix): {sha}
Commit message: {message}
Stage 1 vulnerability class: {vuln_class}

=== Ubuntu 24.04 Source Code (affected functions) ===
{source_2404}

=== Upstream Fix Patch (present in 26.04 but missing from 24.04) ===
{patch}

Answer these questions:
1. Does Ubuntu 24.04 still contain the vulnerability described by the patch?
2. Can the patch be applied cleanly to 24.04, or does it require significant adaptation?
3. What is the exploitability / severity in 24.04?
4. Logical survival assessment: Is the vulnerable code in 24.04 common/core code unlikely
   to have been restructured? Is the patch logically decoupled from version-specific features
   (i.e., it fixes a generic algorithmic or memory-management issue, not a new API)?
   Rate backport feasibility: Trivial (one-line cherry-pick) / Easy (minimal context changes) /
   Moderate (some refactoring needed) / Hard (deep structural dependency on newer codebase).
5. Proof-of-concept reproduction outline: describe step by step how a researcher could
   trigger the vulnerability on Ubuntu 24.04 — the crafted input or API sequence, the
   vulnerable code path that is exercised, and the expected observable outcome
   (crash, memory corruption, logic bypass, etc.). Be concrete but concise (3-6 steps).

Respond with this JSON only:
{{
  "vuln_confirmed_in_2404": true,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
  "vulnerability_type": "one-line description",
  "poc_sketch": "brief one-sentence attack scenario",
  "poc_reproduction_steps": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ],
  "backport_difficulty": "trivial|easy|moderate|hard|infeasible",
  "backport_notes": "key obstacles or prerequisites for backporting",
  "backport_feasibility": "Trivial|Easy|Moderate|Hard",
  "logical_survival": "one-sentence assessment of code stability and patch decoupling",
  "cot_rationale": "chain-of-thought analysis supporting the verdict"
}}"""


def glm_stage2_audit(
    pkg_name: str,
    ver_2404: str,
    ver_2604: str,
    commit: dict,
    source_2404: str,
    client: OpenAI,
) -> dict:
    """Stage 2: confirm vulnerability in 24.04, assess backport difficulty."""
    sha8     = commit.get("short_sha", commit.get("sha", "")[:8])
    vuln_cls = commit.get("stage1", {}).get("vuln_class", "unknown")
    patch    = commit.get("diff", "")[:cfg.MAX_DIFF_CHARS]

    prompt = _STAGE2_TEMPLATE.format(
        package     = pkg_name,
        ver_2404    = ver_2404,
        ver_2604    = ver_2604,
        sha         = commit.get("sha", ""),
        message     = commit.get("message", "").splitlines()[0][:300],
        vuln_class  = vuln_cls,
        source_2404 = source_2404[:8000],
        patch       = patch,
    )

    log.info("[Stage2] SHA=%s  sending audit prompt (%d chars) → zai/%s",
             sha8, len(prompt), cfg.ZAI_MODEL)

    clean = {
        "vuln_confirmed_in_2404":  False,
        "severity":                "INFORMATIONAL",
        "vulnerability_type":      "None",
        "poc_sketch":              "",
        "poc_reproduction_steps":  [],
        "backport_difficulty":     "unknown",
        "backport_notes":          "",
        "cot_rationale":           "",
    }
    try:
        result = _call_glm(client, _STAGE2_SYSTEM, prompt)
    except Exception as exc:
        log.error("[Stage2] SHA=%s call failed: %s", sha8, exc)
        return {**clean, "_error": str(exc)}

    log.info("[Stage2] SHA=%s  confirmed=%s  severity=%s  backport=%s",
             sha8,
             result.get("vuln_confirmed_in_2404"),
             result.get("severity"),
             result.get("backport_difficulty"))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Step 5: Output — Patch Gap report
# ══════════════════════════════════════════════════════════════════════════════

# ── Package normalization & Forge mapping ─────────────────────────────────────
# Explicit map: Ubuntu binary/source package → canonical Launchpad source name.
# Packages absent from both dicts fall back to suffix-strip heuristic.

_LAUNCHPAD_SOURCE: dict[str, str] = {
    "libxml2-dev":          "libxml2",
    "libxml2":              "libxml2",
    "libxslt1-dev":         "libxslt",
    "libxslt1.1":           "libxslt",
    "libssl-dev":           "openssl",
    "libssl3":              "openssl",
    "openssl":              "openssl",
    "libcurl4-openssl-dev": "curl",
    "libcurl4-gnutls-dev":  "curl",
    "curl":                 "curl",
    "libglib2.0-dev":       "glib2.0",
    "libglib2.0-0":         "glib2.0",
    "glib2.0":              "glib2.0",
    "libsqlite3-dev":       "sqlite3",
    "sqlite3":              "sqlite3",
    "zlib1g-dev":           "zlib",
    "zlib1g":               "zlib",
    "libexpat1-dev":        "expat",
    "libexpat1":            "expat",
    "libpcre2-dev":         "pcre2",
    "libpcre2-8-0":         "pcre2",
    "libpng-dev":           "libpng",
    "libpng16-16":          "libpng",
    "libjpeg-turbo8-dev":   "libjpeg-turbo",
    "libjpeg-turbo8":       "libjpeg-turbo",
    "libfreetype6-dev":     "freetype",
    "libfreetype6":         "freetype",
    "libfontconfig1-dev":   "fontconfig",
    "fontconfig":           "fontconfig",
    "libgcrypt20-dev":      "libgcrypt20",
    "libgcrypt20":          "libgcrypt20",
    "libgnutls-dev":        "gnutls28",
    "libgnutls30":          "gnutls28",
    "libgnutls28-dev":      "gnutls28",
    "libssh-dev":           "libssh",
    "libssh-4":             "libssh",
    "libssh2-1-dev":        "libssh2",
    "libssh2-1":            "libssh2",
    "libtiff-dev":          "tiff",
    "libtiff6":             "tiff",
    "systemd":              "systemd",
    "libsystemd-dev":       "systemd",
    "libnss3-dev":          "nss",
    "libnss3":              "nss",
    "libarchive-dev":       "libarchive",
    "freerdp3-dev":         "freerdp3",
    "libopenjp2-7":         "openjpeg2",
    "libonig5":             "oniguruma",
    "libpam0g-dev":         "pam",
    "librados-dev":         "ceph",
    "libucl1":              "libucl",
    "libmupdf-dev":         "mupdf",
    "libevent-dev":         "libevent",
    "libmysqlclient-dev":   "mysql-8.0",
    "libicu-dev":           "icu",
}

_STRIP_PKG_SUFFIXES = re.compile(
    r"(-dev|-utils|-doc|-docs|-bin|-common|-tools|-data|-headers?|-dbg|-debug|-static)$",
    re.IGNORECASE,
)


def _launchpad_source_pkg(raw: str) -> str:
    """Return canonical Launchpad source package name for a binary package."""
    if raw in _LAUNCHPAD_SOURCE:
        return _LAUNCHPAD_SOURCE[raw]
    stripped = _STRIP_PKG_SUFFIXES.sub("", raw)
    if stripped in _LAUNCHPAD_SOURCE:
        return _LAUNCHPAD_SOURCE[stripped]
    return resolve_source_package_name(raw)


# forge_key (= Launchpad source name) → host / path / url_type
# url_type "github" → https://github.com/{path}/commit/{sha}
# url_type "gitlab" → https://{host}/{path}/-/commit/{sha}
# url_type None     → upstream URL unknown; upstream_commit will be null

_FORGE_MAP: dict[str, dict] = {
    "libxml2":       {"host": "gitlab.gnome.org",       "path": "GNOME/libxml2",               "url_type": "gitlab"},
    "libxslt":       {"host": "gitlab.gnome.org",       "path": "GNOME/libxslt",               "url_type": "gitlab"},
    "glib2.0":       {"host": "gitlab.gnome.org",       "path": "GNOME/glib",                  "url_type": "gitlab"},
    "cairo":         {"host": "gitlab.freedesktop.org", "path": "cairo/cairo",                  "url_type": "gitlab"},
    "fontconfig":    {"host": "gitlab.freedesktop.org", "path": "fontconfig/fontconfig",        "url_type": "gitlab"},
    "freetype":      {"host": "gitlab.freedesktop.org", "path": "freetype/freetype",            "url_type": "gitlab"},
    "pixman":        {"host": "gitlab.freedesktop.org", "path": "pixman/pixman",                "url_type": "gitlab"},
    "dbus":          {"host": "gitlab.freedesktop.org", "path": "dbus/dbus",                    "url_type": "gitlab"},
    "wayland":       {"host": "gitlab.freedesktop.org", "path": "wayland/wayland",              "url_type": "gitlab"},
    "mesa":          {"host": "gitlab.freedesktop.org", "path": "mesa/mesa",                    "url_type": "gitlab"},
    "openssl":       {"host": "github.com",             "path": "openssl/openssl",              "url_type": "github"},
    "curl":          {"host": "github.com",             "path": "curl/curl",                    "url_type": "github"},
    "expat":         {"host": "github.com",             "path": "libexpat/libexpat",            "url_type": "github"},
    "zlib":          {"host": "github.com",             "path": "madler/zlib",                  "url_type": "github"},
    "sqlite3":       {"host": "github.com",             "path": "sqlite/sqlite",                "url_type": "github"},
    "pcre2":         {"host": "github.com",             "path": "PCRE2Project/pcre2",           "url_type": "github"},
    "libpng":        {"host": "github.com",             "path": "pnggroup/libpng",              "url_type": "github"},
    "libjpeg-turbo": {"host": "github.com",             "path": "libjpeg-turbo/libjpeg-turbo", "url_type": "github"},
    "libssh":        {"host": "gitlab.com",             "path": "libssh/libssh",                "url_type": "gitlab"},
    "libssh2":       {"host": "github.com",             "path": "libssh2/libssh2",              "url_type": "github"},
    "tiff":          {"host": "gitlab.com",             "path": "libtiff/libtiff",              "url_type": "gitlab"},
    "gnutls28":      {"host": "gitlab.com",             "path": "gnutls/gnutls",                "url_type": "gitlab"},
    "systemd":       {"host": "github.com",             "path": "systemd/systemd",              "url_type": "github"},
    "nss":           {"host": "github.com",             "path": "nss-dev/nss",                  "url_type": "github"},
    "libarchive":    {"host": "github.com",             "path": "libarchive/libarchive",         "url_type": "github"},
    "freerdp3":      {"host": "github.com",             "path": "FreeRDP/FreeRDP",              "url_type": "github"},
    "imagemagick":   {"host": "github.com",             "path": "ImageMagick/ImageMagick",      "url_type": "github"},
    "poppler":       {"host": "gitlab.freedesktop.org", "path": "poppler/poppler",              "url_type": "gitlab"},
    "openjpeg2":     {"host": "github.com",             "path": "uclouvain/openjpeg",           "url_type": "github"},
    "oniguruma":     {"host": "github.com",             "path": "kkos/oniguruma",               "url_type": "github"},
    "pam":           {"host": "github.com",             "path": "linux-pam/linux-pam",          "url_type": "github"},
    "libevent":      {"host": "github.com",             "path": "libevent/libevent",            "url_type": "github"},
    "icu":           {"host": "github.com",             "path": "unicode-org/icu",              "url_type": "github"},
    "opensc":        {"host": "github.com",             "path": "OpenSC/OpenSC",                "url_type": "github"},
    "mupdf":         {"host": "github.com",             "path": "ArtifexSoftware/mupdf",        "url_type": "github"},
    "ffmpeg":        {"host": "github.com",             "path": "FFmpeg/FFmpeg",                "url_type": "github"},
    "containerd":    {"host": "github.com",             "path": "containerd/containerd",        "url_type": "github"},
    "nghttp2":       {"host": "github.com",             "path": "nghttp2/nghttp2",              "url_type": "github"},
    "libwebp":       {"host": "github.com",             "path": "webmproject/libwebp",          "url_type": "github"},
    "libpng":        {"host": "github.com",             "path": "pnggroup/libpng",              "url_type": "github"},
    "mysql-8.0":     {"host": "github.com",             "path": "mysql/mysql-server",           "url_type": "github"},
}

for _forge_info in _FORGE_MAP.values():
    _forge_info.setdefault("forge_type", _forge_info.get("url_type", "generic_git"))

for _generic_forge in ("ffmpeg", "imagemagick"):
    if _generic_forge in _FORGE_MAP:
        _FORGE_MAP[_generic_forge]["forge_type"] = "generic_git"


def _forge_commit_url(pkg: str, sha: str) -> Optional[str]:
    lp   = _launchpad_source_pkg(pkg)
    info = _FORGE_MAP.get(lp)
    if not info or info.get("url_type") is None:
        return None
    host, path = info["host"], info["path"]
    if info["url_type"] == "github":
        return f"https://github.com/{path}/commit/{sha}"
    return f"https://{host}/{path}/-/commit/{sha}"


def _forge_repo_url(pkg: str) -> Optional[str]:
    """Resolve upstream repository URL from the internal forge mapping."""
    lp = _launchpad_source_pkg(pkg)
    info = _FORGE_MAP.get(lp)
    if not info or info.get("url_type") is None:
        return None
    host, path = info["host"], info["path"]
    if info["url_type"] == "github":
        return f"https://github.com/{path}"
    return f"https://{host}/{path}"


def _commit_url_from_source_link(source_url: str, sha: str) -> Optional[str]:
    """
    Detect upstream platform from a git clone/browse URL and build a web commit URL.
    Covers github.com, gitlab.gnome.org, gitlab.freedesktop.org, any gitlab instance.
    Falls back to the bare source_url for git.kernel.org and other unknown hosts.
    """
    if not source_url or not sha:
        return None
    # github.com
    m = re.search(r'github\.com[/:]([^/]+)/([^/\s]+?)(?:\.git)?$', source_url)
    if m:
        return f"https://github.com/{m.group(1)}/{m.group(2)}/commit/{sha}"
    # Any gitlab instance (gitlab.gnome.org, gitlab.freedesktop.org, gitlab.com, …)
    m = re.search(r'(https?://gitlab\.[^/]+)/([^/]+/[^/\s]+?)(?:\.git)?$', source_url)
    if m:
        return f"{m.group(1)}/{m.group(2)}/-/commit/{sha}"
    # git.kernel.org or other unknown host — return source link as reference
    if source_url.startswith("http"):
        return source_url
    return None


def _run_git_ls_remote_tags(repo_url: str) -> list[str]:
    if not repo_url:
        return []
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--tags", repo_url],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception:
        return []
    if result.returncode != 0 or not result.stdout:
        return []
    tags: list[str] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        ref = parts[1].strip()
        if ref.endswith("^{}"):
            ref = ref[:-3]
        if ref.startswith("refs/tags/"):
            tags.append(ref.removeprefix("refs/tags/"))
    return tags


def _match_remote_tag(repo_url: str, candidates: list[str], raw_ver: str) -> tuple[Optional[str], Optional[str], bool]:
    remote_tags = _run_git_ls_remote_tags(repo_url)
    if not remote_tags:
        return (None, None, False)

    candidate_set = {
        c for candidate in candidates
        for c in (candidate, candidate.lstrip("v"), f"v{candidate.lstrip('v')}")
        if c
    }

    for tag in remote_tags:
        if tag in candidate_set:
            return (tag, tag, False)

    raw_norm = raw_ver.lstrip("v")
    best_tag: Optional[str] = None
    best_score: tuple[int, int] | None = None
    for tag in remote_tags:
        tag_norm = tag.lstrip("v")
        if not tag_norm:
            continue
        if raw_norm and raw_norm in tag_norm or tag_norm in raw_norm:
            score = (abs(len(tag_norm) - len(raw_norm)), 0 if tag_norm.startswith(raw_norm) else 1)
            if best_score is None or score < best_score:
                best_tag = tag
                best_score = score
    if best_tag:
        return (best_tag, best_tag, True)
    return (None, None, False)


def _build_browse_tag_url(host: str, path: str, tag: str, *, forge_type: str = "", source_url: str = "") -> str:
    if forge_type == "github" or host == "github.com":
        return f"https://github.com/{path}/tree/{tag}"
    if forge_type == "gitlab" or "gitlab" in host:
        return f"https://{host}/{path}/-/tree/{tag}"
    if source_url:
        return source_url
    return f"https://{host}/{path}/tree/{tag}"


# Known secondary / native git server URLs that NVD may reference instead of
# (or in addition to) the primary forge mirror.  Key = Launchpad source name.
_SECONDARY_GIT_URLS: dict[str, str] = {
    "openssl":  "https://git.openssl.org/gitweb/?p=openssl.git;a=commit;h={sha}",
    "curl":     "https://github.com/curl/curl/commit/{sha}",          # already primary
    "expat":    "https://github.com/libexpat/libexpat/commit/{sha}",  # already primary
    "gnutls28": "https://gitlab.com/gnutls/gnutls/-/commit/{sha}",    # already primary
    "libssh2":  "https://github.com/libssh2/libssh2/commit/{sha}",    # already primary
    "systemd":  "https://github.com/systemd/systemd/commit/{sha}",    # already primary
}


def _build_candidate_commit_urls(pkg: str, sha: str) -> list[str]:
    """
    Return all known commit URLs for this package+SHA.
    Covers the primary forge plus any known native git servers that NVD may cite.
    The NVD reverse-lookup searches each URL so that forge-mirror differences
    don't cause a real CVE to be missed.
    """
    urls: list[str] = []
    primary = _forge_commit_url(pkg, sha)
    if primary:
        urls.append(primary)
    lp  = _launchpad_source_pkg(pkg)
    sec = _SECONDARY_GIT_URLS.get(lp, "").format(sha=sha)
    if sec and sec not in urls:
        urls.append(sec)
    return urls


def _forge_issue_search_url(pkg: str, keyword: str) -> Optional[str]:
    lp   = _launchpad_source_pkg(pkg)
    info = _FORGE_MAP.get(lp)
    if not info or info.get("url_type") is None:
        return None
    kw   = keyword.replace(" ", "+")[:60]
    host, path = info["host"], info["path"]
    if info["url_type"] == "github":
        return f"https://github.com/{path}/issues?q={kw}"
    return f"https://{host}/{path}/-/issues/?search={kw}"


def _extract_first_filepath_from_diff(diff: str) -> Optional[str]:
    """
    Extract the first file path from a git diff.
    Looks for 'diff --git a/<path> b/<path>' lines.
    Returns just the path, or None if not found.
    """
    m = re.search(r"^diff --git a/(.+) b/\1", diff, re.MULTILINE)
    if m:
        return m.group(1)
    return None


def _build_upstream_source_url_for_file(
    pkg: str,
    filepath: str,
    ver_2404: str,
) -> Optional[str]:
    """
    Build an upstream source code browser URL for a specific file at the 24.04 version.
    
    Returns a URL like:
      GitHub: https://github.com/<owner>/<repo>/blob/<upstream_tag>/<filepath>
      GitLab: https://gitlab.{host}/<owner>/<repo>/-/blob/<upstream_tag>/<filepath>
    or None if the forge is unknown.
    """
    lp = _launchpad_source_pkg(pkg)
    info = _FORGE_MAP.get(lp)
    if not info or info.get("url_type") is None:
        return None

    # Extract upstream version tag from Ubuntu 24.04 version
    # e.g., "2.9.14+dfsg-1.3ubuntu3" → "v2.9.14" or "2.9.14"
    raw_ver = ver_2404.strip()
    raw_ver = re.sub(r"^\d+:", "", raw_ver)        # strip epoch
    raw_ver = re.sub(r"[+~].*$", "", raw_ver)      # strip +dfsg / ~beta
    raw_ver = re.sub(r"-.*$", "", raw_ver)          # strip Debian revision
    raw_ver = raw_ver.lstrip("v")

    # Try candidate tags: v<ver>, <ver>, <pkg>-<ver>
    candidates = [f"v{raw_ver}", raw_ver]
    
    host, path = info["host"], info["path"]
    url_type = info["url_type"]

    # For now, build URLs for common candidates
    # In real usage, we'd verify tag existence via API, but here we generate all candidates
    urls: list[str] = []
    for tag in candidates:
        if url_type == "github":
            url = f"https://github.com/{path}/blob/{tag}/{filepath}"
        elif url_type == "gitlab":
            url = f"https://{host}/{path}/-/blob/{tag}/{filepath}"
        else:
            continue
        urls.append(url)
    
    # Return the first candidate (usually v<ver>)
    return urls[0] if urls else None


def _changelogs_org_url(
    pkg: str,
    component: str,
    ver_2404_current: Optional[str],
) -> Optional[str]:
    """
    Build the changelogs.ubuntu.com URL for the Ubuntu 24.04 source package changelog.

    URL format:
      https://changelogs.ubuntu.com/changelogs/pool/{component}/{prefix}/{src_pkg}/{src_pkg}_{ver}/changelog

    prefix: first 4 chars if src_pkg starts with "lib", else first char.
    Returns None if ver_2404_current is None.
    """
    if not ver_2404_current:
        return None
    src_pkg = _launchpad_source_pkg(pkg)
    # Strip common suffixes that may persist after launchpad lookup
    src_pkg = re.sub(r"(-dev|-doc|-bin)$", "", src_pkg)
    comp = component if component and component != "unknown" else "universe"
    prefix = src_pkg[:4] if src_pkg.startswith("lib") else src_pkg[:1]
    return (
        f"https://changelogs.ubuntu.com/changelogs/pool/{comp}/{prefix}/"
        f"{src_pkg}/{src_pkg}_{ver_2404_current}/changelog"
    )


_TAG_URL_CACHE: dict[str, tuple[Optional[str], Optional[str], bool]] = {}  # "{lp}:{raw_ver}" → (url, tag_name, inferred)


def _resolve_upstream_tag_url(
    pkg: str,
    ver_2404: str,
    source_url: str = "",
) -> tuple[Optional[str], Optional[str], bool]:
    """
    Attempt to resolve a browse URL for the upstream tag matching Ubuntu 24.04's version.

    Returns (url, tag_name) on success, or (None, None) if no tag is found.
    Tag candidates tried: [f"v{raw_ver}", raw_ver, f"{src_pkg}-{raw_ver}"]
    Epoch prefix and Debian revision are stripped from ver_2404 before use.
    """
    lp  = _launchpad_source_pkg(pkg)
    info = _FORGE_MAP.get(lp)
    if not info or info.get("url_type") is None:
        return (None, None, False)

    # Strip epoch and Debian revision: "7:6.1.1-3ubuntu5" → "6.1.1"
    raw_ver = ver_2404.strip()
    raw_ver = re.sub(r"^\d+:", "", raw_ver)        # strip epoch
    raw_ver = re.sub(r"[+~].*$", "", raw_ver)      # strip +dfsg / ~beta
    raw_ver = re.sub(r"-.*$", "", raw_ver)          # strip Debian revision
    raw_ver = raw_ver.lstrip("v")

    cache_key = f"{lp}:{raw_ver}:{source_url or ''}"
    if cache_key in _TAG_URL_CACHE:
        return _TAG_URL_CACHE[cache_key]

    src_pkg = lp
    candidates = [f"v{raw_ver}", raw_ver, f"{src_pkg}-{raw_ver}"]
    forge_type = (info.get("forge_type") or info.get("url_type") or "generic_git").lower()

    try:
        import requests as _req
    except ImportError:
        return (None, None, False)

    host     = info["host"]
    path     = info["path"]
    token    = os.environ.get("GITHUB_TOKEN", "")

    try:
        s = _req.Session()
        s.headers["User-Agent"] = "CDSFA-Audit/1.0 (ubuntu-patch-gap)"

        for tag in candidates:
            try:
                if forge_type == "github":
                    api_url = f"https://api.github.com/repos/{path}/git/refs/tags/{tag}"
                    if token:
                        s.headers["Authorization"] = f"token {token}"
                    r = s.get(api_url, timeout=10)
                elif forge_type == "gitlab":
                    proj = urllib.parse.quote(path, safe="")
                    api_url = f"https://{host}/api/v4/projects/{proj}/repository/tags/{tag}"
                    gitlab_token = os.environ.get("GITLAB_TOKEN", "")
                    if gitlab_token:
                        s.headers["PRIVATE-TOKEN"] = gitlab_token
                    r = s.get(api_url, timeout=10)
                elif forge_type in ("cgit", "generic_git"):
                    r = None
                else:
                    continue

                if r is not None and r.status_code == 200:
                    browse_url = _build_browse_tag_url(host, path, tag, forge_type=forge_type, source_url=source_url)
                    log.debug("[tag_url] %s → %s", pkg, browse_url)
                    _TAG_URL_CACHE[cache_key] = (browse_url, tag, False)
                    return (browse_url, tag, False)
            except Exception as exc:
                log.debug("[tag_url] %s tag=%s: %s", pkg, tag, exc)
    except Exception as exc:
        log.debug("[tag_url] session error for %s: %s", pkg, exc)

    fallback_url = source_url
    if fallback_url:
        remote_tag, _, inferred = _match_remote_tag(fallback_url, candidates, raw_ver)
        if remote_tag:
            browse_url = _build_browse_tag_url(host, path, remote_tag, forge_type=forge_type, source_url=source_url)
            _TAG_URL_CACHE[cache_key] = (browse_url, remote_tag, inferred)
            return (browse_url, remote_tag, inferred)

    _TAG_URL_CACHE[cache_key] = (None, None, False)
    return (None, None, False)


def _build_verification_urls(
    pkg: str,
    commit_sha: str,
    cve_ids: list[str],
    usn_ids: list[str],
    ver_2404_current: Optional[str],
    ver_2604: str,
    commit_message: str = "",
    component: str = "unknown",
    ver_2404: str = "",
    source_url: str = "",
    diff: str = "",
) -> dict:
    lp_pkg = _launchpad_source_pkg(pkg)

    # Resolve upstream commit URL: forge map first, then detect from source_url
    _upstream_commit = _forge_commit_url(pkg, commit_sha)
    if _upstream_commit is None and source_url:
        _upstream_commit = _commit_url_from_source_link(source_url, commit_sha)

    cve_pages = (
        [
            {
                "cve_id":         cid,
                "nvd":            f"https://nvd.nist.gov/vuln/detail/{cid}",
                "ubuntu_tracker": f"https://ubuntu.com/security/{cid}",
                "debian_tracker": f"https://security-tracker.debian.org/tracker/{cid}",
                "redhat_tracker": f"https://access.redhat.com/security/cve/{cid}",
                "suse_tracker":   f"https://www.suse.com/security/cve/{cid}.html",
            }
            for cid in cve_ids
        ]
        if cve_ids else None
    )
    usn_pages = [f"https://ubuntu.com/security/notices/{uid}" for uid in usn_ids]

    keyword = next(
        (w.strip(":/(),.") for w in commit_message.split()
         if len(w.strip(":/(),.")) >= 5 and not w.upper().startswith("CVE")),
        "",
    )

    # Issue 4: changelogs.ubuntu.com URL — fall back to recorded ver_2404 when
    # Launchpad did not return the current version (ver_2404_current is None).
    changelogs_url = _changelogs_org_url(pkg, component, ver_2404_current or ver_2404)

    # Issue 6: upstream tag browse URL
    tag_url, tag_name, tag_inferred = _resolve_upstream_tag_url(pkg, ver_2404, source_url=source_url) if ver_2404 else (None, None, False)

    # ── Q1/Q2/Q3 Manual Verification URLs ──────────────────────────────────
    # Q1: Is this commit really for fixing a vulnerability?
    q1_url = _upstream_commit  # Same as upstream_commit

    # Q2: Does this vulnerable code exist in Ubuntu 24.04 (upstream version)?
    q2_url = None
    if ver_2404:
        filepath = _extract_first_filepath_from_diff(diff or "")
        if filepath:
            q2_url = _build_upstream_source_url_for_file(pkg, filepath, ver_2404)

    # Q3: Did Ubuntu 24.04 really not fix this vulnerability?
    q3_url = changelogs_url  # Ubuntu changelog URL

    return {
        "upstream_commit":      _upstream_commit,
        "cve_pages":            cve_pages,
        "usn_pages":            usn_pages,
        "ubuntu_changelog": {
            "package_overview": f"https://launchpad.net/ubuntu/+source/{lp_pkg}/+changelog",
            "noble_current":    (
                f"https://launchpad.net/ubuntu/+source/{lp_pkg}/{ver_2404_current}"
                if ver_2404_current else None
            ),
            "resolute_current": f"https://launchpad.net/ubuntu/+source/{lp_pkg}/{ver_2604}",
        },
        "ubuntu_changelog_changelogs_org": changelogs_url,
        "upstream_2404_tag_url":           tag_url,
        "_upstream_2404_tag_name":         tag_name,
        "_upstream_2404_tag_inferred":      tag_inferred,
        "debian_pkg":           f"https://tracker.debian.org/pkg/{lp_pkg}",
        "upstream_issue_search": _forge_issue_search_url(pkg, keyword) if keyword else None,
        # ── Manual verification URLs (Q1/Q2/Q3) ────────────────────────────
        "q1_upstream_commit":    q1_url,
        "q2_upstream_source":    q2_url,
        "q3_ubuntu_changelog":   q3_url,
    }



def _build_verification_hints(
    commit_sha: str,
    commit_message: str,
    cve_ids: list[str],
    diff: str,
    stage2: dict,
    patch_marker_grep_query: Optional[str],
    actually_patched: Optional[bool],
    severity: str,
) -> dict:
    # Changelog search terms: SHA + CVEs + meaningful words from commit message
    terms: list[str] = [commit_sha[:12]]
    terms.extend(cve_ids)
    _skip = {"commit", "patch", "revert", "merge", "cherry", "fixes", "fixed", "avoid",
              "using", "added", "extra", "check", "check,", "mitigate"}
    for word in commit_message.split():
        w = word.strip(":/(),.").lower()
        if len(w) >= 5 and w not in _skip and not w.startswith("cve"):
            terms.append(w)
        if len(terms) >= 5:
            break

    # Source-code markers: first substantive +/- diff lines ≥30 chars.
    # Require ≥30 chars so the marker is unique enough for Ctrl+F verification;
    # skip generic single-token lines that appear in many unrelated files.
    _GENERIC_LINE_RE = re.compile(
        r'^(return\b.*|\bNULL\b|\btrue\b|\bfalse\b|break;|continue;|goto\s+\w+;|'
        r'int\s+\w+\s*=\s*0;|size_t\s+\w+\s*=\s*0;|\s*[\d]+\s*;?)$',
        re.IGNORECASE,
    )
    _SKIP_PREFIX = ("//", "/*", "*", "#", "diff --git", "index ", "@@", "+++", "---")
    marker_after = marker_before = ""
    for line in diff.splitlines():
        if not marker_after and line.startswith("+") and not line.startswith("+++"):
            s = line[1:].strip()
            if (len(s) >= 30
                    and not any(s.startswith(p) for p in _SKIP_PREFIX)
                    and not _GENERIC_LINE_RE.match(s)):
                marker_after = s[:100]
        if not marker_before and line.startswith("-") and not line.startswith("---"):
            s = line[1:].strip()
            if (len(s) >= 30
                    and not any(s.startswith(p) for p in _SKIP_PREFIX)
                    and not _GENERIC_LINE_RE.match(s)):
                marker_before = s[:100]
        if marker_after and marker_before:
            break
    if not marker_after and patch_marker_grep_query:
        marker_after = patch_marker_grep_query

    sha12    = commit_sha[:12]
    cve_list = ", ".join(cve_ids) if cve_ids else "no CVE assigned"
    marker_q = marker_after or patch_marker_grep_query or "(see diff)"
    vuln_type = stage2.get("vulnerability_type", "")[:80]

    if actually_patched is True:
        expected = (
            f"In the Ubuntu 24.04 (Noble) source package, open debian/patches/ and find a "
            f"patch file whose '+' lines contain '{marker_q}'. "
            f"The Noble changelog should also reference commit {sha12} or {cve_list}."
        )
        disprove = (
            f"If no file in debian/patches/ contains a line beginning with '+' that matches "
            f"'{marker_q}', AND neither {sha12} nor {cve_list} appears in the Noble "
            f"changelog, then patched=true is a false positive."
        )
    elif actually_patched is False:
        expected = (
            f"In the Noble source package, debian/patches/ should contain NO file with a '+' "
            f"line matching '{marker_q}'. The {severity} vulnerability ({vuln_type}) "
            f"should be absent from the Noble changelog entirely."
        )
        disprove = (
            f"If any file in debian/patches/ (Noble security pocket) contains a '+' line "
            f"matching '{marker_q}', or if {cve_list} appears in the Noble changelog, "
            f"then unpatched=false is wrong — the vulnerability is already fixed."
        )
    else:
        expected = (
            f"Patch status is uncertain. Search the Noble changelog for '{sha12}' and "
            f"inspect debian/patches/ for '+' lines matching '{marker_q}'. "
            f"Presence confirms patched; absence confirms unpatched."
        )
        disprove = (
            f"Finding '{marker_q}' on a '+' line in any debian/patches/ file disproves "
            f"'unpatched'; finding no such occurrence disproves 'patched'."
        )

    return {
        "changelog_search_terms":                     terms[:5],
        "source_code_marker_after_patch":             marker_after or None,
        "source_code_marker_before_patch":            marker_before or None,
        "expected_evidence_if_classification_correct": expected,
        "what_would_disprove_classification":         disprove,
    }


def _sanity_check(entry: dict) -> list[str]:
    """
    Advisory warnings only — entry is always saved.
    Automatically flags the false-positive pattern: patched=true with no CVE and no USN.
    """
    flags: list[str] = []
    cve_assigned     = entry.get("cve_assigned", False)
    usn_published    = entry.get("usn_published", False)
    actually_patched = entry.get("ubuntu_2404_actually_patched")
    urls             = entry.get("verification_urls") or {}

    if not cve_assigned and urls.get("cve_pages") is not None:
        flags.append(
            "SCHEMA_VIOLATION: cve_assigned=false but verification_urls.cve_pages is not null"
        )
    if not usn_published and urls.get("usn_pages"):
        flags.append(
            "SCHEMA_VIOLATION: usn_published=false but verification_urls.usn_pages is non-empty"
        )
    if actually_patched is True and not cve_assigned and not usn_published:
        flags.append(
            "CONFIDENCE_LOW: ubuntu_2404_actually_patched=true with no CVE and no USN "
            "— high risk of false positive (marker may match an unrelated patch context line). "
            "Manual review required."
        )
    # CVE_LATE_ASSIGNED: CVE was assigned more than 180 days after upstream commit.
    days_commit_to_cve = entry.get("days_commit_to_cve")
    if days_commit_to_cve is not None and days_commit_to_cve > 180:
        flags.append(
            f"CVE_LATE_ASSIGNED: CVE assigned {days_commit_to_cve} days after upstream commit"
        )

    # UPSTREAM_TAG_NOT_FOUND: tag URL resolution attempted (forge known) but failed.
    v_urls = entry.get("verification_urls") or {}
    if v_urls.get("upstream_2404_tag_url") is None:
        lp_check = _launchpad_source_pkg(entry.get("package", ""))
        if lp_check in _FORGE_MAP:
            flags.append(
                "UPSTREAM_TAG_NOT_FOUND: could not verify upstream tag via forge API"
            )

    # POSSIBLE_BACKPORT_BY_REPORTER: reporter credit found and patch not confirmed.
    reporter_credits = entry.get("reporter_credits", [])
    if reporter_credits and entry.get("ubuntu_2404_actually_patched") is not True:
        for rc in reporter_credits:
            name = rc.get("name", "")
            flags.append(
                f"POSSIBLE_BACKPORT_BY_REPORTER: reporter '{name}' may be credited in "
                f"24.04 changelog — check for backport"
            )

    # Contamination: >3 CVEs for a single silent fix is almost certainly package-name noise.
    cve_ids = entry.get("cve_ids", [])
    if len(cve_ids) > 3:
        flags.append(
            f"CONTAMINATION_RISK: cve_ids has {len(cve_ids)} entries — a single silent fix "
            f"assigning >3 CVEs is extremely unusual; almost certainly package-level query "
            f"contamination. cve_lookup_source={entry.get('_cve_lookup_source', '?')}"
        )
    return flags


def _attach_diagnostic_flags(entry: dict) -> dict:
    """Attach pipeline-level diagnostic flags without duplicating existing prefixes."""
    flags = list(entry.get("_review_flags") or [])

    def _has_prefix(prefix: str) -> bool:
        return any(isinstance(f, str) and f.startswith(prefix) for f in flags)

    apt_ver = entry.get("ubuntu_2404_apt_version_at_check")
    apt_err = entry.get("_apt_fetch_error")
    if apt_ver is None and not _has_prefix("APT_DATA_MISSING:"):
        flags.append(f"APT_DATA_MISSING: {apt_err or 'unknown'}")

    deb_status = entry.get("debian_cve_statuses")
    if (isinstance(deb_status, dict)
            and deb_status.get("_error")
            and deb_status.get("_error") in {"timeout", "endpoint_unreachable", "unknown_exception"}
            and not _has_prefix("DEBIAN_QUERY_FAILED:")):
        flags.append(f"DEBIAN_QUERY_FAILED: {deb_status.get('_error')}")

    patch_method = str(entry.get("ubuntu_2404_patch_method") or "")
    inferred_method = patch_method.startswith("unknown_inferred_") or patch_method.endswith("_inferred_absent")
    if inferred_method and not _has_prefix("PATCH_METHOD_INFERRED:"):
        flags.append(f"PATCH_METHOD_INFERRED: {patch_method}")

    entry["_review_flags"] = flags
    return entry


def _fetch_commit_author_date_from_forge(pkg: str, sha: str) -> Optional[str]:
    """
    Query the upstream forge API for the commit's authored date (not committer/merge date).
    Returns YYYY-MM-DD, or None on failure / unknown forge.
    Reads GITHUB_TOKEN / GITLAB_TOKEN from environment when present.
    """
    lp   = _launchpad_source_pkg(pkg)
    info = _FORGE_MAP.get(lp)
    if not info or info.get("url_type") is None:
        return None

    _date_key = f"{lp}:{sha[:12]}"
    if _date_key in _FORGE_DATE_CACHE:
        log.debug("[cache] forge_date HIT %s", _date_key)
        return _FORGE_DATE_CACHE[_date_key]

    try:
        import requests as _req
    except ImportError:
        return None
    try:
        s = _req.Session()
        s.headers["User-Agent"] = "CDSFA-Audit/1.0 (ubuntu-patch-gap)"
        if info["url_type"] == "github":
            url   = f"https://api.github.com/repos/{info['path']}/commits/{sha}"
            token = os.environ.get("GITHUB_TOKEN", "")
            if token:
                s.headers["Authorization"] = f"token {token}"
            r = s.get(url, timeout=15)
            if not r.ok:
                log.warning("[forge_api] GitHub %s %s: HTTP %s", lp, sha[:12], r.status_code)
                _FORGE_DATE_CACHE[_date_key] = None
                return None
            raw = (r.json().get("commit", {}).get("author", {}).get("date") or "")
            result = raw[:10] or None
            _FORGE_DATE_CACHE[_date_key] = result
            return result
        elif info["url_type"] == "gitlab":
            proj  = urllib.parse.quote(info["path"], safe="")
            url   = f"https://{info['host']}/api/v4/projects/{proj}/repository/commits/{sha}"
            token = os.environ.get("GITLAB_TOKEN", "")
            if token:
                s.headers["PRIVATE-TOKEN"] = token
            r = s.get(url, timeout=15)
            if not r.ok:
                log.warning("[forge_api] GitLab %s %s: HTTP %s", lp, sha[:12], r.status_code)
                _FORGE_DATE_CACHE[_date_key] = None
                return None
            raw = (r.json().get("authored_date") or "")
            result = raw[:10] or None
            _FORGE_DATE_CACHE[_date_key] = result
            return result
    except Exception as exc:
        log.debug("[forge_api] %s/%s: %s", pkg, sha[:12], exc)
        _FORGE_DATE_CACHE[_date_key] = None
        return None


def _get_commit_author_date(repo, pkg: str, sha: str) -> str:
    """
    Return the upstream-authored date (YYYY-MM-DD) for a commit.
    Priority: forge API (authoritative for authored vs committer date)
              → local git authored_datetime
              → local git committed_datetime (last resort; may be tag/release date)
    """
    api_date = _fetch_commit_author_date_from_forge(pkg, sha)
    if api_date:
        log.debug("[commit_date] forge API → %s for %s", api_date, sha[:12])
        return api_date
    try:
        return repo.commit(sha).authored_datetime.strftime("%Y-%m-%d")
    except Exception:
        pass
    try:
        return repo.commit(sha).committed_datetime.strftime("%Y-%m-%d")
    except Exception:
        return ""


# Trigger words are case-insensitive; name capture is strict (requires Title Case).
# Split into two patterns so IGNORECASE applies only to triggers.
_REPORTER_TRIGGER_RE = re.compile(
    r'(?:Thanks to|Reported by|Found by|Discovered by|Credit to|Reporter:)\s+',
    re.IGNORECASE,
)
_REPORTER_NAME_RE = re.compile(
    r'^([A-Z][a-zA-Z\'-]+(?:\s+[A-Z][a-zA-Z\'-]+){0,3})'
    r'(?:\s+(?:from|of|at)\s+'
    r'([A-Z][a-zA-Z\s]+?(?:University|Lab|Inc|Ltd|Corp|Institute)))?'
    r'(?:\s|$|[,.])',
)


def _extract_reporter_credits(text: str) -> list[dict]:
    """Extract reporter/discoverer credits from commit message or PR body."""
    results = []
    seen: set[str] = set()
    for trigger in _REPORTER_TRIGGER_RE.finditer(text):
        rest = text[trigger.end():]
        nm   = _REPORTER_NAME_RE.match(rest)
        if not nm:
            continue
        name        = nm.group(1).strip()
        affiliation = (nm.group(2) or "").strip() or None
        if name and name not in seen:
            seen.add(name)
            results.append({"name": name, "affiliation": affiliation})
    return results


def _preflight_validate_packages(pkg_names: list[str]) -> None:
    """Fail fast if any user-specified package cannot be resolved in the Noble pocket."""
    failures: list[str] = []
    seen: set[str] = set()
    for pkg in pkg_names:
        if not pkg or pkg in seen:
            continue
        seen.add(pkg)
        source_pkg = resolve_source_package_name(pkg)
        component = get_ubuntu_component(pkg)
        if component == "unknown":
            failures.append(f"{pkg} → source={source_pkg} (no Noble pocket entry)")
    if failures:
        raise RuntimeError("Noble pocket validation failed for: " + "; ".join(failures))


def _resolve_merge_commit_pr(
    commit_message: str,
    repo_url: str,
) -> tuple[Optional[str], Optional[str]]:
    """
    If the commit message is a GitHub merge-commit ("Merge pull request #NNN …"),
    fetch the PR title and body from the GitHub API and return a combined string
    plus the PR's HTML URL.

    Returns (pr_content, pr_url) on success, or (None, None) on failure.
    Sets MERGE_COMMIT_UNRESOLVED flag in the caller when None is returned.
    """
    m = re.match(r'^Merge pull request #(\d+)', commit_message, re.IGNORECASE)
    if not m:
        return (None, None)
    pr_number = m.group(1)

    # Only handle github.com repos
    gh_m = re.search(r'github\.com[/:]([^/]+)/([^/.\s]+?)(?:\.git)?$', repo_url)
    if not gh_m:
        return (None, None)
    owner, repo = gh_m.group(1), gh_m.group(2)

    _pr_key = f"github/{owner}/{repo}/{pr_number}"
    if _pr_key in _MERGE_PR_CACHE:
        log.debug("[cache] merge_pr HIT %s", _pr_key)
        return _MERGE_PR_CACHE[_pr_key]

    try:
        import requests as _req
    except ImportError:
        log.debug("[merge_pr] requests not available")
        return (None, None)

    try:
        s = _req.Session()
        s.headers["User-Agent"] = "CDSFA-Audit/1.0 (ubuntu-patch-gap)"
        token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            s.headers["Authorization"] = f"token {token}"
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
        r = s.get(api_url, timeout=15)
        if not r.ok:
            log.warning("[merge_pr] GitHub API %s: HTTP %s", api_url, r.status_code)
            _MERGE_PR_CACHE[_pr_key] = (None, None)
            return (None, None)
        data        = r.json()
        title       = data.get("title", "")
        body        = data.get("body", "") or ""
        pr_html_url = data.get("html_url", "")
        pr_content  = f"PR #{pr_number}: {title}\n\n{body}"
        _MERGE_PR_CACHE[_pr_key] = (pr_content, pr_html_url)
        return (pr_content, pr_html_url)
    except Exception as exc:
        log.warning("[merge_pr] failed to fetch PR #%s for %s/%s: %s", pr_number, owner, repo, exc)
        _MERGE_PR_CACHE[_pr_key] = (None, None)
        return (None, None)


def _make_report_entry(
    pkg: str,
    ver_2404: str,
    ver_2604: str,
    commit: dict,
    stage2: dict,
    *,
    repo_component: str = "unknown",
    silent_at_commit_time: bool = True,
    resolute_inheritance_mode: str = "Natural_Import",
    cve_data: dict | None = None,
    patch_status: dict | None = None,
    commit_date: str = "",
    resolute_evidence: str = "",
    source_url: str = "",
) -> dict:
    stage1       = commit.get("stage1", {})
    priority     = stage1.get("canonical_priority", "Unknown")
    cve_data     = cve_data or {}
    patch_st     = patch_status or {}
    cve_assigned = cve_data.get("cve_assigned", False)
    gap_type     = _maintenance_gap_type(silent_at_commit_time, cve_assigned, priority)
    feasibility  = stage2.get("backport_feasibility") or stage2.get("backport_difficulty", "unknown")

    # ── Time dimension calculations ──────────────────────────────────────────
    cve_date_str = cve_data.get("cve_assignment_date")
    usn_date_str = cve_data.get("usn_first_date")

    def _days(start: Optional[str], end: Optional[str]) -> Optional[int]:
        if not start or not end:
            return None
        try:
            return (_date.fromisoformat(end[:10]) - _date.fromisoformat(start[:10])).days
        except ValueError:
            return None

    days_commit_to_cve = _days(commit_date, cve_date_str)
    days_commit_to_usn = _days(commit_date, usn_date_str)
    days_cve_to_usn    = _days(cve_date_str, usn_date_str)
    # CVE cannot predate its upstream commit; negative means the CVE date is from
    # a package-level record rather than this commit → treat as lookup error.
    if days_commit_to_cve is not None and days_commit_to_cve < 0:
        days_commit_to_cve = None
    if days_commit_to_usn is not None and days_commit_to_usn < 0:
        days_commit_to_usn = None
    actually_patched   = patch_st.get("ubuntu_2404_actually_patched")
    days_commit_to_now_unfixed = (
        (_date.today() - _date.fromisoformat(commit_date)).days
        if commit_date and actually_patched is False
        else None
    )

    # ── Build verification data before assembling entry ───────────────────────
    _v_urls = _build_verification_urls(
        pkg              = pkg,
        commit_sha       = commit.get("sha", ""),
        cve_ids          = cve_data.get("cve_ids", []),
        usn_ids          = cve_data.get("usn_ids", []),
        ver_2404_current = patch_st.get("ubuntu_2404_current_version"),
        ver_2604         = ver_2604,
        commit_message   = commit.get("message", "").splitlines()[0][:200],
        component        = repo_component,
        ver_2404         = ver_2404,
        source_url       = source_url,
        diff             = commit.get("diff", ""),
    )
    _v_hints = _build_verification_hints(
        commit_sha              = commit.get("sha", ""),
        commit_message          = commit.get("message", "").splitlines()[0][:200],
        cve_ids                 = cve_data.get("cve_ids", []),
        diff                    = commit.get("diff", "")[:3000],
        stage2                  = stage2,
        patch_marker_grep_query = patch_st.get("patch_marker_grep_query"),
        actually_patched        = patch_st.get("ubuntu_2404_actually_patched"),
        severity                = stage2.get("severity", "INFORMATIONAL"),
    )

    # ── Issue 7: reporter credits ─────────────────────────────────────────────
    _commit_msg_full  = commit.get("message", "")
    _resolved_pr_body = commit.get("_resolved_pr_body", "")
    reporter_credits  = _extract_reporter_credits(_commit_msg_full + "\n" + _resolved_pr_body)

    entry = {
        # ── Core identification ──────────────────────────────────────────────
        "package":               pkg,
        "ubuntu_2404_version":   ver_2404,
        "ubuntu_2604_version":   ver_2604,
        "commit_sha":            commit.get("sha", ""),
        "commit_message":        commit.get("message", "").splitlines()[0][:120],
        # ── CDSFA classification ─────────────────────────────────────────────
        "silent_at_commit_time":          silent_at_commit_time,
        "canonical_priority_predicted":   priority,
        "ubuntu_component":               repo_component,
        "resolute_inheritance_mode":      resolute_inheritance_mode,
        "maintenance_gap_type":           gap_type,
        # ── External CVE cross-check (ground truth) ──────────────────────────
        "cve_assigned":           cve_assigned,
        "cve_ids":                cve_data.get("cve_ids", []),
        "cve_assignment_date":    cve_date_str,
        "usn_published":          cve_data.get("usn_published", False),
        "usn_ids":                cve_data.get("usn_ids", []),
        # ── Ubuntu 24.04 patch status (ground truth) ─────────────────────────
        "ubuntu_2404_actually_patched":  actually_patched,
        "ubuntu_2404_patch_method":      patch_st.get("ubuntu_2404_patch_method", "unknown"),
        "ubuntu_2404_current_version":   patch_st.get("ubuntu_2404_current_version"),
        "_patch_status":                 patch_st.get("_status", "ok"),
        # ── Vulnerability assessment ─────────────────────────────────────────
        "vuln_confirmed":           stage2.get("vuln_confirmed_in_2404", False),
        "severity":                 stage2.get("severity", "INFORMATIONAL"),
        "vulnerability_type":       stage2.get("vulnerability_type", ""),
        "poc_sketch":               stage2.get("poc_sketch", ""),
        "poc_reproduction_steps":   stage2.get("poc_reproduction_steps", []),
        # ── Backport analysis ────────────────────────────────────────────────
        "backport_feasibility":  feasibility,
        "backport_difficulty":   stage2.get("backport_difficulty", ""),
        "backport_notes":        stage2.get("backport_notes", ""),
        "logical_survival":      stage2.get("logical_survival", ""),
        # ── Stage 1 metadata ─────────────────────────────────────────────────
        "stage1_vuln_class":     stage1.get("vuln_class", ""),
        "stage1_confidence":     stage1.get("confidence", ""),
        "stage1_affected_funcs": stage1.get("affected_functions", []),
        # ── Time dimension (SLA / exposure window) ───────────────────────────
        "upstream_commit_date":         commit_date,
        "days_commit_to_cve":           days_commit_to_cve,
        "days_cve_to_usn":              days_cve_to_usn,
        "days_commit_to_usn":           days_commit_to_usn,
        "days_commit_to_now_unfixed":   days_commit_to_now_unfixed,
        # ── Provenance & reproducibility ─────────────────────────────────────
        "verification_timestamp":            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ubuntu_2404_apt_version_at_check":  patch_st.get("ubuntu_2404_current_version"),
        "patch_marker_grep_query":           patch_st.get("patch_marker_grep_query"),
        "patch_marker_found":                patch_st.get("patch_marker_found"),
        "_marker_quality":                   patch_st.get("_marker_quality"),
        "_apt_fetch_error":                  patch_st.get("_apt_fetch_error"),
        # ── Cross-distro comparison ──────────────────────────────────────────
        "debian_cve_statuses":          cve_data.get("debian_cve_statuses", {}),
        "_debian_query_attempted":      cve_data.get("_debian_query_attempted", False),
        # ── 26.04 evidence ───────────────────────────────────────────────────
        "ubuntu_2604_evidence":         resolute_evidence,
        # ── Debug / provenance ───────────────────────────────────────────────
        "_cot_rationale":            stage2.get("cot_rationale", ""),
        "_cve_lookup_source":        cve_data.get("_cve_lookup_source", ""),
        "_apt_source_method":        patch_st.get("_apt_source_method", ""),
        "_backend":                  f"zai/{cfg.ZAI_MODEL}",
        # ── Reporter credits (Issue 7) ────────────────────────────────────────
        "reporter_credits":          reporter_credits,
        # ── Resolved PR URL (Issue 8) ─────────────────────────────────────────
        "_resolved_pr_url":          commit.get("_resolved_pr_url"),
        # ── API errors encountered during enrichment ──────────────────────────
        "_errors":                   (cve_data.get("_errors") or []) + (stage2.get("_errors") or []) + (patch_st.get("_errors") or []),
        # ── Verification URLs (browser-navigable, built from existing fields) ──
        "verification_urls":  _v_urls,
        # ── Verification hints (Ctrl+F terms & evidence statements) ───────────
        "verification_hints": _v_hints,
    }

    review_flags = _sanity_check(entry)

    # Propagate MARKER_POST_FIX_ONLY from apt check (Issue 3 / Issue 8)
    for _apt_flag in patch_st.get("_apt_review_flags", []):
        if "MARKER_POST_FIX_ONLY" in _apt_flag and "MARKER_POST_FIX_ONLY" not in review_flags:
            review_flags.append("MARKER_POST_FIX_ONLY")
            break

    # Propagate MERGE_COMMIT_UNRESOLVED from commit level (Issue 7 / Issue 8)
    if "MERGE_COMMIT_UNRESOLVED" in commit.get("_review_flags", []) \
            and "MERGE_COMMIT_UNRESOLVED" not in review_flags:
        review_flags.append("MERGE_COMMIT_UNRESOLVED")

    for flag in review_flags:
        log.warning("[SanityCheck] %s  %s → %s", pkg, commit.get("sha", "")[:12], flag)
    entry["_review_flags"] = review_flags
    return _attach_diagnostic_flags(entry)


def _load_report() -> list:
    if _REPORT_FILE.exists():
        try:
            return json.loads(_REPORT_FILE.read_text())
        except json.JSONDecodeError:
            return []
    return []


def _save_report_csv(entries: list, append: bool = True) -> None:
    _REPORT_CSV_FILE.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "package",
        "commit_sha",
        "ubuntu_2404_version",
        "ubuntu_2604_version",
        "ubuntu_2404_apt_version_at_check",
        "_apt_fetch_error",
        "ubuntu_component",
        "ubuntu_2404_patch_method",
        "patch_marker_found",
        "_marker_quality",
        "_debian_query_attempted",
        "debian_cve_statuses",
        "cve_assigned",
        "cve_ids",
        "usn_published",
        "usn_ids",
        "ubuntu_2404_actually_patched",
        "vuln_confirmed",
        "severity",
        "poc_sketch",
        "poc_reproduction_steps",
        "backport_feasibility",
        "maintenance_gap_type",
        "_review_flags",
    ]
    # Extra flattened URL columns from entry['verification_urls'] for easy CSV access
    url_fields = [
        "upstream_commit",
        "upstream_2404_tag_url",
        "ubuntu_changelog_changelogs_org",
        "ubuntu_changelog_package_overview",
        "first_cve_page",
        "first_usn_page",
        "upstream_issue_search",
        "q1_upstream_commit",
        "q2_upstream_source",
        "q3_ubuntu_changelog",
    ]
    fieldnames.extend(url_fields)
    write_header = not append or not _REPORT_CSV_FILE.exists() or _REPORT_CSV_FILE.stat().st_size == 0
    mode = "a" if append else "w"
    with _REPORT_CSV_FILE.open(mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        for entry in entries:
            row = {}
            for key in fieldnames:
                # Primary: direct entry fields
                if key not in (
                    "upstream_commit",
                    "upstream_2404_tag_url",
                    "ubuntu_changelog_changelogs_org",
                    "ubuntu_changelog_package_overview",
                    "first_cve_page",
                    "first_usn_page",
                    "upstream_issue_search",
                    "q1_upstream_commit",
                    "q2_upstream_source",
                    "q3_ubuntu_changelog",
                ):
                    value = entry.get(key)
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value, ensure_ascii=False)
                    elif value is None:
                        row[key] = ""
                    else:
                        row[key] = value
                    continue

                # Secondary: flattened URL fields from verification_urls
                vurls = entry.get("verification_urls") or {}
                if key == "upstream_commit":
                    row[key] = vurls.get("upstream_commit") or ""
                elif key == "upstream_2404_tag_url":
                    row[key] = vurls.get("upstream_2404_tag_url") or ""
                elif key == "ubuntu_changelog_changelogs_org":
                    row[key] = vurls.get("ubuntu_changelog_changelogs_org") or ""
                elif key == "ubuntu_changelog_package_overview":
                    ucb = vurls.get("ubuntu_changelog") or {}
                    row[key] = ucb.get("package_overview") or ""
                elif key == "first_cve_page":
                    cves = vurls.get("cve_pages") or []
                    if isinstance(cves, list) and cves:
                        first = cves[0]
                        if isinstance(first, dict):
                            row[key] = first.get("nvd") or first.get("cve_id") or ""
                        else:
                            row[key] = str(first)
                    else:
                        row[key] = ""
                elif key == "first_usn_page":
                    usns = vurls.get("usn_pages") or []
                    row[key] = usns[0] if isinstance(usns, list) and usns else ""
                elif key == "upstream_issue_search":
                    row[key] = vurls.get("upstream_issue_search") or ""
                elif key == "q1_upstream_commit":
                    row[key] = vurls.get("q1_upstream_commit") or ""
                elif key == "q2_upstream_source":
                    row[key] = vurls.get("q2_upstream_source") or ""
                elif key == "q3_ubuntu_changelog":
                    row[key] = vurls.get("q3_ubuntu_changelog") or ""
            writer.writerow(row)


def _save_report(entries: list, csv_entries: list | None = None) -> None:
    _REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _REPORT_FILE.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    log.info("[Report] Saved %d entries → %s", len(entries), _REPORT_FILE)
    _save_report_csv(csv_entries if csv_entries is not None else entries, append=True)


def print_summary(entries: list) -> None:
    confirmed = [e for e in entries if e.get("vuln_confirmed")]
    print(f"\n{'═'*70}")
    print(f"  Patch Gap Report  —  Ubuntu 24.04 vs 26.04")
    print(f"  Total entries: {len(entries)}   Confirmed vulnerabilities: {len(confirmed)}")
    print(f"{'═'*70}")
    for e in confirmed:
        print(f"\n  Package  : {e['package']}  ({e['ubuntu_2404_version']} → {e['ubuntu_2604_version']})")
        print(f"  Component: {e.get('ubuntu_component', 'unknown')}   "
              f"Gap type: {e.get('maintenance_gap_type', '?')}   "
              f"Silent@commit: {e.get('silent_at_commit_time', '?')}   "
              f"CVE assigned: {e.get('cve_assigned', '?')}")
        print(f"  Commit   : {e['commit_sha'][:12]}  {e['commit_message'][:60]}")
        print(f"  Priority : {e.get('canonical_priority_predicted', '?')}   "
              f"Severity: {e['severity']}   "
              f"Backport: {e.get('backport_feasibility', e.get('backport_difficulty', '?'))}")
        print(f"  Inherit  : {e.get('resolute_inheritance_mode', '?')}")
        cve_ids = ", ".join(e.get("cve_ids", [])) or "none"
        usn_ids = ", ".join(e.get("usn_ids", [])) or "none"
        print(f"  CVEs     : {cve_ids}   (assigned {e.get('cve_assignment_date') or '?'})")
        print(f"  USNs     : {usn_ids}")
        print(f"  24.04 fix: patched={e.get('ubuntu_2404_actually_patched')}  "
              f"method={e.get('ubuntu_2404_patch_method', '?')}")
        print(f"  Type     : {e['vulnerability_type']}")
        print(f"  Survival : {e.get('logical_survival', '')[:100]}")
        print(f"  PoC      : {e['poc_sketch'][:100]}")
    if not confirmed:
        print("\n  No confirmed vulnerabilities in this run.")
    print(f"{'═'*70}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Pipeline entry point
# ══════════════════════════════════════════════════════════════════════════════

def run_single(pkg_name: str) -> list[dict]:
    """Run the full 5-step pipeline for one package."""
    log.info("═" * 60)
    log.info("  Target: %s  [backend: zai/%s]", pkg_name, cfg.ZAI_MODEL)
    log.info("═" * 60)

    # ── Step 1: Resolve versions and repo URL ────────────────────────────────
    pkgs_2404 = _load_pkg_versions(_UBUNTU_2404_DETAIL)
    pkgs_2604 = _load_pkg_versions(_UBUNTU_2604_DETAIL)

    # Handle package name variants (e.g., libxml2 → libxml2-16 in 26.04)
    pkg_2404_name, pkg_2604_name = _find_package_in_dicts(pkg_name, pkgs_2404, pkgs_2604)
    
    if not pkg_2404_name or not pkg_2604_name:
        log.warning("[Step1] %s not found in both 24.04 and 26.04 data", pkg_name)
        return []
    
    ver_2404 = pkgs_2404[pkg_2404_name]
    ver_2604 = pkgs_2604[pkg_2604_name]

    try:
        if not (Version(_normalize_ver(ver_2604)) > Version(_normalize_ver(ver_2404))):
            log.info("[Step1] No version gap for %s (%s vs %s)", pkg_name, ver_2404, ver_2604)
            return []
    except InvalidVersion:
        pass

    log.info("[Step1] %s  24.04=%s  26.04=%s", pkg_name, ver_2404, ver_2604)

    source_pkg = resolve_source_package_name(pkg_name)
    candidates = []
    for name in (pkg_name, pkg_2404_name, pkg_2604_name, source_pkg,
                 resolve_source_package_name(pkg_2404_name),
                 resolve_source_package_name(pkg_2604_name)):
        if name and name not in candidates:
            candidates.append(name)

    repo_url = ""
    for candidate in candidates:
        repo_url = KNOWN_UPSTREAM_REPOS.get(candidate, "")
        if repo_url:
            break
    if not repo_url:
        for candidate in candidates:
            gap = find_gap(candidate)
            repo_url = gap.get("repo_url", "")
            if repo_url:
                break
    if not repo_url:
        for candidate in candidates:
            repo_url = _forge_repo_url(candidate) or ""
            if repo_url:
                log.info("[Step1] Fallback repo from forge map: %s → %s", candidate, repo_url)
                break
    if not repo_url:
        log.warning("[Step1] No upstream repo URL for %s", pkg_name)
        return []

    # ── Step 2: Harvest commits from the version gap ─────────────────────────
    log.info("[Step2] Harvesting commits: %s → %s  (%s)",
             _normalize_ver(ver_2404), _normalize_ver(ver_2604), repo_url)
    try:
        commits = harvest(repo_url, _normalize_ver(ver_2404), _normalize_ver(ver_2604))
    except Exception as exc:
        log.error("[Step2] harvest failed: %s", exc)
        return []

    if not commits:
        log.info("[Step2] No security-relevant commits found for %s", pkg_name)
        return []

    log.info("[Step2] %d candidate commits after regex filter", len(commits))

    # ── Issue 8: Merge commit PR resolution ──────────────────────────────────
    # Before Stage 1, resolve merge-commit messages to their PR title/body.
    # This gives the GLM richer context for filtering.
    for commit in commits:
        msg = commit.get("message", "")
        if re.match(r'^Merge pull request #\d+', msg, re.IGNORECASE):
            pr_content, pr_url = _resolve_merge_commit_pr(msg, repo_url)
            if pr_content:
                commit["message"]          = pr_content + "\n\n---\n" + msg
                commit["_resolved_pr_url"] = pr_url
                commit["_resolved_pr_body"] = pr_content
                log.info("[MergePR] resolved PR for SHA=%s → %s",
                         commit.get("sha", "")[:12], pr_url)
            else:
                flags = commit.setdefault("_review_flags", [])
                if "MERGE_COMMIT_UNRESOLVED" not in flags:
                    flags.append("MERGE_COMMIT_UNRESOLVED")
                log.debug("[MergePR] could not resolve PR for SHA=%s",
                          commit.get("sha", "")[:12])

    # ── Step 3: GLM Stage 1 — no-CVE memory/logic vulnerability filter ───────
    log.info("[Step3] GLM Stage 1 filtering %d commits …", len(commits))
    client   = _build_client()
    filtered = glm_stage1_filter(pkg_name, ver_2404, ver_2604, commits, client)

    if not filtered:
        log.info("[Step3] No commits passed Stage 1 filter for %s", pkg_name)
        return []

    filtered = filtered[:_MAX_COMMITS_STAGE2]
    log.info("[Step3] %d commits proceed to Stage 2 audit", len(filtered))

    # ── Step 4: Source Analysis + GLM Stage 2 ────────────────────────────────
    clean_url, _ = _normalize_repo_url(repo_url)
    local = _local_dir(clean_url)
    try:
        repo = _clone_or_update(clean_url, local)
    except Exception as exc:
        log.error("[Step4] Cannot open repo %s: %s", local, exc)
        return []

    start_tag      = _find_tag_fuzzy(repo, _normalize_ver(ver_2404), label="2404")
    start_tag_name = start_tag.name if start_tag else _normalize_ver(ver_2404)
    end_tag        = _find_tag_fuzzy(repo, _normalize_ver(ver_2604), label="2604")
    end_tag_name   = end_tag.name if end_tag else _normalize_ver(ver_2604)

    # Repository component classification (Main vs Universe) via Launchpad API.
    # main → ESM Infra; universe → ESM Apps (paid).
    repo_component = get_ubuntu_component(pkg_name)
    log.info("[Step4] %s → ubuntu component: %s", pkg_name, repo_component)

    entries: list[dict] = []
    for i, commit in enumerate(filtered, 1):
        sha8 = commit.get("short_sha", commit.get("sha", "")[:8])
        log.info("[Step4] [%d/%d] Source analysis + Stage 2 audit  SHA=%s",
                 i, len(filtered), sha8)

        source_2404 = extract_source_analysis(repo, start_tag_name, commit)
        stage2      = glm_stage2_audit(pkg_name, ver_2404, ver_2604,
                                       commit, source_2404, client)
        commit["stage2"] = stage2

        # ── CDSFA enrichment: origin + commit-time silence flag ─────────────
        commit_sha_full   = commit.get("sha", "")
        silent_at_commit  = not _has_cve(commit.get("message", ""))
        inherit_mode      = _determine_inheritance_mode(repo, commit_sha_full, end_tag_name)
        commit_date       = _get_commit_author_date(repo, pkg_name, commit_sha_full)
        resolute_evidence = _get_resolute_evidence(repo, commit_sha_full, end_tag_name, inherit_mode)
        log.info("[Step4] SHA=%s  silent_at_commit=%s  inheritance=%s  component=%s  date=%s",
                 sha8, silent_at_commit, inherit_mode, repo_component, commit_date)

        # ── Step 5: External CVE cross-check ─────────────────────────────────
        affected_funcs  = commit.get("stage1", {}).get("affected_functions", [])
        candidate_urls  = _build_candidate_commit_urls(pkg_name, commit_sha_full)
        log.info("[Step5] SHA=%s  NVD reverse-lookup  candidate_urls=%s",
                 sha8, candidate_urls)
        cve_data = lookup_cve_for_commit(
            pkg_name, commit_sha_full,
            commit.get("message", ""),
            affected_funcs,
            candidate_urls,
        )
        log.info("[Step5] SHA=%s  cve_assigned=%s  cve_ids=%s  usn_ids=%s",
                 sha8, cve_data["cve_assigned"], cve_data["cve_ids"], cve_data["usn_ids"])

        # ── Step 6: Ubuntu 24.04 patch status (Launchpad / Docker) ───────────
        log.info("[Step6] SHA=%s  checking Ubuntu 24.04 patch status …", sha8)
        patch_status_data = check_ubuntu_patch_status(
            pkg_name, ver_2404, cve_data["cve_ids"]
        )
        # Also run apt-source check (Docker or Launchpad fallback)
        apt_check = check_apt_source(pkg_name, commit_sha_full, ver_2404, commit.get("diff", ""))
        if apt_check.get("_status") == "skipped_due_to_apt_failure":
            patch_status_data.update({
                "ubuntu_2404_actually_patched": None,
                "ubuntu_2404_patch_method": None,
                "ubuntu_2404_current_version": None,
                "_apt_source_method": apt_check.get("_apt_source_method", ""),
                "_apt_fetch_error": apt_check.get("_apt_fetch_error"),
                "_status": "skipped_due_to_apt_failure",
            })
        else:
            # Merge apt-source result with tracker result:
            # • apt_check True  → always overrides (source-level confirmation wins)
            # • apt_check False → only overrides when CVE tracker hasn't already confirmed True;
            #   a strict marker threshold may miss a confirmed patch, so we don't let a
            #   False clobber an authoritative "released" verdict from the Ubuntu CVE tracker.
            # • Provenance fields are always propagated regardless of verdict.
            apt_patched      = apt_check.get("ubuntu_2404_actually_patched")
            existing_patched = patch_status_data.get("ubuntu_2404_actually_patched")
            if apt_patched is True or (apt_patched is False and existing_patched is not True):
                patch_status_data.update({
                    k: v for k, v in apt_check.items()
                    if k in ("ubuntu_2404_actually_patched",
                             "ubuntu_2404_patch_method",
                             "ubuntu_2404_current_version",
                             "_apt_source_method")
                })
            for prov_key in ("patch_marker_grep_query", "patch_marker_found", "_marker_quality", "_apt_fetch_error"):
                if prov_key in apt_check:
                    patch_status_data[prov_key] = apt_check[prov_key]
            # Propagate any MARKER_POST_FIX_ONLY flags from the apt_source check.
            for flag in apt_check.get("_review_flags", []):
                patch_status_data.setdefault("_apt_review_flags", []).append(flag)

        log.info("[Step6] SHA=%s  actually_patched=%s  method=%s",
                 sha8,
                 patch_status_data.get("ubuntu_2404_actually_patched"),
                 patch_status_data.get("ubuntu_2404_patch_method"))

        entry = _make_report_entry(
            pkg_name, ver_2404, ver_2604, commit, stage2,
            repo_component=repo_component,
            silent_at_commit_time=silent_at_commit,
            resolute_inheritance_mode=inherit_mode,
            cve_data=cve_data,
            patch_status=patch_status_data,
            commit_date=commit_date,
            resolute_evidence=resolute_evidence,
            source_url=repo_url,
        )
        entries.append(entry)

        if stage2.get("vuln_confirmed_in_2404"):
            log.info("[Step4] SHA=%s → CONFIRMED in 24.04  severity=%s  backport=%s  gap=%s",
                     sha8, stage2.get("severity"), stage2.get("backport_feasibility"),
                     entry["maintenance_gap_type"])
        else:
            log.info("[Step4] SHA=%s → not confirmed in 24.04", sha8)

    # ── Cross-commit CVE deduplication check ─────────────────────────────────
    # Identical non-empty cve_ids across different commits of the same package
    # almost always means the CVEs were pulled at package level, not commit level.
    if len(entries) > 1:
        fingerprint_to_entries: dict[frozenset, list[dict]] = {}
        for e in entries:
            ids = frozenset(e.get("cve_ids", []))
            if ids:
                fingerprint_to_entries.setdefault(ids, []).append(e)
        for ids_set, group in fingerprint_to_entries.items():
            if len(group) > 1:
                shas = [e.get("commit_sha", "")[:12] for e in group]
                msg = (
                    f"CONTAMINATION_RISK: identical cve_ids {sorted(ids_set)} shared by "
                    f"{len(shas)} commits ({', '.join(shas)}) — "
                    f"CVEs were almost certainly fetched at package level, not per-commit."
                )
                log.warning("[SanityCheck] %s  %s", pkg_name, msg)
                for e in group:
                    e.setdefault("_review_flags", []).append(msg)

    log.info("[Step4] %d report entries for %s", len(entries), pkg_name)
    return entries


def run_package_list(pkg_names: list[str]) -> None:
    """Run pipeline for each package, saving incrementally."""
    _preflight_validate_packages(pkg_names)
    all_entries = _load_report()
    done_keys   = {(e["package"], e["commit_sha"]) for e in all_entries}

    for pkg in pkg_names:
        log.info("[Main] Processing: %s", pkg)
        try:
            new_entries = run_single(pkg)
        except Exception as exc:
            log.error("[Main] %s pipeline error: %s", pkg, exc, exc_info=True)
            continue

        added_entries: list[dict] = []
        for e in new_entries:
            key = (e["package"], e["commit_sha"])
            if key not in done_keys:
                all_entries.append(e)
                done_keys.add(key)
            added_entries.append(e)

        _save_report(all_entries, csv_entries=added_entries)
        log.info("[Main] %s: %d new entries added", pkg, len(added_entries))


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ubuntu 24.04 vs 26.04 Patch Gap Analyzer (GLM edition)"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--package", "-p", metavar="PKG",
                      help="Single package, e.g.: libxml2")
    mode.add_argument("--file", "-f", metavar="FILE",
                      help="File with one package name per line")
    mode.add_argument("--auto", "-a", action="store_true",
                      help="Auto-scan all packages with known repos and a version gap")
    parser.add_argument("--top", "-n", type=int, default=None,
                        help="In --auto mode, limit to the first N packages")
    args = parser.parse_args()

    if args.package:
        try:
            _preflight_validate_packages([args.package])
            entries  = run_single(args.package)
            existing = _load_report()
            done_keys = {(e["package"], e["commit_sha"]) for e in existing}
            new = [e for e in entries if (e["package"], e["commit_sha"]) not in done_keys]
            _save_report(existing + new, csv_entries=new)
            print_summary(new or entries)
        except RuntimeError as exc:
            log.error("[Main] %s", exc)
            sys.exit(1)

    elif args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            log.error("File not found: %s", fpath)
            sys.exit(1)
        pkgs = [ln.strip() for ln in fpath.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")]
        log.info("[Main] Loaded %d packages from %s", len(pkgs), fpath)
        try:
            run_package_list(pkgs)
            print_summary(_load_report())
        except RuntimeError as exc:
            log.error("[Main] %s", exc)
            sys.exit(1)

    else:  # --auto
        gaps = find_version_gaps()
        if args.top:
            gaps = gaps[:args.top]
        try:
            run_package_list([g["package"] for g in gaps])
            print_summary(_load_report())
        except RuntimeError as exc:
            log.error("[Main] %s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()

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
import json
import logging
import re
import sys
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

_MAX_COMMITS_STAGE1 = 20   # max commits sent to Stage 1 GLM filter
_MAX_COMMITS_STAGE2 = 5    # max commits sent to Stage 2 deep audit


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
  "brief_reason": "one-sentence rationale"
}}"""


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
    "whether the vulnerability still exists in 24.04 and assess backport difficulty. "
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

Respond with this JSON only:
{{
  "vuln_confirmed_in_2404": true,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
  "vulnerability_type": "one-line description",
  "poc_sketch": "brief attack scenario",
  "backport_difficulty": "trivial|easy|moderate|hard|infeasible",
  "backport_notes": "key obstacles or prerequisites for backporting",
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
        "vuln_confirmed_in_2404": False,
        "severity":               "INFORMATIONAL",
        "vulnerability_type":     "None",
        "poc_sketch":             "",
        "backport_difficulty":    "unknown",
        "backport_notes":         "",
        "cot_rationale":          "",
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

def _make_report_entry(
    pkg: str,
    ver_2404: str,
    ver_2604: str,
    commit: dict,
    stage2: dict,
) -> dict:
    stage1 = commit.get("stage1", {})
    return {
        "package":               pkg,
        "ubuntu_2404_version":   ver_2404,
        "ubuntu_2604_version":   ver_2604,
        "commit_sha":            commit.get("sha", ""),
        "commit_message":        commit.get("message", "").splitlines()[0][:120],
        "vuln_confirmed":        stage2.get("vuln_confirmed_in_2404", False),
        "severity":              stage2.get("severity", "INFORMATIONAL"),
        "vulnerability_type":    stage2.get("vulnerability_type", ""),
        "poc_sketch":            stage2.get("poc_sketch", ""),
        "backport_difficulty":   stage2.get("backport_difficulty", ""),
        "backport_notes":        stage2.get("backport_notes", ""),
        "stage1_vuln_class":     stage1.get("vuln_class", ""),
        "stage1_confidence":     stage1.get("confidence", ""),
        "stage1_affected_funcs": stage1.get("affected_functions", []),
        "_cot_rationale":        stage2.get("cot_rationale", ""),
        "_backend":              f"zai/{cfg.ZAI_MODEL}",
    }


def _load_report() -> list:
    if _REPORT_FILE.exists():
        try:
            return json.loads(_REPORT_FILE.read_text())
        except json.JSONDecodeError:
            return []
    return []


def _save_report(entries: list) -> None:
    _REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _REPORT_FILE.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    log.info("[Report] Saved %d entries → %s", len(entries), _REPORT_FILE)


def print_summary(entries: list) -> None:
    confirmed = [e for e in entries if e.get("vuln_confirmed")]
    print(f"\n{'═'*70}")
    print(f"  Patch Gap Report  —  Ubuntu 24.04 vs 26.04")
    print(f"  Total entries: {len(entries)}   Confirmed vulnerabilities: {len(confirmed)}")
    print(f"{'═'*70}")
    for e in confirmed:
        print(f"\n  Package  : {e['package']}  ({e['ubuntu_2404_version']} → {e['ubuntu_2604_version']})")
        print(f"  Commit   : {e['commit_sha'][:12]}  {e['commit_message'][:60]}")
        print(f"  Severity : {e['severity']}   Backport: {e['backport_difficulty']}")
        print(f"  Type     : {e['vulnerability_type']}")
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

    ver_2404 = pkgs_2404.get(pkg_name, "")
    ver_2604 = pkgs_2604.get(pkg_name, "")

    if not ver_2404 or not ver_2604:
        log.warning("[Step1] %s not found in both 24.04 and 26.04 data", pkg_name)
        return []

    try:
        if not (Version(_normalize_ver(ver_2604)) > Version(_normalize_ver(ver_2404))):
            log.info("[Step1] No version gap for %s (%s vs %s)", pkg_name, ver_2404, ver_2604)
            return []
    except InvalidVersion:
        pass

    log.info("[Step1] %s  24.04=%s  26.04=%s", pkg_name, ver_2404, ver_2604)

    repo_url = KNOWN_UPSTREAM_REPOS.get(pkg_name, "")
    if not repo_url:
        gap = find_gap(pkg_name)
        repo_url = gap.get("repo_url", "")
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

    entries: list[dict] = []
    for i, commit in enumerate(filtered, 1):
        sha8 = commit.get("short_sha", commit.get("sha", "")[:8])
        log.info("[Step4] [%d/%d] Source analysis + Stage 2 audit  SHA=%s",
                 i, len(filtered), sha8)

        source_2404 = extract_source_analysis(repo, start_tag_name, commit)
        stage2      = glm_stage2_audit(pkg_name, ver_2404, ver_2604,
                                       commit, source_2404, client)
        commit["stage2"] = stage2

        entry = _make_report_entry(pkg_name, ver_2404, ver_2604, commit, stage2)
        entries.append(entry)

        if stage2.get("vuln_confirmed_in_2404"):
            log.info("[Step4] SHA=%s → CONFIRMED in 24.04  severity=%s  backport=%s",
                     sha8, stage2.get("severity"), stage2.get("backport_difficulty"))
        else:
            log.info("[Step4] SHA=%s → not confirmed in 24.04", sha8)

    log.info("[Step4] %d report entries for %s", len(entries), pkg_name)
    return entries


def run_package_list(pkg_names: list[str]) -> None:
    """Run pipeline for each package, saving incrementally."""
    all_entries = _load_report()
    done_keys   = {(e["package"], e["commit_sha"]) for e in all_entries}

    for pkg in pkg_names:
        log.info("[Main] Processing: %s", pkg)
        try:
            new_entries = run_single(pkg)
        except Exception as exc:
            log.error("[Main] %s pipeline error: %s", pkg, exc, exc_info=True)
            continue

        added = 0
        for e in new_entries:
            key = (e["package"], e["commit_sha"])
            if key not in done_keys:
                all_entries.append(e)
                done_keys.add(key)
                added += 1

        _save_report(all_entries)
        log.info("[Main] %s: %d new entries added", pkg, added)


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
        entries  = run_single(args.package)
        existing = _load_report()
        done_keys = {(e["package"], e["commit_sha"]) for e in existing}
        new = [e for e in entries if (e["package"], e["commit_sha"]) not in done_keys]
        _save_report(existing + new)
        print_summary(new or entries)

    elif args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            log.error("File not found: %s", fpath)
            sys.exit(1)
        pkgs = [ln.strip() for ln in fpath.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")]
        log.info("[Main] Loaded %d packages from %s", len(pkgs), fpath)
        run_package_list(pkgs)
        print_summary(_load_report())

    else:  # --auto
        gaps = find_version_gaps()
        if args.top:
            gaps = gaps[:args.top]
        run_package_list([g["package"] for g in gaps])
        print_summary(_load_report())


if __name__ == "__main__":
    main()

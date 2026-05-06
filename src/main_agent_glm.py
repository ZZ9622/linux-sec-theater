#!/usr/bin/env python3
"""
main_agent_glm.py  –  linux-sec-theater core pipeline engine (GLM-5 edition)
=============================================================================

Architecture is identical to main_agent.py; only the LLM backend is swapped
from local Ollama/Qwen2.5-Coder to Z.AI GLM-5 (OpenAI-compatible REST API).

Pipeline
--------
  Step 1  Python → find_gap()           (exit early if no gap)
  Step 2  Python → harvest()            (collect high-risk commit list)
  Step 3  Python for-loop → verify()    (filter, keep only Unpatched)
  Step 4  Python for-loop → GLM-5 audit (each commit audited independently, zero context pollution)

LLM Backend
-----------
  GLM-5 (Z.AI OpenAI-compatible API)
  Configured in config.py:
    ZAI_API_KEY   = os.environ["ZAI_API_KEY"]
    ZAI_BASE_URL  = "https://api.z.ai/api/coding/paas/v4"
    ZAI_MODEL     = "glm-5"

Usage
-----
  export ZAI_API_KEY=<your-key>

  # Single package:
  python src/main_agent_glm.py --package librust-addr2line-dev

  # Batch (process the first N packages with a version gap):
  python src/main_agent_glm.py --batch --top 10

  # File mode:
  python src/main_agent_glm.py --file data/target_pkgs/target_test_20.txt
"""

import argparse
import json
import logging
import re
import sys
import datetime
from pathlib import Path
from typing import Optional

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
import config as cfg

# ── Tool layer (called directly from Python, not dispatched via LLM tools) ───
from tools.version_gap_finder    import find_gap
from tools.diff_harvester        import harvest
from tools.ubuntu_patch_verifier import verify, format_verdict
from prompts.security_audit      import build_audit_prompt

# ── Pydantic audit result validation ─────────────────────────────────────────
from pydantic import BaseModel, field_validator, ValidationError

# ── GLM-5 backend (OpenAI-compatible) ────────────────────────────────────────
from openai import OpenAI


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic audit result validation model (identical to main_agent.py)
# ══════════════════════════════════════════════════════════════════════════════

class AuditResult(BaseModel):
    model_config = {"extra": "allow"}

    hidden_vuln:               bool = False
    vulnerability_type:        str  = "None"
    llm_poc_idea:              str  = "None"
    severity:                  str  = "INFORMATIONAL"
    cot_step1_summary:         str  = ""
    cot_step2_is_security_fix: bool = False
    cot_step2_rationale:       str  = ""
    poc_attack_surface:        str  = ""
    poc_malicious_input:       str  = ""
    poc_impact:                str  = ""
    cot_step6_verdict_rationale: str = ""

    @field_validator("vulnerability_type", "llm_poc_idea", mode="before")
    @classmethod
    def _require_meaningful_or_none_sentinel(cls, v: object) -> str:
        if v is None:
            return "None"
        text = str(v).strip()
        if text == "":
            raise ValueError(
                "field must be 'None' or a meaningful description (≥5 chars); "
                "empty string is not allowed"
            )
        if text != "None" and len(text) < 5:
            raise ValueError(
                f"field must be 'None' or ≥5 chars, got {text!r} ({len(text)} chars)"
            )
        return text


def _validate_audit_result(parsed: dict) -> AuditResult:
    result = AuditResult.model_validate(parsed)
    if not result.hidden_vuln:
        result.vulnerability_type = "None"
        result.llm_poc_idea       = "None"
        result.severity           = "INFORMATIONAL"
    return result


# ── Logging configuration ─────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(name)-28s  %(message)s",
    datefmt = "%H:%M:%S",
)
log = logging.getLogger("main_agent_glm")


# ══════════════════════════════════════════════════════════════════════════════
# CoT logger
# ══════════════════════════════════════════════════════════════════════════════

def _save_audit_cot(
    pkg:    str,
    sha:    str,
    prompt: str,
    raw:    str,
    parsed: dict,
) -> None:
    """Save the full CoT for a single audit as an independent JSON file."""
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = cfg.COT_LOG_DIR / f"audit_glm_{pkg}_{sha[:8]}_{ts}.json"
    record = {
        "package":      pkg,
        "commit_sha":   sha,
        "timestamp":    ts,
        "backend":      f"zai/{cfg.ZAI_MODEL}",
        "prompt":       prompt,
        "raw_response": raw,
        "parsed":       parsed,
    }
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False))
    log.info("[CoT] audit chain-of-thought saved → %s", path)


# ══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ══════════════════════════════════════════════════════════════════════════════

def _flatten_poc_idea(parsed: dict) -> dict:
    """If the LLM returned a nested dict, flatten llm_poc_idea into a single-line string."""
    poc = parsed.get("llm_poc_idea", "")
    if isinstance(poc, dict):
        parts = []
        sf = poc.get("source_file", "")
        fn = poc.get("function_name", "")
        if sf or fn:
            parts.append(f"In {f'{sf}::{fn}'.strip('::')}")
        vs = poc.get("variable_state", "")
        if vs:
            parts.append(f"when {vs}")
        inp = poc.get("specific_input_field_byte", poc.get("malicious_input", ""))
        if inp:
            parts.append(f"by setting {inp}")
        impact = poc.get("impact", poc.get("poc_impact", ""))
        if impact:
            parts.append(f"→ {impact}")
        parsed["llm_poc_idea"] = ", ".join(parts) if parts else json.dumps(poc)
        log.debug("[AuditLLM] llm_poc_idea flattened from dict to string")
    elif not isinstance(poc, str):
        parsed["llm_poc_idea"] = str(poc)
    return parsed


def _build_glm_client() -> OpenAI:
    """Build a Z.AI OpenAI-compatible client. Created fresh before each audit call to ensure statelessness."""
    if not cfg.ZAI_API_KEY:
        raise RuntimeError(
            "ZAI_API_KEY is not set. Please run: export ZAI_API_KEY=<your-key>"
        )
    return OpenAI(
        api_key  = cfg.ZAI_API_KEY,
        base_url = cfg.ZAI_BASE_URL,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Step 4 core: GLM-5 independent audit (fresh client per call, zero context pollution)
# ══════════════════════════════════════════════════════════════════════════════

def _audit_commit_llm(
    pkg_name:     str,
    ubuntu_ver:   str,
    upstream_ver: str,
    commit:       dict,
) -> dict:
    """
    Perform a deep GLM-5 security audit on a single Unpatched commit.

    - A fresh OpenAI client is created for each call, carrying no history.
    - Returns a Pydantic-validated dict; on call failure or validation failure,
      returns a clean record with {"hidden_vuln": False, ...}.
    """
    sha  = commit.get("sha", "")
    diff = commit.get("diff", "")

    if len(diff) > cfg.MAX_DIFF_CHARS:
        diff = diff[:cfg.MAX_DIFF_CHARS] + "\n...[diff truncated]"
        log.warning("[AuditLLM] SHA=%s diff truncated to %d chars",
                    sha[:8], cfg.MAX_DIFF_CHARS)

    commit_for_prompt = {**commit, "diff": diff}
    prompt_text = build_audit_prompt(
        package          = pkg_name,
        ubuntu_ver       = ubuntu_ver,
        upstream_ver     = upstream_ver,
        commit           = commit_for_prompt,
        selection_reason = commit.get("selection_reason", "message keyword match"),
    )

    log.info("[AuditLLM] SHA=%s  sending audit prompt (%d chars) → zai/%s",
             sha[:8], len(prompt_text), cfg.ZAI_MODEL)

    clean_result = {
        "hidden_vuln":        False,
        "vulnerability_type": "None",
        "llm_poc_idea":       "None",
        "severity":           "INFORMATIONAL",
    }
    raw    = ""
    parsed: dict = {}

    # ── Call GLM-5 ────────────────────────────────────────────────────────────
    try:
        client = _build_glm_client()
        resp = client.chat.completions.create(
            model       = cfg.ZAI_MODEL,
            temperature = 0.05,
            messages    = [
                {
                    "role":    "system",
                    "content": (
                        "You are an elite vulnerability researcher. "
                        "Respond ONLY with a single valid JSON object. "
                        "No markdown, no prose outside the JSON."
                    ),
                },
                {"role": "user", "content": prompt_text},
            ],
            response_format={"type": "json_object"},
        )
        raw = resp.choices[0].message.content or ""
    except Exception as exc:
        log.error("[AuditLLM] SHA=%s  GLM-5 call failed: %s", sha[:8], exc)
        _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                        raw="", parsed={**clean_result, "_error": str(exc)})
        return clean_result

    log.info("[AuditLLM] SHA=%s  response received (%d chars)", sha[:8], len(raw))

    # ── Parse JSON ────────────────────────────────────────────────────────────
    try:
        parsed = json.loads(raw.strip())
    except json.JSONDecodeError:
        m = re.search(r"```json\s*(\{.*?\})\s*```", raw, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        if not parsed:
            log.warning("[AuditLLM] SHA=%s  JSON parse failed, marking as clean", sha[:8])
            _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                            raw=raw, parsed={**clean_result, "_parse_error": True})
            return clean_result

    # ── Flatten llm_poc_idea ──────────────────────────────────────────────────
    parsed = _flatten_poc_idea(parsed)

    # ── Pydantic validation ───────────────────────────────────────────────────
    try:
        validated = _validate_audit_result(parsed)
        parsed    = validated.model_dump()
    except ValidationError as ve:
        log.warning("[AuditLLM] SHA=%s  Pydantic validation failed: %s — marking as clean", sha[:8], ve)
        err_result = {**clean_result, "_pydantic_error": str(ve)}
        _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                        raw=raw, parsed=err_result)
        return err_result

    # ── Print summary ─────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  [GLM-5 Audit] SHA={sha[:8]}  hidden_vuln={parsed.get('hidden_vuln')}  "
          f"severity={parsed.get('severity')}")
    print(f"  vuln_type : {parsed.get('vulnerability_type', '')[:120]}")
    print(f"  poc_idea  : {str(parsed.get('llm_poc_idea', ''))[:120]}")
    print(f"{'─'*60}\n")

    _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                    raw=raw, parsed=parsed)
    return parsed


# ══════════════════════════════════════════════════════════════════════════════
# Output persistence (findings file shared with main_agent.py, SHA-based dedup)
# ══════════════════════════════════════════════════════════════════════════════

_FINDINGS_FILE = cfg.FINDINGS_DIR / "hiddenvul_glm.json"


def _load_findings() -> list:
    if _FINDINGS_FILE.exists():
        try:
            return json.loads(_FINDINGS_FILE.read_text())
        except json.JSONDecodeError:
            return []
    return []


def _dedup_findings(findings: list) -> list:
    seen: set[str] = set()
    result = []
    for f in findings:
        key = f.get("missing_commit_hash", "")
        if not key or key in seen:
            if key in seen:
                log.debug("[Dedup] skipping duplicate SHA: %s (%s)", key[:8], f.get("package", ""))
            continue
        seen.add(key)
        result.append(f)
    return result


def _save_findings(findings: list) -> None:
    _FINDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    deduped = _dedup_findings(findings)
    if len(deduped) < len(findings):
        log.warning("[Output] dedup removed %d duplicate entries", len(findings) - len(deduped))
    _FINDINGS_FILE.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
    log.info("[Output] saved %d findings → %s", len(deduped), _FINDINGS_FILE)


def _make_finding(pkg_name: str, ubuntu_ver: str, upstream_ver: str,
                  commit: dict, analysis: dict) -> dict:
    return {
        "package":             pkg_name,
        "vulnerability_type":  analysis.get("vulnerability_type", "Unknown"),
        "missing_commit_hash": commit.get("sha", "unknown"),
        "llm_poc_idea":        analysis.get("llm_poc_idea", ""),
        "ubuntu_status":       "Unpatched verified via CVE Tracker/Changelog",
        "_severity":           analysis.get("severity", ""),
        "_cot_summary":        analysis.get("cot_step1_summary", ""),
        "_poc_attack_surface": analysis.get("poc_attack_surface", ""),
        "_poc_malicious_input": analysis.get("poc_malicious_input", ""),
        "_poc_impact":         analysis.get("poc_impact", ""),
        "_ubuntu_version":     ubuntu_ver,
        "_upstream_version":   upstream_ver,
        "_backend":            f"zai/{cfg.ZAI_MODEL}",
    }


def _make_clean_record(pkg_name: str, ubuntu_ver: str = "",
                       upstream_ver: str = "", gap: bool = False,
                       note: str = "No hidden vulnerability found") -> dict:
    return {
        "package":             pkg_name,
        "vulnerability_type":  "N/A",
        "missing_commit_hash": "N/A",
        "llm_poc_idea":        "N/A",
        "ubuntu_status":       note,
        "_severity":           "INFORMATIONAL",
        "_cot_summary":        "No security-relevant unpatched commits detected.",
        "_ubuntu_version":     ubuntu_ver,
        "_upstream_version":   upstream_ver,
        "_gap":                gap,
        "_scan_status":        "clean",
        "_backend":            f"zai/{cfg.ZAI_MODEL}",
    }


# ══════════════════════════════════════════════════════════════════════════════
# Pipeline entry point
# ══════════════════════════════════════════════════════════════════════════════

def run_single(pkg_name: str) -> list[dict]:
    """
    Run the full pipeline for a single package, returning a list of findings.

    Pipeline:
      Step 1  Python → find_gap()
      Step 2  Python → harvest()
      Step 3  Python for-loop → verify()
      Step 4  Python for-loop → GLM-5 audit
    """
    log.info("═" * 60)
    log.info("  Target package: %s  [backend: zai/%s]", pkg_name, cfg.ZAI_MODEL)
    log.info("═" * 60)

    # ── Step 1: Version gap detection ────────────────────────────────────────
    log.info("[Step 1] Detecting version gap: %s", pkg_name)
    gap_result = find_gap(pkg_name)

    if gap_result.get("error"):
        log.warning("[Step 1] Tool failed: %s", gap_result["error"])
        return [_make_clean_record(pkg_name, note=f"Gap finder error: {gap_result['error']}")]

    ubuntu_ver   = gap_result.get("ubuntu_version", "")
    upstream_ver = gap_result.get("upstream_version", "")
    repo_url     = gap_result.get("repo_url", "")
    has_gap      = gap_result.get("gap", False)

    log.info("[Step 1] ubuntu=%s  upstream=%s  gap=%s", ubuntu_ver, upstream_ver, has_gap)

    if not has_gap:
        log.info("[Step 1] No version gap, skipping %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=False,
                                   note="No version gap detected")]

    if not repo_url:
        log.warning("[Step 1] Could not obtain repo_url, skipping %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="repo_url unavailable")]

    # ── Step 2: High-risk commit extraction ──────────────────────────────────
    log.info("[Step 2] Extracting high-risk commits: %s → %s", ubuntu_ver, upstream_ver)
    try:
        commits = harvest(repo_url, ubuntu_ver, upstream_ver)
    except Exception as exc:
        log.error("[Step 2] harvest failed: %s", exc)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note=f"harvest error: {exc}")]

    commits = commits[:cfg.MAX_COMMITS_PER_AUDIT]
    log.info("[Step 2] Retrieved %d high-risk commits (limit %d)",
             len(commits), cfg.MAX_COMMITS_PER_AUDIT)

    if not commits:
        log.info("[Step 2] No high-risk commits, skipping %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="No security-relevant commits in gap")]

    # ── Step 3: Patch verification ────────────────────────────────────────────
    log.info("[Step 3] Verifying %d commits for backport status …", len(commits))
    unpatched: list[dict] = []
    for i, commit in enumerate(commits, 1):
        sha = commit.get("sha", "")
        log.info("[Step 3] [%d/%d] Verifying SHA=%s  %s",
                 i, len(commits), sha[:8],
                 commit.get("message", "")[:60])
        try:
            verify_result = verify(pkg_name, sha, ubuntu_ver)
            verdict_text  = format_verdict(verify_result)
        except Exception as exc:
            log.warning("[Step 3] SHA=%s verify exception: %s — treating as Unknown, skipping", sha[:8], exc)
            continue

        log.info("[Step 3] SHA=%s → %s", sha[:8], verdict_text.splitlines()[0][:80])

        if "Unpatched" in verdict_text:
            unpatched.append(commit)
            log.info("[Step 3] SHA=%s confirmed Unpatched, added to audit queue", sha[:8])
        else:
            log.info("[Step 3] SHA=%s already backported or Unknown, skipping", sha[:8])

    log.info("[Step 3] Verification complete: %d / %d commits confirmed Unpatched",
             len(unpatched), len(commits))

    if not unpatched:
        log.info("[Step 3] No Unpatched commits, skipping %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="All commits already backported or unknown")]

    # ── Step 4: GLM-5 security audit (each commit independent, zero context pollution) ──
    log.info("[Step 4] Starting GLM-5 audit on %d Unpatched commits …", len(unpatched))
    findings: list[dict] = []

    for i, commit in enumerate(unpatched, 1):
        sha = commit.get("sha", "")
        log.info("[Step 4] [%d/%d] Auditing SHA=%s", i, len(unpatched), sha[:8])

        analysis = _audit_commit_llm(pkg_name, ubuntu_ver, upstream_ver, commit)

        if analysis.get("hidden_vuln", False):
            finding = _make_finding(pkg_name, ubuntu_ver, upstream_ver, commit, analysis)
            findings.append(finding)
            log.info("[Step 4] SHA=%s → hidden vulnerability found (%s)",
                     sha[:8], analysis.get("vulnerability_type", "?"))
        else:
            log.info("[Step 4] SHA=%s → no vulnerability (hidden_vuln=False)", sha[:8])

    log.info("[Step 4] GLM-5 audit complete: %d hidden vulnerabilities found", len(findings))

    if not findings:
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="Unpatched commits found but LLM found no hidden vulnerabilities")]

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# Batch mode
# ══════════════════════════════════════════════════════════════════════════════

def run_batch(top: Optional[int] = None) -> None:
    """Batch-process all librust packages with a version gap."""
    from packaging.version import Version, InvalidVersion
    from tools.version_gap_finder import _ligrust_cache

    gap_data   = _ligrust_cache()
    candidates = []
    for pkg, info in gap_data.items():
        ub = re.sub(r"[+~-].*", "", info.get("ubuntu_full_version", ""))
        ub = re.sub(r"^\d+:", "", ub)
        up = info.get("upstream_version", "")
        try:
            if Version(ub) < Version(up):
                candidates.append(pkg)
        except InvalidVersion:
            pass

    if top:
        candidates = candidates[:top]

    log.info("[Batch] Total packages to process: %d", len(candidates))

    all_findings  = _load_findings()
    done_pkgs     = {f["package"] for f in all_findings}
    existing_shas = {f["missing_commit_hash"] for f in all_findings
                     if f.get("missing_commit_hash")}

    for pkg in candidates:
        if pkg in done_pkgs:
            log.info("[Batch] Skipping (already processed): %s", pkg)
            continue
        try:
            new   = run_single(pkg)
            added = 0
            for finding in new:
                sha   = finding.get("missing_commit_hash", "")
                pkg_f = finding.get("package", "")
                if sha == "N/A":
                    if pkg_f not in done_pkgs:
                        all_findings.append(finding)
                        done_pkgs.add(pkg_f)
                        added += 1
                elif sha and sha not in existing_shas:
                    all_findings.append(finding)
                    existing_shas.add(sha)
                    done_pkgs.add(pkg_f)
                    added += 1
                elif sha:
                    log.debug("[Batch] skipping cross-run duplicate SHA=%s", sha[:8])
            _save_findings(all_findings)
            log.info("[Batch] %s done, %d new findings added (after dedup)", pkg, added)
        except Exception as e:
            log.error("[Batch] %s pipeline error: %s", pkg, e, exc_info=True)


# ══════════════════════════════════════════════════════════════════════════════
# File mode
# ══════════════════════════════════════════════════════════════════════════════

def _run_pkg_list(pkgs: list[str]) -> None:
    """Run run_single for each package in the list, incrementally writing findings."""
    all_findings  = _load_findings()
    done_pkgs     = {f["package"] for f in all_findings}
    existing_shas = {f["missing_commit_hash"] for f in all_findings
                     if f.get("missing_commit_hash")}

    for pkg in pkgs:
        if pkg in done_pkgs:
            log.info("[File] Skipping (already processed): %s", pkg)
            continue
        try:
            new   = run_single(pkg)
            added = 0
            for finding in new:
                sha   = finding.get("missing_commit_hash", "")
                pkg_f = finding.get("package", "")
                if sha == "N/A":
                    if pkg_f not in done_pkgs:
                        all_findings.append(finding)
                        done_pkgs.add(pkg_f)
                        added += 1
                elif sha and sha not in existing_shas:
                    all_findings.append(finding)
                    existing_shas.add(sha)
                    done_pkgs.add(pkg_f)
                    added += 1
                elif sha:
                    log.debug("[File] skipping cross-run duplicate SHA=%s", sha[:8])
            _save_findings(all_findings)
            log.info("[File] %s done, %d new findings added", pkg, added)
        except Exception as e:
            log.error("[File] %s pipeline error: %s", pkg, e, exc_info=True)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="linux-sec-theater: GLM-5 hidden vulnerability discovery pipeline"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--package", "-p", metavar="PKG",
                      help="Single package mode, e.g.: librust-addr2line-dev")
    mode.add_argument("--file", "-f", metavar="FILE",
                      help="File mode: one package name per line")
    mode.add_argument("--batch", "-b", action="store_true",
                      help="Batch mode: process all packages with a version gap")
    parser.add_argument("--top", "-n", type=int, default=None, metavar="N",
                        help="In --batch mode, only process the first N packages")
    args = parser.parse_args()

    if args.package:
        try:
            findings = run_single(args.package)
        except Exception as e:
            log.error("[Single] %s pipeline error: %s", args.package, e, exc_info=True)
            sys.exit(1)
        existing      = _load_findings()
        existing_shas = {f["missing_commit_hash"] for f in existing
                         if f.get("missing_commit_hash") and f["missing_commit_hash"] != "N/A"}
        done_pkgs_set = {f["package"] for f in existing}
        new_findings  = []
        for f in findings:
            sha = f.get("missing_commit_hash", "")
            if sha == "N/A":
                if f.get("package") not in done_pkgs_set:
                    new_findings.append(f)
            elif sha not in existing_shas:
                new_findings.append(f)
        _save_findings(existing + new_findings)

        vuln_findings = [f for f in new_findings if f.get("missing_commit_hash") != "N/A"]
        if vuln_findings:
            print(f"\n{'═'*60}")
            print(f"  Hidden vulnerabilities found: {len(vuln_findings)}")
            print(f"{'═'*60}")
            for f in vuln_findings:
                print(json.dumps(f, indent=2, ensure_ascii=False))
        else:
            print("\nNo confirmed hidden vulnerabilities found. (Clean scan record written.)")

    elif args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            log.error("File not found: %s", fpath)
            sys.exit(1)
        pkgs = [ln.strip() for ln in fpath.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")]
        log.info("[File] Loaded %d packages from %s", len(pkgs), fpath)
        _run_pkg_list(pkgs)

    else:
        run_batch(top=args.top)


if __name__ == "__main__":
    main()

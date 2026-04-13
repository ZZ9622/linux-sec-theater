#!/usr/bin/env python3
"""
main_agent.py  –  linux-sec-theater 核心流水线引擎（Pipeline 重构版）
=====================================================================

架构（重构后）
--------------
  控制流完全由 Python 驱动，LLM 仅作为"审计大脑"，不再负责工具调度：

  Step 1  Python 直接调用 version_gap_finder.find_gap()
            → 若无版本鸿沟，直接退出
  Step 2  Python 直接调用 diff_harvester.harvest()
            → 拿到含安全敏感词的高危 commit 列表
  Step 3  Python for 循环逐个调用 ubuntu_patch_verifier.verify()
            → 过滤掉已回推的，只保留确定 Unpatched 的 commit
  Step 4  Python for 循环，每个 Unpatched commit 实例化一个全新、独立的
          OllamaLLM，输出包含 vulnerability_type / llm_poc_idea / severity
          的 JSON 报告。报告收集后写入 final_hidden_vulnerabilities.json。

  彻底消除 ReAct 循环疲劳与上下文交叉污染（Context Bleed-Over）。

LLM 后端
--------
  Qwen2.5-Coder:7b（本地 Ollama，http://localhost:11434，~32k 上下文）

模型目录
--------
  Ollama 模型存放于 /Volumes/T7/linux-sec-theater/models。
  启动前需设置：export OLLAMA_MODELS=/Volumes/T7/linux-sec-theater/models

数据合法性
----------
  LLM 响应通过 Pydantic AuditResult 模型校验：
    - vulnerability_type / llm_poc_idea 必须为 'None' 或 ≥5 字符的实质内容
    - 空字符串直接触发 ValidationError，异常被捕获后该 commit 标记为 clean

CoT 日志
--------
  每次 _audit_commit_llm() 的完整思考链写入：
    data/findings/cot_logs/audit_{pkg}_{sha8}_{timestamp}.json

使用
----
  export OLLAMA_MODELS=/Volumes/T7/linux-sec-theater/models
  ollama serve && ollama pull qwen2.5-coder:7b

  # 单包测试：
  python src/main_agent.py --package librust-addr2line-dev

  # 批量（取前 N 个有版本鸿沟的包）：
  python src/main_agent.py --batch --top 10
"""

import argparse
import json
import logging
import re
import sys
import datetime
from pathlib import Path
from typing import Optional

# ── 路径 ──────────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
import config as cfg

# ── 工具层（Python 直接调用，不经过 LLM 工具调度）────────────────────────────
from tools.version_gap_finder    import find_gap
from tools.diff_harvester        import harvest
from tools.ubuntu_patch_verifier import verify, format_verdict
from prompts.security_audit      import build_audit_prompt

# ── Pydantic 审计结果校验 ──────────────────────────────────────────────────────
from pydantic import BaseModel, field_validator, ValidationError

# ── LLM 后端（仅用于 Step 4 审计，不再用于工具调度）────────────────────────────
from langchain_ollama import OllamaLLM

# ── 全局禁用 LangChain LLM 缓存，防止跨调用结果复用 ────────────────────────────
from langchain.globals import set_llm_cache
set_llm_cache(None)


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic 审计结果校验模型
# ══════════════════════════════════════════════════════════════════════════════

class AuditResult(BaseModel):
    """
    校验 _audit_commit_llm LLM 输出的合法性。

    关键约束：
    - vulnerability_type / llm_poc_idea 必须为字面量 'None' 或 ≥5 字符的实质内容。
    - 空字符串 / 空白字符串直接触发 ValidationError。
    - 当 hidden_vuln=False 时，代码层会将两个字段统一覆写为 'None'，
      因此 LLM 可以在无漏洞时返回任意 'None' 系值。
    """

    model_config = {"extra": "allow"}   # 允许 LLM 返回额外字段透传

    hidden_vuln:              bool  = False
    vulnerability_type:       str   = "None"
    llm_poc_idea:             str   = "None"
    severity:                 str   = "INFORMATIONAL"
    cot_step1_summary:        str   = ""
    cot_step2_is_security_fix: bool = False
    cot_step2_rationale:      str   = ""
    poc_attack_surface:       str   = ""
    poc_malicious_input:      str   = ""
    poc_impact:               str   = ""
    cot_step6_verdict_rationale: str = ""

    @field_validator("vulnerability_type", "llm_poc_idea", mode="before")
    @classmethod
    def _require_meaningful_or_none_sentinel(cls, v: object) -> str:
        """
        拒绝空字符串；要求值为字面量 'None' 或长度 ≥5 的实质内容。
        若 LLM 返回 None（Python None）则规范化为字符串 'None'。
        """
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
    """
    将 LLM 返回的原始 dict 通过 AuditResult 校验。

    - 若 hidden_vuln=False，强制将 vulnerability_type / llm_poc_idea 设为 'None'。
    - 若校验失败（空字符串等），抛出 ValidationError，由调用方捕获后标记为 clean。
    """
    result = AuditResult.model_validate(parsed)
    if not result.hidden_vuln:
        result.vulnerability_type = "None"
        result.llm_poc_idea       = "None"
        result.severity           = "INFORMATIONAL"
    return result


# ── 日志配置 ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(name)-28s  %(message)s",
    datefmt = "%H:%M:%S",
)
log = logging.getLogger("main_agent")


# ══════════════════════════════════════════════════════════════════════════════
# CoT 日志记录器（独立 JSON 文件，不再依赖 LangChain 回调）
# ══════════════════════════════════════════════════════════════════════════════

def _save_audit_cot(
    pkg:      str,
    sha:      str,
    prompt:   str,
    raw:      str,
    parsed:   dict,
) -> None:
    """将单次审计的完整 CoT 保存为独立 JSON 文件。"""
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = cfg.COT_LOG_DIR / f"audit_{pkg}_{sha[:8]}_{ts}.json"
    record = {
        "package":      pkg,
        "commit_sha":   sha,
        "timestamp":    ts,
        "backend":      f"ollama/{cfg.OLLAMA_MODEL}",
        "prompt":       prompt,
        "raw_response": raw,
        "parsed":       parsed,
    }
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False))
    log.info("[CoT] audit 思考链已保存 → %s", path)


# ══════════════════════════════════════════════════════════════════════════════
# 辅助函数
# ══════════════════════════════════════════════════════════════════════════════

def _flatten_poc_idea(parsed: dict) -> dict:
    """
    保证 llm_poc_idea 始终是纯字符串。
    若 LLM 返回了嵌套字典（{source_file, function_name, ...}），将其展平为
    结构化的单行文本。
    """
    poc = parsed.get("llm_poc_idea", "")
    if isinstance(poc, dict):
        parts = []
        sf = poc.get("source_file", "")
        fn = poc.get("function_name", "")
        if sf or fn:
            loc = f"{sf}::{fn}".strip("::")
            parts.append(f"In {loc}")
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
        log.debug("[AuditLLM] llm_poc_idea 已从 dict 展平为字符串")
    elif not isinstance(poc, str):
        parsed["llm_poc_idea"] = str(poc)
    return parsed


# ══════════════════════════════════════════════════════════════════════════════
# Step 4 核心：独立 LLM 审计（每次调用创建全新实例，零上下文污染）
# ══════════════════════════════════════════════════════════════════════════════

def _audit_commit_llm(
    pkg_name:     str,
    ubuntu_ver:   str,
    upstream_ver: str,
    commit:       dict,
) -> dict:
    """
    对单个 Unpatched commit 进行深度 LLM 安全审计。

    - 每次调用实例化一个全新的 OllamaLLM，不携带任何历史状态。
    - 返回经 Pydantic 校验的 dict；若 LLM 调用失败或校验失败，
      返回 {"hidden_vuln": False, ...} 的 clean 记录。
    """
    sha  = commit.get("sha", "")
    diff = commit.get("diff", "")

    # Qwen2.5-Coder:7b 上下文约 32k，保守截断
    if len(diff) > cfg.MAX_DIFF_CHARS_OLLAMA:
        diff = diff[:cfg.MAX_DIFF_CHARS_OLLAMA] + "\n...[diff truncated]"
        log.warning("[AuditLLM] SHA=%s diff 已截断至 %d chars（Ollama 32k ctx）",
                    sha[:8], cfg.MAX_DIFF_CHARS_OLLAMA)

    commit_for_prompt = {**commit, "diff": diff}
    prompt_text = build_audit_prompt(
        package          = pkg_name,
        ubuntu_ver       = ubuntu_ver,
        upstream_ver     = upstream_ver,
        commit           = commit_for_prompt,
        selection_reason = commit.get("selection_reason", "message keyword match"),
    )

    log.info("[AuditLLM] SHA=%s  发送审计 prompt（%d chars）→ ollama/%s",
             sha[:8], len(prompt_text), cfg.OLLAMA_MODEL)

    # ── 无状态审计调用：每次创建全新 OllamaLLM 实例 ──────────────────────────
    clean_result = {
        "hidden_vuln":        False,
        "vulnerability_type": "None",
        "llm_poc_idea":       "None",
        "severity":           "INFORMATIONAL",
    }
    raw    = ""
    parsed: dict = {}

    try:
        audit_llm = OllamaLLM(
            model       = cfg.OLLAMA_MODEL,
            base_url    = cfg.OLLAMA_BASE_URL,
            temperature = 0.05,
            num_ctx     = 32768,
            format      = "json",
        )
        raw = audit_llm.invoke(prompt_text)
    except Exception as exc:
        log.error("[AuditLLM] SHA=%s  Ollama 调用失败: %s", sha[:8], exc)
        _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                        raw="", parsed={**clean_result, "_error": str(exc)})
        return clean_result

    log.info("[AuditLLM] SHA=%s  收到响应（%d chars）", sha[:8], len(raw))

    # ── 解析 JSON ──────────────────────────────────────────────────────────────
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
            log.warning("[AuditLLM] SHA=%s  JSON 解析失败，标记为 clean", sha[:8])
            _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                            raw=raw, parsed={**clean_result, "_parse_error": True})
            return clean_result

    # ── 展平 llm_poc_idea ──────────────────────────────────────────────────────
    parsed = _flatten_poc_idea(parsed)

    # ── Pydantic 校验 ──────────────────────────────────────────────────────────
    try:
        validated = _validate_audit_result(parsed)
        parsed    = validated.model_dump()
    except ValidationError as ve:
        log.warning("[AuditLLM] SHA=%s  Pydantic 校验失败：%s — 标记为 clean", sha[:8], ve)
        err_result = {**clean_result, "_pydantic_error": str(ve)}
        _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                        raw=raw, parsed=err_result)
        return err_result

    # ── 打印 LLM 输出摘要（供实时观测）────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  [LLM Audit] SHA={sha[:8]}  hidden_vuln={parsed.get('hidden_vuln')}  "
          f"severity={parsed.get('severity')}")
    print(f"  vuln_type : {parsed.get('vulnerability_type', '')[:120]}")
    print(f"  poc_idea  : {str(parsed.get('llm_poc_idea', ''))[:120]}")
    print(f"{'─'*60}\n")

    # ── 保存 CoT ──────────────────────────────────────────────────────────────
    _save_audit_cot(pkg=pkg_name, sha=sha, prompt=prompt_text,
                    raw=raw, parsed=parsed)

    return parsed


# ══════════════════════════════════════════════════════════════════════════════
# 输出持久化
# ══════════════════════════════════════════════════════════════════════════════

def _load_findings() -> list:
    if cfg.FINDINGS_FILE.exists():
        try:
            return json.loads(cfg.FINDINGS_FILE.read_text())
        except json.JSONDecodeError:
            return []
    return []


def _dedup_findings(findings: list) -> list:
    """基于 missing_commit_hash 全局去重，保留首次出现的条目。"""
    seen: set[str] = set()
    result = []
    for f in findings:
        key = f.get("missing_commit_hash", "")
        if not key or key in seen:
            if key in seen:
                log.debug("[Dedup] 跳过重复 SHA: %s (%s)", key[:8], f.get("package", ""))
            continue
        seen.add(key)
        result.append(f)
    return result


def _save_findings(findings: list) -> None:
    cfg.FINDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    deduped = _dedup_findings(findings)
    if len(deduped) < len(findings):
        log.warning("[Output] 去重删除 %d 条重复条目", len(findings) - len(deduped))
    cfg.FINDINGS_FILE.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
    log.info("[Output] 已保存 %d 条发现 → %s", len(deduped), cfg.FINDINGS_FILE)


def _make_finding(pkg_name: str, ubuntu_ver: str, upstream_ver: str,
                  commit: dict, analysis: dict) -> dict:
    """将审计结果和 commit 元数据组合为标准 finding 条目。"""
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
        "_backend":            f"ollama/{cfg.OLLAMA_MODEL}",
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
    }


# ══════════════════════════════════════════════════════════════════════════════
# 流水线入口
# ══════════════════════════════════════════════════════════════════════════════

def run_single(pkg_name: str) -> list[dict]:
    """
    对单个包运行完整流水线，返回 finding 列表。

    Pipeline:
      Step 1  Python → find_gap()           （无 gap 直接退出）
      Step 2  Python → harvest()            （拿高危 commit 列表）
      Step 3  Python for-loop → verify()    （过滤，只留 Unpatched）
      Step 4  Python for-loop → LLM audit  （每 commit 独立实例化 LLM）
    """
    log.info("═" * 60)
    log.info("  目标包: %s  [backend: ollama/%s]", pkg_name, cfg.OLLAMA_MODEL)
    log.info("═" * 60)

    # ── Step 1: 版本鸿沟检测 ──────────────────────────────────────────────────
    log.info("[Step 1] 检测版本鸿沟: %s", pkg_name)
    gap_result = find_gap(pkg_name)

    if gap_result.get("error"):
        log.warning("[Step 1] 工具失败: %s", gap_result["error"])
        return [_make_clean_record(pkg_name, note=f"Gap finder error: {gap_result['error']}")]

    ubuntu_ver   = gap_result.get("ubuntu_version", "")
    upstream_ver = gap_result.get("upstream_version", "")
    repo_url     = gap_result.get("repo_url", "")
    has_gap      = gap_result.get("gap", False)

    log.info("[Step 1] ubuntu=%s  upstream=%s  gap=%s", ubuntu_ver, upstream_ver, has_gap)

    if not has_gap:
        log.info("[Step 1] 无版本鸿沟，跳过 %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=False,
                                   note="No version gap detected")]

    if not repo_url:
        log.warning("[Step 1] 无法获取 repo_url，跳过 %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="repo_url unavailable")]

    # ── Step 2: 高危 commit 提取 ──────────────────────────────────────────────
    log.info("[Step 2] 提取高危 commits: %s → %s", ubuntu_ver, upstream_ver)
    try:
        commits = harvest(repo_url, ubuntu_ver, upstream_ver)
    except Exception as exc:
        log.error("[Step 2] harvest 失败: %s", exc)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note=f"harvest error: {exc}")]

    commits = commits[:cfg.MAX_COMMITS_PER_AUDIT]
    log.info("[Step 2] 获取到 %d 个高危 commit（上限 %d）",
             len(commits), cfg.MAX_COMMITS_PER_AUDIT)

    if not commits:
        log.info("[Step 2] 无高危 commit，跳过 %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="No security-relevant commits in gap")]

    # ── Step 3: Patch 核验（Python 驱动，LLM 不参与）────────────────────────
    log.info("[Step 3] 开始核验 %d 个 commit 是否已回推 …", len(commits))
    unpatched: list[dict] = []
    for i, commit in enumerate(commits, 1):
        sha = commit.get("sha", "")
        log.info("[Step 3] [%d/%d] 核验 SHA=%s  %s",
                 i, len(commits), sha[:8],
                 commit.get("message", "")[:60])
        try:
            verify_result = verify(pkg_name, sha, ubuntu_ver)
            verdict_text  = format_verdict(verify_result)
        except Exception as exc:
            log.warning("[Step 3] SHA=%s verify 异常: %s — 视为 Unknown，跳过", sha[:8], exc)
            continue

        log.info("[Step 3] SHA=%s → %s", sha[:8], verdict_text.splitlines()[0][:80])

        if "Unpatched" in verdict_text:
            unpatched.append(commit)
            log.info("[Step 3] SHA=%s 确认 Unpatched，加入审计队列", sha[:8])
        else:
            log.info("[Step 3] SHA=%s 已回推或 Unknown，跳过", sha[:8])

    log.info("[Step 3] 核验完成：%d / %d 个 commit 确认 Unpatched",
             len(unpatched), len(commits))

    if not unpatched:
        log.info("[Step 3] 无 Unpatched commit，跳过 %s", pkg_name)
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="All commits already backported or unknown")]

    # ── Step 4: LLM 安全审计（每 commit 独立实例，零上下文污染）────────────────
    log.info("[Step 4] 开始 LLM 审计 %d 个 Unpatched commit …", len(unpatched))
    findings: list[dict] = []

    for i, commit in enumerate(unpatched, 1):
        sha = commit.get("sha", "")
        log.info("[Step 4] [%d/%d] 审计 SHA=%s", i, len(unpatched), sha[:8])

        analysis = _audit_commit_llm(pkg_name, ubuntu_ver, upstream_ver, commit)

        if analysis.get("hidden_vuln", False):
            finding = _make_finding(pkg_name, ubuntu_ver, upstream_ver, commit, analysis)
            findings.append(finding)
            log.info("[Step 4] SHA=%s → 发现隐形漏洞 (%s)",
                     sha[:8], analysis.get("vulnerability_type", "?"))
        else:
            log.info("[Step 4] SHA=%s → 无漏洞 (hidden_vuln=False)", sha[:8])

    log.info("[Step 4] LLM 审计完成：%d 个隐形漏洞", len(findings))

    if not findings:
        return [_make_clean_record(pkg_name, ubuntu_ver, upstream_ver, gap=True,
                                   note="Unpatched commits found but LLM found no hidden vulnerabilities")]

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 批量模式
# ══════════════════════════════════════════════════════════════════════════════

def run_batch(top: Optional[int] = None) -> None:
    """批量处理所有有版本鸿沟的 librust 包。"""
    from packaging.version import Version, InvalidVersion
    from tools.version_gap_finder import _ligrust_cache

    gap_data   = _ligrust_cache()
    candidates = []
    for pkg, info in gap_data.items():
        ub  = re.sub(r"[+~-].*", "", info.get("ubuntu_full_version", ""))
        ub  = re.sub(r"^\d+:", "", ub)
        up  = info.get("upstream_version", "")
        try:
            if Version(ub) < Version(up):
                candidates.append(pkg)
        except InvalidVersion:
            pass

    if top:
        candidates = candidates[:top]

    log.info("[Batch] 待处理包总数: %d", len(candidates))

    all_findings  = _load_findings()
    done_pkgs     = {f["package"] for f in all_findings}
    existing_shas = {f["missing_commit_hash"] for f in all_findings
                     if f.get("missing_commit_hash")}

    for pkg in candidates:
        if pkg in done_pkgs:
            log.info("[Batch] 跳过（已处理）: %s", pkg)
            continue
        try:
            new = run_single(pkg)
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
                    log.debug("[Batch] 跳过跨运行重复 SHA=%s", sha[:8])
            _save_findings(all_findings)
            log.info("[Batch] %s 完成，新增 %d 条发现（过滤重复后）", pkg, added)
        except Exception as e:
            log.error("[Batch] %s 流水线异常: %s", pkg, e, exc_info=True)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def _run_pkg_list(pkgs: list[str]) -> None:
    """对包列表逐个执行 run_single，结果增量写入 findings 文件。"""
    all_findings  = _load_findings()
    done_pkgs     = {f["package"] for f in all_findings}
    existing_shas = {f["missing_commit_hash"] for f in all_findings
                     if f.get("missing_commit_hash")}

    for pkg in pkgs:
        if pkg in done_pkgs:
            log.info("[File] 跳过（已处理）: %s", pkg)
            continue
        try:
            new = run_single(pkg)
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
                    log.debug("[File] 跳过跨运行重复 SHA=%s", sha[:8])
            _save_findings(all_findings)
            log.info("[File] %s 完成，新增 %d 条发现", pkg, added)
        except Exception as e:
            log.error("[File] %s 流水线异常: %s", pkg, e, exc_info=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="linux-sec-theater: Ubuntu ESM 隐形漏洞自动挖掘流水线（Pipeline 模式）"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--package", "-p", metavar="PKG",
                      help="单包模式，例如: librust-addr2line-dev")
    mode.add_argument("--file", "-f", metavar="FILE",
                      help="文件模式：每行一个包名，例如: data/target_pkgs/target_test_20.txt")
    mode.add_argument("--batch",   "-b", action="store_true",
                      help="批量模式：处理所有有版本鸿沟的包（需要 _ligrust_cache）")
    parser.add_argument("--top", "-n", type=int, default=None, metavar="N",
                        help="--batch 模式下只处理前 N 个包")
    args = parser.parse_args()

    if args.package:
        try:
            findings = run_single(args.package)
        except Exception as e:
            log.error("[Single] %s 流水线异常: %s", args.package, e, exc_info=True)
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
            print(f"  发现隐形漏洞: {len(vuln_findings)} 条")
            print(f"{'═'*60}")
            for f in vuln_findings:
                print(json.dumps(f, indent=2, ensure_ascii=False))
        else:
            print(f"\n未发现确认的隐形漏洞。（已写入 clean 扫描记录）")

    elif args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            log.error("文件不存在: %s", fpath)
            sys.exit(1)
        pkgs = [ln.strip() for ln in fpath.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")]
        log.info("[File] 从 %s 读取 %d 个包", fpath, len(pkgs))
        _run_pkg_list(pkgs)

    else:
        run_batch(top=args.top)


if __name__ == "__main__":
    main()

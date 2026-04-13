"""
UbuntuPatchVerifier
===================
严格核验：一个上游安全补丁是否已被 Ubuntu 团队 backport 到 noble。

四条核验通道：
  ① ubuntu.com/security/cves.json  — SHA 全文搜索 + 包级 CVE
  ② changelogs.ubuntu.com          — Debian changelog 文本搜索
  ③ Launchpad source diff          — Launchpad patch 文本搜索
  ④ Launchpad web changelog        — 备用：scrape +changelog HTML 页面

核验结论（verdict）：
  "Unpatched"      — 至少一条通道成功运行，均未发现该 commit
  "Already-Backported" — 至少一条通道发现该补丁
  "Verify_Error"   — 所有通道均因网络错误（422/timeout）失败，无法核验
  "Unknown"        — 其他情况

对外暴露唯一入口：verify(pkg_name, commit_sha, ubuntu_ver) → dict
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


# ── 辅助函数 ───────────────────────────────────────────────────────────────────

def _source_pkg_name(pkg_name: str) -> str:
    """
    从二进制包名推导 source 包名。
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
    """判断异常是否为网络/服务器错误（422 / timeout / connection）。"""
    s = str(exc)
    return (
        "422" in s
        or "timed out" in s.lower()
        or "timeout" in s.lower()
        or "ConnectionError" in type(exc).__name__
        or "ConnectTimeout" in type(exc).__name__
    )


# ── 通道 ①：ubuntu.com CVE JSON API ──────────────────────────────────────────

_CVE_PAGE_SIZE = 20   # Ubuntu API 允许的最大 limit 值


def _query_cve_tracker(pkg_name: str) -> tuple[list[dict], Optional[str]]:
    """
    查询包级 CVE 列表，使用分页（limit=20, offset）遍历全部结果。
    返回 (entries, error_type)：error_type 为 None 表示成功，否则为错误描述。
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
                # 记录服务端返回的详细错误体（对 422 尤其有用），然后抛出
                log.warning(
                    "[Verifier①] CVE API 返回 %d（offset=%d）: %s",
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

            # 若本页结果数量小于页大小，说明已到末尾
            if len(page_items) < _CVE_PAGE_SIZE:
                break
            offset += _CVE_PAGE_SIZE

        except Exception as e:
            log.warning("[Verifier①] CVE JSON 查询失败 %s (offset=%d): %s",
                        pkg_name, offset, e)
            err = "network_error" if _is_network_error(e) else str(e)
            # 若第一页就失败则无任何结果；若中途失败则返回已收集的部分
            if not entries:
                return [], err
            # 部分结果仍可用，记录警告后返回
            log.warning("[Verifier①] 分页中断（已收集 %d 条），返回部分结果", len(entries))
            return entries, None

    return entries, None


def _sha_in_cve_tracker(commit_sha: str) -> tuple[list[str], Optional[str]]:
    """全文搜索 commit SHA，返回 (命中的CVE列表, error_type)。"""
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
            last_err = None  # 至少一次成功
        except Exception as e:
            log.warning("[Verifier①] SHA 全文搜索失败 q=%s: %s", q, e)
            if last_err is None:
                last_err = "network_error" if _is_network_error(e) else str(e)
    return list(set(found)), last_err


# ── 通道 ②：changelogs.ubuntu.com ─────────────────────────────────────────────

def _pkg_section(pkg_name: str) -> str:
    if pkg_name.startswith("librust-") or pkg_name.startswith("golang-"):
        return "universe"
    return "main"


def _fetch_changelog(pkg_name: str, ubuntu_ver: str) -> tuple[Optional[str], Optional[str]]:
    """
    从 changelogs.ubuntu.com 拉取 changelog 文本。
    返回 (text, error_type)。
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
            log.debug("[Verifier②] %s fetch 失败: %s", url, e)
            if _is_network_error(e):
                last_err = "network_error"
    return None, last_err


def _sha_in_text(text: str, commit_sha: str) -> bool:
    """在文本中搜索 commit SHA（7/8/12/40 位）。"""
    for length in [7, 8, 12, 40]:
        if re.search(re.escape(commit_sha[:length]), text, re.IGNORECASE):
            return True
    return False


# ── 通道 ③：Launchpad source diff ─────────────────────────────────────────────

def _launchpad_patch_text(pkg_name: str, ubuntu_ver: str) -> tuple[Optional[str], Optional[str]]:
    """通过 Launchpad REST API 获取 source diff 文本。"""
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
        log.debug("[Verifier③] Launchpad diff 查询失败 %s: %s", pkg_name, e)
        err = "network_error" if _is_network_error(e) else str(e)
        return None, err


# ── 通道 ④：Launchpad web changelog（备用） ───────────────────────────────────

def _launchpad_web_changelog(pkg_name: str) -> tuple[Optional[str], Optional[str]]:
    """
    抓取 Launchpad 的 +changelog 页面（HTML），提取 changelog 文本。
    同时尝试 source 包名和原包名。
    URL 形如: https://launchpad.net/ubuntu/+source/rust-addr2line/+changelog
    """
    candidates = list({pkg_name, _source_pkg_name(pkg_name)})
    last_err = "not_found"
    for src in candidates:
        url = f"https://launchpad.net/ubuntu/+source/{src}/+changelog"
        try:
            r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                # changelog 内容在 <div class="changelog"> 或 <pre>
                block = soup.find("div", class_="changelog") or soup.find("pre")
                text = block.get_text() if block else r.text
                if len(text) > 100:
                    log.info("[Verifier④] Launchpad web changelog 获取成功: %s", src)
                    return text, None
            last_err = "not_found"
        except Exception as e:
            log.debug("[Verifier④] Launchpad web changelog 失败 %s: %s", src, e)
            if _is_network_error(e):
                last_err = "network_error"
    return None, last_err


# ── 主入口 ────────────────────────────────────────────────────────────────────

def verify(pkg_name: str, commit_sha: str, ubuntu_ver: str) -> dict:
    """
    对给定 commit 执行四通道核验，返回：
    {
      "verdict":   "Unpatched"|"Already-Backported"|"Verify_Error"|"Unknown",
      "channel":   str | None,
      "evidence":  str,
      "pkg_cves":  list,
      "errors":    list,   # 各通道错误记录
    }

    Verify_Error: 所有通道均因 422/timeout 失败，结论不可信。
    Unpatched:    至少一条通道成功运行且未发现该 commit。
    """
    short = commit_sha[:8]
    log.info("[Verifier] 核验 %s  commit=%s  ubuntu_ver=%s", pkg_name, short, ubuntu_ver)

    result: dict = {
        "verdict":  "Unknown",
        "channel":  None,
        "evidence": "",
        "pkg_cves": [],
        "errors":   [],
    }

    # channels_searched: 通道成功取到内容并主动搜索了 SHA（无论结果）
    # channels_errored:  通道因网络/422等硬错误失败，无法运行
    channels_searched = 0
    channels_errored  = 0

    # ── 内部辅助：记录通道结果 ────────────────────────────────────────────────
    def _record_error(label: str, err: str) -> None:
        nonlocal channels_errored
        result["errors"].append(f"{label}: {err}")
        channels_errored += 1
        log.warning("[Verifier%s] 硬错误（不计入搜索）: %s", label, err)

    def _record_searched(label: str) -> None:
        nonlocal channels_searched
        channels_searched += 1
        log.info("[Verifier%s] 搜索完成（未命中）", label)

    # ① CVE Tracker SHA 全文搜索 ────────────────────────────────────────────────
    cve_hits, err1 = _sha_in_cve_tracker(commit_sha)
    if err1:
        _record_error("①", err1)
    else:
        _record_searched("①")
        if cve_hits:
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "cve_tracker",
                "evidence": f"commit {short} 在 CVE Tracker 中被引用: {', '.join(cve_hits)}",
            })
            log.info("[Verifier①] ✓ 已回推: %s", result["evidence"])
            pkg_cves, _ = _query_cve_tracker(pkg_name)
            result["pkg_cves"] = pkg_cves
            return result

    # ① 包级 CVE 列表（辅助上下文，失败不计入核验计数）
    pkg_cves, _ = _query_cve_tracker(pkg_name)
    result["pkg_cves"] = pkg_cves

    # ② changelogs.ubuntu.com ────────────────────────────────────────────────
    changelog, err2 = _fetch_changelog(pkg_name, ubuntu_ver)
    if err2 == "network_error":
        _record_error("②", err2)
    elif changelog:
        _record_searched("②")
        if _sha_in_text(changelog, commit_sha):
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "changelog",
                "evidence": f"commit {short} 在 Debian changelog 中被引用",
            })
            log.info("[Verifier②] ✓ 已回推（changelog）")
            return result
    else:
        # not_found 或其他：资源不存在，不算硬错误也不算有效搜索
        log.info("[Verifier②] changelog 不存在或获取失败，跳过")

    # ③ Launchpad source diff ────────────────────────────────────────────────
    patch_text, err3 = _launchpad_patch_text(pkg_name, ubuntu_ver)
    if err3 == "network_error":
        _record_error("③", err3)
    elif patch_text:
        _record_searched("③")
        if _sha_in_text(patch_text, commit_sha):
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "launchpad_diff",
                "evidence": f"commit {short} 在 Launchpad source diff 中被引用",
            })
            log.info("[Verifier③] ✓ 已回推（launchpad_diff）")
            return result
    else:
        log.info("[Verifier③] Launchpad diff 不存在或获取失败，跳过")

    # ④ Launchpad web changelog（备用） ─────────────────────────────────────
    web_cl, err4 = _launchpad_web_changelog(pkg_name)
    if err4 == "network_error":
        _record_error("④", err4)
    elif web_cl:
        _record_searched("④")
        if _sha_in_text(web_cl, commit_sha):
            result.update({
                "verdict":  "Already-Backported",
                "channel":  "launchpad_web_changelog",
                "evidence": f"commit {short} 在 Launchpad web changelog 中被引用",
            })
            log.info("[Verifier④] ✓ 已回推（launchpad_web_changelog）")
            return result
    else:
        log.info("[Verifier④] Launchpad web changelog 不存在或获取失败，跳过")

    # ── 最终判定 ──────────────────────────────────────────────────────────────
    if channels_searched > 0:
        # 有通道真正搜索且未命中 → Unpatched（有依据的结论）
        result["verdict"]  = "Unpatched"
        result["evidence"] = (
            f"commit {short} 在 {channels_searched} 条有效通道中均未发现"
            + (f"（另有 {channels_errored} 条通道因网络错误失败）"
               if channels_errored else "")
        )
        log.info("[Verifier] ✗ Unpatched（%d 条通道确认）: %s  %s",
                 channels_searched, pkg_name, short)
    else:
        # 没有任何通道完成有效搜索 → 无法得出结论
        result["verdict"]  = "Verification_Failed"
        result["evidence"] = (
            f"所有通道均未完成有效搜索（{channels_errored} 条硬错误）"
            + (f": {'; '.join(result['errors'])}" if result["errors"] else "")
        )
        log.warning("[Verifier] ⚠ Verification_Failed: %s  %s  errors=%s",
                    pkg_name, short, result["errors"])

    return result


def format_verdict(v: dict) -> str:
    """供 Agent Observation 输出的可读摘要。"""
    lines = [
        f"核验结论: {v['verdict']}",
        f"证据来源: {v['channel'] or '无'}",
        f"详情: {v['evidence']}",
    ]
    if v.get("errors"):
        lines.append(f"通道错误: {'; '.join(v['errors'])}")
    if v.get("pkg_cves"):
        open_cves = [c for c in v["pkg_cves"] if c["status"] in ("needed", "open", "unknown")]
        lines.append(f"包级 CVE: 共 {len(v['pkg_cves'])} 条，其中 {len(open_cves)} 条为 open/needed")
    return "\n".join(lines)

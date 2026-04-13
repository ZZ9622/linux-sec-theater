"""
DiffHarvester
=============
克隆（或更新）上游仓库到 workspace/，提取两个版本 Tag 之间的所有 Commit，
并用轻量级敏感词过滤器只保留安全相关变更。

Tag 匹配策略（按优先级）：
  Start Tag（Ubuntu 版本）:
    1. 版本清洗 → 精确匹配 / v前缀 / 分隔符变体
    2. 末尾模糊匹配
    3. 语义最近邻（packaging.version 距离最小的 tag）
    4. 彻底失败 → 返回空列表（记录日志）

  End Tag（上游版本）:
    同上 1-3，若仍失败 → 兜底使用仓库默认主分支最新 commit（不报错）

对外暴露唯一入口：harvest(repo_url, ubuntu_ver, upstream_ver) → list[dict]
"""

import re
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import git

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
import config as cfg

log = logging.getLogger(__name__)

# ── 保留的代码文件扩展名 ───────────────────────────────────────────────────────
_CODE_EXTS = {
    ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".go", ".s", ".asm",
}

# ── 忽略的路径（非产品代码） ────────────────────────────────────────────────────
_SKIP_PATH_RE = re.compile(
    r"(^|/)("
    r"tests?/|test_|_test\.|benches?/|fuzz/|"
    r"examples?/|docs?/|\.github/|ci/|scripts?/|"
    r"vendor/|third_party/|mocks?/|fakes?/"
    r")",
    re.IGNORECASE,
)

# ── Message 层黑名单（一票否决，命中直接丢弃）─────────────────────────────────
# 这些词标志纯非安全变更：格式/文档/测试/依赖版本/风格整理。
_MSG_BLACKLIST_RE = re.compile(
    r"\b("
    r"clippy|typo|typos|typofix|"
    r"doc|docs|document|documentation|comment|"
    r"format|fmt|style|whitespace|"
    r"chore|cleanup|refactor|refactoring|reformat|reorgani[sz]e|"
    r"test|tests|testing|benchmark|bench|ci|"
    r"changelog|readme|license|copyright|"
    r"bump|update.deps?|upgrade.deps?|"
    r"spelling|grammar|"
    r"memory.leak|resource.leak|goroutine.leak"
    r")\b",
    re.IGNORECASE,
)

# ── Message 层白名单（加分项，命中则记录为"msg_hit"）────────────────────────
# 这些词在 Commit Message 中直接暗示安全相关变更。
_MSG_WHITELIST_RE = re.compile(
    r"\b("
    r"use.after.free|uaf|double.free|"
    r"out.of.bounds|oob|"
    r"overflow|underflow|"
    r"type.confusion|"
    r"memory.corruption|"
    r"race.condition|data.race|"
    r"CVE|GHSA|"
    r"security|secure|"
    r"vuln|vulnerability|"
    r"null.deref|nullptr|nil.deref|"
    r"corrupt|corruption|"
    r"use.after|heap.overflow|stack.overflow|stack.exhaustion|"
    r"integer.overflow|integer.underflow|truncat"
    r")\b",
    re.IGNORECASE,
)

# ── Diff Payload 层代码特征正则（扫描 +/- 行，若 Message 无白名单命中才启用）
# 捕捉"静默补丁"：Message 无害但代码改动涉及安全敏感模式。
_DIFF_SIGNAL_RE = re.compile(
    r"(?mx)"                            # 多行 + verbose
    r"^[-+].*"                          # 只看 +/- 行
    r"("
    # Rust 高危模式（不含 unwrap/expect，它们是常见的 refactor 噪音）
    r"get_unchecked"                    # 不安全 slice 访问
    r"|unsafe\s*\{"                     # unsafe 块
    r"|as_ptr|from_raw_parts"           # 原始指针操作
    r"|checked_add|checked_sub|checked_mul"   # 显式溢出检查（防护增删）
    r"|wrapping_add|saturating_"        # 整数语义变更
    # Go 高危模式
    r"|unsafe\.Pointer"
    r"|uintptr"
    r"|syscall\."
    # 通用边界/内存模式
    r"|out.of.bounds|oob"
    r"|overflow|underflow"
    r"|stack.overflow|stack.exhaustion|heap.overflow"
    r"|memcpy|memmove|memset"           # C 内存函数
    r"|free\(|malloc\(|realloc\("       # C 内存分配
    r"|use.after.free|double.free"      # 显式 UAF/DF 注释或变量名
    r")"
)

# 体积熔断阈值：单 commit +/- 行数超过此值视为 Feature 合并，直接跳过
_MAX_DIFF_LINES = 300


# ── 版本号清洗 ─────────────────────────────────────────────────────────────────

def _sanitize_version(raw: str) -> str:
    """
    去除 Debian/Ubuntu 特有后缀，提取纯数字版本。
    '5.29.2-2'                → '5.29.2'
    '1.2.0+git20160825.89.7' → '1.2.0'
    '0.21.0-0ubuntu1+ds1'    → '0.21.0'
    '3:6.9.12.98+dfsg1'      → '6.9.12.98'
    """
    v = raw.strip().lstrip("v")
    v = re.sub(r"^\d+:", "", v)          # 去 epoch（如 3:）
    v = re.sub(r"[+~].*$", "", v)        # 去 +dfsg / ~beta 及其后
    v = re.sub(r"-.*$", "", v)           # 去 Debian revision（-0ubuntu1 等）
    return v.strip()


def _tag_numeric(tag_name: str) -> str:
    """从 tag 名提取纯数字版本部分（去前缀 v/release- 等）。"""
    t = tag_name.lstrip("v")
    t = re.sub(r"^[a-zA-Z_-]+", "", t)  # 去掉 release- 等前缀
    return t


# ── git 工具 ───────────────────────────────────────────────────────────────────

_TREE_BLOB_RE = re.compile(r"/(?:tree|blob)/")


def _normalize_repo_url(url: str) -> tuple[str, str]:
    """
    检测并规范化包含 /tree/ 或 /blob/ 的 GitHub URL。
    返回 (clean_root_url, subdir) 元组。

    示例:
      "https://github.com/user/repo/tree/main/sub/path"
        → ("https://github.com/user/repo", "sub/path")
      "https://github.com/user/repo"
        → ("https://github.com/user/repo", "")
    """
    raw = url.strip().split("?", 1)[0].split("#", 1)[0].rstrip("/")
    m = _TREE_BLOB_RE.search(raw)
    if m:
        root = raw[:m.start()].rstrip("/")
        remainder = raw[m.end():].strip("/")
        subdir = ""
        if remainder:
            parts = remainder.split("/", 1)
            subdir = (parts[1] if len(parts) > 1 else "").strip("/")

        parsed = urlsplit(root)
        if parsed.scheme in {"http", "https"} and parsed.netloc.endswith("github.com") and not root.endswith(".git"):
            root = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + ".git", "", ""))
        log.info(
            "[DiffHarvester] URL 规范化: %s → root=%s subdir=%s",
            url, root, subdir,
        )
        return root, subdir
    return raw, ""


def _local_dir(repo_url: str) -> Path:
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    name = re.sub(r"[^\w-]", "_", name)
    return cfg.WORKSPACE_DIR / name


def _clone_url(repo_url: str) -> str:
    """将仓库根地址转换为适合 git clone 的传输 URL。"""
    if repo_url.startswith(("http://", "https://")):
        if repo_url.startswith(("https://github.com/", "http://github.com/")):
            return repo_url if repo_url.endswith(".git") else f"{repo_url}.git"
    return repo_url


def _purge_apple_doubles(repo_path: Path) -> None:
    """删除 macOS 在 exFAT/非 HFS 卷上自动生成的 ._ 伴侣文件（会污染 git 对象目录）。"""
    for f in repo_path.rglob("._*"):
        try:
            f.unlink()
        except Exception:
            pass


def _clean_apple_doubles(local: Path) -> None:
    """用 dot_clean（若存在）或手动删除清理仓库内的 ._ 伴侣文件。"""
    if shutil.which("dot_clean"):
        try:
            subprocess.run(["dot_clean", str(local)], check=False, capture_output=True)
            log.debug("[DiffHarvester] dot_clean 完成: %s", local)
        except Exception as e:
            log.debug("[DiffHarvester] dot_clean 失败（非致命）: %s", e)
    else:
        _purge_apple_doubles(local / ".git" / "objects" / "pack")


def _clone_or_update(repo_url: str, local: Path) -> git.Repo:
    if local.exists():
        log.info("[DiffHarvester] 更新已有克隆: %s", local)
        repo = git.Repo(local)
        try:
            repo.remotes.origin.fetch(tags=True)
        except git.GitCommandError as e:
            log.debug("[DiffHarvester] fetch 警告（非致命）: %s", e)
    else:
        clone_url = _clone_url(repo_url)
        log.info("[DiffHarvester] 克隆 %s → %s", clone_url, local)
        repo = git.Repo.clone_from(clone_url, local)
    _clean_apple_doubles(local)
    return repo


def _default_branch_tip(repo: git.Repo) -> Optional[git.Commit]:
    """返回仓库默认主分支的最新 commit（HEAD / main / master）。"""
    for ref_name in ("HEAD", "origin/main", "origin/master",
                     "origin/HEAD", "refs/remotes/origin/main",
                     "refs/remotes/origin/master"):
        try:
            return repo.commit(ref_name)
        except Exception:
            pass
    # 最后兜底：取最新 commit
    try:
        return next(repo.iter_commits())
    except Exception:
        return None


# ── Tag 匹配（全策略） ─────────────────────────────────────────────────────────

def _find_tag_fuzzy(
    repo: git.Repo,
    version: str,
    label: str = "",
) -> Optional[git.TagReference]:
    """
    多策略 tag 查找，返回最佳匹配或 None。

    策略顺序：
      1. 原始字符串精确匹配
      2. 版本清洗后精确匹配 / v前缀 / 下划线/连字符变体
      3. tag 名末尾模糊匹配（兼容 release/v1.2.3）
      4. 语义最近邻：用 packaging.version 找数字最接近的 tag
    """
    tag_list = list(repo.tags)
    if not tag_list:
        return None

    tag_map = {t.name: t for t in tag_list}
    clean = _sanitize_version(version)
    ver_no_v = version.lstrip("v")

    # ① 精确候选集
    candidates = list(dict.fromkeys([
        version,
        f"v{ver_no_v}",
        ver_no_v,
        clean,
        f"v{clean}",
        clean.replace(".", "_"),
        clean.replace(".", "-"),
    ]))
    for c in candidates:
        if c in tag_map:
            log.info("[DiffHarvester] %s tag 精确匹配: %s → %s", label, version, c)
            return tag_map[c]

    # ② 末尾模糊匹配
    for name, tag in tag_map.items():
        num = _tag_numeric(name)
        if num and (num == clean or num == ver_no_v):
            log.info("[DiffHarvester] %s tag 末尾匹配: %s → %s", label, version, name)
            return tag

    # ③ 语义最近邻（packaging.version）
    try:
        from packaging.version import Version, InvalidVersion

        target = Version(clean)
        best_tag = None
        best_dist = None

        for tag in tag_list:
            try:
                tv = Version(_tag_numeric(tag.name))
                # 只选 ≤ target 的 tag（避免选到比目标更新的版本）
                if tv > target:
                    continue
                dist = target.major * 10000 + target.minor * 100 + target.micro \
                     - tv.major * 10000 - tv.minor * 100 - tv.micro
                if best_dist is None or dist < best_dist:
                    best_dist = dist
                    best_tag = tag
            except (InvalidVersion, Exception):
                pass

        if best_tag and best_dist is not None and best_dist <= 9999:
            log.info(
                "[DiffHarvester] %s tag 语义最近邻: %s → %s (dist=%d)",
                label, version, best_tag.name, best_dist,
            )
            return best_tag
    except ImportError:
        pass

    log.warning("[DiffHarvester] %s tag 所有策略均失败: version=%s", label, version)
    return None


# ── Diff 提取 ─────────────────────────────────────────────────────────────────

def _is_code_file(path: str) -> bool:
    if _SKIP_PATH_RE.search(path):
        return False
    return Path(path).suffix in _CODE_EXTS


def _filter_raw_diff(raw_patch: str, subdir: str = "") -> str:
    """从 git show 的原始 patch 文本中，过滤出代码文件的 diff 块。
    若 subdir 不为空，则只保留该子目录下的文件变更。
    """
    chunks = []
    total = 0
    for section in re.split(r"(?=^diff --git )", raw_patch, flags=re.MULTILINE):
        if not section.strip():
            continue
        m = re.search(r"^diff --git a/\S+ b/(\S+)", section, re.MULTILINE)
        if not m:
            continue
        path = m.group(1)
        if subdir and not path.startswith(subdir + "/") and path != subdir:
            continue
        if not _is_code_file(path):
            continue
        chunks.append(section)
        total += len(section)
        if total >= cfg.MAX_DIFF_CHARS:
            chunks.append("\n... [diff 已截断，超过字符上限] ...\n")
            break
    return "\n".join(chunks)


# ── 公开接口 ──────────────────────────────────────────────────────────────────

def harvest(
    repo_url: str,
    ubuntu_ver: str,
    upstream_ver: str,
    max_scan: int = 300,
) -> list[dict]:
    """
    克隆/更新仓库，返回 ubuntu_ver..upstream_ver 范围内
    通过敏感词过滤的 commit 列表。

    每个元素结构：
    {
        "sha":        "abcdef1234567890...",
        "short_sha":  "abcdef12",
        "message":    "fix: prevent integer overflow in parse_header",
        "author":     "Alice <alice@example.com>",
        "date":       "2024-03-15",
        "diff":       "<unified diff, 已截断>",
        "signals":    ["overflow", "fix"],
        "_start_ref": "v0.21.0",   # 实际使用的起始 ref
        "_end_ref":   "v0.24.2",   # 实际使用的终止 ref
    }
    """
    # ── URL 规范化：剥离 /tree/ 或 /blob/ 子路径 ────────────────────────────────
    clean_url, target_subdir = _normalize_repo_url(repo_url)

    local = _local_dir(clean_url)
    try:
        repo = _clone_or_update(clean_url, local)
    except git.GitCommandError as e:
        log.error("[DiffHarvester] git 操作失败: %s", e)
        return []

    # ── Start Tag（Ubuntu 版本）────────────────────────────────────────────────
    start_tag = _find_tag_fuzzy(repo, ubuntu_ver, label="Start")
    if not start_tag:
        log.warning(
            "[DiffHarvester] 无法为 Ubuntu 版本 '%s' 找到任何 tag，放弃扫描 %s",
            ubuntu_ver, repo_url,
        )
        return []   # start 找不到 → 无法定义扫描起点，只能放弃

    start_commit = start_tag.commit

    # ── End Tag（上游版本，失败则兜底用 HEAD）─────────────────────────────────
    end_tag = _find_tag_fuzzy(repo, upstream_ver, label="End")
    if end_tag:
        end_commit = end_tag.commit
        end_ref    = end_tag.name
    else:
        log.warning(
            "[DiffHarvester] 找不到上游版本 '%s' 的 tag，兜底使用默认主分支最新 commit",
            upstream_ver,
        )
        end_commit = _default_branch_tip(repo)
        if not end_commit:
            log.error("[DiffHarvester] 无法获取仓库默认分支最新 commit，放弃")
            return []
        end_ref = f"HEAD({end_commit.hexsha[:8]})"

    log.info(
        "[DiffHarvester] 扫描范围: %s(%s)..%s(%s)",
        start_tag.name, start_commit.hexsha[:8],
        end_ref,        end_commit.hexsha[:8],
    )

    # ── 原生 git log 提取 SHA 列表（绕过 GitPython Annotated Tag 缺陷）─────────
    # 使用 tag 名称（而非 hexsha）让 git 二进制正确解引用 Annotated Tag
    log_range = f"{start_tag.name}..{end_tag.name if end_tag else end_commit.hexsha}"
    log_args  = [log_range, "--no-merges"]
    if target_subdir:
        log_args += ["--", target_subdir]
        log.info("[DiffHarvester] 限定扫描子目录: %s", target_subdir)
    try:
        raw_shas = [s for s in repo.git.rev_list(*log_args).splitlines() if s.strip()]
    except git.GitCommandError as e:
        log.error("[DiffHarvester] git rev-list 失败: %s", e)
        return []

    raw_shas = raw_shas[:max_scan]
    log.info("[DiffHarvester] 找到 %d 个 commits 等待扫描", len(raw_shas))
    print(f"[DiffHarvester] 找到 {len(raw_shas)} 个 commits 等待扫描")

    # ── 多维度启发式过滤 ───────────────────────────────────────────────────────
    kept           = []
    n_blacklisted  = 0
    n_size_skipped = 0
    n_msg_hit      = 0
    n_code_hit     = 0
    n_no_signal    = 0

    for sha in raw_shas:
        try:
            sha8 = sha[:8]

            # 原生 git show：一次调用同时获取 author / date / message / patch
            # 格式: 第1行=author, 第2行=date, 第3行起=commit body, 之后=diff
            raw_show = repo.git.show(
                sha,
                "--format=%an <%ae>\n%cd\n%B",
                "--patch",
                "--date=short",
            )

            # 分离 header（author+date+msg）和 diff 部分
            diff_pos = raw_show.find("\ndiff --git ")
            if diff_pos == -1:
                header    = raw_show
                raw_patch = ""
            else:
                header    = raw_show[:diff_pos]
                raw_patch = raw_show[diff_pos:]

            header_lines = header.splitlines()
            author     = header_lines[0] if header_lines else ""
            date       = header_lines[1] if len(header_lines) > 1 else ""
            msg        = "\n".join(header_lines[2:]).strip() if len(header_lines) > 2 else ""
            first_line = msg.splitlines()[0][:80] if msg else ""

            # ── Step 1: Message 黑名单（一票否决）────────────────────────────────
            if _MSG_BLACKLIST_RE.search(msg):
                n_blacklisted += 1
                log.debug("[DiffHarvester] ✗ 黑名单  [%s] %s", sha8, first_line)
                continue

            # ── Step 2: Message 白名单扫描 ────────────────────────────────────────
            msg_hits = list({m.group(1).lower()
                             for m in _MSG_WHITELIST_RE.finditer(msg)})

            # ── Step 3: 过滤 Diff（只保留代码文件和指定子目录）────────────────────
            diff = _filter_raw_diff(raw_patch, subdir=target_subdir)
            if not diff:
                log.debug("[DiffHarvester] ✗ 无代码diff [%s] %s", sha8, first_line)
                continue

            # ── Step 4: 体积熔断（+/- 行数超过阈值 → 视为 Feature 合并，跳过）────
            diff_lines = sum(
                1 for line in diff.splitlines()
                if line.startswith(("+", "-"))
                and not line.startswith(("+++", "---"))
            )
            if diff_lines > _MAX_DIFF_LINES:
                n_size_skipped += 1
                log.info(
                    "[DiffHarvester] ✗ 体积熔断 [%s] %d 行变动 > %d 阈值  %s",
                    sha8, diff_lines, _MAX_DIFF_LINES, first_line,
                )
                continue

            # ── Step 5: 决策 ─────────────────────────────────────────────────────
            if msg_hits:
                # Message 层命中白名单 → 直接收录
                selection_reason = f"msg:{'+'.join(sorted(msg_hits))}"
                signals          = msg_hits
                n_msg_hit       += 1
                log.info(
                    "[DiffHarvester] ✓ MSG命中  [%s] signals=%s  %s",
                    sha8, signals, first_line,
                )
            else:
                # Message 无白名单命中 → 扫描 Diff Payload 代码特征
                code_hits = list({
                    m.group(1)
                    for m in _DIFF_SIGNAL_RE.finditer(diff)
                    if m.group(1)
                })
                if not code_hits:
                    n_no_signal += 1
                    log.debug(
                        "[DiffHarvester] ✗ 无信号   [%s] %s", sha8, first_line,
                    )
                    continue
                selection_reason = f"code:{'+'.join(sorted(set(code_hits)))}"
                signals          = [s.strip("+-. ") for s in code_hits[:6]]
                n_code_hit      += 1
                log.info(
                    "[DiffHarvester] ✓ CODE命中 [%s] patterns=%s  %s",
                    sha8, code_hits[:4], first_line,
                )

            kept.append({
                "sha":              sha,
                "short_sha":        sha8,
                "message":          msg,
                "author":           author,
                "date":             date,
                "diff":             diff,
                "diff_lines":       diff_lines,
                "signals":          signals,
                "selection_reason": selection_reason,
                "_start_ref":       start_tag.name,
                "_end_ref":         end_ref,
            })

        except Exception as e:
            log.warning("[DiffHarvester] 跳过坏损 commit %s: %s", sha[:8], e)
            continue

    log.info(
        "[DiffHarvester] 扫描 %d commits → 保留 %d  "
        "（黑名单=%d 体积熔断=%d msg命中=%d code命中=%d 无信号=%d）",
        len(raw_shas), len(kept),
        n_blacklisted, n_size_skipped, n_msg_hit, n_code_hit, n_no_signal,
    )
    return kept


def summarise(commits: list[dict]) -> str:
    """供 Agent Observation 打印的简洁摘要，包含每个 commit 的选中原因。"""
    if not commits:
        return "未找到含敏感词的 commit。"
    lines = [f"发现 {len(commits)} 个安全相关 commit："]
    for c in commits[:cfg.MAX_COMMITS_PER_AUDIT]:
        first_line = c["message"].splitlines()[0][:72]
        reason     = c.get("selection_reason", "?")
        diff_lines = c.get("diff_lines", "?")
        lines.append(
            f"  [{c['short_sha']}] {c['date']}  +/-{diff_lines}行"
            f"  [{reason}]  {first_line}"
        )
    if len(commits) > cfg.MAX_COMMITS_PER_AUDIT:
        lines.append(f"  ... 还有 {len(commits) - cfg.MAX_COMMITS_PER_AUDIT} 个未显示")
    if commits:
        lines.append(
            f"\n扫描范围: {commits[0].get('_start_ref','')} .. {commits[0].get('_end_ref','')}"
        )
    return "\n".join(lines)

"""
DiffHarvester
=============
Clones (or updates) the upstream repository into workspace/, extracts all
commits between two version tags, and retains only security-relevant changes
using a lightweight keyword filter.

Tag matching strategy (in priority order):
  Start Tag (Ubuntu version):
    1. Version normalization → exact match / v-prefix / separator variants
    2. Suffix fuzzy match
    3. Semantic nearest-neighbour (minimum packaging.version distance)
    4. Complete failure → return empty list (logged)

  End Tag (upstream version):
    Same steps 1-3; if still not found → fall back to latest commit on the
    repository's default branch (no error raised)

Public interface: harvest(repo_url, ubuntu_ver, upstream_ver) → list[dict]
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

# ── Code file extensions to keep ─────────────────────────────────────────────
_CODE_EXTS = {
    ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".go", ".s", ".asm",
}

# ── Paths to ignore (non-production code) ────────────────────────────────────
_SKIP_PATH_RE = re.compile(
    r"(^|/)("
    r"tests?/|test_|_test\.|benches?/|fuzz/|"
    r"examples?/|docs?/|\.github/|ci/|scripts?/|"
    r"vendor/|third_party/|mocks?/|fakes?/"
    r")",
    re.IGNORECASE,
)

# ── Message-level blacklist (disqualifies a commit outright) ─────────────────
# These keywords indicate purely non-security changes: formatting/docs/tests/
# dependency bumps/style cleanup.
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

# ── Message-level whitelist (positive signal, recorded as "msg_hit") ─────────
# These words in the commit message directly suggest a security-relevant change.
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

# ── Diff payload code signal regex (scans +/- lines; only used when message has no whitelist hit)
# Catches "silent patches": innocuous message but code touches security-sensitive patterns.
_DIFF_SIGNAL_RE = re.compile(
    r"(?mx)"                            # multiline + verbose
    r"^[-+].*"                          # only +/- lines
    r"("
    # Rust high-risk patterns (excluding unwrap/expect — common refactor noise)
    r"get_unchecked"                    # unsafe slice access
    r"|unsafe\s*\{"                     # unsafe block
    r"|as_ptr|from_raw_parts"           # raw pointer operations
    r"|checked_add|checked_sub|checked_mul"   # explicit overflow checks (added/removed)
    r"|wrapping_add|saturating_"        # integer semantics change
    # Go high-risk patterns
    r"|unsafe\.Pointer"
    r"|uintptr"
    r"|syscall\."
    # General boundary/memory patterns
    r"|out.of.bounds|oob"
    r"|overflow|underflow"
    r"|stack.overflow|stack.exhaustion|heap.overflow"
    r"|memcpy|memmove|memset"           # C memory functions
    r"|free\(|malloc\(|realloc\("       # C memory allocation
    r"|use.after.free|double.free"      # explicit UAF/DF comments or variable names
    r")"
)

# Volume circuit-breaker: commits with more than this many +/- lines are treated
# as feature merges and skipped.
_MAX_DIFF_LINES = 300


# ── Version string normalization ──────────────────────────────────────────────

def _sanitize_version(raw: str) -> str:
    """
    Strip Debian/Ubuntu-specific suffixes and extract the bare numeric version.
    '5.29.2-2'                → '5.29.2'
    '1.2.0+git20160825.89.7' → '1.2.0'
    '0.21.0-0ubuntu1+ds1'    → '0.21.0'
    '3:6.9.12.98+dfsg1'      → '6.9.12.98'
    """
    v = raw.strip().lstrip("v")
    v = re.sub(r"^\d+:", "", v)          # strip epoch (e.g. 3:)
    v = re.sub(r"[+~].*$", "", v)        # strip +dfsg / ~beta and beyond
    v = re.sub(r"-.*$", "", v)           # strip Debian revision (-0ubuntu1 etc.)
    return v.strip()


def _tag_numeric(tag_name: str) -> str:
    """Extract the bare numeric portion from a tag name (strip v/release- prefixes etc.)."""
    t = tag_name.lstrip("v")
    t = re.sub(r"^[a-zA-Z_-]+", "", t)  # strip release- and similar prefixes
    return t


# ── git utilities ─────────────────────────────────────────────────────────────

_TREE_BLOB_RE = re.compile(r"/(?:tree|blob)/")


def _normalize_repo_url(url: str) -> tuple[str, str]:
    """
    Detect and normalise GitHub URLs that contain /tree/ or /blob/ sub-paths.
    Returns a (clean_root_url, subdir) tuple.

    Examples:
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
            "[DiffHarvester] URL normalized: %s → root=%s subdir=%s",
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
    """Convert a repository root URL to a git-clone-compatible transport URL."""
    if repo_url.startswith(("http://", "https://")):
        if repo_url.startswith(("https://github.com/", "http://github.com/")):
            return repo_url if repo_url.endswith(".git") else f"{repo_url}.git"
    return repo_url


def _purge_apple_doubles(repo_path: Path) -> None:
    """Delete macOS-generated ._ companion files on exFAT/non-HFS volumes (they corrupt git objects)."""
    for f in repo_path.rglob("._*"):
        try:
            f.unlink()
        except Exception:
            pass


def _clean_apple_doubles(local: Path) -> None:
    """Clean up ._ companion files using dot_clean (if available) or manual deletion."""
    if shutil.which("dot_clean"):
        try:
            subprocess.run(["dot_clean", str(local)], check=False, capture_output=True)
            log.debug("[DiffHarvester] dot_clean complete: %s", local)
        except Exception as e:
            log.debug("[DiffHarvester] dot_clean failed (non-fatal): %s", e)
    else:
        _purge_apple_doubles(local / ".git" / "objects" / "pack")


def _clone_or_update(repo_url: str, local: Path) -> git.Repo:
    if local.exists():
        log.info("[DiffHarvester] Updating existing clone: %s", local)
        repo = git.Repo(local)
        try:
            repo.remotes.origin.fetch(tags=True)
        except git.GitCommandError as e:
            log.debug("[DiffHarvester] fetch warning (non-fatal): %s", e)
    else:
        clone_url = _clone_url(repo_url)
        log.info("[DiffHarvester] Cloning %s → %s", clone_url, local)
        repo = git.Repo.clone_from(clone_url, local)
    _clean_apple_doubles(local)
    return repo


def _default_branch_tip(repo: git.Repo) -> Optional[git.Commit]:
    """Return the latest commit on the repository's default branch (HEAD / main / master)."""
    for ref_name in ("HEAD", "origin/main", "origin/master",
                     "origin/HEAD", "refs/remotes/origin/main",
                     "refs/remotes/origin/master"):
        try:
            return repo.commit(ref_name)
        except Exception:
            pass
    # Last resort: take the most recent commit
    try:
        return next(repo.iter_commits())
    except Exception:
        return None


# ── Tag matching (all strategies) ────────────────────────────────────────────

def _find_tag_fuzzy(
    repo: git.Repo,
    version: str,
    label: str = "",
) -> Optional[git.TagReference]:
    """
    Multi-strategy tag lookup; returns the best match or None.

    Strategy order:
      1. Exact match on the raw string
      2. Exact match after version normalization / v-prefix / underscore/hyphen variants
      3. Suffix fuzzy match (handles release/v1.2.3 style)
      4. Semantic nearest-neighbour: find the numerically closest tag via packaging.version
    """
    tag_list = list(repo.tags)
    if not tag_list:
        return None

    tag_map = {t.name: t for t in tag_list}
    clean = _sanitize_version(version)
    ver_no_v = version.lstrip("v")

    # ① Exact candidates
    # Also try replacing only the *last* dot with a hyphen, e.g. 6.9.12.98 → 6.9.12-98
    # (common in ImageMagick and similar projects that use X.Y.Z-PATCH tagging)
    clean_parts = clean.rsplit(".", 1)
    last_dot_as_hyphen = f"{clean_parts[0]}-{clean_parts[1]}" if len(clean_parts) == 2 else clean
    candidates = list(dict.fromkeys([
        version,
        f"v{ver_no_v}",
        ver_no_v,
        clean,
        f"v{clean}",
        last_dot_as_hyphen,
        f"v{last_dot_as_hyphen}",
        clean.replace(".", "_"),
        clean.replace(".", "-"),
    ]))
    for c in candidates:
        if c in tag_map:
            log.info("[DiffHarvester] %s tag exact match: %s → %s", label, version, c)
            return tag_map[c]

    # ② Suffix fuzzy match — normalize separators (. / - / _) before comparing
    def _sep_normalize(s: str) -> str:
        return re.sub(r"[-_]", ".", s)

    clean_norm = _sep_normalize(clean)
    ver_norm   = _sep_normalize(ver_no_v)
    for name, tag in tag_map.items():
        num = _sep_normalize(_tag_numeric(name))
        if num and (num == clean_norm or num == ver_norm):
            log.info("[DiffHarvester] %s tag suffix match: %s → %s", label, version, name)
            return tag

    # ③ Semantic nearest-neighbour (packaging.version)
    try:
        from packaging.version import Version, InvalidVersion

        target = Version(clean)
        best_tag = None
        best_dist = None

        for tag in tag_list:
            try:
                tv = Version(_tag_numeric(tag.name))
                # Only consider tags ≤ target (avoid selecting a newer version)
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
                "[DiffHarvester] %s tag nearest-neighbour: %s → %s (dist=%d)",
                label, version, best_tag.name, best_dist,
            )
            return best_tag
    except ImportError:
        pass

    log.warning("[DiffHarvester] %s tag all strategies failed: version=%s", label, version)
    return None


# ── Diff extraction ───────────────────────────────────────────────────────────

def _is_code_file(path: str) -> bool:
    if _SKIP_PATH_RE.search(path):
        return False
    return Path(path).suffix in _CODE_EXTS


def _filter_raw_diff(raw_patch: str, subdir: str = "") -> str:
    """Filter code-file diff blocks from raw git show patch text.
    If subdir is non-empty, only keep changes under that subdirectory.
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
            chunks.append("\n... [diff truncated, character limit reached] ...\n")
            break
    return "\n".join(chunks)


# ── Public interface ──────────────────────────────────────────────────────────

def harvest(
    repo_url: str,
    ubuntu_ver: str,
    upstream_ver: str,
    max_scan: int = 300,
) -> list[dict]:
    """
    Clone/update the repository and return the list of commits in the range
    ubuntu_ver..upstream_ver that pass the security-signal filter.

    Each element has the structure:
    {
        "sha":        "abcdef1234567890...",
        "short_sha":  "abcdef12",
        "message":    "fix: prevent integer overflow in parse_header",
        "author":     "Alice <alice@example.com>",
        "date":       "2024-03-15",
        "diff":       "<unified diff, truncated>",
        "signals":    ["overflow", "fix"],
        "_start_ref": "v0.21.0",   # actual start ref used
        "_end_ref":   "v0.24.2",   # actual end ref used
    }
    """
    # ── URL normalization: strip /tree/ or /blob/ sub-paths ──────────────────
    clean_url, target_subdir = _normalize_repo_url(repo_url)

    local = _local_dir(clean_url)
    try:
        repo = _clone_or_update(clean_url, local)
    except git.GitCommandError as e:
        log.error("[DiffHarvester] git operation failed: %s", e)
        return []

    # ── Start Tag (Ubuntu version) ───────────────────────────────────────────
    start_tag = _find_tag_fuzzy(repo, ubuntu_ver, label="Start")
    if not start_tag:
        log.warning(
            "[DiffHarvester] No tag found for Ubuntu version '%s', aborting scan of %s",
            ubuntu_ver, repo_url,
        )
        return []   # no start tag → scan range undefined, must abort

    start_commit = start_tag.commit

    # ── End Tag (upstream version; fall back to HEAD on failure) ─────────────
    end_tag = _find_tag_fuzzy(repo, upstream_ver, label="End")
    if end_tag:
        end_commit = end_tag.commit
        end_ref    = end_tag.name
    else:
        log.warning(
            "[DiffHarvester] No tag found for upstream version '%s', falling back to default branch tip",
            upstream_ver,
        )
        end_commit = _default_branch_tip(repo)
        if not end_commit:
            log.error("[DiffHarvester] Could not obtain default branch tip, aborting")
            return []
        end_ref = f"HEAD({end_commit.hexsha[:8]})"

    log.info(
        "[DiffHarvester] Scan range: %s(%s)..%s(%s)",
        start_tag.name, start_commit.hexsha[:8],
        end_ref,        end_commit.hexsha[:8],
    )

    # ── Native git rev-list to extract SHA list (works around GitPython annotated-tag bug) ──
    # Use tag names (not hexsha) so git correctly dereferences annotated tags
    log_range = f"{start_tag.name}..{end_tag.name if end_tag else end_commit.hexsha}"
    log_args  = [log_range, "--no-merges"]
    if target_subdir:
        log_args += ["--", target_subdir]
        log.info("[DiffHarvester] Restricting scan to subdirectory: %s", target_subdir)
    try:
        raw_shas = [s for s in repo.git.rev_list(*log_args).splitlines() if s.strip()]
    except git.GitCommandError as e:
        log.error("[DiffHarvester] git rev-list failed: %s", e)
        return []

    raw_shas = raw_shas[:max_scan]
    log.info("[DiffHarvester] Found %d commits pending scan", len(raw_shas))
    print(f"[DiffHarvester] Found {len(raw_shas)} commits pending scan")

    # ── Multi-dimensional heuristic filter ───────────────────────────────────
    kept           = []
    n_blacklisted  = 0
    n_size_skipped = 0
    n_msg_hit      = 0
    n_code_hit     = 0
    n_no_signal    = 0

    for sha in raw_shas:
        try:
            sha8 = sha[:8]

            # Native git show: get author / date / message / patch in one call
            # Format: line 1 = author, line 2 = date, line 3+ = commit body, then diff
            raw_show = repo.git.show(
                sha,
                "--format=%an <%ae>\n%cd\n%B",
                "--patch",
                "--date=short",
            )

            # Split header (author+date+msg) from diff
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

            # ── Step 1: Message blacklist (disqualifies outright) ─────────────
            if _MSG_BLACKLIST_RE.search(msg):
                n_blacklisted += 1
                log.debug("[DiffHarvester] x blacklist  [%s] %s", sha8, first_line)
                continue

            # ── Step 2: Message whitelist scan ────────────────────────────────
            msg_hits = list({m.group(1).lower()
                             for m in _MSG_WHITELIST_RE.finditer(msg)})

            # ── Step 3: Filter diff (keep only code files and target subdir) ──
            diff = _filter_raw_diff(raw_patch, subdir=target_subdir)
            if not diff:
                log.debug("[DiffHarvester] x no code diff [%s] %s", sha8, first_line)
                continue

            # ── Step 4: Volume circuit-breaker (+/- lines > threshold → feature merge, skip) ──
            diff_lines = sum(
                1 for line in diff.splitlines()
                if line.startswith(("+", "-"))
                and not line.startswith(("+++", "---"))
            )
            if diff_lines > _MAX_DIFF_LINES:
                n_size_skipped += 1
                log.info(
                    "[DiffHarvester] x size-breaker [%s] %d lines > %d threshold  %s",
                    sha8, diff_lines, _MAX_DIFF_LINES, first_line,
                )
                continue

            # ── Step 5: Decision ──────────────────────────────────────────────
            if msg_hits:
                # Message whitelist hit → accept immediately
                selection_reason = f"msg:{'+'.join(sorted(msg_hits))}"
                signals          = msg_hits
                n_msg_hit       += 1
                log.info(
                    "[DiffHarvester] + MSG hit  [%s] signals=%s  %s",
                    sha8, signals, first_line,
                )
            else:
                # No message whitelist hit → scan diff payload for code signals
                code_hits = list({
                    m.group(1)
                    for m in _DIFF_SIGNAL_RE.finditer(diff)
                    if m.group(1)
                })
                if not code_hits:
                    n_no_signal += 1
                    log.debug(
                        "[DiffHarvester] x no signal   [%s] %s", sha8, first_line,
                    )
                    continue
                selection_reason = f"code:{'+'.join(sorted(set(code_hits)))}"
                signals          = [s.strip("+-. ") for s in code_hits[:6]]
                n_code_hit      += 1
                log.info(
                    "[DiffHarvester] + CODE hit [%s] patterns=%s  %s",
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
            log.warning("[DiffHarvester] Skipping corrupt commit %s: %s", sha[:8], e)
            continue

    log.info(
        "[DiffHarvester] Scanned %d commits → kept %d  "
        "(blacklisted=%d size_skipped=%d msg_hit=%d code_hit=%d no_signal=%d)",
        len(raw_shas), len(kept),
        n_blacklisted, n_size_skipped, n_msg_hit, n_code_hit, n_no_signal,
    )
    return kept


def summarise(commits: list[dict]) -> str:
    """Concise summary for Agent Observation output, including selection reason per commit."""
    if not commits:
        return "No commits with security signals found."
    lines = [f"Found {len(commits)} security-relevant commits:"]
    for c in commits[:cfg.MAX_COMMITS_PER_AUDIT]:
        first_line = c["message"].splitlines()[0][:72]
        reason     = c.get("selection_reason", "?")
        diff_lines = c.get("diff_lines", "?")
        lines.append(
            f"  [{c['short_sha']}] {c['date']}  +/-{diff_lines} lines"
            f"  [{reason}]  {first_line}"
        )
    if len(commits) > cfg.MAX_COMMITS_PER_AUDIT:
        lines.append(f"  ... {len(commits) - cfg.MAX_COMMITS_PER_AUDIT} more not shown")
    if commits:
        lines.append(
            f"\nScan range: {commits[0].get('_start_ref','')} .. {commits[0].get('_end_ref','')}"
        )
    return "\n".join(lines)


# ── Phase 1: GLM Semantic Filter ─────────────────────────────────────────────

_CLASSIFY_SYSTEM = (
    "You are a security-focused code reviewer. "
    "Classify git commits as security fixes or not. "
    "Respond ONLY with a single valid JSON object — no markdown, no prose."
)

_CLASSIFY_TEMPLATE = """\
Analyze this git commit and determine whether it fixes a security vulnerability.

Look specifically for these indicators (paper Phase 1 criteria):
  • Bounds checking added or tightened
  • Pointer / null validation inserted
  • State machine corrections preventing invalid transitions
  • Integer overflow / underflow guards
  • Memory safety fixes (use-after-free, double-free, out-of-bounds)
  • Input validation for externally-supplied data

Commit message:
{message}

Code diff (key lines):
{diff}

Respond ONLY with this JSON (no extra fields, no markdown):
{{
  "is_security_fix": true,
  "confidence": "high",
  "fix_type": "bounds_check|pointer_validation|state_machine|integer_overflow|memory_safety|input_validation|none|other",
  "brief_reason": "one sentence"
}}"""


def glm_filter(commits: list[dict], client: object) -> list[dict]:
    """
    Phase 1 — GLM Semantic Filter.

    Second-pass filter applied after the regex heuristics in harvest().
    Uses GLM-5 to classify each candidate commit as a genuine security fix
    or a non-security change.

    Retention policy:
      • GLM says is_security_fix=True (any confidence)  → KEEP
      • GLM says is_security_fix=False, confidence=low  → KEEP (uncertain)
      • GLM says is_security_fix=False, confidence≠low  → DROP
      • GLM call or parse failure                       → KEEP (fail-safe)

    Each kept commit receives a ``glm_classification`` dict with at least:
      {"is_security_fix": bool, "confidence": str, "fix_type": str,
       "brief_reason": str, "kept": bool}
    """
    import json as _json

    kept: list[dict] = []

    for commit in commits:
        sha8   = commit.get("short_sha", commit.get("sha", "")[:8])
        msg    = commit.get("message", "")[:400]
        diff   = commit.get("diff", "")[:1800]
        prompt = _CLASSIFY_TEMPLATE.format(message=msg, diff=diff)

        cls: dict = {}
        try:
            resp = client.chat.completions.create(  # type: ignore[attr-defined]
                model           = cfg.ZAI_MODEL,
                temperature     = 0.0,
                response_format = {"type": "json_object"},
                messages=[
                    {"role": "system", "content": _CLASSIFY_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
            )
            raw = resp.choices[0].message.content or "{}"
            cls = _json.loads(raw.strip())
        except Exception as exc:
            log.warning("[GLMFilter] SHA=%s classify failed: %s — keeping commit", sha8, exc)
            commit["glm_classification"] = {"error": str(exc), "kept": True}
            kept.append(commit)
            continue

        is_fix   = bool(cls.get("is_security_fix", True))
        conf     = str(cls.get("confidence", "low"))
        fix_type = cls.get("fix_type", "other")
        reason   = cls.get("brief_reason", "")

        keep = is_fix or conf == "low"
        cls["kept"] = keep
        commit["glm_classification"] = cls

        if is_fix:
            log.info("[GLMFilter] KEEP  SHA=%s  fix_type=%-22s  conf=%-6s  %s",
                     sha8, fix_type, conf, reason[:60])
            kept.append(commit)
        elif conf == "low":
            log.info("[GLMFilter] KEEP? SHA=%s  uncertain (conf=low)  %s", sha8, reason[:60])
            kept.append(commit)
        else:
            log.info("[GLMFilter] DROP  SHA=%s  conf=%-6s  %s", sha8, conf, reason[:60])

    log.info("[GLMFilter] %d / %d commits retained after GLM semantic filter",
             len(kept), len(commits))
    return kept

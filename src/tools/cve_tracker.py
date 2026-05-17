"""
cve_tracker.py  –  External CVE / advisory cross-validation for CDSFA-Audit.

Ground-truth checks that a commit flagged as "silent at commit time" has or has
not subsequently been assigned a CVE, covered by an Ubuntu Security Notice (USN),
or patched in Ubuntu 24.04 (Noble) via the Ubuntu security tracker and Launchpad.

Public API
----------
lookup_cve_for_commit(pkg_name, commit_sha, commit_message, affected_funcs)
    → dict with cve_assigned, cve_ids, cve_assignment_date, usn_published, usn_ids

check_ubuntu_patch_status(pkg_name, ver_2404_recorded, cve_ids)
    → dict with ubuntu_2404_actually_patched, ubuntu_2404_patch_method,
             ubuntu_2404_current_version
"""

import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional

from .version_gap_finder import resolve_source_package_name

log = logging.getLogger(__name__)

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    log.warning("'requests' not installed — external CVE lookup will be skipped")

# ── External API endpoints ────────────────────────────────────────────────────
_NVD_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_UBUNTU_CVES_URL  = "https://ubuntu.com/security/cves.json"
_LAUNCHPAD_ARCH   = "https://api.launchpad.net/1.0/ubuntu/+archive/primary"
_OSV_URL          = "https://api.osv.dev/v1/query"   # covers GHSA, OSS-Fuzz, Debian, etc.

_NOBLE            = "noble"        # Ubuntu 24.04 LTS codename
_NVD_DELAY        = 0.7            # seconds between NVD requests (5 req/30 s limit)

# ── Shared session ─────────────────────────────────────────────────────────────
_SESSION: Optional[object] = None

def _session():
    global _SESSION
    if not _HAS_REQUESTS:
        return None
    if _SESSION is None:
        s = _requests.Session()
        s.headers.update({"User-Agent": "CDSFA-Audit/1.0 (security-research)"})
        _SESSION = s
    return _SESSION


def _get(url: str, params: dict | None = None, timeout: int = 15) -> Optional[dict]:
    s = _session()
    if s is None:
        return None
    try:
        r = s.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        log.debug("HTTP GET %s → %s", url, exc)
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mention_check_strict(short_sha: str, text: str) -> bool:
    """SHA-only match. Function-name match is intentionally dropped because
    common function names produce false positives for packages with many
    historical CVEs (e.g. ffmpeg codec functions)."""
    return bool(short_sha) and short_sha.lower() in text.lower()


def _nvd_search(keyword: str, pkg_name: str) -> list[dict]:
    """Single NVD keyword query, filtered to results mentioning pkg_name."""
    data = _get(_NVD_URL, {"keywordSearch": keyword, "resultsPerPage": 10})
    if not data:
        return []
    hits = []
    pkg_l = pkg_name.lower().rstrip("-dev").rstrip("-devel")
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        en_descs = " ".join(
            d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"
        ).lower()
        ref_urls = " ".join(r.get("url", "") for r in cve.get("references", [])).lower()
        if pkg_l in en_descs or pkg_l in ref_urls:
            hits.append(cve)
    return hits


def _ubuntu_cves_for_pkg(pkg_name: str) -> list[dict]:
    """Fetch CVE list from the Ubuntu security tracker for a given package."""
    src = resolve_source_package_name(pkg_name)
    data = _get(_UBUNTU_CVES_URL, {"package": src, "limit": 500})
    if data is None:
        return []
    return data if isinstance(data, list) else data.get("cves", [])


def _ubuntu_cves_search_by_sha(short_sha: str) -> list[dict]:
    """
    Search the Ubuntu CVE tracker for CVEs that mention a commit SHA directly.

    Query: https://ubuntu.com/security/cves.json?q={short_sha}&limit=50
    Returns a list of CVE dicts that mention the SHA in their text.
    """
    if not short_sha:
        return []
    data = _get(_UBUNTU_CVES_URL, {"q": short_sha, "limit": 50})
    if data is None:
        return []
    candidates = data if isinstance(data, list) else data.get("cves", [])
    # Filter to only CVEs that actually contain the SHA somewhere in their text.
    result = []
    for entry in candidates:
        blob = " ".join([
            entry.get("id", ""),
            entry.get("description", ""),
            entry.get("references", ""),
        ])
        if _mention_check_strict(short_sha, blob):
            result.append(entry)
    return result


def _launchpad_current_version(pkg_name: str) -> Optional[str]:
    """Return the most recent Noble source version, checking Security/Updates/Release pockets."""
    src = resolve_source_package_name(pkg_name)
    for pocket in ("Security", "Updates", "Release"):
        data = _get(_LAUNCHPAD_ARCH, {
            "ws.op":         "getPublishedSources",
            "source_name":   src,
            "status":        "Published",
            "distro_series": f"/ubuntu/{_NOBLE}",
            "pocket":        pocket,
        })
        if not data:
            continue
        entries = data.get("entries", [])
        if entries:
            return entries[0].get("source_package_version")
    return None


def _fetch_cve_detail(cve_id: str) -> Optional[dict]:
    """Fetch single-CVE detail (per-release status + linked USNs) from Ubuntu security tracker."""
    return _get(f"https://ubuntu.com/security/cves/{cve_id}.json")


def _usn_data_for_cve(cve_id: str) -> tuple[list[str], Optional[str]]:
    """Return (usn_ids, earliest_published_date) for a CVE via Ubuntu notices API."""
    data = _get("https://ubuntu.com/security/notices.json", {"cves": cve_id, "limit": 20})
    if not data:
        return [], None
    notices = data if isinstance(data, list) else data.get("notices", [])
    ids   = [n.get("id", "") for n in notices if n.get("id")]
    dates = [n.get("published", "")[:10] for n in notices if n.get("published")]
    return ids, (min(dates) if dates else None)


def _noble_status_from_detail(detail: dict) -> Optional[str]:
    """Extract Noble (24.04) patch status from a single-CVE detail JSON."""
    for pkg in detail.get("packages", []):
        for s in pkg.get("statuses", []):
            if s.get("release_codename") == _NOBLE:
                return s.get("status")
    for s in detail.get("statuses", []):
        if s.get("release_codename") == _NOBLE:
            return s.get("status")
    return None


def _osv_search_commit(commit_sha: str) -> list[dict]:
    """Query OSV by commit, then filter to only vulns whose 'fixed' event
    matches this commit. Without this filter, OSV returns all vulns whose
    range covers the commit — i.e. all historical CVEs for that version."""
    s = _session()
    if s is None:
        return []
    try:
        r = s.post(_OSV_URL, json={"commit": commit_sha}, timeout=15)
        if not r.ok:
            return []
        vulns = r.json().get("vulns", [])
    except Exception as exc:
        log.debug("[osv] commit query for %s failed: %s", commit_sha[:12], exc)
        return []

    sha_l = commit_sha.lower()
    fixing: list[dict] = []
    for vuln in vulns:
        is_fix = False
        for aff in vuln.get("affected", []):
            for rng in aff.get("ranges", []):
                if rng.get("type") != "GIT":
                    continue
                for ev in rng.get("events", []):
                    fixed_sha = (ev.get("fixed") or "").lower()
                    if fixed_sha and (fixed_sha == sha_l or fixed_sha.startswith(sha_l[:12])):
                        is_fix = True
                        break
                if is_fix:
                    break
            if is_fix:
                break
        if is_fix:
            fixing.append(vuln)
    return fixing


_SHA_RE = re.compile(r'[/=]([0-9a-f]{12,40})(?:[/?#]|$)', re.IGNORECASE)


def _nvd_search_by_ref_url(candidate_urls: list[str]) -> list[dict]:
    """
    Reverse-lookup: find CVEs whose NVD references explicitly cite this commit.

    Correct semantic: a fix is "silent" when this returns an empty list —
    no CVE in NVD/MITRE references any of the candidate commit URLs.

    Strategy:
      a. For each candidate forge URL, keyword-search NVD and keep only CVEs
         where the commit SHA appears in a reference URL (not just in description).
      b. Also try the 12-char SHA alone — catches CVEs referencing a forge mirror
         that isn't in our candidate list (e.g. native git server).
    Results are deduplicated by CVE-ID across all searches.
    """
    if not candidate_urls:
        return []

    short_sha = ""
    for url in candidate_urls:
        m = _SHA_RE.search(url)
        if m:
            short_sha = m.group(1)[:12]
            break

    found: dict[str, dict] = {}  # cve_id → cve dict, deduplicated

    def _keep_if_sha_in_refs(cve: dict) -> None:
        cve_id = cve.get("id", "")
        if not cve_id or cve_id in found:
            return
        ref_urls = [r.get("url", "") for r in cve.get("references", [])]
        if short_sha and any(short_sha in u for u in ref_urls):
            found[cve_id] = cve

    # a. Search each candidate URL
    for url in candidate_urls[:4]:
        data = _get(_NVD_URL, {"keywordSearch": url, "resultsPerPage": 10})
        if data:
            for vuln in data.get("vulnerabilities", []):
                _keep_if_sha_in_refs(vuln.get("cve", {}))
        time.sleep(_NVD_DELAY)

    # b. SHA-only search — catches other forge mirrors NVD may reference
    if short_sha:
        data = _get(_NVD_URL, {"keywordSearch": short_sha, "resultsPerPage": 10})
        if data:
            for vuln in data.get("vulnerabilities", []):
                _keep_if_sha_in_refs(vuln.get("cve", {}))
        time.sleep(_NVD_DELAY)

    return list(found.values())


def get_ubuntu_component(pkg_name: str) -> str:
    """
    Return the Ubuntu 24.04 component (main/universe/restricted/multiverse)
    for a source package, using the Launchpad getPublishedSources API.
    The component_name field is authoritative; falls back to 'unknown' on failure.
    ESM coverage: main → esm-infra; universe → esm-apps (paid).
    """
    src = resolve_source_package_name(pkg_name)
    for pocket in ("Security", "Updates", "Release"):
        data = _get(_LAUNCHPAD_ARCH, {
            "ws.op":         "getPublishedSources",
            "source_name":   src,
            "status":        "Published",
            "distro_series": f"/ubuntu/{_NOBLE}",
            "pocket":        pocket,
        })
        if not data:
            continue
        entries = data.get("entries", [])
        if entries:
            comp = entries[0].get("component_name", "")
            if comp:
                log.debug("[component] %s → %s (pocket=%s)", pkg_name, comp, pocket)
                return comp.lower()
    log.debug("[component] %s → unknown (Launchpad returned no entry)", pkg_name)
    return "unknown"


def _debian_cve_status_from_tracker(data: dict, cve_id: str) -> Optional[str]:
    """
    Extract Debian stable (bookworm) status string from a source-package tracker
    response dict.  Returns e.g. 'bookworm:resolved' or None if not found.
    """
    entry = data.get(cve_id, {})
    if not isinstance(entry, dict):
        return None
    for release in ("bookworm", "trixie", "bullseye"):
        rel = entry.get(release, {})
        if isinstance(rel, dict):
            status = rel.get("status")
            if status:
                return f"{release}:{status}"
    return None


def _query_debian_tracker_source_package(src_pkg: str) -> tuple[Optional[dict], bool, Optional[dict]]:
    """
    Query Debian security tracker source-package endpoint with explicit failure reasons.
        Returns (data, attempted, error_reason).
            - data: dict on success, {} when endpoint returns valid but empty payload, None on failure
            - attempted: whether an HTTP request was attempted
            - error_reason: dict with code/body_prefix on failure, else None
    
    Note: Debian tracker may not have a stable JSON API for source packages.
    If it returns non-JSON (e.g., HTML), this is expected and we gracefully skip it.
    """
    if not _HAS_REQUESTS:
        return None, False, {"code": "endpoint_unreachable"}

    s = _session()
    if s is None:
        return None, False, {"code": "endpoint_unreachable"}

    # Try JSON endpoint first; if it doesn't exist, the tracker will silently return non-JSON.
    # This is expected behavior and we handle it gracefully.
    url_candidates = [
        f"https://security-tracker.debian.org/tracker/json/package/{src_pkg}",
        f"https://security-tracker.debian.org/tracker/source-package/{src_pkg}",
    ]

    attempted = False
    last_error = None

    for url in url_candidates:
        for i in range(2):
            attempted = True
            try:
                r = s.get(url, timeout=15)
                if r.status_code != 200:
                    code = f"http_{r.status_code}"
                    if 500 <= r.status_code < 600 and i < 1:
                        continue
                    last_error = {"code": code, "url": url, "body_prefix": (r.text or "")[:100]}
                    break
                
                content_type = r.headers.get("Content-Type", "")
                if "application/json" not in content_type.lower():
                    # Not JSON — try next URL candidate
                    last_error = {"code": "non_json_response", "url": url, "content_type": content_type}
                    break
                
                try:
                    data = r.json()
                except Exception:
                    last_error = {"code": "json_decode_error", "url": url, "body_prefix": (r.text or "")[:100]}
                    break
                
                # Success
                return (data if isinstance(data, dict) else {}), attempted, None
            
            except Exception as exc:
                name = exc.__class__.__name__.lower()
                msg = str(exc).lower()
                is_timeout = "timeout" in name or "timed out" in msg
                is_network = is_timeout or "connection" in name or "connection" in msg
                if is_network and i < 1:
                    continue
                if is_timeout:
                    last_error = {"code": "timeout", "url": url}
                elif is_network:
                    last_error = {"code": "endpoint_unreachable", "url": url}
                else:
                    last_error = {"code": "unknown_exception", "url": url, "detail": exc.__class__.__name__}
                break

    # All candidates failed or didn't return JSON
    if last_error is None:
        last_error = {"code": "all_endpoints_failed"}
    
    return None, attempted, last_error


# ══════════════════════════════════════════════════════════════════════════════
# Public: CVE lookup
# ══════════════════════════════════════════════════════════════════════════════

_EMPTY_CVE = {
    "cve_assigned":          False,
    "cve_ids":               [],
    "cve_assignment_date":   None,
    "usn_published":         False,
    "usn_ids":               [],
    "debian_cve_statuses":   {},
    "_debian_query_attempted": False,
    "_cve_lookup_source":    "unavailable",
}


def lookup_cve_for_commit(
    pkg_name:              str,
    commit_sha:            str,
    commit_message:        str,
    affected_funcs:        list[str],
    upstream_commit_urls:  list[str] = (),
) -> dict:
    """
    Cross-reference an upstream commit against external CVE / advisory databases.

    Sources queried (in order):
      1. Ubuntu CVE tracker  (package-scoped; filters by SHA mention in CVE text)
      2. NVD reverse reference-URL lookup  (correct semantic: find CVEs that cite
         this commit URL in their references field; empty result = silent fix)
      3. Debian security tracker  (JSON via security-tracker.d.o; SHA mention check)
      4. OSV.dev commit-hash query  (exact SHA match)

    upstream_commit_urls: list of candidate forge commit URLs for this SHA, e.g.
      ["https://github.com/openssl/openssl/commit/<sha>",
       "https://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=<sha>"]
    An empty result from step 2 is the ground-truth signal that the fix is silent.

    Returns a dict with keys matching the CDSFA report schema.
    All fields are factual observations — no LLM involved.
    """
    if not _HAS_REQUESTS:
        return {**_EMPTY_CVE, "_cve_lookup_source": "no_requests_lib",
                "_api_timestamp": datetime.now(timezone.utc).isoformat()}

    short_sha = commit_sha[:12]
    found_cves: list[str] = []
    cve_dates:  list[str] = []
    usn_ids:    list[str] = []
    sources:    list[str] = []
    debian_cve_statuses: dict[str, str] = {}
    _deb_data_cache: Optional[dict] = None  # reused by Debian tracker and status lookup
    _deb_query_attempted: bool = False
    _deb_query_error: Optional[str] = None

    # ── Step 0. Ubuntu CVE tracker — SHA-based direct search ─────────────────
    # Search by commit SHA before the package-scoped query; catches CVEs that
    # were assigned after initial ingestion and reference the commit directly.
    for entry in _ubuntu_cves_search_by_sha(short_sha):
        cve_id = entry.get("id", "")
        if not cve_id:
            continue
        if cve_id not in found_cves:
            found_cves.append(cve_id)
            pub = entry.get("published", "")[:10]
            if pub:
                cve_dates.append(pub)
            sources.append("ubuntu_tracker_sha")
        for notice in entry.get("notices", []):
            usn = notice.get("id", "")
            if usn and usn not in usn_ids:
                usn_ids.append(usn)

    # ── 1. Ubuntu CVE tracker ─────────────────────────────────────────────────
    for entry in _ubuntu_cves_for_pkg(pkg_name):
        cve_id = entry.get("id", "")
        if not cve_id:
            continue
        blob = " ".join([
            cve_id,
            entry.get("description", ""),
            entry.get("references", ""),
        ])
        if _mention_check_strict(short_sha, blob):
            if cve_id not in found_cves:
                found_cves.append(cve_id)
                pub = entry.get("published", "")[:10]
                if pub:
                    cve_dates.append(pub)
                sources.append("ubuntu_tracker")
            for notice in entry.get("notices", []):
                usn = notice.get("id", "")
                if usn and usn not in usn_ids:
                    usn_ids.append(usn)

    # ── 2. Debian security tracker ────────────────────────────────────────────
    # Priority: Ubuntu tracker > Debian tracker > NVD (Ubuntu is already done above)
    src_pkg  = resolve_source_package_name(pkg_name)
    deb_data, _deb_query_attempted, _deb_query_error = _query_debian_tracker_source_package(src_pkg)
    _deb_data_cache = deb_data if isinstance(deb_data, dict) else None
    if _deb_query_error:
        log.debug(
            "[lookup_cve] Debian tracker query skipped for %s (src=%s): %s",
            pkg_name, src_pkg, _deb_query_error.get("code", "unknown")
        )
    if _deb_data_cache:
        deb_text = str(_deb_data_cache)
        if _mention_check_strict(short_sha, deb_text):
            for m in re.findall(r"CVE-\d{4}-\d+", deb_text):
                if m not in found_cves:
                    found_cves.append(m)
                    sources.append("debian_tracker")

    # ── 3. NVD reverse reference-URL lookup ──────────────────────────────────
    # Find CVEs whose references explicitly cite one of the candidate commit URLs.
    # Empty result is the ground-truth "silent fix" signal.
    # No keyword/package-name fallback — that approach contaminates results with
    # unrelated historical CVEs for the same package.
    # No date-based filtering: searches the full current CVE database regardless
    # of when the CVE was assigned relative to the commit.
    for cve in _nvd_search_by_ref_url(list(upstream_commit_urls)):
        cve_id = cve.get("id", "")
        if cve_id and cve_id not in found_cves:
            found_cves.append(cve_id)
            pub = cve.get("published", "")[:10]
            if pub:
                cve_dates.append(pub)
            sources.append("nvd_ref_url")

    # ── 4. OSV.dev — commit-hash query (covers GitHub GHSA, OSS-Fuzz, Debian) ─
    for vuln in _osv_search_commit(commit_sha):
        aliases = vuln.get("aliases", []) + [vuln.get("id", "")]
        for alias in aliases:
            if alias and re.match(r"CVE-\d{4}-\d+", alias) and alias not in found_cves:
                found_cves.append(alias)
                pub = (vuln.get("published") or "")[:10]
                if pub:
                    cve_dates.append(pub)
                sources.append("osv")

    # ── USN enrichment + Debian per-CVE status ────────────────────────────────
    usn_first_date: Optional[str] = None
    for cve_id in found_cves:
        ids, pub_date = _usn_data_for_cve(cve_id)
        for usn in ids:
            if usn not in usn_ids:
                usn_ids.append(usn)
        if pub_date and (usn_first_date is None or pub_date < usn_first_date):
            usn_first_date = pub_date
        if _deb_data_cache:
            st = _debian_cve_status_from_tracker(_deb_data_cache, cve_id)
            if st:
                debian_cve_statuses[cve_id] = st
        time.sleep(_NVD_DELAY)

    earliest_date = min(cve_dates) if cve_dates else None
    # debian_cve_statuses: {} = queried OK but no matching data;
    #                       {"_error":"<reason>"} = network/http/parse failure;
    #                       {cve_id: "bookworm:resolved", ...} = real data found.
    if _deb_query_error:
        deb_statuses_out = {
            "_error": _deb_query_error.get("code", "unknown_exception")
        }
        if _deb_query_error.get("body_prefix"):
            deb_statuses_out["_body_prefix"] = _deb_query_error.get("body_prefix")
        if _deb_query_error.get("content_type"):
            deb_statuses_out["_content_type"] = _deb_query_error.get("content_type")
    elif debian_cve_statuses:
        deb_statuses_out = debian_cve_statuses
    else:
        deb_statuses_out = {}
    return {
        "cve_assigned":          len(found_cves) > 0,
        "cve_ids":               found_cves,
        "cve_assignment_date":   earliest_date,
        "usn_published":         len(usn_ids) > 0,
        "usn_ids":               usn_ids,
        "usn_first_date":        usn_first_date,
        "debian_cve_statuses":   deb_statuses_out,
        "_debian_query_attempted": _deb_query_attempted,
        "_cve_lookup_source":    "|".join(dict.fromkeys(sources)) or "no_match",
        "_api_timestamp":        datetime.now(timezone.utc).isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Public: Ubuntu 24.04 patch status
# ══════════════════════════════════════════════════════════════════════════════

_EMPTY_PATCH = {
    "ubuntu_2404_actually_patched": None,   # None = could not determine
    "ubuntu_2404_patch_method":     "unknown",
    "ubuntu_2404_current_version":  None,
}


def check_ubuntu_patch_status(
    pkg_name:           str,
    ver_2404_recorded:  str,
    cve_ids:            list[str],
) -> dict:
    """
    Determine whether the fix is present in the CURRENT Ubuntu 24.04 source.

    Strategy (in order, stops on first conclusive answer):

    A. If we have CVE IDs from lookup_cve_for_commit():
       Query Ubuntu CVE tracker for each CVE → check Noble status field.
       "released" in noble pocket → actually_patched=True, method="backport"

    B. Launchpad current Noble source version:
       - Same as recorded ver_2404 → fix not yet released → patched=False, method="none"
       - Different (newer) → version was bumped, likely carries the fix →
         patched=True, method="version_bump"
       (Security backports usually have a different version suffix, not a major bump,
        so a version change in Noble almost always means a deliberate security update.)

    Returns dict with ubuntu_2404_actually_patched (bool|None), ubuntu_2404_patch_method,
    ubuntu_2404_current_version.
    """
    if not _HAS_REQUESTS:
        return {**_EMPTY_PATCH, "_patch_check_source": "no_requests_lib"}

    # ── A. CVE-based: use per-CVE detail endpoint for authoritative Noble status ─
    if cve_ids:
        for cve_id in cve_ids[:3]:
            detail = _fetch_cve_detail(cve_id)
            if not detail:
                continue
            status = _noble_status_from_detail(detail)
            if status == "released":
                return {
                    "ubuntu_2404_actually_patched": True,
                    "ubuntu_2404_patch_method":     "backport",
                    "ubuntu_2404_current_version":  None,
                    "_patch_check_source":          f"ubuntu_cve_detail/{cve_id}",
                }
            elif status in ("needed", "ignored", "deferred"):
                return {
                    "ubuntu_2404_actually_patched": False,
                    "ubuntu_2404_patch_method":     "none",
                    "ubuntu_2404_current_version":  None,
                    "_patch_check_source":          f"ubuntu_cve_detail/{cve_id}",
                }

    # ── B. Launchpad version bump detection ───────────────────────────────────
    current_ver = _launchpad_current_version(pkg_name)
    if current_ver is None:
        return {**_EMPTY_PATCH, "_patch_check_source": "launchpad_unavailable"}

    from packaging.version import Version, InvalidVersion
    try:
        recorded = Version(_strip_ver(ver_2404_recorded))
        current  = Version(_strip_ver(current_ver))
    except InvalidVersion:
        return {
            "ubuntu_2404_actually_patched": None,
            "ubuntu_2404_patch_method":     "unknown",
            "ubuntu_2404_current_version":  current_ver,
            "_patch_check_source":          "launchpad_parse_error",
        }

    if current > recorded:
        # Version was bumped (e.g. ubuntu3 → ubuntu3.7) but we cannot confirm
        # THIS specific commit is included — the bump may be for a different CVE.
        # Return None (uncertain) so check_apt_source() gets the definitive say.
        return {
            "ubuntu_2404_actually_patched": None,
            "ubuntu_2404_patch_method":     "version_bump_unverified",
            "ubuntu_2404_current_version":  current_ver,
            "_patch_check_source":          "launchpad_version_delta",
        }
    return {
        "ubuntu_2404_actually_patched": False,
        "ubuntu_2404_patch_method":     "none",
        "ubuntu_2404_current_version":  current_ver,
        "_patch_check_source":          "launchpad_version_match",
    }


def _strip_ver(raw: str) -> str:
    """Normalize Ubuntu version string for packaging.version comparison."""
    v = raw.strip().lstrip("v")
    v = re.sub(r"^\d+:", "", v)      # strip epoch
    v = re.sub(r"[+~].*$", "", v)    # strip +dfsg / ~beta
    v = re.sub(r"-.*$",    "", v)    # strip Debian revision
    return v.strip()

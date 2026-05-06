"""
config.py  –  linux-sec-theater global configuration
All paths are rooted at the T7 external drive mount point.
"""
import os
from pathlib import Path

BASE_DIR      = Path("/Volumes/T7/linux-sec-theater")
WORKSPACE_DIR = BASE_DIR / "workspace"      # git clone destination
DATA_DIR      = BASE_DIR / "data"
MODELS_DIR    = BASE_DIR / "models"         # local GGUF fallback

OUTPUT_DIR    = DATA_DIR / "output"         # pre-computed version-gap JSON
FINDINGS_DIR  = DATA_DIR / "findings"
COT_LOG_DIR   = FINDINGS_DIR / "cot_logs"  # LLM chain-of-thought (paper reference)

# Ensure directories exist at startup
for _d in [WORKSPACE_DIR, FINDINGS_DIR, COT_LOG_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

FINDINGS_FILE = FINDINGS_DIR / "hiddenvul.json"
LIGRUST_GAP_FILE = OUTPUT_DIR / "ligrust_upstream_vs_ubuntu_versions.json"
GOLANG_GAP_FILE  = OUTPUT_DIR / "golang_upstream_vs_ubuntu_versions.json"

UBUNTU_RELEASE   = "noble"          # 24.04 LTS
UBUNTU_SERIES_LP = f"https://api.launchpad.net/1.0/ubuntu/{UBUNTU_RELEASE}"

# ── Upstream registries ───────────────────────────────────────────────────────
CRATES_IO_API   = "https://crates.io/api/v1/crates/{crate}"
GITHUB_TAGS_API = "https://api.github.com/repos/{owner}/{repo}/tags?per_page=100"
GITHUB_TOKEN    = os.environ.get("GITHUB_TOKEN", "")   # optional, prevents rate-limiting

# ── Ubuntu CVE / Changelog verification ──────────────────────────────────────
UBUNTU_CVE_JSON    = "https://ubuntu.com/security/cves.json"
UBUNTU_CHANGELOG   = (
    "https://changelogs.ubuntu.com/changelogs/pool"
    "/{section}/{first}/{pkg}/{pkg}_{ver}/changelog"
)
LAUNCHPAD_DIFF_URL = (
    "https://launchpad.net/ubuntu/+source/{src}/+diff/{ver}"
)

# ── Local Ollama / Qwen2.5-Coder ──────────────────────────────────────────────
OLLAMA_BASE_URL  = "http://localhost:11434"
OLLAMA_MODEL     = "qwen2.5-coder:7b"
# Model file directory (set before starting Ollama: export OLLAMA_MODELS=/Volumes/T7/linux-sec-theater/models)
OLLAMA_MODELS_DIR = MODELS_DIR   # = BASE_DIR / "models"
# Max diff chars (qwen2.5-coder:7b ~32k ctx, leave headroom)
MAX_DIFF_CHARS_OLLAMA = 28000

# ── Groq API ──────────────────────────────────────────────────────────────────
GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL    = "llama-3.3-70b-versatile"
# Groq supports large context; diff truncation threshold matches GLM edition
MAX_DIFF_CHARS_GROQ = 28000

# ── Z.AI GLM-5.1 API ──────────────────────────────────────────────────────────
ZAI_API_KEY      = os.environ.get("ZAI_API_KEY", "")
ZAI_BASE_URL     = "https://api.z.ai/api/coding/paas/v4/"
# ReAct Agent and Deep Audit share the same model; stateless calls via ZaiClient
ZAI_MODEL        = "glm-5.1"
# Deep audit model (same model, called directly via ZaiClient for statelessness)
ZAI_AUDIT_MODEL  = "glm-5.1"


MAX_COMMITS_PER_AUDIT = 5
MAX_DIFF_CHARS = 28000

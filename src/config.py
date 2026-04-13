"""
config.py  –  linux-sec-theater 全局配置
所有路径以 T7 外置硬盘挂载点为根。
"""
import os
from pathlib import Path

# ── 根目录 ────────────────────────────────────────────────────────────────────
BASE_DIR      = Path("/Volumes/T7/linux-sec-theater")

# ── 存储布局 ──────────────────────────────────────────────────────────────────
WORKSPACE_DIR = BASE_DIR / "workspace"      # git clone 目标
DATA_DIR      = BASE_DIR / "data"
MODELS_DIR    = BASE_DIR / "models"         # 本地 GGUF 备用

OUTPUT_DIR    = DATA_DIR / "output"         # 预计算版本鸿沟 JSON
FINDINGS_DIR  = DATA_DIR / "findings"
COT_LOG_DIR   = FINDINGS_DIR / "cot_logs"  # LLM 思考链（论文引用）

# 运行时确保目录存在
for _d in [WORKSPACE_DIR, FINDINGS_DIR, COT_LOG_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# ── 主输出文件 ─────────────────────────────────────────────────────────────────
FINDINGS_FILE = FINDINGS_DIR / "final_hidden_vulnerabilities.json"

# ── 预计算版本鸿沟输入 ────────────────────────────────────────────────────────
LIGRUST_GAP_FILE = OUTPUT_DIR / "ligrust_upstream_vs_ubuntu_versions.json"
GOLANG_GAP_FILE  = OUTPUT_DIR / "golang_upstream_vs_ubuntu_versions.json"

# ── Ubuntu / Launchpad ────────────────────────────────────────────────────────
UBUNTU_RELEASE   = "noble"          # 24.04 LTS
UBUNTU_SERIES_LP = f"https://api.launchpad.net/1.0/ubuntu/{UBUNTU_RELEASE}"

# ── 上游注册表 ────────────────────────────────────────────────────────────────
CRATES_IO_API   = "https://crates.io/api/v1/crates/{crate}"
GITHUB_TAGS_API = "https://api.github.com/repos/{owner}/{repo}/tags?per_page=100"
GITHUB_TOKEN    = os.environ.get("GITHUB_TOKEN", "")   # 可选，防速率限制

# ── Ubuntu CVE / Changelog 核验 ───────────────────────────────────────────────
UBUNTU_CVE_JSON    = "https://ubuntu.com/security/cves.json"
UBUNTU_CHANGELOG   = (
    "https://changelogs.ubuntu.com/changelogs/pool"
    "/{section}/{first}/{pkg}/{pkg}_{ver}/changelog"
)
LAUNCHPAD_DIFF_URL = (
    "https://launchpad.net/ubuntu/+source/{src}/+diff/{ver}"
)

# ── 本地 Ollama / Qwen2.5-Coder ───────────────────────────────────────────────
OLLAMA_BASE_URL  = "http://localhost:11434"
OLLAMA_MODEL     = "qwen2.5-coder:7b"
# 模型文件目录（启动 Ollama 前设置：export OLLAMA_MODELS=/Volumes/T7/linux-sec-theater/models）
OLLAMA_MODELS_DIR = MODELS_DIR   # = BASE_DIR / "models"
# Diff 最大字符数（qwen2.5-coder:7b ~32k ctx，保留余量）
MAX_DIFF_CHARS_OLLAMA = 28000

# ── Groq API ──────────────────────────────────────────────────────────────────
GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL    = "llama-3.3-70b-versatile"
# Groq 支持大上下文，diff 截断阈值与 GLM 版保持一致
MAX_DIFF_CHARS_GROQ = 28000

# ── Z.AI GLM-5.1 API ──────────────────────────────────────────────────────────
ZAI_API_KEY      = os.environ.get("ZAI_API_KEY", "")
ZAI_BASE_URL     = "https://api.z.ai/api/paas/v4"
# ReAct Agent 编排模型（OpenAI 兼容接口，供 LangChain ChatOpenAI 使用）
ZAI_MODEL        = "glm-5"
# 深度审计模型（同模型，通过 ZaiClient 直接调用，确保无状态）
ZAI_AUDIT_MODEL  = "glm-5"

# 每次审计最多送给 LLM 的 commit 数量（控制上下文）
MAX_COMMITS_PER_AUDIT = 5
# Diff 文本最大字符数（GLM-5 支持 128k ctx，可显著提升）
MAX_DIFF_CHARS = 28000

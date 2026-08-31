# Linux Sec Theater

An agent-assisted research pipeline for finding Ubuntu package version gaps and
investigating security fixes that may be missing from an older Ubuntu release.

The current workflow compares **Ubuntu 24.04 LTS (Noble)** with **Ubuntu 26.04
(Resolute)**. It maps Ubuntu binary packages to their upstream projects, finds
the commits between the two packaged versions, and uses GLM to triage commits
that may fix memory-safety or logic vulnerabilities. Candidate fixes are then
checked against upstream source, public CVE data, and Ubuntu patch information.

> This project produces security-research leads, not authoritative vulnerability
> determinations. Every reported finding should be manually verified before it
> is published or used to make security decisions.

## What it does

For each package, the agent can:

1. Read package versions from Ubuntu 24.04 and 26.04 repository snapshots.
2. Detect whether the newer Ubuntu release contains a later upstream version.
3. Resolve the Ubuntu binary package to its source package and upstream Git
   repository.
4. Collect commits between the old and new upstream version tags.
5. Use a first GLM pass to filter for possible memory-safety and logic fixes.
6. Inspect the Ubuntu 24.04-era source and use a second GLM pass to assess
   whether the issue is still present and how difficult a backport may be.
7. Cross-check CVE/USN information and Ubuntu patch status using public data.
8. Write an evidence-rich JSON and CSV report for manual review.

It supports C/C++ libraries and selected Go and Rust packages through the
package-to-source and package-to-upstream mappings in
`src/tools/version_gap_finder.py`.

## Analysis flow

```text
Ubuntu 24.04 package data ─┐
                           ├─ version comparison ─ upstream commit range
Ubuntu 26.04 package data ─┘                         │
                                                    ▼
                                      security-relevant commit filter
                                                    │
                                                    ▼
                                      GLM triage and source analysis
                                                    │
                                                    ▼
                                    CVE + Ubuntu patch cross-checks
                                                    │
                                                    ▼
                                      JSON/CSV findings for review
```

## Requirements

- Python 3.10 or newer
- Git
- A Z.AI API key for the GLM analysis stages
- Internet access to Ubuntu, Launchpad, upstream Git forges, and vulnerability
  data sources
- Optional: Docker, for a stronger Ubuntu 24.04 `apt-get source` verification
  path. The code falls back to Launchpad when Docker is unavailable.

The repository is currently configured for the local path
`/Volumes/T7/linux-sec-theater`. If you clone it elsewhere, update `BASE_DIR` in
`src/config.py` before running the pipeline.

## Installation

```bash
git clone https://github.com/ZZ9622/linux-sec-theater.git
cd linux-sec-theater

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Set the required model credential:

```bash
export ZAI_API_KEY="your-z.ai-api-key"
```

An optional GitHub token reduces API rate-limit problems when resolving GitHub
commits and pull requests:

```bash
export GITHUB_TOKEN="your-github-token"
```

Do not commit API keys or local agent permission files to the repository.

## Package data

The pipeline expects these two files:

```text
data/output/ubuntu_24.04/ubuntu_24.04_packages_detail.json
data/output/ubuntu_26.04/ubuntu_26.04_packages_detail.json
```

Snapshots are included in the repository. To refresh them from the Ubuntu
archive, run:

```bash
python fetch_pkgs/fetch_ubuntu_pkgs.py
python fetch_pkgs/fetch_ubuntu_26_pkgs.py
```

Before refreshing, note that the fetch scripts currently build their output
paths relative to `fetch_pkgs/`. Confirm the generated location and move or
adjust it to match the paths above if necessary.

## Usage

### Analyze one package

```bash
python src/main_agent_glm.py --package libxml2
```

Short form:

```bash
python src/main_agent_glm.py -p libxml2
```

### Analyze a package list

The input file should contain one package name per line. Blank lines and lines
beginning with `#` are ignored.

```bash
python src/main_agent_glm.py \
  --file data/target_pkgs/target_test_20.txt
```

### Automatically scan known packages

Scan packages that have a known upstream repository and a detected version gap:

```bash
python src/main_agent_glm.py --auto
```

Limit an initial run to ten packages:

```bash
python src/main_agent_glm.py --auto --top 10
```

Upstream repositories are cloned or updated under `workspace/`. Large scans can
therefore take substantial time, disk space, network traffic, and model tokens.

## Output

The main agent writes incremental reports to:

```text
data/findings/patch_gap_report.json
data/findings/patch_gap_report.csv
```

Entries may include:

- Ubuntu 24.04 and 26.04 package versions
- upstream repository, commit hash, commit date, and source evidence
- suspected vulnerability type and affected functions
- GLM reasoning summary, severity, and backport feasibility
- CVE and USN identifiers found during cross-checking
- Ubuntu 24.04 patch verdict and verification method
- inheritance mode, maintenance-gap classification, and review flags
- Q1/Q2/Q3 links for upstream commit, upstream source, and Ubuntu changelog

Reports are saved incrementally during multi-package scans. Existing entries are
deduplicated by package and commit hash. See
`Q1_Q2_Q3_VERIFICATION_GUIDE.md` for the manual evidence-review workflow.

## Repository layout

```text
linux-sec-theater/
├── src/
│   ├── main_agent_glm.py          # CLI and analysis pipeline
│   ├── config.py                  # paths, endpoints, and model settings
│   └── tools/
│       ├── version_gap_finder.py  # package/version/upstream resolution
│       ├── diff_harvester.py      # Git tag and commit-range analysis
│       ├── cve_tracker.py         # CVE, USN, and Ubuntu status checks
│       ├── ubuntu_patch_verifier.py
│       └── pipeline_cache.py
├── fetch_pkgs/                    # Ubuntu, SUSE, and Red Hat data collectors
├── data/
│   ├── output/                    # package snapshots and comparisons
│   ├── findings/                  # generated research reports
│   └── target_pkgs/               # package lists for batch scans
├── workspace/                     # local upstream clones; not committed
├── requirements.txt
└── Q1_Q2_Q3_VERIFICATION_GUIDE.md
```

## Interpreting results safely

A version difference alone does not prove that Ubuntu 24.04 is vulnerable. A
fix may already have been backported without changing the upstream version, the
affected code may differ, or a model-generated classification may be wrong.

For each candidate, verify at least:

1. The upstream commit actually fixes a security-relevant defect.
2. The vulnerable code exists and is reachable in the Ubuntu 24.04 source.
3. Ubuntu has not already backported an equivalent patch.
4. The CVE/USN association is specific to that commit rather than only to the
   package.
5. Any proof of concept is tested only in an isolated, authorized environment.

The report's review flags and Q1/Q2/Q3 evidence links are intended to make this
manual verification explicit.

## Current limitations

- The active comparison is fixed to Ubuntu 24.04 versus Ubuntu 26.04.
- `src/config.py` contains a machine-specific absolute base path.
- Upstream repository coverage depends partly on maintained mappings.
- Version normalization and fuzzy tag matching can be ambiguous for complex
  Debian/Ubuntu version strings.
- Network services, API limits, missing tags, or inaccessible source packages
  can produce incomplete results.
- GLM output is probabilistic and can contain false positives or false
  negatives.
- Docker-based source verification is stronger than the Launchpad fallback but
  is optional and may not be available in every environment.

## Responsible use

Use this project only for defensive research and on systems or data you are
authorized to test. Follow coordinated disclosure practices for newly confirmed
security issues.

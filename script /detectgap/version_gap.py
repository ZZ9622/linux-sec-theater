#!/usr/bin/env python3
"""Build Ubuntu vs upstream version map for target Golang packages.

The script reads package names from target_golang.txt, looks up current
Ubuntu package versions from ubuntu_24.04_packages_detail.json, fetches Debian
upstream version information via Debian tracker endpoints, and writes output in
the format requested by the user.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


USER_AGENT = "linux-sec-theater/version-gap (+https://tracker.debian.org/)"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3


def read_target_packages(path: Path) -> list[str]:
	return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_ubuntu_versions(path: Path) -> dict[str, str]:
	data = json.loads(path.read_text(encoding="utf-8"))
	package_to_version: dict[str, str] = {}

	for repo in ("main", "universe"):
		for entry in data.get(repo, []):
			pkg = entry.get("Package")
			version = entry.get("Version")
			if pkg and version:
				package_to_version[pkg] = version

	return package_to_version


def http_json(url: str) -> Optional[dict[str, Any]]:
	req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
	with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
		return json.loads(resp.read().decode("utf-8"))


def http_text(url: str) -> str:
	req = Request(url, headers={"User-Agent": USER_AGENT})
	with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
		return resp.read().decode("utf-8", errors="replace")


def normalize_upstream_from_version(version: Optional[str]) -> Optional[str]:
	if not version:
		return None
	core = version.split(":", 1)[-1]
	if "-" in core:
		core = core.rsplit("-", 1)[0]
	return core


def extract_upstream_from_payload(payload: dict[str, Any]) -> Optional[str]:
	# Try known key variants returned by Debian tracker and legacy PTS formats.
	for key in (
		"upstream_version",
		"upstream-version",
		"upstream",
		"latest_upstream_version",
	):
		value = payload.get(key)
		if isinstance(value, str) and value.strip():
			return value.strip()

	versions = payload.get("versions")
	if isinstance(versions, dict):
		for key in ("upstream", "upstream_version", "upstream-version"):
			value = versions.get(key)
			if isinstance(value, str) and value.strip():
				return value.strip()

	version_value = payload.get("version")
	if isinstance(version_value, str) and version_value.strip():
		return normalize_upstream_from_version(version_value.strip())

	return None


def scrape_tracker_version(pkg: str) -> Optional[str]:
	# Fallback when JSON endpoints are unavailable: scrape the tracker page
	# "version:" field and derive upstream by removing Debian revision suffix.
	html = http_text(f"https://tracker.debian.org/pkg/{quote(pkg)}")
	match = re.search(r"<b>version:</b>\s*</span>(.*?)</li>", html, flags=re.S)
	if match:
		block = match.group(1)
		block = re.sub(r"<[^>]+>", "", block)
		version = " ".join(block.split()).strip()
		return normalize_upstream_from_version(version)
	return None


def fetch_upstream_version(pkg: str) -> Optional[str]:
	# Try Debian tracker API endpoints first, then legacy PTS endpoint.
	endpoints = [
		f"https://tracker.debian.org/api/v1/packages/{quote(pkg)}",
		f"https://tracker.debian.org/api/v1/source/{quote(pkg)}",
		f"https://qa.debian.org/cgi-bin/pts-json.cgi?package={quote(pkg)}",
	]

	for _ in range(MAX_RETRIES):
		for url in endpoints:
			try:
				payload = http_json(url)
				if payload:
					upstream = extract_upstream_from_payload(payload)
					if upstream:
						return upstream
			except HTTPError as exc:
				if exc.code == 404:
					continue
			except (URLError, TimeoutError, ValueError):
				continue

		try:
			scraped = scrape_tracker_version(pkg)
			if scraped:
				return scraped
		except (HTTPError, URLError, TimeoutError):
			pass

		time.sleep(0.4)

	return None


def build_result(target_pkgs: Iterable[str], ubuntu_versions: dict[str, str], workers: int) -> dict[str, dict[str, Optional[str]]]:
	result: dict[str, dict[str, Optional[str]]] = {
		pkg: {
			"ubuntu_full_version": ubuntu_versions.get(pkg),
			"upstream_version": None,
		}
		for pkg in target_pkgs
	}

	with ThreadPoolExecutor(max_workers=workers) as pool:
		future_map = {pool.submit(fetch_upstream_version, pkg): pkg for pkg in target_pkgs}
		for future in as_completed(future_map):
			pkg = future_map[future]
			try:
				result[pkg]["upstream_version"] = future.result()
			except Exception:
				result[pkg]["upstream_version"] = None

	return result


def parse_args() -> argparse.Namespace:
	workspace_root = Path(__file__).resolve().parents[2]
	default_target = workspace_root / "data" / "target_pkgs" / "target_golang.txt"
	default_ubuntu_json = workspace_root / "data" / "output" / "ubuntu_24.04" / "ubuntu_24.04_packages_detail.json"
	default_out = workspace_root / "data" / "output" / "golang_upstream_vs_ubuntu_versions.json"

	parser = argparse.ArgumentParser(description="Collect upstream and Ubuntu package versions for target packages.")
	parser.add_argument("--target", type=Path, default=default_target, help="Path to target package list.")
	parser.add_argument("--ubuntu-json", type=Path, default=default_ubuntu_json, help="Path to Ubuntu package detail JSON.")
	parser.add_argument("--out", type=Path, default=default_out, help="Output JSON path.")
	parser.add_argument("--workers", type=int, default=12, help="Concurrent worker count for upstream lookups.")
	return parser.parse_args()


def main() -> None:
	args = parse_args()

	target_pkgs = read_target_packages(args.target)
	ubuntu_versions = load_ubuntu_versions(args.ubuntu_json)
	result = build_result(target_pkgs, ubuntu_versions, max(1, args.workers))

	args.out.parent.mkdir(parents=True, exist_ok=True)
	args.out.write_text(json.dumps(result, indent=4, ensure_ascii=False), encoding="utf-8")
	print(f"Wrote {len(result)} packages to {args.out}")


if __name__ == "__main__":
	main()

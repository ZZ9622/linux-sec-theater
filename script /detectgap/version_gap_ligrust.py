#!/usr/bin/env python3
"""Build Ubuntu vs upstream version map for target librust packages."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


def load_version_gap_module():
    module_path = Path(__file__).with_name("version_gap_golang.py")
    spec = importlib.util.spec_from_file_location("version_gap", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module from {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args() -> argparse.Namespace:
    workspace_root = Path(__file__).resolve().parents[2]
    default_target = workspace_root / "data" / "target_pkgs" / "target_ligrust.txt"
    default_ubuntu_json = workspace_root / "data" / "output" / "ubuntu_24.04" / "ubuntu_24.04_packages_detail.json"
    default_out = workspace_root / "data" / "output" / "ligrust_upstream_vs_ubuntu_versions.json"

    parser = argparse.ArgumentParser(
        description="Collect upstream and Ubuntu package versions for librust target packages."
    )
    parser.add_argument("--target", type=Path, default=default_target, help="Path to target package list.")
    parser.add_argument("--ubuntu-json", type=Path, default=default_ubuntu_json, help="Path to Ubuntu package detail JSON.")
    parser.add_argument("--out", type=Path, default=default_out, help="Output JSON path.")
    parser.add_argument("--workers", type=int, default=12, help="Concurrent worker count for upstream lookups.")
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process first N packages (0 means all). Useful for quick tests.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    version_gap = load_version_gap_module()

    target_pkgs = version_gap.read_target_packages(args.target)
    if args.limit and args.limit > 0:
        target_pkgs = target_pkgs[: args.limit]

    ubuntu_versions = version_gap.load_ubuntu_versions(args.ubuntu_json)
    result = version_gap.build_result(target_pkgs, ubuntu_versions, max(1, args.workers))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=4, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(result)} packages to {args.out}")


if __name__ == "__main__":
    main()

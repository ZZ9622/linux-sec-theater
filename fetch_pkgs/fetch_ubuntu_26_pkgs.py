#!/usr/bin/env python3
"""
Ubuntu 26.04 (Resolute) Package Statistics Script
Count total supported packages in Main and Universe repositories
"""

import gzip
import urllib.request
import urllib.error
import os
import json
from pathlib import Path
from datetime import datetime

UBUNTU_MIRROR = "http://archive.ubuntu.com/ubuntu"
UBUNTU_VERSION = "resolute"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), ".", "data", "output", "ubuntu_26.04")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def download_packages(repo_type):
    """
    Download and parse Packages.gz file

    Args:
        repo_type: 'main' or 'universe'

    Returns:
        Set of package names and list of package information
    """
    url = f"{UBUNTU_MIRROR}/dists/{UBUNTU_VERSION}/{repo_type}/binary-amd64/Packages.gz"

    print(f"Downloading {repo_type} repository package list...")
    print(f"URL: {url}")

    try:
        response = urllib.request.urlopen(url, timeout=30)
        compressed_data = response.read()
        print(f"✓ Downloaded {len(compressed_data) / 1024 / 1024:.2f} MB")

        decompressed_data = gzip.decompress(compressed_data)
        text_content = decompressed_data.decode('utf-8')

        packages = set()
        package_list = []
        current_package = {}

        for line in text_content.split('\n'):
            if line.startswith('Package: '):
                if current_package and 'Package' in current_package:
                    packages.add(current_package['Package'])
                    package_list.append(current_package)

                package_name = line[9:].strip()
                current_package = {
                    'Package': package_name,
                    'Repository': repo_type
                }
            elif line.startswith('Version: '):
                current_package['Version'] = line[9:].strip()
            elif line.startswith('Description: '):
                current_package['Description'] = line[13:].strip()

        if current_package and 'Package' in current_package:
            packages.add(current_package['Package'])
            package_list.append(current_package)

        print(f"✓ Parsed {len(packages)} packages")
        return packages, package_list

    except urllib.error.URLError as e:
        print(f"✗ Download failed: {e}")
        return set(), []
    except Exception as e:
        print(f"✗ Failed to process {repo_type} repository: {e}")
        return set(), []


def main():
    print("=" * 60)
    print("Ubuntu 26.04 (Resolute) Package Statistics")
    print("=" * 60)
    print()

    main_packages, main_list = download_packages("main")
    print()
    universe_packages, universe_list = download_packages("universe")
    print()

    main_count = len(main_packages)
    universe_count = len(universe_packages)
    total_count = main_count + universe_count

    stats = {
        "timestamp": datetime.now().isoformat(),
        "ubuntu_version": "26.04 (Resolute)",
        "main": {
            "count": main_count,
            "type": "Canonical maintained"
        },
        "universe": {
            "count": universe_count,
            "type": "Community maintained (ESM scope)"
        },
        "total": total_count
    }

    print("=" * 60)
    print("Statistics Results")
    print("=" * 60)
    print(f"Main repository (Canonical maintained):  {main_count:>8} packages")
    print(f"Universe repository (Community/ESM):     {universe_count:>8} packages")
    print("-" * 60)
    print(f"Total:                                    {total_count:>8} packages")
    print("=" * 60)
    print()

    stats_file = os.path.join(OUTPUT_DIR, "ubuntu_26.04_package_stats.json")
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    print(f"✓ Statistics saved to: {stats_file}")

    packages_file = os.path.join(OUTPUT_DIR, "ubuntu_26.04_packages_detail.json")
    detail_data = {
        "main": main_list,
        "universe": universe_list
    }
    with open(packages_file, 'w', encoding='utf-8') as f:
        json.dump(detail_data, f, indent=2, ensure_ascii=False)
    print(f"✓ Detailed package list saved to: {packages_file}")

    main_packages_file = os.path.join(OUTPUT_DIR, "ubuntu_26.04_main_packages.txt")
    with open(main_packages_file, 'w', encoding='utf-8') as f:
        for pkg in sorted(main_packages):
            f.write(pkg + '\n')
    print(f"✓ Main packages list saved to: {main_packages_file}")

    universe_packages_file = os.path.join(OUTPUT_DIR, "ubuntu_26.04_universe_packages.txt")
    with open(universe_packages_file, 'w', encoding='utf-8') as f:
        for pkg in sorted(universe_packages):
            f.write(pkg + '\n')
    print(f"✓ Universe packages list saved to: {universe_packages_file}")

    print()
    print("✓ All files saved to data/output directory")


if __name__ == "__main__":
    main()

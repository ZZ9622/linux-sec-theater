#!/usr/bin/env python3
"""
run_batch_from_file.py
从文本文件读取包名列表，逐包运行流水线，结果合并到 final_hidden_vulnerabilities.json。
用法:
    python run_batch_from_file.py data/target_pkgs/target_test_20.txt
"""
import sys
import json
import subprocess
from pathlib import Path

FINDINGS_FILE = Path("data/findings/final_hidden_vulnerabilities.json")


def load_findings():
    if FINDINGS_FILE.exists():
        try:
            return json.loads(FINDINGS_FILE.read_text())
        except Exception:
            return []
    return []


def existing_shas(findings):
    return {f["missing_commit_hash"] for f in findings if f.get("missing_commit_hash")}


def main():
    if len(sys.argv) < 2:
        print("用法: python run_batch_from_file.py <pkg_list.txt>")
        sys.exit(1)

    pkg_file = Path(sys.argv[1])
    pkgs = [l.strip() for l in pkg_file.read_text().splitlines() if l.strip()]
    total = len(pkgs)
    print(f"[Batch] 共 {total} 个包待处理\n")

    done_pkgs = {f["package"] for f in load_findings()}

    for i, pkg in enumerate(pkgs, 1):
        print(f"[{i}/{total}] {'='*50}")
        print(f"[{i}/{total}] 处理: {pkg}")

        if pkg in done_pkgs:
            print(f"[{i}/{total}] 跳过（已有结果）\n")
            continue

        result = subprocess.run(
            ["python", "src/main_agent.py", "--package", pkg],
            capture_output=False,   # 实时打印到终端
        )

        if result.returncode != 0:
            print(f"[{i}/{total}] ⚠ {pkg} 返回非零退出码 {result.returncode}")

        # 重新加载文件（main_agent.py 已写入）
        done_pkgs = {f["package"] for f in load_findings()}
        new_count = sum(1 for f in load_findings() if f.get("package") == pkg)
        print(f"[{i}/{total}] {pkg} 完成，本包新增 {new_count} 条发现\n")

    all_findings = load_findings()
    print(f"\n{'='*60}")
    print(f"全部完成！final_hidden_vulnerabilities.json 共 {len(all_findings)} 条发现")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

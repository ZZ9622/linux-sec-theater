import subprocess
import csv

def get_rhel_count():
    # 使用 --available 替换 --enabled
    # 增加 --refresh 确保获取的是最新的元数据
    cmd = "dnf repoquery --available --qf '%{name}' -y"
    try:
        output = subprocess.check_output(cmd, shell=True).decode()
        # splitlines() 会根据换行符切分，set() 自动去重
        pkgs = set(line.strip() for line in output.splitlines() if line.strip())
        return sorted(list(pkgs))
    except subprocess.CalledProcessError as e:
        print(f"执行 DNF 命令失败: {e}")
        return []

# 执行并保存
rhel_list = get_rhel_count()

if rhel_list:
    # 确保 ../data 目录存在
    import os
    os.makedirs('./data', exist_ok=True)
    with open('./data/rhel_10_pkgs.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Package Name"])
        for p in rhel_list:
            writer.writerow([p])
    print(f"RHEL 10.1 Official Packages: {len(rhel_list)}")
else:
    print("未能获取到任何软件包。")
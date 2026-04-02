# from rhel machine 
# cat /etc/redhat-release
# Red Hat Enterprise Linux release 10.1 (Coughlan)

import subprocess
import csv

def get_rhel_count():

    cmd = "dnf repoquery --available --qf '%{name}' -y"
    try:
        output = subprocess.check_output(cmd, shell=True).decode()
        # splitlines() will split the output into lines, and we use a set to ensure uniqueness
        pkgs = set(line.strip() for line in output.splitlines() if line.strip())
        return sorted(list(pkgs))
    except subprocess.CalledProcessError as e:
        print(f"failed to execute DNF command: {e}")
        return []

rhel_list = get_rhel_count()

if rhel_list:
    import os
    os.makedirs('./data', exist_ok=True)
    with open('./data/rhel_10_pkgs.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Package Name"])
        for p in rhel_list:
            writer.writerow([p])
    print(f"RHEL 10.1 Official Packages: {len(rhel_list)}")
else:
    print("failed to retrieve any packages.")
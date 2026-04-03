"""
openSUSE Tumbleweed: https://download.opensuse.org/tumbleweed/repo/oss/repodata/
openSUSE Leap 16.0: https://download.opensuse.org/distribution/leap/16.0/repo/oss/repodata/
SUSE Linux Enterprise Server (SLES) 16.1: REPO_URL = "https://download.opensuse.org/source/distribution/leap/16.1/repo/oss/repodata/"

"""

import requests
import zstandard as zstd
import gzip
import xml.etree.ElementTree as ET
import csv
import os
from io import BytesIO

# Target repository: openSUSE Leap 16.0 OSS (corresponds to commercial SLES 16 core)
# Source packages repository
SRC_REPO_URL = "https://download.opensuse.org/source/distribution/leap/16.1/repo/oss/repodata/"
OUTPUT_FILE = "./data/output/suse/sles_16_src_pkgs.csv"

def get_suse_src_pkg_list(base_url):
    print(f"Processing repository: {base_url}")
    try:
        response = requests.get(base_url + "repomd.xml", timeout=30)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        
        ns = {'repo': 'http://linux.duke.edu/metadata/repo',
              'common': 'http://linux.duke.edu/metadata/common'}
        
        primary_path = ""
        for data in root.findall('repo:data', ns):
            if data.get('type') == 'primary':
                primary_path = data.find('repo:location', ns).get('href')
                break
        
        full_url = base_url + "../" + primary_path
        pkg_res = requests.get(full_url, timeout=60)
        compressed_data = pkg_res.content

        dctx = zstd.ZstdDecompressor()
        xml_content = b"".join(dctx.read_to_iter(compressed_data))

        pkg_root = ET.fromstring(xml_content)
        src_pkgs = {}
        
        total_found = 0
        
        for entry in pkg_root.findall('common:package', ns):
            total_found += 1
            arch_elem = entry.find('common:arch', ns)
            arch = arch_elem.text if arch_elem is not None else ""
            
            # We are only interested in source packages (arch == 'src')
            if arch == 'src':
                name_elem = entry.find('common:name', ns)
                if name_elem is not None:
                    pkg_name = name_elem.text
                    if pkg_name not in src_pkgs:
                        v_elem = entry.find('common:version', ns)
                        ver = v_elem.get('ver', 'N/A') if v_elem is not None else 'N/A'
                        src_pkgs[pkg_name] = {'version': ver}

        print(f"Processing complete. Total entries in repository: {total_found}, unique source packages: {len(src_pkgs)}")
        return sorted(list(src_pkgs.keys())), src_pkgs


    except Exception as e:
        print(f"Error occurred: {e}")
        return [], {}

def save_to_csv(pkg_list, pkg_dict, file_path):
    # Ensure directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Package Name", "Version"])
        for pkg in pkg_list:
            version = pkg_dict[pkg].get('version', 'N/A')
            writer.writerow([pkg, version])
    print(f"Results saved to: {file_path}")

if __name__ == "__main__":
    all_src_packages, pkg_details = get_suse_src_pkg_list(SRC_REPO_URL)
    
    if all_src_packages:
        print(f"Successfully fetched {len(all_src_packages)} unique source packages (deduplicated).")
        save_to_csv(all_src_packages, pkg_details, OUTPUT_FILE)
    else:
        print("Failed to fetch source package list, please check network or URL.")
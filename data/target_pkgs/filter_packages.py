#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import os

# 文件路径
ubuntu_file = "/Volumes/T7/linux-sec-theater/data/output/ubuntu_24.04/ubuntu_24.04_universe_packages.txt"
rhel_file = "/Volumes/T7/linux-sec-theater/data/output/rhel/rhel_10_pkgs.csv"
output_dir = "/Volumes/T7/linux-sec-theater/data/target_pkgs"

# 读取 Ubuntu 包列表
with open(ubuntu_file, 'r') as f:
    ubuntu_packages = set(line.strip() for line in f if line.strip())

print(f"Ubuntu 包总数: {len(ubuntu_packages)}")

# 读取 RHEL 包列表
rhel_packages = set()
with open(rhel_file, 'r') as f:
    reader = csv.reader(f)
    next(reader)  # 跳过 header
    for row in reader:
        if row:
            pkg_name = row[0].strip().strip('"')
            rhel_packages.add(pkg_name)

print(f"RHEL 包总数: {len(rhel_packages)}")

# 去除 RHEL 中存在的包
filtered = ubuntu_packages - rhel_packages
print(f"去重后包数: {len(filtered)}")

# 按条件筛选
def matches_criteria(pkg_name):
    name_lower = pkg_name.lower()
    
    # 排除条件：剔除不包含可执行代码的包
    exclude_patterns = ['-doc', '-data', '-theme', '-fonts', 'fonts-']
    for pattern in exclude_patterns:
        if pattern in name_lower:
            return False
    
    # 条件1: 以 lib 开头的 C/C++ 库
    if name_lower.startswith('lib'):
        return True
    
    # 条件2: 多媒体与文件解析器
    multimedia_patterns = [
        'imagemagick', 'ffmpeg', 'poppler', 'graphicsmagick',
        'libav', 'libx264', 'libx265', 'libopus', 'libvpx',
        'libaom', 'libheif', 'libwebp', 'libjpeg', 'libpng',
        'libtiff', 'libexif', 'ghostscript', 'mplayer', 'vlc',
        'gstreamer', 'libmysqlclient', 'postgresql', 'sqlite',
        'lcms', 'potrace', 'netpbm', 'imagick', 'cairo',
        'pango', 'freetype', 'harfbuzz', 'fontconfig', 'exif',
        'jpeg', 'png', 'tiff', 'webp', 'heif', 'pdf',
        'codec', 'video', 'audio', 'image'
    ]
    for pattern in multimedia_patterns:
        if pattern.lower() in name_lower:
            return True
    
    # 条件3: 网络相关组件
    if any(keyword in name_lower for keyword in ['net', 'tcp', 'http', 'socket', 'dns', 'ssl', 'tls', 'smtp', 'ftp', 'ssh']):
        return True
    
    return False

target_packages = sorted([pkg for pkg in filtered if matches_criteria(pkg)])
print(f"筛选后包数: {len(target_packages)}")

# 从大名单中提取最符合条件的 100 个高优先包
def score_for_top100(pkg_name):
    name_lower = pkg_name.lower()
    score = 0

    # 最高优先级关键词：解析器/协议/网络/编解码/文档处理
    critical_keywords = [
        'parser', 'codec', 'auth', 'crypt', 'net', 'http',
        'xml', 'json', 'image', 'video', 'pdf'
    ]
    for kw in critical_keywords:
        if kw in name_lower:
            score += 12

    # 次高优先级关键词：插件/嵌入式组件/跨平台工具链
    high_keywords = ['dev', 'cross', 'mod', 'plugin', 'java', 'perl', 'python']
    for kw in high_keywords:
        if kw in name_lower:
            score += 6

    # 针对复杂格式解析、网络中间件、安全运行时进一步加权
    thematic_boost_keywords = [
        'magick', 'poppler', 'font', 'archive', 'zip', 'tar', 'faad',
        'matroska', 'xine', 'thrift', 'zookeeper', 'solr', 'irc',
        'mail', 'dkim', 'san', 'asan', 'ubsan', 'tsan', 'pam', 'yubikey', 'olm'
    ]
    for kw in thematic_boost_keywords:
        if kw in name_lower:
            score += 10

    # 命中用户给出的建议包名时提高优先级
    preferred_packages = {
        'libmagickcore-6-headers',
        'libapache2-mod-python',
        'libfaad-dev',
        'libarchive-ar-perl',
        'libzookeeper-java',
        'libbcmatroska2-dev',
        'libnet-irc-perl',
        'libasan6-armel-cross',
        'libwebservice-solr-perl',
        'libdkim1d-dbg',
    }
    if name_lower in preferred_packages:
        score += 40

    # lib 前缀且为开发包时，通常代表可被上层应用广泛链接
    if name_lower.startswith('lib'):
        score += 4
    if name_lower.endswith('-dev'):
        score += 3

    return score


scored_packages = sorted(
    ((pkg, score_for_top100(pkg)) for pkg in target_packages),
    key=lambda item: (-item[1], item[0])
)

top100_packages = [pkg for pkg, score in scored_packages if score > 0][:2000]
if len(top100_packages) < 2000:
    # 如果高分条目不足，则按排序补齐至 2000
    remaining = [pkg for pkg in target_packages if pkg not in set(top100_packages)]
    top100_packages.extend(remaining[: 2000 - len(top100_packages)])

print(f"Top2000 候选包数量: {len(top2000_packages)}")

# 创建输出目录
os.makedirs(output_dir, exist_ok=True)

# 输出完整列表
output_file = os.path.join(output_dir, "target_packages.txt")
with open(output_file, 'w') as f:
    for pkg in target_packages:
        f.write(pkg + '\n')
print(f"\n完整结果已输出到: {output_file}")

# 输出自动化筛选的 Top2000 风险包
target2000_file = os.path.join(output_dir, "target2000_01.txt")
with open(target2000_file, 'w') as f:
    for pkg in top2000_packages:
        f.write(pkg + '\n')
print(f"Top2000 包列表已输出到: {target2000_file}")

# 额外筛选：提取所有 Golang 相关库
def is_golang_library(pkg_name):
    name_lower = pkg_name.lower()
    # 严格规则：仅保留 golang- 前缀包。
    # 如需包含 Go 运行时相关库，可把 libgo 前缀放开。
    return name_lower.startswith('golang-')

golang_packages = sorted([pkg for pkg in target_packages if is_golang_library(pkg)])
target_golang_file = os.path.join(output_dir, "target_golang.txt")
with open(target_golang_file, 'w') as f:
    for pkg in golang_packages:
        f.write(pkg + '\n')

print(f"\nGolang 库包数量: {len(golang_packages)}")
print(f"Golang 包列表已输出到: {target_golang_file}")

# 额外筛选：提取所有 librust 前缀包
def is_librust_library(pkg_name):
    return pkg_name.lower().startswith('librust')

ligrust_packages = sorted([pkg for pkg in target_packages if is_librust_library(pkg)])
target_ligrust_file = os.path.join(output_dir, "target_ligrust.txt")
with open(target_ligrust_file, 'w') as f:
    for pkg in ligrust_packages:
        f.write(pkg + '\n')

print(f"\nlibrust 前缀包数量: {len(ligrust_packages)}")
print(f"librust 包列表已输出到: {target_ligrust_file}")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import os
import random

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

# 进一步筛选高危包 (High-Risk Targeting)
def is_high_risk(pkg_name):
    name_lower = pkg_name.lower()
    
    # 聚焦高危区域
    high_risk_patterns = [
        # 1. 各种动态链接库
        'lib',
        # 2. 多媒体处理（漏洞重灾区）
        'image', 'media', 'audio', 'video',
        # 3. 网络工具
        'net', 'web', 'proxy'
    ]
    
    for pattern in high_risk_patterns:
        if pattern in name_lower:
            return True
    
    return False

high_risk_packages = [pkg for pkg in target_packages if is_high_risk(pkg)]
print(f"高危包数: {len(high_risk_packages)}")

# 随机抽取 500 个高危包
random.seed(27)  # 设置随机种子以确保可重现性
sample_size = min(500, len(high_risk_packages))
sampled_packages = random.sample(high_risk_packages, sample_size)
sampled_packages.sort()  # 排序以保持一致性

print(f"随机抽样: {len(sampled_packages)} 个包")

# 创建输出目录
os.makedirs(output_dir, exist_ok=True)

# 输出完整列表
output_file = os.path.join(output_dir, "target_packages.txt")
with open(output_file, 'w') as f:
    for pkg in target_packages:
        f.write(pkg + '\n')

# 输出高危包随机样本
output_sample_file = os.path.join(output_dir, "target500_01.txt")
with open(output_sample_file, 'w') as f:
    for pkg in sampled_packages:
        f.write(pkg + '\n')

print(f"\n完整结果已输出到: {output_file}")
print(f"高危样本已输出到: {output_sample_file}")
print(f"\n高危样本前30个包示例:")
for pkg in sampled_packages[:30]:
    print(f"  {pkg}")

print(f"\n高危样本最后10个包示例:")
for pkg in sampled_packages[-10:]:
    print(f"  {pkg}")

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

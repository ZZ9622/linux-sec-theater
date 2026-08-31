# CSV 中的三个验证链接 (Q1/Q2/Q3)

## 概述
为了便于人工审核漏洞报告，CSV 中新增了三个链接列用于回答关键问题：

| 列名 | 问题 | 用途 |
|-----|------|------|
| `q1_upstream_commit` | **Q1: Is this commit really for fixing a vulnerability?** | 查看上游 commit 消息和 diff，判断是否真的修复了漏洞 |
| `q2_upstream_source` | **Q2: Does this vulnerable code exist in Ubuntu 24.04?** | 在上游源代码中搜索受影响的文件，用指定版本的源代码验证漏洞是否存在 |
| `q3_ubuntu_changelog` | **Q3: Did Ubuntu 24.04 really not fix this vulnerability?** | 在 Ubuntu changelog 中搜索该修复，判断 24.04 是否已修复 |

---

## Q1: Upstream Commit (`q1_upstream_commit`)

### 链接内容
指向上游源代码仓库中对应的 commit 页面。

### 如何验证
1. 点击链接打开 commit 页面
2. **查看 commit 消息**：
   - ✓ **YES** - 包含漏洞关键词：`overflow`, `crash`, `OOB`, `UAF`, `NULL deref`, `leak`, `DoS`, `use-after-free`, `double-free`, `race`, `injection`
   - ✓ **YES** - 以下格式也表示漏洞修复：`Add X limit`, `Add Y check`, `Reject malformed Z`
   - ? **需看 diff** - `add`, `improve`, `refactor`（需看代码变化）
   - ✗ **NO** - 纯功能：`Add feature`, `New API`

3. **如果消息不明确，查看 diff**：
   - ✓ 加了 `if (...) return ERROR` / 加了计数器 / 加了 max 检查 → 漏洞修复
   - ✗ 新功能、新 API、大段重写 → 功能特性

---

## Q2: Upstream Source (`q2_upstream_source`)

### 链接内容
指向上游源代码浏览器（GitHub/GitLab），链接到 **Ubuntu 24.04 版本对应的上游版本** 中的受影响文件。

**注意**: 链接包含的版本号是通过以下方式从 Ubuntu 24.04 版本号推导的：
- Ubuntu 24.04 版本: `2.9.14+dfsg-1.3ubuntu3`
- 上游版本号: `v2.9.14`（去掉 `+dfsg` 之后的 Debian 标记）

### 如何验证
1. 点击链接进入文件浏览页面
2. **Ctrl+F 搜索关键词**：在 CSV `verification_hints` 字段中查找 `source_code_marker_after_patch` 或 `source_code_marker_before_patch`
3. 搜索结果：
   - ✓ **YES (存在)** - 命中 ≥ 1 次 → 漏洞代码存在于 24.04 版本
   - ✗ **NO (不存在)** - 命中 0 次 → 标为 `not_applicable`，跳过 Q3

**示例**:
- 若 CSV 中 `source_code_marker_after_patch` = `max_depth >= MAX_DEPTH`
- 在 Q2 链接页面中 Ctrl+F 搜索 `max_depth`
- 如果找到，说明这行代码在 24.04 中存在

---

## Q3: Ubuntu Changelog (`q3_ubuntu_changelog`)

### 链接内容
指向官方 Ubuntu changelog 页面（changelogs.ubuntu.com），记录了 Ubuntu 24.04 (Noble) 版本中该源码包的所有补丁记录。

### 如何验证
1. 点击链接打开 Ubuntu changelog 页面
2. **Ctrl+F 搜索四个关键词**（按优先级）：
   - CSV 中 `commit_sha` 的前 8 位（例如 `abc12345`）
   - CSV 中 `commit_message` 中最特别的词（例如 `recursion`, `self-referencing`）
   - CVE 编号（如果有）
   - 漏洞特征词（例如 `include limit`, `stack overflow`）

3. 搜索结果判断：
   - **全部 0 命中** → ✓ **YES, real_gap** ✅ - 真正的未修复漏洞
   - **有命中** → 检查上下文：
     - 是否是修复该漏洞的记录 → **false_positive**（已修复）
     - 是否是别的同名洞的修复 → **real_gap**（真正未修复）

**示例**:
- CSV 中 commit_sha = `c2d31064abc`, commit_message = "Fix C14N type confusion"
- 搜索 1: `c2d31064` → 没找到
- 搜索 2: `C14N` → 没找到
- 搜索 3: `type confusion` → 没找到
- **结论**: real_gap ✅

---

## CSV 列说明

### 支持验证的相关 CSV 列

| 列名 | 说明 |
|-----|------|
| `package` | 包名 |
| `commit_sha` | 上游 commit SHA（前 8 位用于 Q3 搜索） |
| `commit_message` | commit 消息（Q1 关键词检查；Q3 搜索） |
| `ubuntu_2404_version` | Ubuntu 24.04 版本号（用于推导上游版本） |
| `ubuntu_component` | Ubuntu 组件（main/universe，用于 Q3 URL）|
| `cve_ids` | CVE 编号列表（Q3 搜索） |
| `q1_upstream_commit` | ← **点击这个链接答 Q1** |
| `q2_upstream_source` | ← **点击这个链接答 Q2** |
| `q3_ubuntu_changelog` | ← **点击这个链接答 Q3** |

---

## 工作流程

### 对每一行数据的检查步骤

1. **Q1 检查** → 点击 `q1_upstream_commit`
   - 看 commit message + diff
   - 判断：YES / NO / 需仔细检查

2. **Q2 检查** → 点击 `q2_upstream_source`（仅在 Q1=YES 时）
   - 搜索代码标记
   - 判断：YES（存在） / NO（不存在） / not_applicable

3. **Q3 检查** → 点击 `q3_ubuntu_changelog`（仅在 Q2=YES 时）
   - 搜索四个关键词
   - 判断：real_gap / false_positive

---

## 常见问题

### Q: 链接无法打开或返回 404?
- 可能原因：上游版本号推导有误（例如有特殊的版本标签）
- 解决：手动修改 URL 中的版本号，例如把 `v2.9.14` 改成 `v2.9.13` 再试
- 或者查看 `upstream_2404_tag_url` 列获得已验证的标签 URL

### Q: 搜索时找不到标记？
- 可能是标记提取有误或代码结构完全不同
- 可以手动查看文件，用 `Ctrl+F` 搜索关键字（如函数名、宏定义）

### Q: changelog 链接报 404?
- 可能包名或版本号有误
- 参考 `ubuntu_changelog_package_overview` 列，访问更宽泛的 changelog 入口

---

## 示例工作流

### 示例：libxml2 commit

```
Package:           libxml2
commit_sha:        c2d31064
commit_message:    Add specific check to avoid signed integer overflow
ubuntu_2404_version: 2.9.14+dfsg-1.3ubuntu3
ubuntu_component:  main
q1_upstream_commit: https://gitlab.gnome.org/GNOME/libxml2/-/commit/c2d31064
q2_upstream_source: https://gitlab.gnome.org/GNOME/libxml2/-/blob/v2.9.14/tree.c
q3_ubuntu_changelog: https://changelogs.ubuntu.com/changelogs/pool/main/libx/libxml2/libxml2_2.9.14+dfsg-1.3ubuntu3/changelog
```

#### Step 1: Q1 检查
- 打开 Q1 链接
- Message: "Add specific check to avoid signed integer overflow"
- 包含 "overflow" → **YES ✓**

#### Step 2: Q2 检查
- 打开 Q2 链接，搜索 `xmlBuildQName`（来自 commit diff 的函数名）
- 找到了该函数 → **YES ✓**

#### Step 3: Q3 检查
- 打开 Q3 链接
- Ctrl+F 搜 `c2d310` → 没找到
- Ctrl+F 搜 `overflow` → 没找到
- Ctrl+F 搜 `integer overflow` → 没找到
- **结论: real_gap ✅**（24.04 确实未修复）

---

## 快速参考

```
Q1: Commit 真的在修漏洞吗？
└─> 答案: YES / NO
    ├─ YES → 继续 Q2
    ├─ NO  → 跳过这行（是功能，不是漏洞）

Q2: 漏洞在 24.04 的版本里存在吗？
└─> 答案: YES / NO / not_applicable
    ├─ YES → 继续 Q3
    ├─ NO  → not_applicable（24.04 版本根本没这个漏洞）

Q3: Ubuntu 24.04 真的没修这个漏洞吗？
└─> 答案: YES (real_gap) / NO (false_positive)
    ├─ YES ✅ → 这是真正的未修复漏洞
    ├─ NO ❌ → 24.04 已有补丁（已修复）
```

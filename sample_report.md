# 安全审计报告

---

## 一、扫描概览

| 项目 | 详情 |
| --- | --- |
| 代码单元总数 | 5 |
| 检测到漏洞数 | 3 |
| 证据包数量 | 3 |
| 综合风险评分 | 72.5/100 |
| 扫描语言 | Python |

### 扫描文件列表

- `app.py`
- `utils.py`
- `config.py`
- `auth.py`
- `api/routes/scan.py`

## 二、漏洞统计

### 按严重程度分布

- 🔴 **ERROR**: 2 个
- 🟡 **WARN**: 1 个

### 按漏洞类型分布

- **SQL Injection**: 1 个
- **Path Traversal**: 1 个
- **Hardcoded Secret**: 1 个

## 三、风险等级评估

- **综合风险等级**: 🟡 中危
- **风险评分**: 72.5/100
- **评估说明**: 系统存在中等风险漏洞，建议尽快修复

## 四、漏洞详情

### 1. SQL Injection

| 项目 | 详情 |
|------|------|
| **规则ID** | `sql-injection-001` |
| **CWE编号** | `CWE-89` |
| **风险等级** | 🔴 高危 |
| **置信度** | high |
| **代码位置** | `app.py:42-45` |

**漏洞描述:**

> 检测到 SQL 注入漏洞：用户输入直接拼接到 SQL 查询语句中，未进行参数化处理。

**代码片段:**

```python
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
```
*文件: app.py，行号: 42*

**修复建议:**

> 使用参数化查询或 ORM 框架，避免直接拼接 SQL 语句。

---

### 2. Path Traversal

| 项目 | 详情 |
|------|------|
| **规则ID** | `path-traversal-001` |
| **CWE编号** | `CWE-22` |
| **风险等级** | 🔴 高危 |
| **置信度** | medium |
| **代码位置** | `utils.py:15` |

**漏洞描述:**

> 检测到路径遍历漏洞：用户输入直接用于文件路径拼接，可能导致任意文件读取。

**代码片段:**

```python
def read_file(filename):
    with open(f'/data/{filename}', 'r') as f:
        return f.read()
```
*文件: utils.py，行号: 15*

**修复建议:**

> 对用户输入进行严格的路径校验，使用白名单机制限制可访问的目录。

---

### 3. Hardcoded Secret

| 项目 | 详情 |
|------|------|
| **规则ID** | `hardcoded-secret-001` |
| **CWE编号** | `CWE-798` |
| **风险等级** | 🟡 中危 |
| **置信度** | high |
| **代码位置** | `config.py:23` |

**漏洞描述:**

> 检测到硬编码密钥：代码中包含明文密码或 API 密钥。

**代码片段:**

```python
SECRET_KEY = 'my_secret_password_123'
```
*文件: config.py，行号: 23*

**修复建议:**

> 将敏感配置存储在环境变量或专用配置管理系统中。

---

*报告生成时间: 自动生成*
*工具: VulnPatch 源代码安全审计平台*
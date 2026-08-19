# dsh-code-vetter（AI 代码安全审查器）

> 📦 仓库地址：https://github.com/SongYuhui14/dsh-code-vetter

DeepSeek Harness (DSH) 插件：**审查代码安全性**——专门针对 AI 生成代码（也适用于任何代码），检测常见安全漏洞。

## 解决什么问题

AI 写的代码越来越多，但**AI 代码常有安全漏洞**：SQL 注入、硬编码密钥、危险函数、弱加密……开发者往往"能跑就行"，忽略了安全。本插件给代码做**快速安全体检**，直接告诉你哪里有问题、怎么修。

## 检测规则（11 条，对齐 OWASP/CWE）

| 类别 | 规则 | 严重度 |
|---|---|---|
| SQL 注入 | SQL 字符串拼接（CWE-89）| 🔴 关键 |
| 命令注入 | exec/spawn 拼接（CWE-78）| 🔴 关键 |
| 密钥泄露 | 硬编码 API key/口令（CWE-798）| 🔴 关键 |
| 代码执行 | eval/new Function/vm（CWE-95）| 🟠 高危 |
| 私钥/口令 | 明文私钥、明文密码（CWE-312）| 🟠 高危 |
| XSS | innerHTML/v-html（CWE-79）| 🟠 高危 |
| 弱加密 | MD5/SHA1/DES/RC4（CWE-327）| 🟠 高危 |
| 认证绕过 | allowAll/bypassAuth（CWE-287）| 🟠 高危 |
| 危险函数 | strcpy/gets 等（CWE-676）| 🟠 高危 |
| 明文传输 | http:// 非本地地址（CWE-319）| 🟡 中危 |
| 依赖风险 | 版本通配符（CWE-1104）| 🟡 中危 |

## 使用方式

对话中直接说：

- "审查这段代码安全吗"
- "检查 AI 生成的代码有没有漏洞"
- "vet-code 这段代码"
- 或把代码粘贴给我，说"帮我审查安全性"

## 输出示例

```
🛡️ AI 代码安全审查报告
==================================================
审查对象: inline-code.js
发现: 2 个安全问题
严重度: 🔴关键 1 ｜ 🟠高危 1 ｜ 🟡中危 0 ｜ 🔵低危 0
安全评分: 65/100 ⚠️

🔴 [CRITICAL] SECRET-001 密钥泄露 (CWE-798)
   位置: :3
   代码: const apiKey = "sk-1234567890abcdefghij"
   问题: 检测到疑似硬编码密钥/口令
   修复: 密钥移入环境变量/密钥管理系统

🟠 [HIGH] SQL-INJ-001 注入 (CWE-89)
   位置: :5
   代码: db.query("SELECT * FROM users WHERE id = " + userId)
   问题: 检测到 SQL 拼接，可能存在 SQL 注入
   修复: 使用参数化查询 / 预编译语句
```

## 开发

```
rules/security-rules.js — 安全规则库（11 条，可扩展）
lib/scan.js             — 扫描引擎（单文件/多文件/评分/报告）
lib/index.js            — 插件入口
```

## 许可

MIT

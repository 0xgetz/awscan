# awscan

面向**授权安全测试**的自动化 Web 漏洞扫描器 — 零依赖，Python 3.9+，仅用标准库。

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](#requirements) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇬🇧 [English](README.md) · 🇮🇩 [Bahasa Indonesia](README.id.md)

## 功能

指向一个 URL — 或只给站点根目录加 `--crawl`，它自动发现全部可注入参数 — 随即执行一整套经过验证的检查：

| 检查 | 技术 |
|---|---|
| 同源爬取 | BFS 遍历链接/表单/JS，收集页面与所有 GET 参数；401/403 路径自动收进绕过测试清单 |
| SQL 注入 | DBMS 错误标记嗅探 + TRUE/FALSE 状态锚点差分 — 绝不凭原始响应长度差判定 |
| 布尔盲注提取 | 通过已确认的 oracle 逐字符恢复（可移植的 `substr()` 等值比较，兼容 SQLite/MySQL/PostgreSQL 形态） |
| 时间盲注 | 堆叠延迟 payload（MySQL `SLEEP`、Postgres `pg_sleep`、MSSQL `WAITFOR`）对比基线延迟中位数 — 一律标注需人工复核 |
| 反射型 XSS | 唯一探测串逐字节反射（引号未被编码），再以事件处理器 payload 二次确认 |
| SSTI | 算术模板探测（`{{7*7}}` 类、`${{…}}`、ERB、Freemarker）— 判定要求 payload 被**计算**而非原样回显 |
| 开放重定向 | 把参数换成外部 canary 域名，用 `Location` 头验证 |
| Host 头注入 | canary `Host:` 出现在响应正文/链接中 — 即密码重置投毒一类漏洞 |
| 403/401 绕过套件 | 路径技巧（`;/`、`..;`、`%2e`、双斜杠）+ 头技巧（`X-Forwarded-For`、`X-Original-URL`、`X-Rewrite-URL`）逐一打到发现的 forbidden 路径 |
| GraphQL | 对常见端点发只读 `__schema` introspection 探测 |
| JS 密钥扫描 | 爬取到的 `.js` 中搜 AWS/GCP/GitHub/Stripe/JWT/私钥模式 — **报告中脱敏**，磁盘上绝不落完整密钥 |
| 安全响应头 + Cookie | 缺失 CSP / XFO / HSTS / XCTO / Referrer-Policy / Permissions-Policy，Cookie `HttpOnly/Secure/SameSite` 审计，服务器版本泄露 |
| 敏感路径 | 常规敏感路径（`.env`、`.git/HEAD`、备份文件），结合内容确认实际泄露 |
| WAF/CDN 指纹 | 被动头 + 良性 payload 响应分析（Cloudflare、AWS WAF、Akamai、mod_security、Imperva 等）— 信息级，用于调整编码策略 |

每条发现都附带使用的精确向量 URL，可手工复现或延伸。报告输出 **JSON + Markdown + SARIF 2.1.0** — SARIF 可直接导入 GitHub Security 面板、VS Code 或 DefectDojo。

## 范围门禁

**目标主机不在 scope 文件里，awscan 拒绝发出任何请求。** 这是硬门禁，不是可选参数 — 爬虫每一跳前也会复检：

```
$ python3 -m awscan.cli --target https://别人的站点.com/x?q=TEST --scope my-scope.txt
[!] host '别人的站点.com' is NOT in the scope file — refusing to send any request.
```

只有持有书面授权时才添加主机：自有资产、实验环境，或漏洞赏金计划声明的范围内目标。

## 快速开始

```bash
git clone https://github.com/0xgetz/awscan && cd awscan
cp scope.example.txt my-scope.txt        # 编辑：加入你的授权主机

# 1) 用内置故意存在漏洞的实验室自检（仅绑定 loopback）
python3 lab_server.py --port 8777 &
python3 -m awscan.cli --crawl --root http://127.0.0.1:8777 \
  --scope my-scope.txt --delay 0.05
# → 10 条发现：盲注提取的 secret、被绕过的 /admin、JS 密钥扫描等

# 2) 手工单表面 + 携带你的会话 + 盲注提取演示
python3 -m awscan.cli --target "http://127.0.0.1:8777/search?q=TEST" \
  --scope my-scope.txt --delay 0.05 \
  --extract-sql "SELECT secret FROM secrets LIMIT 1"

# 3) 正式扫描授权目标（保持默认节奏：delay ≥ 1s）
python3 -m awscan.cli --crawl --root https://in-scope.example.com \
  --scope my-scope.txt --header "Cookie: session=<你的>"
```

手工 target URL 里的 `TEST` 是注入占位符 — 扫描器按 payload 逐一替换。用 `--crawl` 则不需要占位符。

## 参数

| 参数 | 默认 | 含义 |
|---|---|---|
| `--target` | — | 含 `TEST` 占位参数值的 URL（手工表面） |
| `--crawl` | 关 | 同源爬取，自动发现可注入表面 |
| `--root` | 取自 target | 爬取种子 URL |
| `--max-pages` | 60 | 爬取页面上限 |
| `--scope` | `scope.example.txt` | 授权主机清单（`*.domain` = 子域名通配） |
| `--delay` | `1.0` | 请求间隔秒数（对生产目标保持 ≥ 1） |
| `--budget` | `900` | 秒级挂钟预算，超时 SIGALRM 硬退出（socket 挂起时协作式限速无法自救，此兜底会刷缓冲后退出） |
| `--header` | 无 | 可重复的认证/自定义头，如 `--header "Cookie: sid=abc"`（测需登录的表面） |
| `--extract-sql` | 关 | 对一个 `SELECT` 表达式做盲注提取演示 |
| `--out` | `reports` | 报告输出目录（JSON + MD + SARIF） |

## 置信模型（防止自欺）

字节数变化永远不构成发现。注入结论必须有 DBMS 错误标记**或**稳定状态锚点（行数）上的 TRUE/FALSE 差分。绕过 WAF 但锚点纹丝不动的 payload = *不存在注入* — 工具会直接这么说，而不是用原始扫描噪音淹没你。计时类发现一律标注「需人工复核」，因为网络抖动会造假。这与漏洞赏金计划要求的人工验证纪律一致。

## 开发

```bash
python3 -m unittest discover -s test   # 27 项测试，完全离线（自动拉起 loopback 实验室，随机端口）
```

保持本工具可信度的规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 负责任使用

- 仅限授权目标 — 范围门禁让"走正道"成为最省事的道。
- 结果是*候选*发现；上报或修复前请人工验证。
- 内置 `lab_server.py` 故意不安全且仅绑定 loopback。切勿部署。

## 许可证

MIT — 见 [LICENSE](LICENSE)。

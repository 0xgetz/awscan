# awscan

面向**授权安全测试**的自动化 Web 漏洞扫描器 — 零依赖，Python 3.9+，仅用标准库。

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](#requirements) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇬🇧 [English](README.md) · 🇮🇩 [Bahasa Indonesia](README.id.md)

## 功能

指向带参数占位符的 URL，即执行一整套经过验证的检查：

| 检查 | 技术 |
|---|---|
| SQL 注入 | DBMS 错误标记嗅探 + TRUE/FALSE 状态锚点差分 — 绝不凭原始响应长度差判定 |
| 布尔盲注提取 | 通过已确认的 oracle 逐字符恢复（可移植的 `substr()` 等值比较，兼容 SQLite/MySQL/PostgreSQL 形态） |
| 反射型 XSS | 唯一探测串逐字节反射（引号未被编码），再以事件处理器 payload 二次确认 |
| 开放重定向 | 把参数换成外部 canary 域名，用 `Location` 头验证 |
| 安全响应头 | 缺失 CSP / XFO / HSTS / XCTO + 服务器版本泄露 |
| 敏感路径 | 常规敏感路径（`.env`、`.git/HEAD`、备份文件），结合内容确认实际泄露 |

每条发现都附带使用的精确向量 URL，可手工复现或延伸。报告输出 JSON + Markdown。

## 范围门禁

**目标主机不在 scope 文件里，awscan 拒绝发出任何请求。** 这是硬门禁，不是可选参数：

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
python3 -m awscan.cli --target "http://127.0.0.1:8777/search?q=TEST" \
  --scope my-scope.txt --delay 0.05 \
  --extract-sql "SELECT secret FROM secrets LIMIT 1"
# → reports/scan-*.md 含 5 条发现，包括被提取出的 secret

# 2) 正式扫描（保持默认节奏：delay ≥ 1s）
python3 -m awscan.cli --target "https://in-scope.example.com/search?q=TEST" --scope my-scope.txt
```

URL 里的 `TEST` 是注入占位符 — 扫描器按 payload 逐一替换。

## 参数

| 参数 | 默认 | 含义 |
|---|---|---|
| `--target` | 必填 | 含 `TEST` 占位参数值的 URL |
| `--scope` | `scope.example.txt` | 授权主机清单（`*.domain` = 子域名通配） |
| `--delay` | `1.0` | 请求间隔秒数（对生产目标保持 ≥ 1） |
| `--budget` | `900` | 秒级挂钟预算，超时 SIGALRM 硬退出（socket 挂起时协作式限速无法自救，此兜底会刷缓冲后退出） |
| `--extract-sql` | 关 | 对一个 `SELECT` 表达式做盲注提取演示 |
| `--out` | `reports` | 报告输出目录 |

## 置信模型（防止自欺）

字节数变化永远不构成发现。注入结论必须有 DBMS 错误标记**或**稳定状态锚点（行数）上的 TRUE/FALSE 差分。绕过 WAF 但锚点纹丝不动的 payload = *不存在注入* — 工具会直接这么说，而不是用原始扫描噪音淹没你。这与漏洞赏金计划要求的人工验证纪律一致。

## 开发

```bash
python3 -m unittest discover -s test   # 17 项测试，完全离线（自动拉起 loopback 实验室，随机端口）
```

保持本工具可信度的规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 负责任使用

- 仅限授权目标 — 范围门禁让"走正道"成为最省事的道。
- 结果是*候选*发现；上报或修复前请人工验证。
- 内置 `lab_server.py` 故意不安全且仅绑定 loopback。切勿部署。

## 许可证

MIT — 见 [LICENSE](LICENSE)。

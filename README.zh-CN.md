<div align="center">
  <img src="assets/logo.png" alt="awscan 标志" width="128" height="128">
  <h1>awscan</h1>
  <p>面向获授权安全测试的自动化 Web 漏洞扫描器。<br>
  零依赖，仅需 Python 3.9+ 标准库。</p>
  <p>
    <a href="https://github.com/0xgetz/awscan/releases"><img src="https://img.shields.io/github/v/release/0xgetz/awscan?color=e8a33d" alt="版本"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT 许可证"></a>
    <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
    <img src="https://img.shields.io/badge/deps-none-informational" alt="零依赖">
  </p>
  <p>
    <a href="README.md">English</a> · <a href="README.id.md">Bahasa Indonesia</a> · 中文 · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a>
  </p>
</div>

## 工具简介

awscan 对目标站点执行一组经过验证的注入、信息泄露与错误配置检测，并为每项发现附上精确的请求向量，便于手工复现。它建立在两条同类工具普遍缺失的纪律之上：

1. **硬性范围闸门。** 凡是不在 scope 文件里的主机，扫描器拒绝发出任何一个请求。没有绕过用的参数；爬虫在每一次跳转前都会重新校验闸门。
2. **置信度模型。** 原始字节长度差永远不会算作发现。注入类结论必须有 DBMS 报错标记，或在稳定锚点上的 TRUE/FALSE 差分。计时类结果一律标注需人工复核，因为网络抖动会造假。

报告输出为 JSON、Markdown 与 SARIF 2.1.0。SARIF 文件可直接导入 GitHub Security 标签页、VS Code 或 DefectDojo，每条结果都带有 CWE 映射。

## 检测项

| 领域 | 技术 |
|---|---|
| 同源爬取 | 沿链接、表单与 JS bundle 做 BFS，自动发现页面及全部 GET 参数；401/403 路径会被收集进绕过检测队列 |
| SQL 注入 | DBMS 报错标记嗅探，加上稳定状态锚点上的 TRUE/FALSE 差分判据 |
| 布尔盲注提取 | 通过已确认的预言机逐字符恢复，采用可移植的 `substr()` 等值判断（兼容 SQLite、MySQL、PostgreSQL 形态） |
| 时间盲注 | 堆叠延迟载荷（MySQL `SLEEP`、PostgreSQL `pg_sleep`、MSSQL `WAITFOR`），以基线延迟中位数为参照测量 |
| 反射型 XSS | 唯一探针（引号未转义）逐字节回显，随后用事件处理载荷二次确认 |
| SSTI | 算术模板探针（`{{7*7}}` 一类、`${...}`、ERB、Freemarker）；命中要求探针被**计算**后返回，而不是原样回显 |
| 开放重定向 | 将参数替换为外部金丝雀主机，并以 `Location` 响应头验证 |
| Host 头注入 | 金丝雀 `Host:` 头反射进正文或链接；即密码重置投毒那一类漏洞 |
| 403/401 绕过 | 路径技巧（`;/`、`..;`、`%2e`、双斜杠）加头部技巧（`X-Forwarded-For`、`X-Original-URL`、`X-Rewrite-URL`），对全部发现的受限路径执行 |
| GraphQL | 在常见端点上做只读 `__schema` 内省探测 |
| JS 中的密钥 | 扫描爬取到的 bundle 中的 AWS、GCP、GitHub、Stripe、JWT、私钥模式；报告中一律脱敏，绝不落盘完整密钥 |
| 头部与 Cookie | 缺失的 CSP、X-Frame-Options、HSTS、XCTO、Referrer-Policy、Permissions-Policy；Cookie 的 HttpOnly/Secure/SameSite 审计；服务器版本泄露 |
| 暴露路径 | 常规敏感路径（`.env`、`.git/HEAD`、备份文件），并做内容感知确认 |
| WAF/CDN 指纹 | 被动的头部与良性载荷响应分析（Cloudflare、AWS WAF、Akamai、mod_security、Imperva）；属提示性信息，用于决定切换哪种编码策略 |

## 环境要求

- Python 3.9 或更新版本，无任何第三方包
- 对每一个指向的目标持有书面授权

## 安装

```bash
# 从 GitHub 安装（pipx、uv 或 pip 均可）
pipx install git+https://github.com/0xgetz/awscan.git
# 或直接从克隆仓库运行，无需安装步骤
git clone https://github.com/0xgetz/awscan && cd awscan
python3 -m awscan.cli --help
```

## 范围闸门

```
$ awscan --target https://someone-elses-site.com/x?q=TEST --scope my-scope.txt
[!] host 'someone-elses-site.com' is NOT in the scope file. Refusing to send any request.
```

仅在持有授权时添加主机：漏洞赏金计划声明的范围、你自己的资产、或实验靶场。示例文件预置的只有回环地址。

## 快速上手

```bash
cp scope.example.txt my-scope.txt   # 编辑：加入你获授权的主机

# 1) 对内置的故意脆弱靶场做自检（仅限回环地址）
python3 lab_server.py --port 8777 &
awscan --crawl --root http://127.0.0.1:8777 --scope my-scope.txt --delay 0.05
# → 靶场命中 10 项：SQLi（含盲注提取的密钥）、SSTI、XSS、开放重定向、
#   Host 头注入、被绕过的 /admin、GraphQL、JS 密钥、暴露路径、头部卫生

# 2) 带登录会话的单一入口手工模式，并演示盲注提取
awscan --target "http://127.0.0.1:8777/search?q=TEST" --scope my-scope.txt \
  --delay 0.05 --extract-sql "SELECT secret FROM secrets LIMIT 1"

# 3) 获授权的生产目标（保持礼貌的默认值：delay >= 1 秒）
awscan --crawl --root https://in-scope.example.com --scope my-scope.txt \
  --header "Cookie: session=<你的>"
```

在手工 `--target` URL 中，`TEST` 是占位符，扫描器会按载荷逐个替换。使用 `--crawl` 时完全不需要占位符。

## 参数

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--target` | （除非爬取，否则必填） | 含 `TEST` 占位参数值的 URL |
| `--crawl` | 关闭 | 同源爬取，自动发现可注入入口 |
| `--root` | 取自 target | 爬取种子 URL |
| `--max-pages` | 60 | 爬取页数上限 |
| `--scope` | `scope.example.txt` | 授权主机文件；`*.domain` 匹配子域 |
| `--delay` | 1.0 | 请求间隔秒数（生产环境保持 >= 1） |
| `--budget` | 900 | 墙钟秒数上限，超时硬退出；挂死的 socket 无法绕过这道保障 |
| `--header` | 无 | 可重复的自定义头部，如 `--header "Cookie: sid=abc"` |
| `--extract-sql` | 关闭 | 对一个 SELECT 表达式做布尔盲注演示提取 |
| `--out` | `reports` | JSON、Markdown 与 SARIF 的输出目录 |

## 开发

```bash
python3 -m unittest discover -s test   # 27 项测试，完全离线
```

测试套件在每个用例中都会在临时回环端口上拉起靶场；任何测试都不会触网。维持本工具可信度的规则写在 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 负责任使用

- 只用于获授权的目标。范围闸门的意义在于让诚实的路径成为最省事的路径。
- 所有发现都只是候选项。提交或修复前务必人工验证。
- `lab_server.py` 故意不安全且仅限回环。切勿对外暴露。

## 许可证

MIT。见 [LICENSE](LICENSE)。

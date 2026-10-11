# LogLens 📋

> 轻量级日志分析工具 · 纯 Python 标准库 · 零依赖

LogLens 帮你快速看懂一份"陌生"的日志文件：自动识别格式、统计级别与状态码分布、
把散落的错误日志**聚类成可读的错误模式**、按时间/级别/关键字过滤，最后可以一键产出
自包含的 HTML 报告。不需要 ELK，不需要装任何依赖——拷一个文件就能用。

在线演示：<https://1fzx23.github.io/loglens/>

## 功能亮点

- **多格式自动识别**：Nginx/Apache combined 访问日志、经典 syslog、常见应用日志
  （ISO 时间戳开头）、以及回退的纯文本模式，也可用 `--format` 强制指定。
- **stats 统计**：级别分布、HTTP 状态码、Top 来源 IP / 请求路径 / 应用进程、
  按时间桶（`1m/5m/1h/1d`）汇总的 ASCII 时间线。
- **errors 错误聚类**：把消息里的数字、IP、UUID、路径等归一化成占位符，
  同类错误自动合并，一眼看出"哪个错误最多、持续了多久"。
- **filter 过滤**：级别（`--level ERROR,CRITICAL`）、时间范围（`--since/--until`）、
  子串（`--match`，可多次 AND）、正则（`--regex`），支持 stdin 管道。
- **report 报告**：自包含 HTML（内嵌 SVG 图表，无 JS 依赖）、Markdown、JSON 三种格式。
- **零依赖**：只用 Python 标准库，Windows / macOS / Linux 通用。

## 安装

```bash
# 方式一：直接下载单文件使用
git clone https://github.com/1fzx23/loglens.git
cd loglens
python loglens.py --help

# 方式二：pip 安装（提供 loglens 命令）
pip install .
loglens --help
```

要求 Python 3.9+，无任何第三方依赖。

## 快速上手

```bash
# 统计一份 nginx 访问日志
python loglens.py stats access.log

# 错误聚类：同类错误合并计数（WARN 以上）
python loglens.py errors app.log --top 20

# 过滤今晚 22 点以后的 ERROR / CRITICAL
python loglens.py filter app.log --level ERROR,CRITICAL --since "2026-10-11T22:00"

# 组合过滤：关键字 + 正则
python loglens.py filter syslog.log --match "sshd" --regex "Failed.*password"

# 管道 stdin
cat error.log | python loglens.py errors -

# 生成自包含 HTML 报告（默认输出 access.log.report.html）
python loglens.py report access.log

# Markdown / JSON 报告
python loglens.py report app.log -f md --out report.md
python loglens.py stats access.log -o json   # 供脚本/AI 消费
```

## 错误聚类示例

输入（3 条不同的超时报错）：

```
2026-10-11 09:02:41,902 ERROR orders Order 98765 failed: TimeoutError after 30s connecting to payment-gw:8443
2026-10-11 09:02:42,101 ERROR orders Order 98766 failed: TimeoutError after 30s connecting to payment-gw:8443
2026-10-11 09:05:30,944 ERROR orders Order 98768 failed: TimeoutError after 30s connecting to payment-gw:8443
```

`loglens errors` 输出：

```
[1] ×4      ERROR            10-11 09:02~10-11 09:05
    orders Order <N> failed: TimeoutError after <N>s connecting to payment-gw:<N>
    示例: 2026-10-11 09:02:41,902 ERROR orders Order 98765 failed: ...
```

订单号、端口等变量被归一化为 `<N>` / `<IP>` / `<UUID>` / `<PATH>`，
同类错误合并成一个模式，附带出现次数与时间跨度。

## 示例日志

`examples/` 目录自带三份样例，可直接体验：

```bash
python loglens.py stats examples/sample-access.log
python loglens.py errors examples/sample-app.log
python loglens.py errors examples/sample-syslog.log   # syslog 无级别词，自动按关键词推断
```

## 设计说明

- **零 locale 陷阱**：nginx 时间格式 `12/Oct/2026` 用手工解析，不依赖 `strptime` 的 `%b`。
- **时区友好**：解析结果保留原始时区；`--since/--until` 未写时区时按文件本地时间对齐。
- **可集成**：`stats -o json` / `errors -o json` 输出结构化数据，方便接脚本、CI 或 AI 工作流。
- **单文件核心**：所有逻辑在 `loglens/loglens.py`，方便直接拷走或内嵌。

## License

MIT © 2026 [1fzx23](https://github.com/1fzx23) · 「每两周一个小工具」系列

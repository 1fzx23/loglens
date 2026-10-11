#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LogLens — 轻量级日志分析工具（纯 Python 标准库，零依赖）

功能：
  stats   解析日志并输出统计（级别分布 / 状态码 / Top IP / 时间线）
  errors  把 WARN/ERROR 级别的日志按“归一化模式”聚类，快速定位高频错误
  filter  按级别 / 时间范围 / 关键字 / 正则过滤日志行
  report  生成自包含的 HTML / Markdown / JSON 报告

支持格式（自动识别，也可用 --format 指定）：
  nginx    Nginx/Apache combined 访问日志
  syslog   经典 syslog 格式（如 /var/log/syslog、auth.log）
  iso      常见应用日志（时间戳在前，如 "2026-10-12 10:00:00,123 INFO ..."）
  plain    无法识别时回退：整行作为消息，无时间戳

用法示例：
  python loglens.py stats access.log
  python loglens.py errors app.log --top 20
  python loglens.py filter app.log --level ERROR --since 2026-10-01T00:00
  python loglens.py report access.log --format html --out report.html
  cat app.log | python loglens.py stats -
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Tuple

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

LEVEL_ORDER = {
    "TRACE": 5, "DEBUG": 10, "INFO": 20, "NOTICE": 25,
    "WARN": 30, "WARNING": 30, "ERROR": 40, "ERR": 40,
    "CRITICAL": 50, "CRIT": 50, "FATAL": 60, "PANIC": 60,
}


@dataclass
class Entry:
    """一条解析后的日志记录。"""
    raw: str                                  # 原始行（不含换行符）
    ts: Optional[datetime] = None             # 解析出的时间（带 tz 时保留 tz）
    level: Optional[str] = None               # 归一化级别（大写）
    message: str = ""                         # 消息正文
    host: Optional[str] = None                # 来源 IP / 主机名
    method: Optional[str] = None              # HTTP 方法（访问日志）
    path: Optional[str] = None                # 请求路径
    status: Optional[int] = None              # HTTP 状态码
    bytes_sent: Optional[int] = None          # 响应字节数
    referer: Optional[str] = None
    user_agent: Optional[str] = None
    app: Optional[str] = None                 # 应用/进程名（syslog）
    pid: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ts": self.ts.isoformat() if self.ts else None,
            "level": self.level,
            "message": self.message,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "bytes": self.bytes_sent,
            "referer": self.referer,
            "user_agent": self.user_agent,
            "app": self.app,
            "pid": self.pid,
        }


# ---------------------------------------------------------------------------
# 正则与解析器
# ---------------------------------------------------------------------------

# Nginx/Apache combined: 1.2.3.4 - user [12/Oct/2026:10:00:00 +0800] "GET /p HTTP/1.1" 200 1234 "ref" "ua"
RE_NGINX = re.compile(
    r'^(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
    r'\s*(?P<rest>.*)$'
)

# syslog: Oct 12 10:00:00 myhost sshd[1234]: message
RE_SYSLOG = re.compile(
    r'^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) (?P<app>[\w./-]+?)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$'
)

# ISO 时间戳开头（应用日志）: 2026-10-12T10:00:00,123 [INFO] logger : message
RE_ISO = re.compile(
    r'^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[T ]'
    r'(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})'
    r'(?:[.,](?P<frac>\d{1,6}))?'
    r'(?P<tz>Z| ?[+-]\d{2}:?\d{2})?\s*'
    r'(?P<rest>.*)$'
)

RE_LEVEL_TOKEN = re.compile(
    r'\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRIT(?:ICAL)?|FATAL|PANIC)\b',
    re.IGNORECASE,
)

# syslog 行内通常不带级别词，用关键词推断（仅用于 syslog 格式）
RE_SYSLOG_ERR = re.compile(
    r'\b(fail(?:ed|ure)?|error|timed? ?out|denied|refused|unable|panic|critical|fatal|unavailable)\b',
    re.IGNORECASE,
)
RE_SYSLOG_WARN = re.compile(r'\bwarn(?:ing|s)?\b', re.IGNORECASE)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _canon_level(text: str) -> Optional[str]:
    """从文本中提取并归一化日志级别。"""
    m = RE_LEVEL_TOKEN.search(text)
    if not m:
        return None
    lv = m.group(1).upper()
    return "WARN" if lv in ("WARNING",) else ("ERROR" if lv == "ERR" else ("CRITICAL" if lv in ("CRIT",) else lv))


def _parse_nginx_time(s: str) -> Optional[datetime]:
    """手动解析 '12/Oct/2026:10:00:00 +0800'（避免 %b 的 locale 依赖）。"""
    m = re.match(r'(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ?([+-]\d{4})?', s)
    if not m or m.group(2) not in MONTHS:
        return None
    day, mon, year, hh, mm, ss, off = m.groups()
    try:
        dt = datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None
    if off:
        sign = 1 if off[0] == "+" else -1
        dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))))
    return dt


def _parse_iso_tz(tz: Optional[str]) -> Optional[timezone]:
    if not tz or tz == "Z":
        return timezone.utc if tz else None
    s = tz.strip()
    sign = 1 if s[0] == "+" else -1
    s = s[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(s[:2]), minutes=int(s[2:4])))


def parse_nginx(line: str) -> Optional[Entry]:
    m = RE_NGINX.match(line)
    if not m:
        return None
    g = m.groupdict()
    e = Entry(raw=line, ts=_parse_nginx_time(g["time"]), message=line)
    e.host = g["host"]
    e.method = g["method"]
    e.path = g["path"]
    e.status = int(g["status"])
    e.bytes_sent = None if g["bytes"] == "-" else int(g["bytes"])
    e.referer = g.get("referer") or None
    e.user_agent = g.get("ua") or None
    return e


def parse_syslog(line: str, year: Optional[int] = None) -> Optional[Entry]:
    m = RE_SYSLOG.match(line)
    if not m:
        return None
    g = m.groupdict()
    if g["mon"] not in MONTHS:
        return None
    hh, mm, ss = g["time"].split(":")
    y = year if year is not None else datetime.now().year
    try:
        ts = datetime(y, MONTHS[g["mon"]], int(g["day"]), int(hh), int(mm), int(ss))
    except ValueError:
        return None
    e = Entry(raw=line, ts=ts, message=g["msg"], host=g["host"], app=g["app"], pid=g.get("pid"))
    e.level = _canon_level(g["msg"])
    if e.level is None:
        # syslog 无显式级别：按关键词推断，便于 errors 聚类
        if RE_SYSLOG_ERR.search(g["msg"]):
            e.level = "ERROR"
        elif RE_SYSLOG_WARN.search(g["msg"]):
            e.level = "WARN"
    return e


def parse_iso(line: str) -> Optional[Entry]:
    m = RE_ISO.match(line)
    if not m:
        return None
    g = m.groupdict()
    micro = int((g["frac"] or "0").ljust(6, "0"))
    try:
        tz = _parse_iso_tz(g["tz"])
        ts = datetime(int(g["y"]), int(g["mo"]), int(g["d"]),
                      int(g["h"]), int(g["mi"]), int(g["s"]), micro, tzinfo=tz)
    except ValueError:
        return None
    rest = g["rest"]
    e = Entry(raw=line, ts=ts, message=rest)
    e.level = _canon_level(rest)
    if e.level:
        # 把级别词从消息正文前面剥掉，剩下的作为正文
        e.message = RE_LEVEL_TOKEN.sub("", rest, count=1).lstrip(" []:-—,")
    return e


def parse_plain(line: str) -> Entry:
    return Entry(raw=line, message=line, level=_canon_level(line))


PARSERS = {"nginx": parse_nginx, "syslog": parse_syslog, "iso": parse_iso, "plain": parse_plain}


def detect_format(lines: List[str]) -> str:
    """抽样检测日志格式：按各解析器的命中率选择，命中率太低则回退 plain。"""
    sample = [ln for ln in lines if ln.strip()][:200]
    if not sample:
        return "plain"
    best, best_ratio = "plain", 0.0
    for name in ("nginx", "syslog", "iso"):
        hit = 0
        for ln in sample:
            if PARSERS[name](ln) is not None:
                hit += 1
        ratio = hit / len(sample)
        if ratio > best_ratio:
            best, best_ratio = name, ratio
    return best if best_ratio >= 0.5 else "plain"


# ---------------------------------------------------------------------------
# 读取与解析
# ---------------------------------------------------------------------------

def read_lines(path: str) -> Iterable[str]:
    """读取文件或 stdin，忽略无法解码的字节。"""
    fh = sys.stdin if path == "-" else open(path, "r", encoding="utf-8", errors="replace")
    try:
        for line in fh:
            yield line.rstrip("\r\n")
    finally:
        if fh is not sys.stdin:
            fh.close()


def parse_file(path: str, fmt: Optional[str] = None) -> Tuple[str, List[Entry], int]:
    """返回 (格式, 成功解析列表, 跳过行数)。"""
    lines = [ln for ln in read_lines(path) if ln.strip()]
    fmt = fmt or detect_format(lines)
    parser = PARSERS[fmt]
    entries, skipped = [], 0
    for ln in lines:
        e = parser(ln)
        if e is None:
            skipped += 1
            continue
        entries.append(e)
    return fmt, entries, skipped


# ---------------------------------------------------------------------------
# 错误模式聚类
# ---------------------------------------------------------------------------

RE_UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')
RE_LONG_HEX = re.compile(r'\b[0-9a-fA-F]{12,}\b')
RE_QUOTED = re.compile(r'(["\'])[^"\']*\1')
RE_PATH = re.compile(r'(?<![\w<])(/[\w./-]+|\\[w\\./-]+)')
RE_NUM = re.compile(r'\d+(?:\.\d+)?')


def normalize_message(msg: str) -> str:
    """把消息里的变量归一化成占位符，得到“错误模式模板”。"""
    s = msg
    s = RE_UUID.sub("<UUID>", s)
    s = RE_IPV4.sub("<IP>", s)
    s = RE_LONG_HEX.sub("<HEX>", s)
    s = RE_QUOTED.sub("<Q>", s)
    s = RE_PATH.sub("<PATH>", s)
    s = RE_NUM.sub("<N>", s)
    return s.strip()[:160]


@dataclass
class Pattern:
    template: str
    count: int = 0
    levels: Counter = field(default_factory=Counter)
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    sample: str = ""

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "count": self.count,
            "levels": dict(self.levels),
            "first": self.first_ts.isoformat() if self.first_ts else None,
            "last": self.last_ts.isoformat() if self.last_ts else None,
            "sample": self.sample,
        }


def cluster(entries: List[Entry], include_info: bool = False) -> List[Pattern]:
    """按归一化模板聚类 WARN+ 日志（include_info=True 时包含全部级别）。"""
    patterns: dict = {}
    for e in entries:
        if not include_info:
            lv = LEVEL_ORDER.get(e.level or "", 0)
            if lv < LEVEL_ORDER["WARN"]:
                continue
        key = normalize_message(e.message) or "(empty)"
        p = patterns.get(key)
        if p is None:
            p = patterns[key] = Pattern(template=key, sample=e.raw[:300])
        p.count += 1
        p.levels[e.level or "UNKNOWN"] += 1
        if e.ts:
            if p.first_ts is None or e.ts < p.first_ts:
                p.first_ts = e.ts
            if p.last_ts is None or e.ts > p.last_ts:
                p.last_ts = e.ts
    return sorted(patterns.values(), key=lambda p: -p.count)


# ---------------------------------------------------------------------------
# 时间过滤
# ---------------------------------------------------------------------------

def parse_since(s: str) -> datetime:
    """解析 --since/--until，支持 'YYYY-MM-DD' 或完整 ISO 时间，按文件内时区对齐。"""
    s = s.replace(" ", "T")
    if "T" not in s:
        s += "T00:00:00"
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def match_level(e: Entry, levels: Optional[List[str]]) -> bool:
    if not levels:
        return True
    return (e.level or "UNKNOWN") in {l.upper() for l in levels}


# ---------------------------------------------------------------------------
# 统计
# ---------------------------------------------------------------------------

BUCKET_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_bucket(s: str) -> int:
    m = re.fullmatch(r'(\d+)([smhd])', s)
    if not m:
        raise ValueError(f"无效的时间桶: {s}（示例: 1m / 5m / 1h / 1d）")
    return int(m.group(1)) * BUCKET_UNITS[m.group(2)]


def bucket_key(ts: datetime, seconds: int) -> datetime:
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, tz=ts.tzinfo)


def timeline(entries: List[Entry], seconds: int) -> List[Tuple[datetime, int]]:
    c: Counter = Counter()
    for e in entries:
        if e.ts:
            c[bucket_key(e.ts, seconds)] += 1
    return sorted(c.items())


def ascii_bars(buckets: List[Tuple[datetime, int]], max_width: int = 40) -> List[str]:
    if not buckets:
        return []
    peak = max(v for _, v in buckets) or 1
    out = []
    for ts, v in buckets:
        width = max(1, round(v / peak * max_width))
        out.append(f"{ts.strftime('%m-%d %H:%M')}  {v:>6}  {'#' * width}")
    return out


def collect_stats(entries: List[Entry], fmt: str, path: str, skipped: int,
                  bucket: str) -> dict:
    """汇总统计（文本与 JSON 共用）。"""
    levels = Counter(e.level or "UNKNOWN" for e in entries)
    statuses = Counter(e.status for e in entries if e.status is not None)
    hosts = Counter(e.host for e in entries if e.host)
    paths = Counter(e.path for e in entries if e.path)
    apps = Counter(e.app for e in entries if e.app)
    tss = [e.ts for e in entries if e.ts]
    sec = parse_bucket(bucket)

    return {
        "file": path,
        "format": fmt,
        "total_entries": len(entries),
        "skipped_lines": skipped,
        "time_range": {
            "first": min(tss).isoformat() if tss else None,
            "last": max(tss).isoformat() if tss else None,
        },
        "levels": dict(levels.most_common()),
        "status_codes": {str(k): v for k, v in statuses.most_common()},
        "top_hosts": hosts.most_common(10),
        "top_paths": paths.most_common(10),
        "top_apps": apps.most_common(10),
        "bucket": bucket,
        "timeline": [{"bucket": ts.isoformat(), "count": v} for ts, v in timeline(entries, sec)],
    }


def print_stats(s: dict) -> None:
    tr = s["time_range"]
    print(f"文件: {s['file']}    格式: {s['format']}")
    print(f"解析: {s['total_entries']} 条（跳过 {s['skipped_lines']} 行）")
    if tr["first"]:
        print(f"时间范围: {tr['first']}  →  {tr['last']}")
    if s["levels"]:
        total = sum(s["levels"].values()) or 1
        print("\n按级别:")
        for lv, n in s["levels"].items():
            print(f"  {lv:<10} {n:>8}  ({n / total * 100:5.1f}%)")
    if s["status_codes"]:
        print("\n按状态码:")
        for code, n in s["status_codes"].items():
            print(f"  {code}  {n:>8}")
    for key, title in (("top_hosts", "Top 来源/主机"), ("top_paths", "Top 请求路径"), ("top_apps", "Top 应用/进程")):
        if s[key]:
            print(f"\n{title}:")
            for name, n in s[key]:
                print(f"  {n:>8}  {name}")
    buckets = [(datetime.fromisoformat(t["bucket"]), t["count"]) for t in s["timeline"]]
    if buckets:
        print(f"\n时间线（{s['bucket']}）:")
        for line in ascii_bars(buckets):
            print("  " + line)


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------

def bar_svg(values: List[Tuple[str, int]], width: int = 640, height: int = 120,
            color: str = "#4ade80") -> str:
    """生成简单 SVG 条形图（自包含，无 JS）。"""
    if not values:
        return "<p style='color:#64748b'>（无数据）</p>"
    peak = max(v for _, v in values) or 1
    n = len(values)
    slot = width / n
    bars = []
    for i, (label, v) in enumerate(values):
        h = max(2, v / peak * (height - 30))
        bars.append(
            f'<rect x="{i * slot + slot * 0.15:.1f}" y="{height - 20 - h:.1f}" '
            f'width="{slot * 0.7:.1f}" height="{h:.1f}" fill="{color}" rx="2"></rect>'
        )
        if n <= 24:
            bars.append(
                f'<text x="{i * slot + slot / 2:.1f}" y="{height - 6}" font-size="9" '
                f'fill="#94a3b8" text-anchor="middle">{label}</text>'
            )
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'xmlns="http://www.w3.org/2000/svg">{"".join(bars)}</svg>')


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def report_html(path: str, fmt: str, entries: List[Entry], skipped: int,
                bucket: str, top_patterns: List[Pattern]) -> str:
    stats = collect_stats(entries, fmt, path, skipped, bucket)
    levels = [(k, v) for k, v in stats["levels"].items()]
    statuses = [(k, v) for k, v in stats["status_codes"].items()]
    hosts = stats["top_hosts"]
    tl = [(t["bucket"][5:16], t["count"]) for t in stats["timeline"]]
    tr = stats["time_range"]

    pattern_rows = "".join(
        f"<tr><td class='tpl'>{_esc(p.template)}</td><td>{p.count}</td>"
        f"<td>{','.join(sorted(p.levels))}</td>"
        f"<td class='mono'>{_esc(p.sample[:120])}</td></tr>"
        for p in top_patterns[:15]
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LogLens 报告 — {_esc(path)}</title>
<style>
body{{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem;line-height:1.6}}
.container{{max-width:960px;margin:0 auto}}
h1{{color:#fff}} h2{{font-size:1.2rem;border-left:3px solid #4ade80;padding-left:.7rem;margin-top:2rem}}
.card{{background:#1e293b;border-radius:10px;padding:1.2rem;margin:.8rem 0}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th,td{{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #334155;vertical-align:top}}
th{{color:#94a3b8}} td.tpl{{color:#fca5a5;font-family:monospace}} .mono{{font-family:monospace;color:#94a3b8;word-break:break-all}}
.kv{{display:flex;gap:2rem;flex-wrap:wrap}} .kv b{{color:#4ade80}}
footer{{color:#64748b;font-size:.8rem;text-align:center;padding:2rem 0}}
</style></head><body><div class="container">
<h1>📋 LogLens 日志分析报告</h1>
<div class="card kv">
  <span>文件 <b>{_esc(path)}</b></span><span>格式 <b>{fmt}</b></span>
  <span>解析 <b>{stats['total_entries']}</b> 条</span><span>跳过 <b>{skipped}</b> 行</span>
  <span>时间范围 <b>{tr['first'] or '-'} → {tr['last'] or '-'}</b></span>
</div>
<h2>级别分布</h2><div class="card">{bar_svg(levels)}</div>
{'<h2>状态码分布</h2><div class="card">' + bar_svg(statuses, color='#60a5fa') + '</div>' if statuses else ''}
<h2>请求量时间线（{bucket}）</h2><div class="card">{bar_svg(tl, color='#fbbf24')}</div>
{('<h2>Top 来源/主机</h2><div class="card">' + bar_svg(hosts[:12], color='#a78bfa') + '</div>') if hosts else ''}
{'<h2>高频错误模式（归一化聚类）</h2><div class="card"><table><tr><th>模式</th><th>次数</th><th>级别</th><th>示例</th></tr>' + pattern_rows + '</table></div>' if pattern_rows else ''}
<footer>由 <a href="https://github.com/1fzx23/loglens" style="color:#94a3b8">LogLens v{__version__}</a> 生成 · {datetime.now().strftime('%Y-%m-%d %H:%M')}</footer>
</div></body></html>"""


def report_markdown(path: str, fmt: str, entries: List[Entry], skipped: int,
                    bucket: str, top_patterns: List[Pattern]) -> str:
    stats = collect_stats(entries, fmt, path, skipped, bucket)
    lines = [
        f"# LogLens 报告 — {path}", "",
        f"- 格式：`{fmt}`　解析：**{stats['total_entries']}** 条（跳过 {skipped} 行）",
        f"- 时间范围：{stats['time_range']['first']} → {stats['time_range']['last']}", "",
        "## 级别分布", "",
        "| 级别 | 次数 |", "|---|---:|",
    ]
    lines += [f"| {k} | {v} |" for k, v in stats["levels"].items()]
    if stats["status_codes"]:
        lines += ["", "## 状态码", "", "| 状态码 | 次数 |", "|---|---:|"]
        lines += [f"| {k} | {v} |" for k, v in stats["status_codes"].items()]
    if stats["top_hosts"]:
        lines += ["", "## Top 来源/主机", "", "| 主机 | 次数 |", "|---|---:|"]
        lines += [f"| {h} | {n} |" for h, n in stats["top_hosts"]]
    if top_patterns:
        lines += ["", "## 高频错误模式", "", "| 模式 | 次数 | 级别 |", "|---|---:|---|"]
        lines += [f"| `{p.template[:100]}` | {p.count} | {','.join(sorted(p.levels))} |"
                  for p in top_patterns[:15]]
    lines.append(f"\n---\n*由 LogLens v{__version__} 生成*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="loglens", description="LogLens — 轻量级日志分析工具（零依赖）")
    p.add_argument("--version", action="version", version=f"loglens {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("file", help="日志文件路径，'-' 表示 stdin")
        sp.add_argument("--format", choices=["nginx", "syslog", "iso", "plain"],
                        default=None, help="强制指定日志格式（默认自动识别）")

    sp = sub.add_parser("stats", help="统计：级别/状态码/Top主机/时间线")
    add_common(sp)
    sp.add_argument("-b", "--bucket", default="5m", help="时间线粒度，如 1m/5m/1h/1d（默认 5m）")
    sp.add_argument("-o", "--output", choices=["text", "json"], default="text")

    sp = sub.add_parser("errors", help="错误模式聚类（WARN+ 归一化）")
    add_common(sp)
    sp.add_argument("-t", "--top", type=int, default=10, help="显示前 N 个模式（默认 10）")
    sp.add_argument("--all", action="store_true", help="包含 INFO 及以下级别一起聚类")
    sp.add_argument("-o", "--output", choices=["text", "json"], default="text")

    sp = sub.add_parser("filter", help="按级别/时间/关键字/正则过滤")
    add_common(sp)
    sp.add_argument("-l", "--level", default=None,
                    help="级别过滤，逗号分隔，如 ERROR,CRITICAL")
    sp.add_argument("--since", default=None, help="起始时间（ISO，如 2026-10-01T08:00）")
    sp.add_argument("--until", default=None, help="结束时间（ISO）")
    sp.add_argument("-m", "--match", action="append", default=[], help="子串过滤（可多次，AND 关系）")
    sp.add_argument("-r", "--regex", default=None, help="正则过滤")
    sp.add_argument("-c", "--count-only", action="store_true", help="只输出匹配行数")

    sp = sub.add_parser("report", help="生成 HTML/Markdown/JSON 报告")
    add_common(sp)
    sp.add_argument("-b", "--bucket", default="5m", help="时间线粒度（默认 5m）")
    sp.add_argument("-t", "--top", type=int, default=10, help="错误模式条数（默认 10）")
    sp.add_argument("-f", "--fmt-out", choices=["html", "md", "json"], default="html")
    sp.add_argument("--out", default=None, help="输出文件路径（默认 <file>.report.<ext> 或 stdout）")
    return p


def _load(path: str, fmt: Optional[str]) -> Tuple[str, List[Entry], int]:
    try:
        return parse_file(path, fmt)
    except FileNotFoundError:
        print(f"loglens: 文件不存在: {path}", file=sys.stderr)
        sys.exit(1)


def cmd_stats(args) -> int:
    fmt, entries, skipped = _load(args.file, args.format)
    stats = collect_stats(entries, fmt, args.file, skipped, args.bucket)
    if args.output == "json":
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    else:
        print_stats(stats)
    return 0


def cmd_errors(args) -> int:
    fmt, entries, skipped = _load(args.file, args.format)
    patterns = cluster(entries, include_info=args.all)[:args.top]
    if args.output == "json":
        print(json.dumps({"file": args.file, "format": fmt,
                          "patterns": [p.to_dict() for p in patterns]},
                         ensure_ascii=False, indent=2))
        return 0
    print(f"文件: {args.file}    格式: {fmt}    "
          f"错误模式: {len(patterns)} 个（{'全部级别' if args.all else 'WARN+'}）\n")
    if not patterns:
        print("未发现错误/警告模式 🎉")
        return 0
    width = max(len(p.template) for p in patterns[:5]) if patterns else 0
    for i, p in enumerate(patterns, 1):
        lv = ",".join(sorted(p.levels))
        rng = ""
        if p.first_ts and p.last_ts:
            rng = f"{p.first_ts.strftime('%m-%d %H:%M')}~{p.last_ts.strftime('%m-%d %H:%M')}"
        print(f"[{i}] ×{p.count:<6} {lv:<16} {rng}")
        print(f"    {p.template}")
        if len(p.template) <= 120:
            print(f"    示例: {p.sample[:160]}")
        print()
    return 0


def cmd_filter(args) -> int:
    fmt, entries, _ = _load(args.file, args.format)
    since = parse_since(args.since) if args.since else None
    until = parse_since(args.until) if args.until else None
    levels = args.level.split(",") if args.level else None
    rx = re.compile(args.regex) if args.regex else None

    def keep(e: Entry) -> bool:
        if not match_level(e, levels):
            return False
        if since or until:
            ts = e.ts
            if ts is None:
                return False
            # 无时区的 --since/--until 与文件本地时间对齐：同为 naive 比较
            if since and ts.tzinfo and since.tzinfo:
                if ts < since.astimezone(ts.tzinfo):
                    return False
            elif since and ts < since:
                return False
            if until and ts.tzinfo and until.tzinfo:
                if ts > until.astimezone(ts.tzinfo):
                    return False
            elif until and ts > until:
                return False
        for kw in args.match:
            if kw not in e.raw:
                return False
        if rx and not rx.search(e.raw):
            return False
        return True

    hits = [e for e in entries if keep(e)]
    if args.count_only:
        print(len(hits))
        return 0
    for e in hits:
        print(e.raw)
    return 0


def cmd_report(args) -> int:
    fmt, entries, skipped = _load(args.file, args.format)
    top = cluster(entries)[:args.top]
    if args.fmt_out == "html":
        content = report_html(args.file, fmt, entries, skipped, args.bucket, top)
        ext = "html"
    elif args.fmt_out == "md":
        content = report_markdown(args.file, fmt, entries, skipped, args.bucket, top)
        ext = "md"
    else:
        stats = collect_stats(entries, fmt, args.file, skipped, args.bucket)
        stats["top_error_patterns"] = [p.to_dict() for p in top]
        content = json.dumps(stats, ensure_ascii=False, indent=2)
        ext = "json"
    if args.out:
        out = args.out
    elif args.file != "-":
        out = f"{args.file}.report.{ext}"
    else:
        out = None
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"报告已生成: {out}")
    else:
        print(content)
    return 0


COMMANDS = {"stats": cmd_stats, "errors": cmd_errors, "filter": cmd_filter, "report": cmd_report}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.cmd](args)
    except BrokenPipeError:
        return 0
    except (ValueError, re.error) as exc:
        print(f"loglens: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

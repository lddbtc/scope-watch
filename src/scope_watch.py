#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scope-watch — Authorized Bug Bounty Asset & Subdomain Monitor
================================================================

FOR AUTHORIZED SECURITY TESTING ONLY.
仅用于你已获得书面授权 / 已 enrolled 的漏洞赏金项目范围内的资产监控。

这个工具帮助赏金猎人维护「在范围（in-scope）资产」清单，并在多次扫描之间
发现新出现的子域名。它只使用公开、被动的数据源：

  * 证书透明度日志（crt.sh）—— 被动收集已签发证书里的域名
  * 系统 DNS 解析（A / AAAA 记录）

设计原则（红线）：
  1. 必须显式传入 --authorized，确认你对 scope 文件里的每个目标都有授权；
  2. scope 文件必须为每个目标填写 program_url 作为授权证明，否则拒绝运行；
  3. 不主动攻击、不探测范围外主机、不发送任何 exploit 载荷；
  4. 仅做被动信息收集，用于「盘点你自己的在范围资产」。

依赖：Python 3.8+，仅标准库（urllib / json / socket / hashlib）。
可选：安装 requests 可获得更好的超时与重试，但不强制。

用法：
  python3 scope_watch.py --authorized --scope scope.json
  python3 scope_watch.py --authorized --scope scope.json --report report.md
"""

import argparse
import json
import os
import socket
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

TOOL_VERSION = "1.0.0"
USER_AGENT = f"scope-watch/{TOOL_VERSION} (authorized-bugbounty-monitor)"
CRTSH_API = "https://crt.sh/?q=%25.{domain}&output=json"


# --------------------------------------------------------------------------- #
# 授权校验
# --------------------------------------------------------------------------- #
def guard_authorization(args, scope):
    """双重授权闸门：必须 --authorized 且每个目标带 program_url。"""
    if not args.authorized:
        sys.stderr.write(
            "\n[!] 拒绝运行：未通过授权校验。\n"
            "    本工具仅可用于你已获授权的漏洞赏金项目范围。\n"
            "    若你确实对下方每个目标都有书面授权 / 已 enrolled，请加 --authorized 重新运行。\n\n"
        )
        return False

    if not isinstance(scope, dict) or not scope.get("targets"):
        sys.stderr.write("[!] scope 文件缺少 targets 列表。\n")
        return False

    ok = True
    for i, t in enumerate(scope["targets"], 1):
        if not t.get("domain"):
            sys.stderr.write(f"[!] 第 {i} 个目标缺少 domain 字段。\n")
            ok = False
        if not t.get("program_url"):
            sys.stderr.write(
                f"[!] 目标 {t.get('domain', f'#{i}')} 缺少 program_url（授权证明）。\n"
                "    每个目标都必须附上你 enrolled 的赏金项目链接，工具才会运行。\n"
            )
            ok = False
    return ok


# --------------------------------------------------------------------------- #
# 数据源：证书透明度（被动）
# --------------------------------------------------------------------------- #
def fetch_crtsh_subdomains(domain, timeout=20):
    """从 crt.sh 被动获取已签发证书中的子域名。仅收集，不请求目标主机。"""
    subs = set()
    url = CRTSH_API.format(domain=domain)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", "replace")
        entries = json.loads(data)
        for entry in entries:
            name = entry.get("name_value", "")
            for part in name.replace("\n", ",").split(","):
                part = part.strip().lower()
                if part.startswith("*."):
                    part = part[2:]
                if part and domain in part:
                    subs.add(part)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            socket.timeout, TimeoutError) as e:
        sys.stderr.write(f"[!] crt.sh 查询 {domain} 失败：{e}\n")
    return subs


def resolve_ips(host, timeout=5):
    """解析 A / AAAA 记录（被动 DNS，不连接服务端口）。"""
    ips = set()
    try:
        socket.setdefaulttimeout(timeout)
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return sorted(ips)


# --------------------------------------------------------------------------- #
# 快照读写
# --------------------------------------------------------------------------- #
def snapshot_path(base_dir, domain):
    safe = domain.replace("/", "_").replace(":", "_")
    return os.path.join(base_dir, "snapshots", f"{safe}.json")


def load_snapshot(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_snapshot(path, snap):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def scan_target(target, snap_dir):
    domain = target["domain"]
    print(f"[*] 扫描 {domain} （范围证明：{target.get('program_url')}）")
    subs = fetch_crtsh_subdomains(domain)
    assets = {}
    for sub in sorted(subs):
        assets[sub] = {"ips": resolve_ips(sub)}
    snap = {
        "domain": domain,
        "program_url": target.get("program_url"),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "assets": assets,
    }
    save_snapshot(snapshot_path(snap_dir, domain), snap)
    return snap


def diff_snapshots(old, new):
    old_assets = set(old.get("assets", {}).keys()) if old else set()
    new_assets = set(new.get("assets", {}).keys())
    added = sorted(new_assets - old_assets)
    removed = sorted(old_assets - new_assets)
    return added, removed


def render_report(scope, snaps, diffs):
    lines = [
        f"# scope-watch 资产监控报告",
        "",
        f"- 生成时间：{datetime.now(timezone.utc).isoformat()}",
        f"- 目标数：{len(scope.get('targets', []))}",
        f"- 声明：仅覆盖你已获授权的在范围资产（For authorized scope only）",
        "",
    ]
    for (target, snap), (added, removed) in zip(snaps, diffs):
        domain = target["domain"]
        lines.append(f"## {domain}")
        lines.append(f"- 范围证明：{target.get('program_url')}")
        lines.append(f"- 当前资产数：{len(snap.get('assets', {}))}")
        if added:
            lines.append(f"- 🟢 新增子域名（{len(added)}）：")
            for a in added:
                lines.append(f"  - `{a}` → {', '.join(snap['assets'].get(a, {}).get('ips', [])) or '—'}")
        else:
            lines.append("- 🟢 新增子域名：无")
        if removed:
            lines.append(f"- 🔴 消失子域名（{len(removed)}）：")
            for r in removed:
                lines.append(f"  - `{r}`")
        else:
            lines.append("- 🔴 消失子域名：无")
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Authorized Bug Bounty Asset & Subdomain Monitor (passive, CT-log based)."
    )
    parser.add_argument("--scope", required=True, help="scope JSON 文件路径（含 targets + program_url）")
    parser.add_argument("--authorized", action="store_true",
                        help="确认你对 scope 内每个目标都有书面授权 / 已 enrolled")
    parser.add_argument("--report", default="report.md", help="报告输出路径（默认 report.md）")
    parser.add_argument("--snap-dir", default="snapshots", help="快照目录（默认 ./snapshots）")
    args = parser.parse_args()

    # 加载 scope
    try:
        with open(args.scope, "r", encoding="utf-8") as f:
            scope = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        sys.stderr.write(f"[!] 无法读取 scope 文件：{e}\n")
        sys.exit(2)

    # 授权闸门
    if not guard_authorization(args, scope):
        sys.exit(3)

    print(f"scope-watch v{TOOL_VERSION} — 授权模式已确认，开始被动扫描...\n")

    snaps = []
    diffs = []
    for target in scope["targets"]:
        domain = target["domain"]
        new_snap = scan_target(target, args.snap_dir)
        old_snap = load_snapshot(snapshot_path(args.snap_dir, domain))
        added, removed = diff_snapshots(old_snap, new_snap)
        snaps.append((target, new_snap))
        diffs.append((added, removed))
        # 打印简要
        print(f"    → 共 {len(new_snap['assets'])} 个资产 | 新增 {len(added)} | 消失 {len(removed)}")
        # 覆盖写回快照（含本次结果），下次运行即能 diff
        save_snapshot(snapshot_path(args.snap_dir, domain), new_snap)

    report = render_report(scope, snaps, diffs)
    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"\n[✓] 报告已写入：{args.report}")
    print("[✓] 合规提示：本工具仅用于授权范围；请勿对范围外资产运行。")


if __name__ == "__main__":
    main()

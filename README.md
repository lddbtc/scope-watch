# scope-watch · Authorized Bug Bounty Asset & Subdomain Monitor

> **FOR AUTHORIZED SECURITY TESTING ONLY.**
> 仅用于你已获得书面授权 / 已 enrolled 的漏洞赏金项目范围。
> 本工具不做任何主动攻击，仅被动收集公开信息用于「盘点你自己的在范围资产」。

被动、合规的资产监控器，帮赏金猎人在多次扫描之间发现新出现的子域名。
数据源全部公开、被动：

- **证书透明度日志（crt.sh）** — 被动抓取已签发证书里的域名
- **系统 DNS 解析（A / AAAA）** — 仅解析，不连接任何服务端口

零依赖：Python 3.8+，**仅用标准库**，clone 即用，无需 `pip install`。

---

## 为什么做这个（以及为什么合规）

很多侦察/扫描工具游走在灰产边缘。本工具刻意做减法：

1. **强制授权闸门** — 必须传 `--authorized`，且 scope 里每个目标都要附 `program_url`（你 enrolled 的项目链接），否则直接拒绝运行；
2. **只认在范围资产** — 不碰范围外主机，不做端口扫描、不做漏洞利用；
3. **纯被动** — 只用证书透明度和公开 DNS，不向目标发送任何探测流量。

它解决的是合法赏金猎人的真实痛点：同一个项目范围里，资产会持续变化，
新上线的子域名往往是最容易出成果的地方。把「变化」自动 diff 出来，省去手工人肉。

---

## 安装

```bash
git clone https://github.com/<你的用户名>/scope-watch.git
cd scope-watch
# 可选：安装 requests 获得更好的超时/重试（不装也能跑）
# pip install -r requirements.txt
python3 src/scope_watch.py --help
```

---

## 用法

1. 复制示例并填写你**已授权**的目标：

   ```bash
   cp scope.example.json scope.json
   # 编辑 scope.json：把 domain 换成你的在范围域名，program_url 换成你 enrolled 的项目链接
   ```

2. 运行（必须带 `--authorized`）：

   ```bash
   python3 src/scope_watch.py --authorized --scope scope.json --report report.md
   ```

3. 第一次运行会建立快照；**隔一段时间再跑一次**，报告里就会列出
   🟢 新增子域名 / 🔴 消失子域名，以及对应的 IP。

---

## scope.json 格式

```json
{
  "targets": [
    { "domain": "example.com", "program_url": "https://hackerone.com/example/programs/example-com" }
  ]
}
```

- `domain`：你在范围内、需要监控的域名
- `program_url`：**必填**，你 enrolled 的赏金项目链接 —— 既是授权证明，也是合规红线

---

## 输出

- `snapshots/<domain>.json`：每次扫描的资产快照（自动维护，用于 diff）
- `report.md`：人类可读的变更报告

---

## 法律与道德

- 你**必须**对你监控的每一个域名拥有书面授权或已通过官方赏金项目 enrolled。
- 禁止将本工具用于任何未授权目标。违反者后果自负，与作者无关。
- 本工具不含任何 exploit / 攻击载荷，也不发起主动探测。

---

## 配套产品

本仓库是 **Bug Bounty Report Kit** 生态的引流开源组件（Product #3）。
如果你想把「漏洞写成厂商愿意付钱的报告」，看这里 👉
配套付费包：15 个英文报告模板 + 提交前自检清单 + AI 报告工作流 Prompt 包。

---

## 支持本项目（Sponsors）

如果这个工具帮你省了时间，欢迎在 GitHub 上 **Sponsor** 我 ☕
（See the "Sponsor" button on the repo page. Edit `.github/FUNDING.yml` to add your handle.）

License: MIT

#!/usr/bin/env bash
# push.sh — 把 scope-watch 推送到你的 GitHub（需先有 GitHub 账号）
#
# 用法：
#   GITHUB_USERNAME=dongdongliu ./push.sh
# 或：
#   ./push.sh dongdongliu
#
# 说明：
#   1. 脚本会 git init / add / commit，并把 remote 设为
#      https://github.com/<你的用户名>/scope-watch.git
#   2. 推送时需要 GitHub 身份：请在 GitHub 生成一个 Classic PAT（勾 repo 权限），
#      然后选下面任一种方式认证：
#        - 把 PAT 配置到 git 凭据，或直接 `git push` 时粘贴；
#        - 或改 remote 为 https://<PAT>@github.com/<用户>/scope-watch.git
#   3. 首次 push 前，请先去 github.com 手动 New repository 建一个同名空仓库
#      （不要勾 README，保持空，便于首次 push）。

set -euo pipefail

USER="${1:-${GITHUB_USERNAME:-}}"
if [ -z "$USER" ]; then
  echo "用法: GITHUB_USERNAME=你的用户名 ./push.sh   （或 ./push.sh 你的用户名）"
  exit 1
fi

REPO="scope-watch"
REMOTE="https://github.com/${USER}/${REPO}.git"

cd "$(dirname "$0")"

git init -q 2>/dev/null || true
git add -A
if git diff --cached --quiet; then
  echo "[*] 没有可提交的改动，跳过 commit。"
else
  git commit -q -m "feat: scope-watch v1.0.0 — authorized asset & subdomain monitor"
fi

# 设置默认分支为 main
git branch -M main 2>/dev/null || true

# 已存在同名 remote 则更新，否则新增
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE"
else
  git remote add origin "$REMOTE"
fi

echo "[*] 准备推送到：$REMOTE"
echo "[*] 若提示输入密码，请粘贴你的 GitHub PAT（经典令牌，勾 repo 权限）。"
git push -u origin main

echo "[✓] 完成。仓库地址：https://github.com/${USER}/${REPO}"
echo "[*] 记得把 .github/FUNDING.yml 里的用户名改成 ${USER}，开启 Sponsors。"

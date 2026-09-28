# workbuddy-auto-checkin

WorkBuddy（codebuddy.cn 桌面端）「Buddy 加油站」每日自动签到脚本。每天 09:00 自动领取积分，幂等、不会重复领；也可以脱离 WorkBuddy 作为独立 Python 工具运行。

## 形式

本仓库同时是 **WorkBuddy Skill**：根目录的 `SKILL.md` 让 WorkBuddy 在对话中自动识别并调用；脚本本身也能独立运行。

## 安装

### 作为 WorkBuddy Skill

把本仓库克隆到本地 skill 目录即可：

```bash
git clone https://github.com/jiyan1989/workbuddy-auto-checkin.git ~/.workbuddy/skills/workbuddy-auto-checkin
```

（Windows 上 `~` 即 `%USERPROFILE%`。）重启 WorkBuddy 后，对话中即可让它帮你做每日签到或排查问题。

### 注册 Windows 计划任务（每日 09:00 自动跑）

```powershell
powershell -ExecutionPolicy Bypass -File install_task.ps1
```

脚本依赖 WorkBuddy 自带的托管 Python，无需另行安装。

## 独立运行

需要 Python 3（建议 3.10+）与 `cryptography`：

```bash
pip install cryptography
python workbuddy_checkin.py                 # 正常签到
python workbuddy_checkin.py --check-only    # 只查状态，不领取
python workbuddy_checkin.py --json          # 仅输出 JSON 结果
python workbuddy_checkin.py --quiet         # 不写日志
```

## 工作原理（重要）

WorkBuddy 桌面端把登录态落在 `%LOCALAPPDATA%\CodeBuddyExtension\Data\*\auth\workbuddy-desktop.info`。**自 2026-09-28 起，该文件里的 `accessToken` 已是加密信封（AES-GCM），本机不再有明文 JWT。** 所以本脚本不再直接读 token，而是：

1. 枚举 WorkBuddy 进程，扫描其可读内存页，提取当前账号的 JWT（按 `uid` / `sub` / `iss` 精确匹配当前账号）；
2. 用 Keycloak JWK 公钥（`https://www.codebuddy.cn/auth/realms/copilot/protocol/openid-connect/certs`）对签名段做「从后向前截断 + RS256 验签」清洗——因为进程内存里 JWT 是连续存储的，正则会把签名段尾部多吞字符，导致验签失败（APISIX 网关 401）；
3. 调用签到接口时带 `X-Domain: www.codebuddy.cn` 头（APISIX 网关要求该头，否则 401）。

客户端未运行时，脚本回退到最近一次成功缓存的 token（约 55 天有效，存于本地 `checkin_token_cache.json`），缓存失效后再打开客户端重新提取即可。

## 隐私

- 脚本**不收集、不上传**任何凭据。Token 仅从你本机运行的 WorkBuddy 进程内存提取，或缓存于本机脚本目录。
- 登录态文件、token 缓存（`checkin_token_cache.json`）、运行日志（`checkin.log`）均已在 `.gitignore` 中排除，**不会进入本仓库**。
- 注意：请勿把 `workbuddy-desktop-ai.info`（www.workbuddy.ai 的另一个账号）混用，否则会签错账。

## 适用对象

仅适用于 WorkBuddy / CodeBuddy 桌面端（codebuddy.cn 账号）的「Buddy 加油站」签到活动。

## 免责声明

本工具仅用于个人自动化签到，请遵守对应平台的使用条款；因使用产生的任何后果由使用者自行承担。

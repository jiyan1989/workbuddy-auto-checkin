---
name: workbuddy-checkin
description: 在本机搭建 WorkBuddy「Buddy 加油站」每日签到自动领取。当用户说「设置 WorkBuddy 自动签到」「自动领积分」「每天自动签到 WorkBuddy」「Buddy 加油站签到」时使用。会读取本机登录态、验证接口、并注册每天 09:00 的 Windows 计划任务。
---

# WorkBuddy 每日签到自动化

在本机把 WorkBuddy 每日签到做成「到点必跑」的自动化，不依赖 AI 服务可用性。

## 原理（已验证）

WorkBuddy 桌面端把登录态 JSON 落在本机（`workbuddy-desktop.info`）。2026-09-28 起 `auth.accessToken` 已加密落盘，本机不再有明文 JWT；脚本改为从**运行中的客户端进程内存**提取当前账号令牌（客户端发请求时 token 必在内存明文）。

```
%LOCALAPPDATA%\CodeBuddyExtension\Data\<Public|uid>\auth\workbuddy-desktop.info
  ├─ auth.accessToken   Bearer 令牌（JWT，有效期约 55 天，客户端自动续期）
  ├─ auth.domain        接口域名（本机实测 www.codebuddy.cn）
  └─ account.uid
```

官方接口：

```
POST https://<auth.domain>/v2/billing/meter/checkin-activity-status   查状态
POST https://<auth.domain>/v2/billing/meter/daily-checkin             领取
Header: Authorization: Bearer <accessToken>  +  X-User-Id: <uid>
       Accept: application/json, Content-Type: application/json
```

**关键坑**：调用接口必须带 `X-Domain: www.codebuddy.cn` 头，否则 APISIX 网关返回 401（客户端自身也带此头）。域名取本机登录态的 `auth.domain`（`www.codebuddy.cn`）即可，无需改用 `copilot.tencent.com`。

## 搭建步骤

1. 确认 WorkBuddy 客户端**已登录**。登录态文件不存在就先让用户登录一次。

2. 把本目录的 `workbuddy_checkin.py` 复制到稳定路径（建议）：

   ```
   %USERPROFILE%\.workbuddy\scripts\workbuddy_checkin.py
   ```

3. 先只查状态验证链路（**不领取**）：

   ```
   "<python>" "%USERPROFILE%\.workbuddy\scripts\workbuddy_checkin.py" --check-only
   ```

   期望输出形如：`{"action":"check_only","status_http":200,"today_signed":false,...}`
   - `status_http:200` → 链路通
   - `error=unauthorized` → 令牌过期，让用户打开一次客户端
   - `error=no_session` → 登录态文件没找到

4. 注册每天 09:00 的 Windows 计划任务（需要 `install_task.ps1`）：

   ```
   powershell -ExecutionPolicy Bypass -File "<脚本目录>\install_task.ps1"
   ```

   任务名 `WorkBuddyDailyCheckin-SystemTask`，已开「错过补跑 / 唤醒执行 / 需联网」。

5. 验证：

   ```
   Start-ScheduledTask -TaskName 'WorkBuddyDailyCheckin-SystemTask'
   Get-ScheduledTaskInfo -TaskName 'WorkBuddyDailyCheckin-SystemTask'   # LastTaskResult 应为 0
   ```

   再读同目录 `checkin.log`，出现 `action=skip_already_signed` 或 `action=clicked` 即正常。

## 输出语义

| action | 含义 |
|---|---|
| `clicked` | 领取成功 |
| `skip_already_signed` | 今天已签过，幂等跳过（**正常，不是失败**） |
| `check_only` | 只查了状态 |
| `error` | 见 `error` / `msg` 字段 |

## 已知故障与修复（2026-09-28 起）

> **已修复**：原脚本直接读明文 `accessToken` 会因加密信封崩溃（`AttributeError: 'dict' object has no attribute 'strip'`）。现脚本改为从运行进程内存提取 JWT + JWK 公钥做"截断+验签"清洗（内存里 JWT 连续存储会让正则把签名段尾部多吞字符，必须从后向前截断重验，否则 APISIX 网关验签失败→401）。本机无需明文令牌即可自动签到；客户端未运行时回退到 `scripts/checkin_token_cache.json` 缓存（约 55 天有效）。


2026-09-28 起，WorkBuddy 桌面端把敏感字段**加密落盘**，`workbuddy-desktop.info` 里：

```json
"auth": { "accessToken": { "$wbEncrypted": 1, "envelope": "eyJzdWl0ZSI6MS..." } }
```

`accessToken` / `refreshToken` / `account.nickname` / `account.phoneNumber` 均从明文字符串
变成信封对象（内层 `{"suite":1,"keyId":..,"nonce":..,"authTag":..,"ciphertext":..}`，AES-GCM）。
`auth.domain`、`account.uid` **仍是明文**。密钥在客户端侧，本机 `Data/` 与 `.workbuddy/local_storage/`
均无明文副本可复用（已实测搜不到 JWT）。

**症状**：脚本在 `load_session()` 抛
`AttributeError: 'dict' object has no attribute 'strip'`（第 91 行），退出码 1，**不产出任何 JSON**。
注意这不是三态之一（clicked / skip_already_signed / error）。

**不要**把 `workbuddy-desktop-ai.info` 当替代品：它是**另一个账号/产品**的旧明文会话
（domain `www.workbuddy.cn`，与当前 `www.codebuddy.cn` 账号 uid 不同），签错了账。

**恢复前提**：要么客户端重新写回明文令牌，要么脚本获得信封解密能力（需先从客户端取到 suite key）。

## 注意事项

- 脚本**幂等**：先查状态，已签就跳过，绝不重复领取。
- 脚本只读本机登录态、只请求官方域名，不外传数据，**不含任何个人凭据**，可安全分享。
- 要验证「领取」而不是「跳过」，必须挑**当天还没手动签到**的时候跑。
- 换机器时重新跑一次 `install_task.ps1` 即可；卸载见交付说明。
- Windows PowerShell 5.1 读无 BOM 的 UTF-8 脚本会乱码，`.ps1` 一律用纯 ASCII 写。

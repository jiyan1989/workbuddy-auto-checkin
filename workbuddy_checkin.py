#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkBuddy「Buddy 加油站」每日自动签到（2026-09-28 之后版本）。

背景与修复
----------
2026-09-28 起，WorkBuddy 桌面端把 workbuddy-desktop.info 里的 accessToken 加密落盘
（AES-GCM 信封），本机已无明文 JWT；且即便拿到 token，APISIX 网关还要求 X-Domain 头，
内存里 JWT 连续存储又会导致正则把签名段尾部多吞字符（验签失败/401）。

本脚本因此改为：枚举 WorkBuddy 进程 -> 扫描内存提取当前账号 JWT -> 用 Keycloak JWK
公钥做"截断+验签"清洗 -> 带 X-Domain 头调用签到接口。客户端运行时即可自动签到；
客户端未运行时，会回退使用最近一次成功缓存的 token（55 天有效期内可续签）。

用法
----
    python workbuddy_checkin.py               # 正常签到（默认）
    python workbuddy_checkin.py --check-only  # 只查状态，不领取
    python workbuddy_checkin.py --json        # 只输出 JSON 结果
    python workbuddy_checkin.py --quiet       # 不写 stderr 日志

仅用 Python 标准库 + ctypes（Windows）。验签需 cryptography（缺失时回退裸用并依赖缓存）。
只读本机登录态明文域/uid、只读运行进程内存，不外传任何数据。
"""
import argparse
import glob
import io
import json
import os
import sys
import time
import base64
import re
import urllib.request
import urllib.error
import ctypes
from ctypes import wintypes

# ---------------------------------------------------------------- 常量
STATUS_PATH = "/v2/billing/meter/checkin-activity-status"
CLAIM_PATH = "/v2/billing/meter/daily-checkin"
TIMEOUT = 20
LOG_NAME = "checkin.log"
HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_NAME = "checkin_token_cache.json"
JWKS_URL = "https://www.codebuddy.cn/auth/realms/copilot/protocol/openid-connect/certs"

# cryptography 可在缺失时回退
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


# ---------------------------------------------------------------- 日志
QUIET = False


def log(msg):
    line = "%s  %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with io.open(os.path.join(HERE, LOG_NAME), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if not QUIET:
        sys.stderr.write(line + "\n")


# ---------------------------------------------------------------- 编解码
def b64url(s):
    if isinstance(s, str):
        s = s.encode("ascii")
    s = s.rstrip(b"=")
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_payload(seg):
    try:
        return json.loads(b64url(seg))
    except Exception:
        return None


# ---------------------------------------------------------------- Windows API
kernel32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
READABLE = (PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
MAX_REGION = 64 * 1024 * 1024

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


def list_wb_pids():
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.CHAR * 260),
        ]

    h = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h == ctypes.c_void_p(-1).value:
        return []
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    res = []
    if kernel32.Process32First(h, ctypes.byref(pe)):
        while True:
            name = pe.szExeFile.decode("utf-8", "ignore")
            if "workbuddy" in name.lower() or "codebuddy" in name.lower():
                res.append((pe.th32ProcessID, name))
            if not kernel32.Process32Next(h, ctypes.byref(pe)):
                break
    kernel32.CloseHandle(h)
    return res


JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


def scan_pid(pid, want_uid, max_bytes=400 * 1024 * 1024):
    p = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not p:
        return []
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    scanned = 0
    found = []
    while addr < (1 << 47):
        if not kernel32.VirtualQueryEx(
            p, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
        ):
            break
        base_int = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and size <= MAX_REGION:
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(
                p, ctypes.c_void_p(base_int), buf, size, ctypes.byref(read)
            ):
                scanned += read.value
                data = buf.raw[: read.value]
                for m in JWT_RE.finditer(data):
                    tok = m.group(0)
                    parts = tok.split(b".")
                    pl = decode_payload(parts[1]) if len(parts) == 3 else None
                    if pl and (
                        pl.get("uid") == want_uid
                        or pl.get("sub") == want_uid
                        or "codebuddy" in str(pl.get("iss", "")).lower()
                    ):
                        found.append(tok.decode("ascii"))
                        break
        addr = base_int + size
        if scanned >= max_bytes:
            break
    kernel32.CloseHandle(p)
    return found


def load_plain():
    local = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local")
    data_root = os.path.join(local, "CodeBuddyExtension", "Data")
    for path in sorted(glob.glob(os.path.join(data_root, "*", "auth", "workbuddy-desktop.info"))):
        try:
            d = json.load(io.open(path, "r", encoding="utf-8", errors="replace"))
        except Exception:
            continue
        auth = d.get("auth") or {}
        acc = d.get("account") or {}
        domain = (auth.get("domain") or "www.codebuddy.cn")
        domain = domain.replace("https://", "").replace("http://", "").strip("/")
        uid = acc.get("uid") or ""
        if uid:
            return domain, uid, path
    return None, None, None


# ---------------------------------------------------------------- 签名清洗
def fetch_jwks():
    try:
        with urllib.request.urlopen(JWKS_URL, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def clean_and_verify(tok, jwks):
    """内存里 JWT 连续存储会导致签名段尾部被多吞字符；从后向前截断签名段并用 JWK 验签。"""
    try:
        parts = tok.split(".")
        if len(parts) != 3:
            return None
        h, p, third = parts
        hdr = decode_payload(h)
        if not isinstance(hdr, dict):
            return None
        kid = hdr.get("kid")
        jwk = None
        for k in (jwks or {}).get("keys", []):
            if k.get("use") == "sig" and (kid is None or k.get("kid") == kid):
                jwk = k
                break
        if not jwk:
            return None
        n = int.from_bytes(b64url(jwk["n"]), "big")
        e = int.from_bytes(b64url(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        signing_input = (h + "." + p).encode("ascii")
        for L in range(len(third), 200, -1):
            sig_raw = b64url(third[:L])
            if len(sig_raw) < 200:
                continue
            try:
                pub.verify(sig_raw, signing_input, padding.PKCS1v15(), hashes.SHA256())
                return h + "." + p + "." + third[:L]
            except Exception:
                continue
    except Exception:
        return None
    return None


def token_exp(tok):
    try:
        parts = tok.split(".")
        pl = decode_payload(parts[1])
        return pl.get("exp") if isinstance(pl, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------- 缓存
def load_cache():
    try:
        with io.open(os.path.join(HERE, CACHE_NAME), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_cache(tok):
    try:
        with io.open(os.path.join(HERE, CACHE_NAME), "w", encoding="utf-8") as f:
            json.dump({"token": tok, "saved_at": int(time.time()),
                       "exp": token_exp(tok)}, f)
    except Exception:
        pass


# ---------------------------------------------------------------- HTTP
def http_post(domain, path, token, uid):
    url = "https://%s%s" % (domain, path)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer %s" % token,
        "X-User-Id": uid or "",
        "X-Domain": "www.codebuddy.cn",
        "User-Agent": "WorkBuddy-Checkin/2.1",
    }
    req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, raw, str(e)
    except Exception as e:
        return None, "", "%s: %s" % (type(e).__name__, e)


def pick(d, *names):
    if not isinstance(d, dict):
        return None
    for n in names:
        if n in d and d[n] is not None:
            return d[n]
    return None


def find_valid_token(domain, uid, tokens):
    for tok in sorted(set(tokens), key=len, reverse=True):
        st, raw, err = http_post(domain, STATUS_PATH, tok, uid)
        if st == 200:
            payload = None
            try:
                payload = json.loads(raw)
            except Exception:
                payload = None
            return tok, st, payload, raw
    return None, None, None, None


# ---------------------------------------------------------------- 主流程
def main():
    global QUIET
    ap = argparse.ArgumentParser(description="WorkBuddy 每日自动签到")
    ap.add_argument("--check-only", action="store_true", help="只查状态，不领取")
    ap.add_argument("--json", action="store_true", help="只输出 JSON 结果")
    ap.add_argument("--quiet", action="store_true", help="不写 stderr 日志")
    args = ap.parse_args()
    QUIET = args.quiet

    result = {"ts": int(time.time()), "action": "unknown"}

    domain, uid, path = load_plain()
    if not uid:
        result["action"] = "error"
        result["error"] = "no_session"
        result["msg"] = "未找到本机 WorkBuddy 登录态（domain/uid），请先在客户端登录"
        emit(result, args)
        return 2

    result["domain"] = domain

    # 1) 从运行进程内存提取 + 清洗
    raw_candidates = []
    for pid, name in list_wb_pids():
        try:
            raw_candidates.extend(scan_pid(pid, uid))
        except Exception:
            pass
    raw_candidates = list(dict.fromkeys(raw_candidates))

    jwks = fetch_jwks() if HAVE_CRYPTO else None
    clean = []
    if HAVE_CRYPTO and jwks:
        for c in raw_candidates:
            t = clean_and_verify(c, jwks)
            if t:
                clean.append(t)
    clean = list(dict.fromkeys(clean))
    result["memory_tokens"] = len(clean)

    # 2) 内存无果 -> 回退缓存 token（客户端未运行时）
    if not clean:
        c = load_cache()
        if c and isinstance(c, dict) and c.get("token"):
            exp = c.get("exp")
            if not exp or exp > int(time.time()) + 3600:
                clean.append(c["token"])
                result["used_cache"] = True

    if not clean:
        result["action"] = "error"
        result["error"] = "no_token"
        result["msg"] = "进程内存与本地缓存均未找到可用 token；请打开 WorkBuddy 客户端后再试"
        emit(result, args)
        return 3

    tok, st, payload, raw = find_valid_token(domain, uid, clean)
    if tok is None:
        result["action"] = "error"
        result["error"] = "no_valid_token"
        result["msg"] = "所有候选 token 都未通过状态接口（401/网络）"
        emit(result, args)
        return 4

    result["token_len"] = len(tok)
    # 成功后刷新缓存（用内存提取到的、验签通过的 token）
    if not result.get("used_cache"):
        save_cache(tok)

    # 3) 查状态
    if st == 401:
        result["action"] = "error"
        result["error"] = "unauthorized"
        result["msg"] = "token 失效（401），请打开 WorkBuddy 客户端重新登录"
        emit(result, args)
        return 5
    if st is None:
        result["action"] = "error"
        result["error"] = "network"
        result["msg"] = raw
        emit(result, args)
        return 6

    body = payload.get("data") if isinstance(payload, dict) else None
    if body is None and isinstance(payload, dict):
        body = payload
    today_signed = bool(pick(body, "today_checked_in", "todayCheckedIn", "signed_today"))
    result["today_signed"] = today_signed
    streak = pick(body, "streak_days", "streakDays")
    if streak is not None:
        result["streak_days"] = streak
    result["status_http"] = st

    if args.check_only:
        result["action"] = "check_only"
        emit(result, args)
        return 0

    if today_signed:
        result["action"] = "skip_already_signed"
        result["msg"] = "今天已签到，幂等跳过（未重复领取）"
        emit(result, args)
        return 0

    # 4) 领取
    cst, craw, cerr = http_post(domain, CLAIM_PATH, tok, uid)
    result["claim_http"] = cst
    cpayload = None
    try:
        cpayload = json.loads(craw)
    except Exception:
        cpayload = None
    cbody = cpayload.get("data") if isinstance(cpayload, dict) else None
    code = cpayload.get("code") if isinstance(cpayload, dict) else None
    result["claim_code"] = code

    if cst == 200 and (code in (0, None)):
        credit = pick(cbody, "credit", "credit_added", "today_credit") if isinstance(cbody, dict) else None
        result["action"] = "clicked"
        result["credit"] = credit if credit is not None else "?"
        result["msg"] = "签到成功" + ("，+%s 积分" % credit if credit is not None else "")
        emit(result, args)
        return 0

    msg = ""
    if isinstance(cpayload, dict):
        msg = cpayload.get("msg") or cpayload.get("message") or ""
    result["action"] = "error"
    result["error"] = "claim_failed"
    result["msg"] = msg or cerr or ("HTTP %s" % cst)
    emit(result, args)
    return 7


def emit(result, args):
    line = json.dumps(result, ensure_ascii=False)
    if not args.quiet:
        log("action=%s %s" % (result.get("action"), line))
    if args.json or not args.quiet:
        print(line)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

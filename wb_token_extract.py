#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从运行中的 WorkBuddy 桌面端进程内存提取当前账号的明文 accessToken，并完成每日签到。

背景
----
2026-09-28 起，WorkBuddy 桌面端把 workbuddy-desktop.info 里的 accessToken 加密落盘
（AES-GCM 信封），本机已无明文 JWT。但客户端运行时 token 必在内存明文（用于发 API 请求）。
本脚本枚举 WorkBuddy 进程、扫描其可读内存页，按 JWT 特征提取当前账号（uid 精确匹配）
的所有候选，再用 Keycloak JWK 公钥对签名段做"截断+验签"清洗（因为内存里 JWT 连续存储，
正则会把签名段尾部多吞后续字符导致签名损坏），最后用干净 token 完成签到。

仅用 Python 标准库 + ctypes（Windows）。验签需 cryptography（可选，缺失时回退裸用）。
"""
import sys, os, re, json, io, glob, base64, argparse, time, urllib.request, urllib.error
import ctypes
from ctypes import wintypes

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

STATUS_PATH = "/v2/billing/meter/checkin-activity-status"
CLAIM_PATH = "/v2/billing/meter/daily-checkin"
TIMEOUT = 20
LOG_NAME = "checkin.log"
HERE = os.path.dirname(os.path.abspath(__file__))

JWKS_URL = "https://www.codebuddy.cn/auth/realms/copilot/protocol/openid-connect/certs"


def log(msg):
    line = "%s  %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with io.open(os.path.join(HERE, LOG_NAME), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
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
        return [], 0
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
    return found, scanned


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
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


def fetch_jwks():
    try:
        with urllib.request.urlopen(JWKS_URL, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def clean_and_verify(tok, jwks):
    """内存里 JWT 连续存储会导致签名段尾部被多吞字符；从后向前截断签名段并用 JWK 验签，
    返回真正验签通过的干净 token；失败返回 None。"""
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
        # 从长到短尝试截断签名段（标准 2048-bit RSA 签名 base64url 约 342 字符）
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


# ---------------------------------------------------------------- HTTP
def http_post(domain, path, token, uid):
    url = "https://%s%s" % (domain, path)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer %s" % token,
        "X-User-Id": uid or "",
        "X-Domain": "www.codebuddy.cn",
        "User-Agent": "WorkBuddy-Checkin/2.0",
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


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--claim", action="store_true", help="提取到 token 后执行签到")
    ap.add_argument("--inspect", action="store_true", help="只解包候选 token 的 payload")
    ap.add_argument("--verify", action="store_true", help="验证候选 token 签名清洗结果")
    ap.add_argument("--probe", action="store_true", help="试探多个端点")
    args = ap.parse_args()

    domain, uid, info_path = load_plain()
    out = {"domain": domain, "uid": uid, "info_path": info_path}
    if not uid:
        out["error"] = "no_plain_uid"
        log("action=error %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 1

    pids = list_wb_pids()
    out["wb_processes"] = len(pids)
    if not pids:
        out["error"] = "no_wb_process"
        out["msg"] = "未找到运行中的 WorkBuddy 进程，请先打开客户端"
        log("action=error %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 2

    raw_candidates = []
    total_scanned = 0
    for pid, name in pids:
        try:
            toks, scanned = scan_pid(pid, uid)
        except Exception as e:
            toks, scanned = [], 0
            out.setdefault("scan_errors", []).append("%s:%s" % (pid, e))
        total_scanned += scanned
        for t in toks:
            if t not in raw_candidates:
                raw_candidates.append(t)
    out["scanned_bytes"] = total_scanned
    out["raw_candidates"] = len(raw_candidates)

    # 签名清洗
    jwks = fetch_jwks() if HAVE_CRYPTO else None
    clean = []
    if HAVE_CRYPTO and jwks:
        for c in raw_candidates:
            t = clean_and_verify(c, jwks)
            if t:
                clean.append(t)
    if not clean:
        clean = list(raw_candidates)  # 回退：无 cryptography 或清洗全失败
    clean = list(dict.fromkeys(clean))  # 去重保序
    out["clean_tokens"] = len(clean)
    out["token_candidates"] = len(clean)

    if not clean:
        out["error"] = "no_token_in_memory"
        out["msg"] = "进程内存中未找到当前账号 token（客户端可能刚启动尚未发请求）"
        log("action=error %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 3

    if args.verify:
        out["action"] = "verify"
        out["have_crypto"] = HAVE_CRYPTO
        out["jwks_keys"] = len((jwks or {}).get("keys", []))
        out["clean_count"] = len(clean)
        out["sample_len"] = len(clean[0]) if clean else 0
        log("action=verify %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 0

    if args.inspect:
        inspected = []
        for tok in sorted(set(clean), key=len, reverse=True)[:5]:
            parts = tok.split(".")
            pl = decode_payload(parts[1]) if len(parts) == 3 else None
            if pl:
                item = {k: pl[k] for k in pl if k not in ("sig", "signature")}
                if "exp" in item and isinstance(item["exp"], (int, float)):
                    item["exp_readable"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(item["exp"]))
                item["_len"] = len(tok)
                inspected.append(item)
        out["inspected"] = inspected
        out["action"] = "inspect"
        print(json.dumps(out, ensure_ascii=False))
        return 0

    if args.probe:
        tok = max(set(clean), key=len)
        tests = [
            ("copilot.tencent.com", STATUS_PATH, True),
            ("www.codebuddy.cn", STATUS_PATH, True),
            ("copilot.tencent.com", CLAIM_PATH, True),
            ("copilot.tencent.com", "/auth/realms/copilot/protocol/openid-connect/userinfo", True),
        ]
        results = []
        for d, p, xu in tests:
            st, raw, err = http_post(d, p, tok, (uid if xu else None))
            results.append({"domain": d, "path": p, "status": st,
                            "snippet": (raw or err or "")[:200]})
        out["action"] = "probe"
        out["probe"] = results
        print(json.dumps(out, ensure_ascii=False))
        return 0

    tok, st, payload, raw = find_valid_token(domain, uid, clean)
    if tok is None:
        out["action"] = "error"
        out["error"] = "no_valid_token"
        out["msg"] = "所有候选 token 都未通过状态接口（401/网络），可能客户端已登出或 token 失效"
        log("action=error %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 4

    out["token_len"] = len(tok)

    if not args.claim:
        out["action"] = "extract_only"
        out["status_http"] = st
        log("action=extract_only %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 0

    body = payload.get("data") if isinstance(payload, dict) else None
    if body is None and isinstance(payload, dict):
        body = payload
    today_signed = bool(pick(body, "today_checked_in", "todayCheckedIn", "signed_today"))
    out["today_signed"] = today_signed
    streak = pick(body, "streak_days", "streakDays")
    if streak is not None:
        out["streak_days"] = streak
    out["status_http"] = st

    if today_signed:
        out["action"] = "skip_already_signed"
        out["msg"] = "今天已签到，幂等跳过（未重复领取）"
        log("action=skip_already_signed %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 0

    cst, craw, cerr = http_post(domain, CLAIM_PATH, tok, uid)
    out["claim_http"] = cst
    cpayload = None
    try:
        cpayload = json.loads(craw)
    except Exception:
        cpayload = None
    cbody = cpayload.get("data") if isinstance(cpayload, dict) else None
    code = cpayload.get("code") if isinstance(cpayload, dict) else None
    out["claim_code"] = code
    if cst == 200 and (code in (0, None)):
        credit = pick(cbody, "credit", "credit_added", "today_credit") if isinstance(cbody, dict) else None
        out["action"] = "clicked"
        out["credit"] = credit if credit is not None else "?"
        out["msg"] = "签到成功" + ("，+%s 积分" % credit if credit is not None else "")
        log("action=clicked %s" % json.dumps(out, ensure_ascii=False))
        print(json.dumps(out, ensure_ascii=False))
        return 0

    msg = ""
    if isinstance(cpayload, dict):
        msg = cpayload.get("msg") or cpayload.get("message") or ""
    out["action"] = "error"
    out["error"] = "claim_failed"
    out["msg"] = msg or cerr or ("HTTP %s" % cst)
    log("action=error %s" % json.dumps(out, ensure_ascii=False))
    print(json.dumps(out, ensure_ascii=False))
    return 6


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

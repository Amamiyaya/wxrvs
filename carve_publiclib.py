#!/usr/bin/env python
"""从运行中的 WeChatAppEx.exe 进程内存里 carve 出解密后的 wxapkg（publicLib/小程序包）。

纯 ReadProcessMemory（不注入、不写目标内存、不受反注入影响）：
    VirtualQueryEx 枚举 MEM_PRIVATE 已提交页 -> ReadProcessMemory 大块读 -> bytes.find 找特征串
    -> 从命中点回扫 0BE wxapkg 头 -> 结构校验 -> 整包拉回 -> 解包。

用法：
    python carve_publiclib.py            # 扫全部 WeChatAppEx 进程
    python carve_publiclib.py 6808 8376  # 只扫指定 PID
"""
import ctypes
import struct
import sys
from ctypes import wintypes
from pathlib import Path

OUT = Path(r"C:/Users/soraya/Desktop/wxrvs/out/carved")
OUT.mkdir(parents=True, exist_ok=True)

# publicLib 特征串：解密包体在堆上是明文；MEM_PRIVATE 排除了 flue.dll 镜像，不会撞自身字符串
PATTERNS = [b"/WAPCAdapter", b"WAService"]

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_size_t]

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
READABLE = {0x02, 0x04, 0x06, 0x20, 0x40}  # READONLY, READWRITE, EXECUTE_READ, EXECUTE_READWRITE


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("__pad", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)]


def open_pid(pid: int):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def read_mem(h, addr: int, size: int) -> bytes | None:
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    addr_full = addr & 0xFFFFFFFFFFFFFFFF
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr_full), buf, size, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def private_regions(h) -> list:
    regions, addr, mbi = [], 0, MBI()
    while True:
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not r:
            break
        if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                and mbi.Protect in READABLE and mbi.RegionSize < (1 << 31)):
            regions.append((mbi.BaseAddress or 0, mbi.RegionSize))
        nxt = (mbi.BaseAddress or 0) + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
        if addr >= (1 << 47):
            break
    return regions


def u32(b, o):
    return struct.unpack(">I", b[o:o + 4])[0]


def find_hits(h, regions, pattern: bytes, cap=24, budget=3 << 30) -> list:
    hits, CH, OV = [], 16 << 20, len(pattern)
    scanned = 0
    for base, size in regions:
        if len(hits) >= cap or scanned > budget:
            break
        if size > (1 << 30):
            size = 1 << 30
        off, tail = 0, b""
        while off < size and len(hits) < cap and scanned <= budget:
            n = min(CH, size - off)
            chunk = read_mem(h, base + off, n)
            scanned += n
            if scanned >> 20 != (scanned - n) >> 20 and chunk is not None:
                print(f"    ...scanned {scanned >> 20} MB", flush=True)
            if chunk:
                data = tail + chunk
                i = 0
                while True:
                    i = data.find(pattern, i)
                    if i < 0:
                        break
                    hits.append(base + off - len(tail) + i)
                    if len(hits) >= cap:
                        break
                    i += 1
                tail = chunk[-OV:]
            off += n
    return hits


def validate_header(h, head_addr: int):
    head = read_mem(h, head_addr, 64)
    if not head or len(head) < 18 or head[0] != 0xBE:
        return None
    index_len, body_len, count = u32(head, 5), u32(head, 9), u32(head, 14)
    if not (1024 <= index_len <= 16 << 20 and 1 << 10 <= body_len <= 200 << 20
            and 1 <= count <= 10000):
        return None
    idx = read_mem(h, head_addr + 18, min(index_len, 4 << 20))
    if not idx:
        return None
    p, names = 0, []
    for _ in range(min(count, 4000)):
        if p + 4 > len(idx):
            return None
        nl = u32(idx, p); p += 4
        if not (1 <= nl <= 4096) or p + nl + 8 > len(idx):
            return None
        name = idx[p:p + nl]
        if not all(32 <= c < 127 for c in name):
            return None
        p += nl + 8
        names.append(name.decode())
    if not names or p > index_len or not any(n.endswith((".js", ".html")) for n in names):
        return None
    return index_len, body_len, count, names


def try_header(h, hit: int):
    """从命中地址回扫找 0BE wxapkg 头（命中点可能在 index 或 body 任意深度）。"""
    STEP, MAXBACK = 4 << 20, 64 << 20
    for back in range(0, MAXBACK, STEP):
        addr = hit - back - STEP
        if addr < 0x10000:
            break
        chunk = read_mem(h, addr, STEP + STEP // 4)
        if not chunk:
            continue
        i = 0
        while True:
            i = chunk.find(b"\xBE\x00\x00\x00\x00", i)
            if i < 0:
                break
            cand = addr + i
            v = validate_header(h, cand)
            if v:
                return cand, v
            i += 1
    return None


def carve_pid(pid: int) -> bool:
    print(f"\n=== PID {pid}")
    h = open_pid(pid)
    try:
        regions = private_regions(h)
        total = sum(s for _, s in regions)
        print(f"  private committed: {total >> 20} MB in {len(regions)} regions")
        for pattern in PATTERNS:
            hits = find_hits(h, regions, pattern)
            print(f"  {pattern!r} hits: {len(hits)}")
            for hit in hits:
                found = try_header(h, hit)
                if not found:
                    continue
                head_addr, (index_len, body_len, count, names) = found
                print(f"  HEADER @ {hex(head_addr)}  files={count} index={index_len} body={body_len}")
                print(f"  sample: {names[:6]}")
                total = 18 + index_len + body_len + (1 << 12)
                CH = 4 << 20
                pkg = bytearray()
                for off in range(0, min(total, 512 << 20), CH):
                    part = read_mem(h, head_addr + off, min(CH, total - off))
                    if not part:
                        break
                    pkg += part
                out = OUT / f"pid{pid}_{hex(head_addr)[2:]}.wxapkg"
                out.write_bytes(pkg)
                print(f"  saved {out} ({len(pkg)} bytes)")
                wx = bytes(pkg)
                p = 18
                dest = OUT / f"pid{pid}_{hex(head_addr)[2:]}_files"
                extracted = 0
                for _ in range(count):
                    nl = u32(wx, p); p += 4
                    name = wx[p:p + nl].decode(); p += nl
                    off, size = u32(wx, p), u32(wx, p + 4); p += 8
                    if off + size > len(wx):
                        continue
                    fn = dest / name.lstrip("/")
                    fn.parent.mkdir(parents=True, exist_ok=True)
                    fn.write_bytes(wx[off:off + size])
                    extracted += 1
                print(f"  unpacked {extracted} files -> {dest}")
                return True
        return False
    finally:
        ctypes.windll.kernel32.CloseHandle(h)


def main():
    if len(sys.argv) > 1:
        pids = [int(x) for x in sys.argv[1:]]
    else:
        import subprocess
        outp = subprocess.run(["powershell", "-NoProfile", "-Command",
                               "(Get-Process WeChatAppEx).Id"],
                              capture_output=True, text=True)
        pids = sorted((int(x) for x in outp.stdout.split()), reverse=True)
    print("WeChatAppEx PIDs:", pids)
    for pid in pids:
        try:
            if carve_pid(pid):
                print(f"\n[+] success via PID {pid}")
                return
        except Exception as exc:  # noqa: BLE001
            print(f"  PID {pid} {type(exc).__name__}: {exc}")
    print("\n[-] 未在内存中找到已解密的 publicLib —— 需要重新打开一个小程序后立刻再跑一次。")


if __name__ == "__main__":
    main()

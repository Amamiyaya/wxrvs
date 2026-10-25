#!/usr/bin/env python
"""PC WeChat 3.9 wxapkg (V1MMWX) decryptor — verified against 3.9.12.51.

Usage:
    python decrypt_wxapkg.py <encrypted.wxapkg> <appid> [output.wxapkg]

The password is the mini program's appid (the directory name under
WeChat Files/Applet/<appid>/). publicLib packages use a runtime-supplied
password that is NOT the appid (see wxlogin_investigation.md).

Algorithm (reverse-engineered from flue.dll 14315):
    key  = PBKDF2-HMAC-SHA1(password, b"saltiest", 1000, 32)
    iv   = b"the iv: 16 bytes"          (literal, embedded in flue.dll)
    head = AES-256-CBC(key, iv).decrypt(data[6:1030])[:1023]   # PKCS#7 pad byte dropped
    body = data[1030:] XOR (ord(password[-2]) or 0x66)
"""
import hashlib, struct, sys
from pathlib import Path
from Crypto.Cipher import AES

IV = b"the iv: 16 bytes"
SALT = b"saltiest"


def decrypt(data: bytes, password: str) -> bytes:
    if data[:6] != b"V1MMWX":
        raise ValueError("not a V1MMWX package")
    key = hashlib.pbkdf2_hmac("sha1", password.encode(), SALT, 1000, 32)
    head = AES.new(key, AES.MODE_CBC, IV).decrypt(data[6:6 + 1024])[:1023]
    xk = ord(password[-2]) if len(password) >= 2 else 0x66
    return head + bytes(b ^ xk for b in data[1030:])


def unpack(wx: bytes, dest: Path) -> None:
    if wx[0] != 0xBE:
        raise ValueError(f"bad magic {wx[0]:#x}")
    u32 = lambda o: struct.unpack(">I", wx[o:o + 4])[0]
    count, p = u32(14), 18
    for _ in range(count):
        nl = u32(p); p += 4
        name = wx[p:p + nl].decode("utf8"); p += nl
        off, size = u32(p), u32(p + 4); p += 8
        fn = dest / name.lstrip("/")
        fn.parent.mkdir(parents=True, exist_ok=True)
        fn.write_bytes(wx[off:off + size])
    print(f"unpacked {count} files -> {dest}")


if __name__ == "__main__":
    src, appid = Path(sys.argv[1]), sys.argv[2]
    plain = decrypt(src.read_bytes(), appid)
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else src.with_suffix(".dec.wxapkg")
    out.write_bytes(plain)
    print(f"{out} ({len(plain)} bytes, magic {plain[0]:#x})")
    if len(sys.argv) > 4 and sys.argv[4] == "--unpack":
        unpack(plain, out.with_suffix(""))

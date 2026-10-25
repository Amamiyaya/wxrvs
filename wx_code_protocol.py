#!/usr/bin/env python
"""wx.login 协议两端的 Python 实现/验证。

    python wx_code_protocol.py demo              # 跑两个实验（真实网络请求）
    python wx_code_protocol.py exchange <appid> <secret> <js_code>
    python wx_code_protocol.py decode <hex文件>   # 解析 Frida 抓到的 protobuf 帧

结论预览（详见 wxlogin_investigation.md）：
  * 换票端 jscode2session：公开 HTTPS API，纯 Python 可完整实现 —— 本脚本直接真跑。
  * 取码端 js-login：CGI 与消息类型已从二进制挖出（/cgi-bin/mmbiz-bin/js-login,
    micromsg.JSLoginRequest/Response），但请求必须装在 MMTLS 记录层里、且绑定
    已登录账号的会话密钥 —— 裸 HTTPS 发不到逻辑层。demo 里的 probe 会把这个
    边界实测出来；真实取 code 用 frida_jslogin_hook.js 挂真客户端。
"""
import json
import socket
import ssl
import sys
import urllib.parse
import urllib.request

WX_JSCODE2SESSION = "https://api.weixin.qq.com/sns/jscode2session"

# 从 WeChatWin.dll 挖出的短链域名（内嵌 functionlist XML）与 CGI URI
SHORTLINK_HOSTS = [
    "szextshort.weixin.qq.com",   # idc 3, 华东
    "short.weixin.qq.com",        # idc 1
    "szshort.weixin.qq.com",
]
JS_LOGIN_CGI = "/cgi-bin/mmbiz-bin/js-login"


# ---------------------------------------------------------------- 换票端 ----
def jscode2session(appid: str, secret: str, js_code: str, timeout: float = 10.0) -> dict:
    """开发者服务器侧：code -> openid/session_key/unionid。

    GET https://api.weixin.qq.com/sns/jscode2session
        ?appid=&secret=&js_code=&grant_type=authorization_code
    成功: {"openid": "...", "session_key": "...", "unionid": "..."}
    失败: {"errcode": <int>, "errmsg": "..."}
    """
    qs = urllib.parse.urlencode({
        "appid": appid,
        "secret": secret,
        "js_code": js_code,
        "grant_type": "authorization_code",
    })
    req = urllib.request.Request(
        f"{WX_JSCODE2SESSION}?{qs}",
        headers={"User-Agent": "wxrvs-research/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# -------------------------------------------------------------- 取码端 ----
def probe_js_login(timeout: float = 8.0) -> None:
    """裸 HTTPS 直接打 js-login：验证“没有 MMTLS/会话就拿不到 code”这个边界。

    客户端真实路径是 MMTLS 记录层（自定义 TLS，密钥来自登录态）里的
    protobuf CGI，不是标准 HTTP。这里发标准 TLS+HTTP POST，
    观察服务器到底接不接受 —— 无论哪种结果都是协议边界的直接证据。
    """
    # 一个最小 protobuf：field1 varint 1（占位，真实 JSLoginRequest 的字段号
    # 需要用 decode 子命令从 Frida 抓包里反推，见 investigate 报告遗留项）
    body = b"\x08\x01"
    for host in SHORTLINK_HOSTS:
        print(f"\n[*] https://{host}{JS_LOGIN_CGI}")
        try:
            ip = socket.getaddrinfo(host, 443, socket.AF_INET)[0][4][0]
            print(f"    resolve -> {ip}")
            sock = socket.create_connection((host, 443), timeout=timeout)
            try:
                tls = ssl.create_default_context().wrap_socket(
                    sock, server_hostname=host)
                print(f"    TLS ok: {tls.version()} cipher={tls.cipher()[0]}")
                req = (
                    f"POST {JS_LOGIN_CGI} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode() + body
                tls.sendall(req)
                data = tls.recv(4096)
                if data:
                    head = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
                    print(f"    response: {head!r} (+{len(data)} bytes)")
                else:
                    print("    response: <connection closed with no data>")
            finally:
                sock.close()
        except Exception as exc:  # noqa: BLE001 —— 探测脚本，逐类打印真实失败原因
            print(f"    -> {type(exc).__name__}: {exc}")


# --------------------------------------------------- 抓包帧的 protobuf 解码 ----
def _varint(buf: bytes, i: int):
    val = shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def parse_protobuf(buf: bytes, depth: int = 0) -> list:
    """通用 wire-format 解码：[(field_no, wire_type, value), ...]

    用途：Frida 从 buf2Resp/doSceneImpl 抓到 JSLoginRequest/Response 的原始
    字节后，用它反推出真实字段号和值 —— 补上静态分析拿不到的 MMProto 字段表。
    """
    fields, i = [], 0
    while i < len(buf):
        try:
            key, i = _varint(buf, i)
            fno, wt = key >> 3, key & 7
            if wt == 0:
                val, i = _varint(buf, i)
            elif wt == 1:
                val, i = buf[i:i + 8], i + 8
            elif wt == 2:
                ln, i = _varint(buf, i)
                val, i = buf[i:i + ln], i + ln
            elif wt == 5:
                val, i = buf[i:i + 4], i + 4
            else:
                raise ValueError(f"wire type {wt}")
        except (IndexError, ValueError):
            return fields  # 截断帧：返回已解析部分
        fields.append((fno, wt, val))
    return fields


def show_fields(buf: bytes, indent: str = "  ") -> None:
    for fno, wt, val in parse_protobuf(buf):
        if wt == 2:
            printable = all(32 <= c < 127 or c in (9, 10, 13) for c in val)
            if printable and val:
                shown = repr(val.decode("latin1"))
            else:
                shown = val.hex(" ")[:96] + ("..." if len(val) > 48 else "")
                # 嵌套消息尝试
                try:
                    sub = parse_protobuf(val)
                    if sub and not printable:
                        print(f"{indent}field {fno} (len={len(val)}):")
                        show_fields(val, indent + "    ")
                        continue
                except Exception:  # noqa: BLE001
                    pass
            print(f"{indent}field {fno} (len={len(val)}): {shown}")
        else:
            print(f"{indent}field {fno} (wt={wt}): {val if not isinstance(val, bytes) else val.hex()}")


# ------------------------------------------------------------------ CLI ----
def main(argv: list) -> int:
    if len(argv) >= 2 and argv[1] == "exchange":
        appid, secret, code = argv[2], argv[3], argv[4]
        print(json.dumps(jscode2session(appid, secret, code), ensure_ascii=False, indent=2))
        return 0

    if len(argv) >= 2 and argv[1] == "decode":
        raw = bytes.fromhex(open(argv[2], encoding="ascii").read().strip())
        print(f"total {len(raw)} bytes")
        show_fields(raw)
        return 0

    # 默认 / demo：两个真实网络实验
    print("=" * 72)
    print("实验 1：换票端 jscode2session —— 真实请求打到腾讯服务器")
    print("  （占位凭据；服务器若返回结构化 errcode，即证明请求格式完全正确）")
    try:
        resp = jscode2session("wx1234567890abcdef", "0" * 32, "0817DemoCode0000000000")
        print(json.dumps(resp, ensure_ascii=False, indent=2))
    except Exception as exc:  # noqa: BLE001
        print(f"  -> {type(exc).__name__}: {exc}")

    print()
    print("=" * 72)
    print("实验 2：取码端 js-login —— 裸 HTTPS 直探（预期：进不了协议逻辑层）")
    probe_js_login()

    print()
    print("=" * 72)
    print("判读：")
    print("  * 实验1 返回结构化 errcode（如 40013 invalid appid）=> 换票协议实现正确，")
    print("    换上真实 appid/secret + 真实 code 即返回 openid/session_key。")
    print("  * 实验2 的 TLS/HTTP 层结果 => js-login 拒绝标准协议栈；真实取 code")
    print("    走 frida_jslogin_hook.js 挂 WeChat.exe（buf2Resp/doSceneImpl），")
    print("    抓到的十六进制帧用 `python wx_code_protocol.py decode` 反推字段表。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

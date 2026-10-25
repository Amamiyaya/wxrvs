# wx.login() 链路逆向调查报告（PC 微信 3.9.12.51）

日期：2026-10-24。目标：搞清 `wx.login()` 客户端到底做了什么、code 是否本地生成。

## 结论（TL;DR）

**code 不是客户端生成的。** `wx.login()` 在客户端只做一件事：把请求打包成 protobuf（`micromsg.JSLoginRequest`），POST 到腾讯服务器 `/cgi-bin/mmbiz-bin/js-login`，服务器在 `JSLoginResponse` 里返回 code，客户端原样透传给小程序 JS。openid 更是完全不出现在客户端——它只存在于"开发者服务器 ↔ 微信服务器"的 jscode2session 交换里，这一段客户端根本不参与。

所以"code 的生成逻辑"不在本机任何文件里，能挖到的是**请求协议本身**（见下）。

## 客户端证据链（本机静态分析）

环境：微信 3.9.12.51（`D:\Tencent\WeChat`），小程序运行时 WMPF：
`%APPDATA%\Tencent\WeChat\XPlugin\Plugins\RadiumWMPF\14315\extracted\runtime\`（核心 `flue.dll`，182MB，Chromium 系）。

主进程 `WeChatWin.dll`（101MB）里的 Applet 插件：

| 环节 | 符号/字符串 | 出处 |
|---|---|---|
| JS API 处理器 | `JsApiLoginJsApiHandler::eventProc`、`AppletHost::LoginRequest/LoginResponse`（flue↔主进程 IPC） | WeChatWin.dll `05_plugins\Applet\handler\JsApiLoginJsApiHandler.cpp` |
| 网络场景 | `NetSceneJSLogin::doSceneImpl` / `onGYNetEnd`，protobuf `micromsg.JSLoginRequest/JSLoginResponse` | WeChatWin.dll `05_plugins\Applet\scene\NetSceneJSLogin.cpp` |
| **CGI URI** | **`/cgi-bin/mmbiz-bin/js-login`**、`/cgi-bin/mmbiz-bin/js-login-confirm` | WeChatWin.dll 0x5043f20 附近字符串池 |
| 响应检查 | `do NetSceneJSLogin faild. jsapibaseresponse.errCode = %d` | 同上 |
| 确认场景 | `NetSceneJSLoginConfirm` → `js-login-confirm` | 同上 |
| 相邻 API | `JSAuthorize*`（授权）、`JSOperateWxData*`（operateWXData）、`JSRefreshSession*`（刷新 session） | flue.dll 0x9b17048 类型表 |

流程还原：

```
小程序 JS: wx.login()
  → appservice 基础库 (publicLib) invoke("login")
  → mmmojo → WeChatWin.dll Applet 插件 JsApiLoginJsApiHandler
  → NetSceneJSLogin, protobuf JSLoginRequest
  → 短链(szx*/szext*.weixin.qq.com, MMTLS) POST /cgi-bin/mmbiz-bin/js-login
  → JSLoginResponse{BaseResponse.errCode, code, ...}   ← code 在这里诞生（服务端）
  → AppletHost::LoginResponse 回传 flue → JS success({code})
```

**openid 在客户端出现次数：0**（flue.dll 里仅有的 "openId" 两处属于 `joinVoIPChat` 的房间内成员标识，与登录无关）。

## wx.login / openid / uid 概念澄清

- `wx.login()` 只返回临时 `code`（约 5 分钟有效、一次性）。
- openid / unionid 是**服务端**概念：开发者服务器调
  `GET https://api.weixin.qq.com/sns/jscode2session?appid&secret&js_code&grant_type=authorization_code`
  换取 `{openid, session_key, unionid?}`。这一步发生在开发者服务器与微信服务器之间，**客户端（含 PC 微信）既不发起也看不见**，所以换票协议分析不依赖客户端逆向，走官方文档 + 自己服务器抓包即可。
- 客户端本地的 `uin` 是账号级数字 ID，与 openid（应用级、按 appid 隔离）不是一个体系。

## wxapkg 包解密（已完整复现，附带工作脚本）

PC 3.9 的 `V1MMWX` 包加密（`WeChat Files` 下所有 .wxapkg）：

```python
# 见 decrypt_wxapkg.py
key = PBKDF2-HMAC-SHA1(password, b"saltiest", 1000, 32)   # password = 小程序 appid（目录名）
iv  = b"the iv: 16 bytes"                                  # 字面量，就在 flue.dll 里
head = AES-256-CBC(key, iv).decrypt(data[6:1030])[:1023]   # 1023 字节，PKCS#7 填充字节丢弃
xk   = ord(appid[-2])                                      # 倒数第二个字符；len<2 时 0x66
body = bytes(b ^ xk for b in data[1030:])
plain = head + body                                        # 0xBE 开头的标准 wxapkg
```

验证：`Applet\wx01bb1ef166cd3f4e\2357\__APP__.wxapkg` 完整解开（222 个文件，索引全部可解析）。

注意两个公开资料没讲清的坑：
1. AES 区是 **1023 字节**（多解出来的第 1024 字节是填充，必须丢掉），XOR 段从文件偏移 **1030** 开始——边界错一位整个索引就花掉；
2. Git Bash 下 grep 正则别用 `/cgi-bin/...` 开头（MSYS 路径转换会吃掉模式）。

**遗留项（已解决，见下节）**：publicLib 的 V1MMWX 口令是运行时传入，静态爆破失败；改走内存 carve。

## 内存 carve：拿到 wx.login 的 JS 层实现（2026-10-24 补充）

微信运行中（WeChatAppEx.exe 多实例），用**纯只读 ReadProcessMemory**（`carve_publiclib.py`，
不注入不受反调试影响）从 PID 7588 的私有内存里定位到已解密的 WAService 基础库源码：
按 `APP-SERVICE-SDK` / `WAService.js` 等特征锚定，切出连续明文 JS。

**wx.login 在 PC 客户端的全部 JS 侧逻辑**（`out/liteapp_getlogincode.js`，LiteAppAdapter）：

```js
getLoginCode(e) {                     // ← wx.login 的本质
  liteAppLoginPromise ||= new Promise((resolve) => {
    lite.jsapi.invoke("login", getLoginParams(e), (t) => resolve(t))
  });                                 // 纯桥接调用，没有任何本地计算
  await liteAppLoginPromise;
}
doRequest(e) {                        // 顺带发现：wx.request 自动带 code
  code = await this.getLoginCode(e);
  fetch(buildURL(url, {...params, _loginAppId: this.options.appId}))  // code 附在请求上
  // 响应判定 isSessionInvalid(data) → 清掉 promise，20s 限频后重取 code 重试一次
}
```

至此三层全部落实：JS 层 `invoke("login")`（本次，内存 carve）→ 原生层 `JsApiLoginJsApiHandler`
→ 网络 `NetSceneJSLogin` → `/cgi-bin/mmbiz-bin/js-login`（服务端产码）。客户端全程零生成逻辑。

### 关于"脱离客户端/模拟登录态"的可行性结论

1. code 是服务器为（登录会话 × appid）现发的工件，不可离线计算。脱离客户端 ⇒ 复刻整个协议栈：
   MMTLS（Citizen Lab 2024 有公开协议分析，可复刻）+ 登录态（首次必须手机扫码确认，会话密钥
   由手机参与派生）+ MMProto 封包（字段号需 hook 反推）。理论可行，按周计工作量，
   且腾讯对非官方客户端有指纹检测，账号有风控/封禁风险。
2. 官方替代路径（推荐）：微信开发者工具 + `miniprogram-automator`（`callWxMethod('login')`）
   或 Python `minium`（`call_wx_method`），程序化取真 code，完全官方支持。
3. 最低成本路径：挂运行中的客户端（本报告方案）——hook JS 层即可，无需碰网络层。

## 后续可做的动态分析

1. **验证 code 服务端来源**：x64dbg/FRIDA 挂 `NetSceneJSLogin::buf2Resp`，观察响应缓冲区里 code 字段直接来自网络包。
2. **抓 js-login 明文**：MMTLS 之上抓不到，需在 `req2Buf/buf2Resp` 边界 hook，可拿到 JSLoginRequest 的完整字段表（字段号+值，反推 proto 定义）。
3. **publicLib 口令**：运行时 hook/内存 carve（见上）。

## 协议实现与实测（2026-10-24 补充）

交付：`wx_code_protocol.py`（换票实现 + 直探实验 + protobuf 帧解码）、`frida_jslogin_hook.js`（真客户端抓 code）。

实测结果（真实网络请求）：

1. **换票端 jscode2session：✅ 纯 Python 可实现，已真跑。** 用占位凭据请求
   `https://api.weixin.qq.com/sns/jscode2session`，腾讯返回结构化错误
   `{"errcode":40013,"errmsg":"invalid appid, rid:..."}` —— 服务器解析的是**凭据**而不是请求格式，
   即协议实现已正确；换上真实 appid+secret+code 即返回 openid/session_key。
2. **取码端 js-login：❌ 裸协议栈不可达（实测）。** 对 szextshort/short/szshort.weixin.qq.com:443
   发标准 TLS ClientHello，三台服务器全部直接断开（`SSLEOFError: UNEXPECTED_EOF_WHILE_READING`）——
   短链端口只讲 MMTLS（微信自研记录层，会话密钥绑定登录态），第一字节起就拒绝标准 TLS。
   加上 JSLoginRequest 的字段号仍未恢复、且 code 必须落在已登录账号+appid 的会话上下文里，
   纯 Python 重实现取码端不现实。可行路径是挂真实客户端：`frida -n WeChat.exe -l frida_jslogin_hook.js`
   （自动定位 js-login 字符串→代码引用→hook doSceneImpl/响应处理函数），抓到的帧用
   `python wx_code_protocol.py decode <hex>` 反推字段表。

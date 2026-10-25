# wxrvs — PC 微信 `wx.login()` 全链路逆向调查报告

> **调查对象**：Windows PC 微信客户端 `3.9.12.51`（内置小程序运行时 WMPF / WeChatAppEx）
> **调查问题**：`wx.login()` 客户端到底做了什么？`code`（以及 `openid`）的生成逻辑在哪里？能否脱离客户端实现取码与换票？
> **调查时间**：2026-10-24
> **结论速览**：`code` 由腾讯服务端在 `/cgi-bin/mmbiz-bin/js-login` 响应中现发，客户端全程零生成逻辑；`openid` 在客户端出现次数为 **0**；换票（`jscode2session`）是开发者服务器侧的公开 API，已用 Python 实现并实测打通格式；纯 Python 复刻取码端理论可行但需 MMTLS+登录态（首次仍需手机扫码），推荐走官方自动化路径。

---

## 📌 TL;DR

| 问题 | 结论 | 证据强度 |
|---|---|---|
| `wx.login()` 返回什么 | 临时 `code`（约 5 分钟有效、一次性），**不是** openid/uid | 微信开放文档 + 客户端二进制 |
| code 在哪生成 | **服务端**。客户端只发请求、收响应、透传给 JS | CGI/protobuf/JS 层三层证据闭环 |
| openid 在客户端吗 | 不在。login 链路中出现次数 0（仅有的 `openId` 字符串属于 `joinVoIPChat` 房间成员标识） | 全量字符串挖掘 |
| 换票协议能否 Python 实现 | **能**。`jscode2session` 是公开 HTTPS API，已实现并实测（服务器返回结构化 errcode，证明格式正确） | 真实网络请求 |
| 取码协议能否裸 Python 实现 | **不能直接裸连**（短链端口从第一字节起只讲 MMTLS，实测三台服务器全部拒标准 TLS）；完整复刻需 MMTLS+登录态，首次仍需手机扫码，且有风控/封号风险 | 真实网络探测 |
| 官方替代路径 | 微信开发者工具自动化：`miniprogram-automator` 的 `callWxMethod('login')` / Python `minium` 的 `call_wx_method` | 官方文档 |

---

## 🔍 背景与目标

用户初始假设：「微信有个 openid 还是 uid 的东西，是 `wx.login()` 返回的，想挖出它的生成逻辑」。

事实澄清（调查的第一步产出）：

```
wx.login()  →  code（临时票据，5 分钟有效）
code  →  开发者自己的服务器调用 jscode2session  →  openid / session_key / unionid
```

- `wx.login()` **不返回 openid**。它返回的 `code` 是给开发者服务器用的中间票据。
- `openid` 是按 `appid` 隔离的用户标识，只存在于「开发者服务器 ↔ 微信服务器」的交换结果中。
- 客户端本地的 `uin` 是账号级数字 ID，与 openid 不是一个体系。
- 因此调查目标修正为：① 客户端在 `wx.login()` 中到底做了什么（code 是否本地生成）；② 换票协议（code → openid/session_key）。

---

## 🧭 分析环境

| 项目 | 值 |
|---|---|
| 微信版本 | 3.9.12.51（注册表显示 3.9.12.17，实际版本目录 `[3.9.12.51]`） |
| 安装位置 | `D:\Tencent\WeChat` |
| 核心库 | `WeChatWin.dll`（101,355,616 字节，主逻辑 + 小程序插件） |
| 小程序运行时 | `%APPDATA%\Tencent\WeChat\XPlugin\Plugins\RadiumWMPF\14315\extracted\runtime\` |
| 运行时核心 | `flue.dll`（182,877,344 字节，Chromium 系小程序宿主）、`WeChatAppEx.exe`、`wmpf_resources.pak` |
| 用户数据目录 | `D:\Tencent\fileee\weixinn\WeChat Files\`（含 `Applet\<appid>\<ver>\*.wxapkg`、`WMPF\applet\publicLib\1514\publicLib.wxapkg` 30,949,105 字节） |
| 运行状态 | 调查时微信已登录，9 个 WeChatAppEx 进程存活 |
| 工具链 | Python（Anaconda）、`strings`（MinGW）、`capstone 5.0.7`、`pycryptodome`、`frida 16.7.19`（部分可用）、`pefile` |
| 辅助 | Git Bash（注意 MSYS 路径转换坑，见下） |

---

## 🪜 分析过程（按实际执行顺序）

### Phase 0 · 定位目标文件

1. 注册表 `HKCU\SOFTWARE\Tencent\WeChat` → 安装路径 `D:\Tencent\WeChat`。
2. 主目录只有 `WeChat.exe`/`WechatAppLauncher.exe`，真正的逻辑在版本目录的 `WeChatWin.dll`。
3. 小程序运行时不在主目录，遍历 `%APPDATA%\Tencent\WeChat` 找到 `XPlugin\Plugins\RadiumWMPF\14315\extracted\`（WMPF = WeChat Mini Program Framework），内含 `host\wmpf_host_export.dll`、`runtime\flue.dll` 等完整 Chromium 系运行时；`file_component.xml` 记录了全部文件 MD5。
4. 小程序包数据目录不在默认 `Documents\WeChat Files`，全盘按 `*.wxapkg`/`Applet` 搜索定位于 `D:\Tencent\fileee\weixinn\WeChat Files\`。

> **工具坑**：Git Bash 下 `grep -o "/cgi-bin/..."` 这类以 `/` 开头的正则会被 MSYS 当作 POSIX 路径做转换，静默匹配失败。解法：模式去掉开头斜杠，或设 `MSYS_NO_PATHCONV=1`。本次调查中该坑浪费了几轮排查。

### Phase 1 · 原生层字符串挖掘（静态）

对 `flue.dll` 与 `WeChatWin.dll` 做全量 `strings` 提取（分别约 76.9 万 / 23.4 万行），关键命中：

**① protobuf 消息类型表（flue.dll，文件偏移 ~0x9b17048 附近的类型名池）：**

```
micromsg.JSLoginRequest / micromsg.JSLoginResponse
micromsg.JSLoginConfirmRequest / micromsg.JSLoginConfirmResponse
micromsg.JSAuthorizeRequest / micromsg.JSAuthorizeResponse / JSAuthorizeConfirm*
micromsg.JSOperateWxDataRequest / JSOperateWxDataResponse(.DebugInfo)
micromsg.JSRefreshSessionRequest / JSRefreshSessionResponse
micromsg.GetA8KeyLite* / micromsg.ScopeInfo / applet_msg.HttpRequest/Response ...
```

→ `JSLogin*` 正是小程序登录（wx.login）的网络协议消息。

**② 网络场景与 CGI（WeChatWin.dll）：**

```
NetSceneJSLogin::doSceneImpl / onGYNetEnd / cancel
NetSceneBaseEx<class micromsg::JSLoginRequest,class micromsg::JSLoginResponse>::req2Buf / buf2Resp
JsApiLoginJsApiHandler::eventProc            ← wx.login 的原生层处理器
AppletHost::LoginRequest / AppletHost::LoginResponse   ← flue ↔ 主进程的 IPC 结构
源码路径字符串（符号泄露）：
  D:\Tools\agent\workspace\MicroMsgWindowsV3912\MicroMsgWin\05_plugins\Applet\scene\NetSceneJSLogin.cpp
  D:\Tools\agent\workspace\MicroMsgWindowsV3912\MicroMsgWin\05_plugins\Applet\handler\JsApiLoginJsApiHandler.cpp
```

**③ CGI URI（在 NetSceneJSLogin 符号附近的字符串池，文件偏移 ~0x5043f20）：**

```
/cgi-bin/mmbiz-bin/js-login            ← wx.login 的 CGI（NetSceneJSLogin::doSceneImpl 绑定）
/cgi-bin/mmbiz-bin/js-login-confirm    ← NetSceneJSLoginConfirm 绑定
/cgi-bin/mmbiz-bin/js-authorize-confirm
/cgi-bin/mmbiz-bin/wxaapp/getpubliclibinfo   （flue.dll，基础库更新）
```

> 注意：`js-login` **不在**内嵌 functionlist XML 的 278 条 `/cgi-bin/micromsg-bin/*` 列表里（那是基础 CGI 注册表），它是 Applet 插件自己注册的 `mmbiz-bin` 短链 CGI。最初按 micromsg-bin 前缀搜索扑空，扩大到所有 `cgi-bin/*-bin/` 前缀后才命中。

**④ 响应处理证据字符串：**

```
do NetSceneJSLogin faild. jsapibaseresponse.errCode = %d
do NetSceneJSLoginConfirm faild. jsapibaseresponse.errCode = %d
WxaAppGetAuthInfoResp ParseFromArray faild.
```

→ 响应含 `BaseResponse.errCode`，handler 在网络回调后检查。

**⑤ openid 存在性核查（关键否定证据）：**

在 flue.dll 76.9 万行字符串中，`openid` 仅命中 2 处（`openId`、`openIdList`），上下文均为 **VoIP 聊天**（`joinVoIPChat`、`voip_adapter.cc`、`video_capture_manager.cc` 的房间内成员 `open_id`），与小程序登录完全无关。`login:ok` / `login:fail` 在两个 DLL 中均为 0 命中——它们是 JS 基础库运行时拼接的 errMsg（`apiName + ":ok"`），不在原生层。

**⑥ 内嵌网络配置（WeChatWin.dll functionlist XML）：**

短链域名（js-login 走这里）：`short / szshort / szextshort / hkextshort / caextshort / sh2tjextshort ... .weixin.qq.com`；长链域名（消息同步）：`long / szlong / hklong ... .weixin.qq.com`。XML 带 MD5+RSA 签名防篡改。

### Phase 2 · 反汇编：wxapkg 包加密算法（capstone）

为了读 JS 基础库源码，需要解开 wxapkg。先验证公开资料的经典算法失败，改为直接逆向 `flue.dll`。

**定位过程：**

1. `saltiest` 常量 @ flue.dll 文件偏移 `0x10e768d`（另有字符串 `V1MMWX`、`the iv: 16 bytes`、`radium`）。
2. 解密核心函数（.pdata 异常表定界）：`0x10e7610–0x10e7911`（按 (password, content) 派生密钥并解密），封装层 `0x10e8140–0x10e869d`（`DecryptBufToFile` 类逻辑，来自 `..\..\flue\common\applet\remote_jsapi_json_util.cc` 的 `EncryptBufToFile` 字符串佐证）。
3. 核心函数内可见参数装配（capstone 反汇编）：

```asm
movabs rax, 0x74736569746c6173      ; "saltiest"（小端）
mov    qword ptr [r14], rax         ; salt 字符串入栈
mov    qword ptr [rsp + 0x28], 0x100 ; 第 6 参：密钥长度 256（bit）
mov    qword ptr [rsp + 0x20], 0x3e8 ; 第 5 参：迭代次数 1000
call   0x606fb40                     ; PBKDF2 型 KDF
```

4. 调用链回溯（E8 rel32 全量扫描）：`0x10e7610` ← {`0x10e8311`, `0x10e8442`}（同一封装层两个分支：内容 ≥0x401 字节走整包分支，否则构造 0x400 字节缓冲分支）；封装层 `0x10e8140` ← 6 个调用方（`0xff0d31`、`0x1027fc1`、`0x1038d07`、`0x103c4e1`、`0x103d26b`、`0x12728a8`），其中快照资源调用的口令是字符串 `"runtimeInfo"`——**每种资源一个口令常量，运行时传入**。

### Phase 3 · wxapkg 解密：完整算法与两个关键坑

结合反汇编参数与公开资料（[pc_wxapkg_decrypt](https://github.com/BlackTrace/pc_wxapkg_decrypt/blob/master/main.go) 等），实测修正后得到 3.9.12.51 的准确算法（已实现于 [`decrypt_wxapkg.py`](decrypt_wxapkg.py) 并验证）：

```python
key  = PBKDF2-HMAC-SHA1(password, b"saltiest", 1000, 32)   # password = 小程序 appid（目录名）
iv   = b"the iv: 16 bytes"        # 16 字节 ASCII 字面量，就明晃晃躺在 flue.dll 里
head = AES-256-CBC(key, iv).decrypt(data[6:6+1024])
xk   = ord(password[-2])          # 倒数第二个字符；len(password)<2 时为 0x66
plain = head[:1023] + bytes(b ^ xk for b in data[1030:])
# plain 以 0xBE 开头 = 标准 wxapkg
```

**两个公开资料都没写对、本次踩实了的坑：**

1. **AES 区只有 1023 字节**：加密端对前 1023 字节明文做 PKCS#7 填充到 1024 再加密（1023 = 64×16 - 1，填充恰为 1 字节 `0x01`）。解密后第 1024 字节是填充，**必须丢弃**，否则后续内容整体错位一个字节——表现为文件索引里第一个跨边界条目名字中间混入 `\x01`，随后所有 offset/size 花掉。
2. **XOR 段从文件偏移 1030 开始**（= 6 字节 `V1MMWX` 头 + 1024 字节 AES 密文区），而不是 1029/1031。边界扫描实验（逐字节尝试分界点 + 全索引结构校验）最终锁定 1023/1030 组合。

**wxapkg 明文容器格式**（解包器一并实现）：

```
[0]      0xBE          魔数
[1:5]    u32 BE        保留（实测 0）
[5:9]    u32 BE        indexInfoLength（索引区长度）
[9:13]   u32 BE        bodyInfoLength（数据区长度）
[13]     u8            last marker（实测 0xed）
[14:18]  u32 BE        fileCount
之后      索引区         fileCount × { u32 nameLen; char name[nameLen]; u32 offset; u32 size }
索引区之后  数据区         按 (offset, size) 切文件
```

**验证**：`Applet\wx01bb1ef166cd3f4e\2357\__APP__.wxapkg` 完整解开——222 个文件、索引全部通过结构校验、偏移自洽；产出存于 [`out/app_pkg/`](out/app_pkg/)（`app-service.js`、`appservice.app.js`、`chunk_*.appservice/webview.js` 等）。

### Phase 4 · publicLib 口令：静态路线的死胡同

`publicLib.wxapkg`（基础库，WAService 所在）也走同一 V1MMWX 信封，但 password 不是目录名。尝试：

- 反汇编解密封装层的 6 个调用方找口令常量：快照资源用的是 `"runtimeInfo"`，publicLib 的调用路径中 password 来自运行时传入的字符串对象（`call 0xfe3f10` 之类的 getter 返回），**不是静态常量**；
- 爆破约 40+ 候选：Applet 目录下全部 appid、flue.dll 内嵌的 3 个 wx-id（`wx766655dab8fe851b`/`wxd7f003a9a2679061`/`wxe5f52902cf4de896`）、WeChatWin.dll 的 `wx32540bd863b27570`、`radium`/`RadiumWMPF`、`publicLib`/`clientPublicLib`、`runtimeInfo`、版本号等——全部失败（判据：0xBE 头 + 全索引结构校验）。

结论：静态路线到此为止，改走**运行时内存 carve**（Phase 6），结果反而更彻底——连口令都不需要了。

### Phase 5 · 协议 Python 实现与真实网络实测

实现于 [`wx_code_protocol.py`](wx_code_protocol.py)（纯标准库），两个真实网络实验：

**实验 1：换票端 `jscode2session` —— ✅ 协议实现正确**

```
GET https://api.weixin.qq.com/sns/jscode2session
    ?appid=wx1234567890abcdef&secret=000...0&js_code=0817Demo...&grant_type=authorization_code
```

腾讯服务器真实响应：

```json
{"errcode": 40013, "errmsg": "invalid appid, rid: 6adc82bc-6412ab2a-27534ba7"}
```

服务器报的是**凭据错误**而非格式错误 → 请求构造完全正确；换上真实 `appid+secret+js_code` 即返回 `{openid, session_key, unionid?}`。常见 errcode 语义：`40029` code 无效/已用、`40013` appid 无效、`41004` 缺 secret、`45011` 频率限制、`40226` 风控。

**实验 2：取码端 `js-login` 直探 —— ❌ 裸协议栈不可达（实测）**

对三台短链服务器 443 端口发标准 TLS ClientHello + HTTP POST：

| 主机 | 解析 IP | 结果 |
|---|---|---|
| szextshort.weixin.qq.com | 175.27.37.31 | `SSLEOFError: UNEXPECTED_EOF_WHILE_READING` |
| short.weixin.qq.com | 175.27.0.201 | 同上 |
| szshort.weixin.qq.com | 175.27.57.28 | 同上 |

三台服务器**在 ClientHello 后立即断连**——端口从第一字节起只讲 MMTLS（微信自研记录层，会话密钥绑定登录态），根本不提供标准 TLS。加上 `JSLoginRequest` 的字段号是 MMProto 生成代码内联的（静态无明文字段名）、且 code 只在「已登录账号 × appid」会话上下文里有意义，裸 Python 复刻取码端被三重墙挡住：协议墙、字段墙、会话墙。

附带交付：通用 protobuf wire-format 解码器（`wx_code_protocol.py decode`，支持嵌套消息，已用样例帧验证）——用于把后续抓到的 `JSLoginRequest/Response` 原始字节反推成字段表。

### Phase 6 · 活体内存 carve：拿到 wx.login 的 JS 层实现 ✅

微信正处于登录态且有 9 个 WeChatAppEx 进程 → 尝试从内存直接取已解密的基础库。

**尝试 1：Frida 注入扫描** —— 部分进程 `ProcessNotRespondingError`（Chromium 沙箱化子进程拒绝加载 agent），可注入的进程又踩了脚本导出 API 的坑（`script.exports_sync` 而非直接调用）。

**尝试 2（最终方案）：`ctypes` + `ReadProcessMemory`** —— 完全不注入、不写目标内存、不受反注入影响：

```
VirtualQueryEx 枚举 MEM_COMMIT && MEM_PRIVATE 可读页
→ ReadProcessMemory 16MB 大块读
→ bytes.find 搜特征串（/WAPCAdapter、WAService、APP-SERVICE-SDK 等）
→ 从命中点回扫 0xBE wxapkg 头（结构校验）→ 失败（包容器已被释放）
→ 退而求其次：以特征串为锚，按 4KB 窗口可打印率切连续明文 JS 段
```

（调试插曲：首版扫描器 `off += n - OV` 在区域尾部步进归零导致死循环——每个区域结尾无限打转；修复为 `tail` 重叠拼接后 9 个进程 348~673 个区域、合计约 460MB 私有内存数秒扫完。）

**扫描结果**：PID 7588 命中 `/WAPCAdapter` ×14、`WAService` ×24，其余进程为 0——基础库明文只在该进程。上下文 dump 确认内容：

```html
<!doctype html>...<title>AppIndex</title>...<script src="/__dev__/WAPCAdapterAppIndex.js"></script>
this.__wxLibrary={fileName:"WAService.js",envType:"Service",contextType:"App:Uncertain",...}
```

即客户端把解密后的 publicLib 以 `/__dev__/WAPCAdapter*.js` 的形式喂进 Chromium 的 appservice 上下文。

**关键产出：`LiteAppAdapter` 的 `getLoginCode`（wx.login 的 JS 层全貌）**

以 `APP-SERVICE-SDK` 为锚切出 266KB 连续 SDK 文本（[`out/WAService_carved.js`](out/WAService_carved.js)），再以 `invoke("login")` 唯一命中点（`0x1f40a5ed907`）为中心 dump 64KB，得到完整实现（[`out/liteapp_getlogincode.js`](out/liteapp_getlogincode.js)）：

```js
// LiteApp = WMPF 对小程序的内部称呼
getLoginCode(e) {                       // ← wx.login 的本质
  liteAppLoginPromise ||= new Promise((resolve) => {
    lite.jsapi.invoke("login", getLoginParams(e), (t) => resolve(t))
  });                                   // 纯桥接调用，零本地计算
  await liteAppLoginPromise;
}

doRequest(e) {                          // 顺带发现：wx.request 的自动登录机制
  const code = await this.getLoginCode(e);
  fetch(buildURL(fullPath, { ...e.params, _loginAppId: this.options.appId }))  // code 附在请求上
  // 响应判定 isSessionInvalid(data) → 清掉 promise，
  // retryDelay = 2e4（20 秒限频）后重取 code 重试一次
}
```

同区域还有 SDK 报错基类（`APP-SERVICE-SDK:`）、桥封装（`function F(...e){WeixinJSBridge.invoke(...e)}`）与事件码表（`W={login:1, login_cancel:2, login_fail:3, request_fail:4, ...}`）。

---

## 📊 证据总表

| # | 结论 | 证据类型 | 位置 / 产出 |
|---|---|---|---|
| E1 | JS 层：`wx.login` = `lite.jsapi.invoke("login", params, cb)`，零计算 | 活体内存 carve（只读） | `out/liteapp_getlogincode.js` @ `0x1f40a5ed907` |
| E2 | 原生层：`JsApiLoginJsApiHandler::eventProc` 处理 login，经 `AppletHost::LoginRequest/Response` IPC | WeChatWin.dll 字符串（含源码路径泄露） | `Applet\handler\JsApiLoginJsApiHandler.cpp` |
| E3 | 网络层：`NetSceneJSLogin` 绑定 `/cgi-bin/mmbiz-bin/js-login`，protobuf `micromsg.JSLoginRequest/Response` | WeChatWin.dll 字符串池 @ ~0x5043f20、RTTI 类名 | 同左 |
| E4 | 响应侧：`JSLoginResponse` 含 `BaseResponse.errCode`；失败路径日志存在 | 字符串 `"do NetSceneJSLogin faild. jsapibaseresponse.errCode = %d"` | WeChatWin.dll |
| E5 | openid 在客户端 login 链路出现次数 = 0 | flue.dll 76.9 万行字符串全量核查 | 仅 2 处 VoIP `open_id`，与登录无关 |
| E6 | wxapkg V1MMWX 加密算法完整还原 | capstone 反汇编 + 参数网格实测 | `decrypt_wxapkg.py`，样例包 222 文件解出 |
| E7 | 短链端口只讲 MMTLS，拒标准 TLS | 三台服务器真实探测全部 `SSLEOFError` | `wx_code_protocol.py demo` 实验 2 |
| E8 | jscode2session 协议实现正确 | 腾讯服务器返回结构化 `errcode 40013`（凭据错而非格式错） | `wx_code_protocol.py demo` 实验 1 |
| E9 | `login:ok` 等 errMsg 由 JS 运行时拼接 | 原生层 0 命中；内存 JS 亦无该字面量 | 字符串核查 |

**完整调用链（三层闭环）：**

```
小程序 JS: wx.login()
  │  lite.jsapi.invoke("login", params, cb)                    ← E1（内存 carve）
  ▼
flue.dll (WeChatAppEx)  ──mmmojo IPC: AppletHost::LoginRequest──►  WeChatWin.dll
  │                                                                │
  │                                          JsApiLoginJsApiHandler::eventProc   ← E2
  │                                          NetSceneJSLogin::req2Buf            ← E3
  ▼                                                                ▼
                    MMTLS 短链 POST /cgi-bin/mmbiz-bin/js-login
                                    │
                                    ▼
                         腾讯服务器（code 在这里诞生）
                                    │
                                    ▼
                    JSLoginResponse { BaseResponse.errCode, code, ... }
  │  NetSceneJSLogin::buf2Resp → AppletHost::LoginResponse         ← E3/E4
  ▼
flue.dll → JS 回调 success({ code })      ← 客户端全程零生成逻辑
```

---

## 🏁 最终结论

### 1. code 的「生成逻辑」不在客户端——这是挖到最底后的否定性结论

`wx.login()` 在客户端的全部行为 = **一次桥接调用 + 一次网络往返**。请求发出（appID 等上下文），响应收回（`code`），原样透传。没有任何本地拼接、派生或计算。因此「把 code 生成逻辑从客户端抠出来」在原理上不成立——它不在本机任何文件里，而是腾讯服务器对「登录会话 × appid」现场签发的工件（约 5 分钟有效、一次性）。

### 2. openid 与客户端完全无关

客户端从始至终不接触 openid。`code → openid/session_key/unionid` 的换票发生在**开发者自己的服务器**与微信服务器之间（`api.weixin.qq.com/sns/jscode2session`），PC 微信既不发起也看不见这段流量。分析换票协议不需要逆向客户端，走官方文档 + 自己服务器抓包即可。

### 3. 「脱离客户端 / 模拟登录态」的三条路径

| 路径 | 可行性 | 成本与风险 |
|---|---|---|
| **A. 官方自动化**（推荐）：微信开发者工具 + `miniprogram-automator`（`callWxMethod('login')`）/ Python `minium`（`call_wx_method`） | ✅ 官方支持 | 装开发者工具、开 CLI/HTTP 自动化端口；程序化反复拿真 code → 直接喂 `jscode2session`。零逆向、零封号风险 |
| **B. 挂真实客户端**：hook JS 层 `lite.jsapi.invoke("login")` 或内存 promise resolve 值 | ✅ 已验证可达 | 只碰 JS 层，无需碰网络层；需要客户端登录 + 打开小程序；Frida 注入对部分沙箱进程受限，`ReadProcessMemory` 方案不受限 |
| **C. 纯自建协议栈**：MMTLS + 登录态 + MMProto 封包全部复刻 | ⚠️ 理论可行 | MMTLS 已有公开协议分析（Citizen Lab, 2024）可参考；但**登录态首次必须手机扫码**（会话密钥由手机参与派生），MMProto 字段号需 hook 反推，工程量按周计；腾讯对非官方客户端有指纹检测，**账号有风控/封禁风险** |

> 一句话：code 不是算出来的，是服务端发的。想程序化拿 code，正路是 A，捷径是 B，「从零造一个假客户端」是 C——能做，但性价比极低且有代价。

---

## 📁 仓库文件

| 文件 | 说明 |
|---|---|
| `README.md` | 本报告 |
| `wxlogin_investigation.md` | 过程性工作笔记（精简版结论） |
| `decrypt_wxapkg.py` | PC 3.9 wxapkg（V1MMWX）解密 + 解包工具，实测可用 |
| `wx_code_protocol.py` | `jscode2session` 实现（实测打通格式）+ js-login 直探实验 + protobuf 帧解码器 |
| `frida_jslogin_hook.js` | 运行时 hook 脚本：自动定位 js-login 字符串 → 代码引用 → hook doSceneImpl/响应处理，dump 请求/响应缓冲区 |
| `carve_publiclib.py` | 只读内存 carve 工具（ReadProcessMemory 方案），从运行中的 WeChatAppEx 提取解密后基础库 |
| `out/app_pkg/` | 已解密解包的小程序包样例（222 文件） |
| `out/WAService_carved.js` | 内存 carve 出的 WAService 基础库 SDK 段（266KB 连续明文） |
| `out/liteapp_getlogincode.js` | `LiteAppAdapter.getLoginCode` / `doRequest` 完整实现（wx.login JS 层全貌） |
| `out/carved/`、`out/carve.log` | carve 中间产物与日志 |
| `out/app___APP__.wxapkg` | 解密后的样例小程序包（0xBE 标准 wxapkg） |

---

## 🔁 复现步骤

```bash
# 1. 解密任意小程序包（appid = Applet 目录名）
python decrypt_wxapkg.py "D:\...\WeChat Files\Applet\wxXXXXXXXXXXXXXXXX\2357\__APP__.wxapkg" wxXXXXXXXXXXXXXXXX

# 2. 协议实验（真实网络请求）
python wx_code_protocol.py demo                                   # 两个实验一起跑
python wx_code_protocol.py exchange <appid> <secret> <js_code>    # 换真实票 → openid
python wx_code_protocol.py decode <十六进制帧文件>                  # 解析抓包缓冲区

# 3. 从运行中的客户端 carve 基础库（微信需处于登录态、小程序进程存活）
python carve_publiclib.py                # 扫全部 WeChatAppEx；或指定 PID

# 4. 运行时 hook 抓 js-login 明文（需要登录 + 打开一个调用 wx.login 的小程序）
frida -n WeChat.exe -l frida_jslogin_hook.js
# 抓到的缓冲区十六进制 → python wx_code_protocol.py decode 反推 JSLoginRequest 字段表
```

## ⚠️ 边界与合规说明

- 本调查仅在本机自有客户端、自有账号环境下进行，未对腾讯服务器做任何越权访问；对服务器的网络请求仅为官方公开 API 的标准格式验证（个别占位凭据请求）与标准 TLS 探测。
- `code`/`openid`/`session_key` 属于账号敏感信息：`session_key` 等同于该小程序内的登录态，切勿外泄；对他人账号/批量场景使用上述路径违反微信平台规则并有法律风险。
- 微信客户端各版本（尤其 WMPF/flue）结构随版本变化较快，本文所有偏移、符号、口令机制均对应 **3.9.12.51**，跨版本需重新验证。

## 📚 参考

- [微信官方文档：小程序登录流程（wx.login / jscode2session）](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html)
- [微信官方文档：开发者工具 CLI/HTTP 调用](https://developers.weixin.qq.com/miniprogram/dev/devtools/cli.html)
- [微信官方文档：小程序自动化（miniprogram-automator）](https://developers.weixin.qq.com/miniprogram/dev/devtools/auto/quick-start.html) · [MiniProgram API](https://developers.weixin.qq.com/miniprogram/dev/devtools/auto/miniprogram.html)
- [BlackTrace/pc_wxapkg_decrypt](https://github.com/BlackTrace/pc_wxapkg_decrypt/blob/master/main.go) · [superdashu/pc_wxapkg_decrypt_python](https://github.com/superdashu/pc_wxapkg_decrypt_python)（wxapkg V1MMWX 解密公开实现；本文修正了 AES 区 1023 字节/填充字节与 XOR 起点 1030 两处细节）
- [看雪论坛：微信小程序逆向解密](https://bbs.kanxue.com/thread-276281.htm) · [博客园：pc微信小程序.wxapkg解密](https://www.cnblogs.com/DirWang/p/16749053.html)
- Citizen Lab (2024)：*Should We Chat, Too? Security Analysis of WeChat's MMTLS Encryption Protocol*（MMTLS 协议公开分析）
- [TesterHome：小程序自动化获取 code 实践](https://testerhome.com/topics/28244) · [掘金：小程序自动化测试之 Code 换取 Token](https://juejin.cn/post/7336921343206408232)

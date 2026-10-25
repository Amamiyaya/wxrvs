/*
 * frida_jslogin_hook.js —— 从真实 PC 客户端抓 wx.login() 的 code（取码端的可行实现）
 *
 * 用法：
 *   frida -n WeChat.exe -l frida_jslogin_hook.js
 *   然后在微信里打开任意调用 wx.login() 的小程序。
 *
 * 原理（对应 wxlogin_investigation.md 的证据链，全部运行时自动定位，免偏移）：
 *   1. 在 WeChatWin.dll 里搜字符串 "/cgi-bin/mmbiz-bin/js-login"（NetSceneJSLogin 的 URI）
 *   2. 扫 .text 找 rip 相对 lea 对该字符串的引用 -> 定位 NetSceneJSLogin::doSceneImpl
 *   3. hook doSceneImpl 入口：dump 寄存器/栈上指向的缓冲区（序列化好的 JSLoginRequest）
 *   4. 搜 "do NetSceneJSLogin faild. jsapibaseresponse.errCode = %d" 字符串，
 *      同法定位响应处理函数并 hook（JSLoginResponse，code 就在里面）
 *   5. 抓到的十六进制帧贴进 `python wx_code_protocol.py decode` 反推 proto 字段号
 *
 * 说明：3.9 的函数无符号、参数寄存器含义未经 live 校验，hook 会把入口处
 * RCX/RDX/R8/R9 指向的内存都 dump 出来，人工辨认哪个是 protobuf 缓冲区；
 * 第一次跑通后可把确认的偏移写死。
 */

'use strict';

const MOD = 'WeChatWin.dll';
const STR_JS_LOGIN = '/cgi-bin/mmbiz-bin/js-login';
const STR_LOGIN_FAIL = 'do NetSceneJSLogin faild. jsapibaseresponse.errCode = %d';

function findStringAddr(mod, str) {
  const pattern = str.split('').map(c =>
    ('0' + c.charCodeAt(0).toString(16)).slice(-2)).join(' ');
  const ranges = mod.enumerateRanges('r--').concat(mod.enumerateRanges('r-x'));
  for (const r of ranges) {
    try {
      const found = Memory.scanSync(r.base, r.size, pattern);
      if (found.length) return found[0].address;
    } catch (e) { /* range 不可读，跳过 */ }
  }
  return null;
}

// 在可执行段里找 rip 相对引用（lea reg, [rip+disp32]），返回引用指令附近地址。
// 直接按字节扫 disp32：target = disp_pos + 4 + disp。
function findRipRef(mod, strAddr, maxHits) {
  const exec = mod.enumerateRanges('r-x');
  const hits = [];
  const target = strAddr;
  for (const r of exec) {
    const size = r.size.toNumber();
    const CHUNK = 1 << 22;
    for (let off = 0; off + 8 < size && hits.length < maxHits; off += CHUNK - 8) {
      const len = Math.min(CHUNK, size - off);
      let buf;
      try { buf = Memory.readByteArray(r.base.add(off), len); } catch (e) { continue; }
      const u8 = new Uint8Array(buf);
      const dv = new DataView(buf);
      for (let i = 0; i + 4 <= u8.length; i++) {
        const disp = dv.getInt32(i, true);
        const dispPos = r.base.add(off + i);
        const t = dispPos.add(4).add(disp);
        if (t.equals(target)) {
          hits.push({ insnEnd: dispPos.add(4), range: r });
          if (hits.length >= maxHits) return hits;
        }
      }
    }
  }
  return hits;
}

function hexdumpSafe(ptr, n) {
  try { return hexdump(ptr, { length: n, ansi: false }); }
  catch (e) { return '<unreadable ' + ptr + '>'; }
}

// 从引用指令往回找函数入口：cc 填充 + 常见序言
function functionStart(insnAddr, range) {
  let p = insnAddr;
  for (let i = 0; i < 0x8000; i++) {
    p = p.sub(1);
    if (p.compare(range.base) < 0) break;
    const b = p.readU8();
    if (b === 0xcc) {
      const c = p.add(1);
      const b1 = c.readU8();
      // 48/40 开头（REX）或 push rbp(55)/rbx(53)/rsi(56)/rdi(57)
      if (b1 === 0x48 || b1 === 0x40 || b1 === 0x55 || b1 === 0x53 ||
          b1 === 0x56 || b1 === 0x57) return c;
    }
  }
  return insnAddr.sub(0x400); // 兜底：往前 1KB（大概率落在函数中部，仍可观察）
}

function hookFn(name, addr) {
  Interceptor.attach(addr, {
    onEnter(args) {
      const tid = this.thread.id;
      console.log(`\n[${name}] enter tid=${tid} ` +
        `rcx=${args[0]} rdx=${args[1]} r8=${args[2]} r9=${args[3]}`);
      for (const [rn, p] of [['rcx', args[0]], ['rdx', args[1]], ['r8', args[2]]]) {
        try {
          const q = p.readPointer();
          // std::string 情形：{ptr|buf, size}——把两种可能都试一下
          console.log(`  [${rn}=${p}] *p=${q}`);
          console.log(hexdumpSafe(p, 64));
        } catch (e) { /* */ }
      }
      console.log('  [rsp+0x20..0x60]');
      console.log(hexdumpSafe(this.context.rsp.add(0x20), 64));
    },
    onLeave(retval) {
      console.log(`[${name}] leave retval=${retval}`);
    }
  });
  console.log(`[+] hooked ${name} @ ${addr}`);
}

function main() {
  const mod = Process.findModuleByName(MOD);
  if (!mod) { console.error('WeChatWin.dll 未加载（先登录微信）'); return; }
  console.log(`[+] ${MOD} base=${mod.base} size=${mod.size}`);

  const uri = findStringAddr(mod, STR_JS_LOGIN);
  if (!uri) { console.error('未找到 js-login URI 字符串'); return; }
  console.log(`[+] URI string @ ${uri}`);

  const refs = findRipRef(mod, uri, 8);
  if (!refs.length) { console.error('未找到 URI 的代码引用'); return; }
  console.log(`[+] ${refs.length} code xref(s)`);

  // NetSceneJSLogin::doSceneImpl —— 引用 URI 的函数；同函数还有其构造/析构
  const sceneStart = functionStart(refs[0].insnEnd, refs[0].range);
  console.log(`[+] NetSceneJSLogin::doSceneImpl? -> ${sceneStart}`);
  hookFn('doSceneImpl', sceneStart);

  // 响应侧：失败日志字符串所在函数（onGYNetEnd / JsApiLoginJsApiHandler::eventProc）
  const failStr = findStringAddr(mod, STR_LOGIN_FAIL);
  if (failStr) {
    const frefs = findRipRef(mod, failStr, 8);
    if (frefs.length) {
      const respStart = functionStart(frefs[0].insnEnd, frefs[0].range);
      console.log(`[+] JSLogin response handler? -> ${respStart}`);
      hookFn('jslogin_response', respStart);
    }
  }
  console.log('\n[*] 就绪：在微信里打开一个调用 wx.login() 的小程序，观察输出。');
  console.log('[*] 把打印出的缓冲区十六进制贴给 `python wx_code_protocol.py decode`。');
}

setImmediate(main);

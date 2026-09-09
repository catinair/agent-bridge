/**
 * Self-contained viewer page served at GET /h/:id.
 *
 * Doubles as the machine discovery entry point: the raw HTML embeds a real
 * <a> (plus <link rel="alternate">) pointing at the JSON envelope endpoint,
 * because web-retrieval agents cannot guess derived URLs — they can only
 * follow links found on a page they were given. The link must therefore be
 * server-rendered, not injected by JS.
 *
 * The page also decrypts in-browser with WebCrypto for human readers; the
 * secret is never sent anywhere. The decrypt routine is exported separately
 * so tests can execute the exact same source in Node against ciphertext
 * produced by the shared encoder.
 *
 * Embedded JS deliberately avoids template literals so this file can use
 * plain TS template strings without escaping hazards.
 */

export const DECRYPT_FN_SOURCE = `(async function bridgeDecrypt(envelopeJson, secretInput) {
  'use strict';
  var ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  function b32norm(s) { return s.replace(/[\\s-]/g, '').toUpperCase(); }
  function b32decode(s) {
    s = b32norm(s);
    var AMBIG = { I: 1, L: 1, O: 0 };
    var bits = 0, value = 0, out = [];
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      var d = ALPHABET.indexOf(ch);
      if (d < 0) d = AMBIG[ch] !== undefined ? AMBIG[ch] : -1;
      if (d < 0) throw new Error('bad secret character: ' + ch);
      value = (value << 5) | d;
      bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }
  function b64decode(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  var envelope = typeof envelopeJson === 'string' ? JSON.parse(envelopeJson) : envelopeJson;
  if (!envelope || envelope.v !== 1 || envelope.algorithm !== 'AES-256-GCM') {
    throw new Error('unsupported envelope');
  }
  var km = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(b32norm(secretInput)), 'PBKDF2', false, ['deriveKey']);
  var key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64decode(envelope.salt), iterations: envelope.iterations, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  var pt;
  try {
    pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(envelope.iv) },
      key, b64decode(envelope.ciphertext));
  } catch (e) {
    throw new Error('wrong password or corrupted payload');
  }
  return new TextDecoder().decode(pt);
})`;

export function renderViewerPage(id: string, origin = ''): string {
  // ids are validated by the route already; standalone safety for direct use
  if (!/^[A-Za-z0-9]+$/.test(id)) {
    throw new Error('invalid handoff id');
  }
  return VIEWER_PAGE_HTML.replace(/__API_PATH__/g, `/v1/handoffs/${id}`).replace(
    /__API_URL__/g,
    `${origin}/v1/handoffs/${id}`,
  );
}

const VIEWER_PAGE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:">
<link rel="alternate" type="application/vnd.agent-handoff+json" href="__API_URL__">
<title>Secure Agent Handoff</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
         background: #0f1115; color: #e6e6e6; margin: 0;
         display: flex; min-height: 100vh; align-items: flex-start; justify-content: center; }
  .card { max-width: 56rem; width: 100%; margin: 4rem 1rem; background: #161a22;
          border: 1px solid #262c38; border-radius: 12px; padding: 2rem; }
  h1 { font-size: 1.15rem; margin: 0 0 0.25rem; }
  .sub { color: #8b93a3; font-size: 0.85rem; margin: 0 0 1.5rem; }
  .row { display: flex; gap: 0.5rem; }
  input[type=password] { flex: 1; font-size: 1rem; padding: 0.65rem 0.8rem; border-radius: 8px;
         border: 1px solid #2c3442; background: #0f1115; color: #e6e6e6; }
  input[type=password]:focus { outline: 2px solid #4c8dff; border-color: transparent; }
  button { font-size: 1rem; padding: 0.65rem 1.1rem; border-radius: 8px; border: 0;
           background: #4c8dff; color: #fff; cursor: pointer; }
  button:disabled { opacity: 0.5; cursor: default; }
  button.secondary { background: #2c3442; }
  .msg { margin-top: 1rem; font-size: 0.9rem; min-height: 1.2em; }
  .msg.err { color: #ff7a7a; }
  .msg.warn { color: #ffc46b; }
  pre { display: none; margin: 1.25rem 0 0; padding: 1rem; background: #0f1115;
        border: 1px solid #262c38; border-radius: 8px; white-space: pre-wrap;
        word-break: break-word; font-size: 0.85rem; line-height: 1.55; max-height: 70vh; overflow: auto; }
  .meta { display: none; margin-top: 0.75rem; font-size: 0.8rem; color: #8b93a3; }
  .agent-link { margin-top: 1.5rem; font-size: 0.78rem; color: #8b93a3; }
  .agent-link a { color: #8b93a3; }
  .hint { color: #8b93a3; font-size: 0.78rem; margin-top: 1.25rem; line-height: 1.5; }
</style>
</head>
<body>
<div class="card">
  <h1>🔐 Secure Agent Handoff</h1>
  <p class="sub">内容为端到端加密，密码只在你本地解密，服务器无法读取。</p>
  <div class="row">
    <input id="pwd" type="password" placeholder="输入临时密码（XXXX-XXXX-...）" autocomplete="off" autofocus>
    <button id="open">解密查看</button>
  </div>
  <div id="msg" class="msg"></div>
  <pre id="content"></pre>
  <div id="meta" class="meta"></div>
  <p class="agent-link">Agent access: <a rel="alternate" type="application/vnd.agent-handoff+json" href="__API_URL__">Agent-readable encrypted JSON</a> at __API_PATH__</p>
</div>
<script>
const bridgeDecrypt = ${DECRYPT_FN_SOURCE};
(function () {
  'use strict';
  var id = location.pathname.split('/').filter(Boolean).pop();
  var elPwd = document.getElementById('pwd');
  var elOpen = document.getElementById('open');
  var elMsg = document.getElementById('msg');
  var elContent = document.getElementById('content');
  var elMeta = document.getElementById('meta');
  var envelope = null;

  function say(text, cls) {
    elMsg.textContent = text;
    elMsg.className = 'msg' + (cls ? ' ' + cls : '');
  }

  fetch('/v1/handoffs/' + id).then(async function (r) {
    if (r.status === 404) {
      say('不存在或已过期（临时交接在几分钟后自动销毁）。', 'err');
      elPwd.disabled = true; elOpen.disabled = true;
      return;
    }
    if (!r.ok) { say('读取失败（HTTP ' + r.status + '）。', 'err'); return; }
    envelope = await r.json();
    var exp = envelope.expires_at ? new Date(envelope.expires_at) : null;
    if (exp && exp.getTime() <= Date.now()) {
      say('已过期。', 'err');
      elPwd.disabled = true; elOpen.disabled = true;
      return;
    }
    elPwd.focus();
  }).catch(function () { say('网络错误，无法读取加密内容。', 'err'); });

  function countdown() {
    if (!envelope || !envelope.expires_at) return;
    var left = new Date(envelope.expires_at).getTime() - Date.now();
    if (left <= 0) { elMeta.textContent = '⏱ 已过期（服务器端已销毁）'; return; }
    var m = Math.floor(left / 60000);
    var s = Math.floor((left % 60000) / 1000);
    elMeta.textContent = '⏱ 服务器端 ' + m + ':' + (s < 10 ? '0' : '') + s + ' 后自动销毁 · 类型 ' + (envelope.content_type || '');
  }
  setInterval(countdown, 1000);

  async function open() {
    if (!envelope) { say('加密内容尚未就绪。', 'warn'); return; }
    var secret = elPwd.value;
    if (!secret.trim()) { say('请输入密码。', 'warn'); return; }
    elOpen.disabled = true; elPwd.disabled = true;
    say('正在派生密钥并解密…');
    try {
      var t0 = Date.now();
      var plain = await bridgeDecrypt(envelope, secret);
      elContent.textContent = plain;
      elContent.style.display = 'block';
      elMeta.style.display = 'block';
      countdown();
      say('✅ 解密成功（' + ((Date.now() - t0) / 1000).toFixed(1) + 's）。');
      var copy = document.createElement('button');
      copy.textContent = '复制全文';
      copy.className = 'secondary';
      copy.style.marginTop = '0.75rem';
      copy.onclick = function () {
        navigator.clipboard.writeText(plain).then(function () { copy.textContent = '已复制'; });
      };
      elMeta.parentNode.insertBefore(copy, elMeta);
    } catch (e) {
      say('❌ ' + (e && e.message ? e.message : '解密失败'), 'err');
      elPwd.disabled = false; elPwd.select(); elPwd.focus();
    }
    elOpen.disabled = false;
  }

  elOpen.addEventListener('click', open);
  elPwd.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') open(); });
})();
</script>
</body>
</html>`;

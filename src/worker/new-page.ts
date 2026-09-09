/**
 * GET /new — human-facing Context Bundle creator.
 *
 * Everything happens in the browser: files are read locally, screened by the
 * same firewall rules as the CLI, assembled into a Context Bundle, encrypted
 * with WebCrypto, and only the ciphertext is POSTed to the Worker. The page
 * needs the long-term upload token (same one the CLI uses); it can be
 * remembered in localStorage — the trade-off of a self-hosted instance is
 * that creators must hold the upload token.
 */
import { CREATE_LIB_SOURCE } from './create-lib.js';

export function renderCreatePage(): string {
  return CREATE_PAGE_HTML.replace(/__CREATE_LIB__/g, () => CREATE_LIB_SOURCE);
}

const CREATE_PAGE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:">
<title>Create a secure handoff</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
         background: #0f1115; color: #e6e6e6; margin: 0;
         display: flex; min-height: 100vh; align-items: flex-start; justify-content: center; }
  .card { max-width: 46rem; width: 100%; margin: 3rem 1rem 4rem; background: #161a22;
          border: 1px solid #262c38; border-radius: 12px; padding: 2rem; }
  h1 { font-size: 1.15rem; margin: 0 0 0.25rem; }
  .sub { color: #8b93a3; font-size: 0.85rem; margin: 0 0 1.5rem; line-height: 1.5; }
  #drop { border: 2px dashed #2c3442; border-radius: 10px; padding: 1.8rem 1rem;
          text-align: center; color: #8b93a3; font-size: 0.9rem; transition: border-color .15s; }
  #drop.over { border-color: #4c8dff; color: #c7cdd8; }
  #drop input { display: none; }
  .label { font-size: 0.85rem; color: #8b93a3; margin: 1.25rem 0 0.4rem; }
  #files { margin-top: 0.75rem; font-size: 0.85rem; }
  .f { display: flex; gap: 0.5rem; padding: 0.3rem 0.2rem; border-bottom: 1px solid #1d222c; }
  .f:last-child { border-bottom: 0; }
  .f.ok { color: #c7cdd8; }
  .f.bad { color: #ff7a7a; }
  .f .sz { color: #8b93a3; margin-left: auto; }
  textarea, input[type=password], input[type=text] { width: 100%; font-size: 0.95rem;
      padding: 0.65rem 0.8rem; border-radius: 8px; border: 1px solid #2c3442;
      background: #0f1115; color: #e6e6e6; }
  textarea { min-height: 5.5rem; resize: vertical; }
  textarea:focus, input:focus { outline: 2px solid #4c8dff; border-color: transparent; }
  .row { display: flex; gap: 0.5rem; align-items: center; margin-top: 1.5rem; }
  button { font-size: 1rem; padding: 0.7rem 1.2rem; border-radius: 8px; border: 0;
           background: #4c8dff; color: #fff; cursor: pointer; }
  button:disabled { opacity: 0.5; cursor: default; }
  button.secondary { background: #2c3442; }
  #create { flex: 1; padding: 0.8rem; font-size: 1rem; }
  .msg { margin-top: 1rem; font-size: 0.9rem; min-height: 1.2em; white-space: pre-wrap; }
  .msg.err { color: #ff7a7a; }
  .remember { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; color: #8b93a3; }
  #result { display: none; }
  #result .box { margin-top: 0.75rem; padding: 0.8rem 1rem; background: #0f1115;
                 border: 1px solid #262c38; border-radius: 8px; font-size: 0.9rem;
                 white-space: pre-wrap; word-break: break-word; line-height: 1.6; }
  .k { color: #8b93a3; font-size: 0.78rem; margin-bottom: 0.2rem; }
  .copyline { display: flex; gap: 0.5rem; align-items: stretch; margin-top: 0.9rem; }
  .copyline .box { flex: 1; margin-top: 0; }
  .copyline button { background: #2c3442; }
  #countdown { color: #8b93a3; font-size: 0.85rem; margin-top: 1rem; }
  a { color: #4c8dff; }
</style>
</head>
<body>
<div class="card">
  <div id="form">
    <h1>🔐 Create a secure handoff</h1>
    <p class="sub">文件在<b>你的浏览器本地</b>完成防火墙检查与加密，服务器只收到密文。
       5 分钟后自动销毁。</p>

    <div id="drop">
      拖拽文件到此处，或 <a href="#" id="pick">点击选择</a><br>
      <span style="font-size:0.78rem">.md · .txt · .json · .yaml · .ts · .py · .sql · html · css …（仅文本）</span>
      <input id="file" type="file" multiple>
    </div>
    <div id="files"></div>

    <div class="label">你想让 AI 做什么（随交接一起发送）</div>
    <textarea id="prompt" placeholder="例如：帮我 review 这几份文档里的方案，重点看逻辑漏洞和遗漏"></textarea>

    <div class="label">补充说明（可选：文件之间的关系、阅读顺序）</div>
    <textarea id="notes" style="min-height:3rem" placeholder="例如：docs/architecture.md 是核心设计；config/models.yaml 是实际配置，注意两者差异"></textarea>

    <div class="label">上传令牌（BRIDGE_UPLOAD_TOKEN，仅用于本次加密上传）</div>
    <input id="token" type="password" placeholder="与 CLI 共用同一个令牌" autocomplete="off">
    <div class="remember" style="margin-top:0.5rem">
      <input id="remember" type="checkbox" checked>
      <span>记住令牌（保存在本浏览器 localStorage，仅限你自己的设备）</span>
    </div>

    <div class="row">
      <button id="create">创建安全交接</button>
      <button id="reset" class="secondary">重置</button>
    </div>
    <div id="msg" class="msg"></div>
  </div>

  <div id="result">
    <h1>✅ Handoff ready</h1>
    <p id="countdown"></p>
    <div class="k">URL（给人 / Agent 打开的页面）</div>
    <div class="copyline"><div id="rUrl" class="box"></div><button id="cUrl">复制</button></div>
    <div class="k" style="margin-top:1rem">密码（与 URL 分开发送）</div>
    <div class="copyline"><div id="rPwd" class="box"></div><button id="cPwd">复制</button></div>
    <div class="k" style="margin-top:1rem">粘给 ChatGPT / Claude 的四行</div>
    <div id="rSnippet" class="box"></div>
    <div class="copyline"><button id="cSnippet" style="flex:1">Copy for ChatGPT</button></div>
    <p class="sub" style="margin-top:1.5rem">另一个 Tab 想再创建？<a href="/new">重新开始</a></p>
  </div>
</div>
<script>
const createLib = __CREATE_LIB__;
(function () {
  'use strict';
  var elDrop = document.getElementById('drop');
  var elFile = document.getElementById('file');
  var elFiles = document.getElementById('files');
  var elPrompt = document.getElementById('prompt');
  var elNotes = document.getElementById('notes');
  var elToken = document.getElementById('token');
  var elRemember = document.getElementById('remember');
  var elMsg = document.getElementById('msg');
  var elCreate = document.getElementById('create');
  var entries = [];   // { path, text }
  var timer = null;

  function say(text, cls) {
    elMsg.textContent = text;
    elMsg.className = 'msg' + (cls ? ' ' + cls : '');
  }

  var saved = null;
  try { saved = localStorage.getItem('bridge_upload_token'); } catch (e) {}
  if (saved) elToken.value = saved;

  var elPick = document.getElementById('pick');
  elPick.onclick = function (e) { e.preventDefault(); elFile.click(); };
  elDrop.onclick = function (e) { if (e.target === elDrop) elFile.click(); };
  elDrop.ondragover = function (e) { e.preventDefault(); elDrop.classList.add('over'); };
  elDrop.ondragleave = function () { elDrop.classList.remove('over'); };
  elDrop.ondrop = function (e) {
    e.preventDefault(); elDrop.classList.remove('over');
    addFiles(Array.prototype.slice.call(e.dataTransfer.files));
  };
  elFile.onchange = function () {
    // snapshot first: clearing input.value empties the live FileList mid-iteration
    var files = Array.prototype.slice.call(elFile.files);
    elFile.value = '';
    addFiles(files);
  };

  function human(n) { return n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B'; }

  var pendingReads = 0;
  function setBusy(b) {
    elCreate.disabled = b;
    if (b) say('正在读取文件…');
    else if (elMsg.className.indexOf('err') < 0) say('就绪，' + entries.length + ' 个文件待加密。');
  }

  async function addFiles(fileList) {
    for (var i = 0; i < fileList.length; i++) {
      var f = fileList[i];
      if (entries.length >= createLib.LIMITS.maxFiles) { say('文件数超过上限 ' + createLib.LIMITS.maxFiles, 'err'); break; }
      var row = document.createElement('div');
      row.className = 'f';
      row.textContent = '读取中… ' + f.name;
      elFiles.appendChild(row);
      pendingReads++;
      elCreate.disabled = true;
      try {
        var buf = new Uint8Array(await f.arrayBuffer());
        var path = createLib.normalizeBundlePath(f.name);
        if (buf.length > createLib.LIMITS.maxFileBytes) throw new Error('超过单文件大小上限');
        if (createLib.looksBinary(buf)) throw new Error('二进制文件（仅支持文本）');
        if (!createLib.isTextPath(path)) throw new Error('非文本扩展名');
        var text = new TextDecoder().decode(buf);
        var fw = createLib.firewallCheckFile(path, text);
        var blockFindings = fw.findings.filter(function (x) { return x.severity === 'block'; });
        if (fw.blocked) throw new Error('防火墙拒绝：' + blockFindings.map(function (x) { return x.rule + (x.line ? ' (行 ' + x.line + ')' : ''); }).join('；'));
        entries.push({ path: path, text: text });
        var warns = fw.findings.filter(function (x) { return x.severity === 'warn'; }).length;
        row.className = 'f ok';
        row.textContent = '';
        row.appendChild(document.createTextNode('✓ ' + path + (warns ? '  ⚠️ ' + warns + ' 条告警' : '')));
        var sz = document.createElement('span');
        sz.className = 'sz'; sz.textContent = human(buf.length);
        row.appendChild(sz);
      } catch (err) {
        row.className = 'f bad';
        row.textContent = '✗ ' + f.name + '：' + (err && err.message ? err.message : '无法读取');
      } finally {
        pendingReads--;
      }
    }
    if (pendingReads === 0) setBusy(false);
  }

  elCreate.onclick = async function () {
    if (pendingReads > 0) { say('文件仍在读取中，请稍候。', 'err'); return; }
    if (entries.length === 0) { say('请先添加至少一个文件。', 'err'); return; }
    var token = elToken.value.trim();
    if (!token) { say('需要上传令牌（与 CLI 的 BRIDGE_UPLOAD_TOKEN 相同）。', 'err'); return; }
    if (elRemember.checked) { try { localStorage.setItem('bridge_upload_token', token); } catch (e) {} }
    elCreate.disabled = true;
    say('🛡 防火墙已通过 → 正在本地构建 Bundle 并加密…');
    try {
      var total = entries.reduce(function (s, e) { return s + new TextEncoder().encode(e.text).length; }, 0);
      if (total > createLib.LIMITS.maxTotalBytes) throw new Error('总大小超过上限 ' + createLib.LIMITS.maxTotalBytes + ' 字节');
      var bundle = await createLib.buildBundleJson(entries, elPrompt.value.trim(), elNotes.value.trim());
      var enc = await createLib.encryptBundle(bundle);
      var res = await fetch('/v1/handoffs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify(Object.assign({}, enc.envelope, { expires_in: 300 }))
      });
      if (res.status === 401) throw new Error('上传令牌无效（HTTP 401）');
      if (!res.ok) throw new Error('上传失败：HTTP ' + res.status);
      var created = await res.json();
      showResult(created, enc.secret, bundle, total);
    } catch (err) {
      say('❌ ' + (err && err.message ? err.message : '创建失败'), 'err');
      elCreate.disabled = false;
    }
  };

  function showResult(created, secret, bundle, total) {
    document.getElementById('form').style.display = 'none';
    var box = document.getElementById('result');
    box.style.display = 'block';
    document.getElementById('rUrl').textContent = created.url;
    document.getElementById('rPwd').textContent = secret;
    var snippet = '继续这个项目：\\n' + created.url + '\\n密码：' + secret + '\\n（5 分钟内有效）';
    document.getElementById('rSnippet').textContent = snippet;
    var summary = '📦 Context Bundle：' + bundle.files.length + ' 个文件，共 ' + human(total);
    if (bundle.request.prompt) summary += '\\n🎯 ' + bundle.request.prompt;
    document.getElementById('rSnippet').parentNode.insertBefore(
      (function () { var d = document.createElement('div'); d.className = 'box'; d.textContent = summary; return d; })(),
      document.getElementById('rSnippet'));
    document.getElementById('cUrl').onclick = function () { navigator.clipboard.writeText(created.url); };
    document.getElementById('cPwd').onclick = function () { navigator.clipboard.writeText(secret); };
    document.getElementById('cSnippet').onclick = function () {
      navigator.clipboard.writeText(snippet).then(function () {
        document.getElementById('cSnippet').textContent = '已复制，去粘贴吧';
      });
    };
    timer = setInterval(function () {
      var left = new Date(created.expires_at).getTime() - Date.now();
      if (left <= 0) { document.getElementById('countdown').textContent = '⏱ 已过期（服务器端已销毁）'; return; }
      var m = Math.floor(left / 60000), s = Math.floor((left % 60000) / 1000);
      document.getElementById('countdown').textContent =
        '⏱ 服务器端 ' + m + ':' + (s < 10 ? '0' : '') + s + ' 后自动销毁';
    }, 500);
  }

  document.getElementById('reset').onclick = function () { location.reload(); };
})();
</script>
</body>
</html>`;

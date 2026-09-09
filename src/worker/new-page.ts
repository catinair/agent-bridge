/**
 * GET /new — human-facing Context Bundle creator.
 *
 * Everything happens in the browser: files are read locally, screened by the
 * same firewall rules as the CLI, assembled into a split Context Bundle,
 * encrypted with WebCrypto, and only the ciphertext is POSTed to the Worker.
 * The page needs the long-term upload token (same one the CLI uses); it may
 * optionally be remembered in localStorage — remembering is OFF by default.
 */
import { CREATE_LIB_SOURCE } from './create-lib.js';

export function renderCreatePage(): string {
  return CREATE_PAGE_HTML.replace(/__CREATE_LIB__/g, () => CREATE_LIB_SOURCE);
}

const CREATE_PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:">
<title>Create a context drop</title>
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
  .label strong { color: #c7cdd8; font-weight: 600; }
  #files { margin-top: 0.75rem; font-size: 0.85rem; }
  #totals { margin-top: 0.5rem; font-size: 0.8rem; color: #8b93a3; }
  .f { display: flex; gap: 0.5rem; padding: 0.3rem 0.2rem; border-bottom: 1px solid #1d222c; align-items: center; }
  .f:last-child { border-bottom: 0; }
  .f.ok { color: #c7cdd8; }
  .f.bad { color: #ff7a7a; }
  .f .path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .f .sz { color: #8b93a3; margin-left: auto; }
  .f .rm { background: none; border: 0; color: #8b93a3; cursor: pointer; font-size: 0.9rem; padding: 0 0.2rem; }
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
  .remember { display: flex; align-items: flex-start; gap: 0.45rem; font-size: 0.8rem;
              color: #8b93a3; margin-top: 0.5rem; line-height: 1.45; }
  .remember input { margin-top: 0.15rem; }
  details.settings { margin-top: 1.25rem; border: 1px solid #262c38; border-radius: 8px; }
  details.settings summary { cursor: pointer; padding: 0.6rem 0.8rem; font-size: 0.85rem; color: #8b93a3; }
  details.settings .inner { padding: 0.25rem 0.8rem 0.9rem; }
  #result { display: none; }
  .statusline { margin: 0.75rem 0 0; font-size: 0.85rem; }
  .statusline .dot { color: #ffc46b; }
  #result .box { margin-top: 0.75rem; padding: 0.8rem 1rem; background: #0f1115;
                 border: 1px solid #262c38; border-radius: 8px; font-size: 0.9rem;
                 white-space: pre-wrap; word-break: break-word; line-height: 1.6; }
  .k { color: #8b93a3; font-size: 0.78rem; margin-bottom: 0.2rem; margin-top: 1rem; }
  .copyline { display: flex; gap: 0.5rem; align-items: stretch; margin-top: 0.9rem; }
  .copyline .box { flex: 1; margin-top: 0; }
  .copyline button { background: #2c3442; }
  #countdown { color: #8b93a3; font-size: 0.85rem; margin-top: 1rem; }
  a { color: #4c8dff; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #1d222c;
            font-size: 0.75rem; color: #8b93a3; }
</style>
</head>
<body>
<div class="card">
  <div id="form">
    <h1>🔐 Create a context drop</h1>
    <p class="sub">Files are screened and encrypted locally in your browser.
       The bridge receives ciphertext only — and burns it after reading.</p>

    <div id="drop">
      Drop files here, or <a href="#" id="pick">browse</a><br>
      <span style="font-size:0.78rem">.md · .txt · .json · .yaml · .ts · .py · .sql · html · css … (text only)</span>
      <input id="file" type="file" multiple>
    </div>
    <div id="files"></div>
    <div id="totals"></div>

    <div class="label"><strong>What do you want the AI to do?</strong></div>
    <textarea id="prompt" placeholder="e.g. Review the current model-routing design. Is it over-designed? Which tasks deserve a flagship model?"></textarea>

    <div class="label">Additional context <span style="opacity:.7">(optional — file relationships, reading order, known differences)</span></div>
    <textarea id="notes" style="min-height:3rem" placeholder="e.g. docs/model-routing.md is the design doc; config/models.yaml is the live config and may be out of sync"></textarea>

    <details class="settings">
      <summary>Bridge settings</summary>
      <div class="inner">
        <div class="label" style="margin-top:0.6rem">Upload token <span style="opacity:.7">(same token the CLI uses)</span></div>
        <input id="token" type="password" autocomplete="off">
        <div class="remember">
          <input id="remember" type="checkbox">
          <span>Remember upload token on this device.<br>
          Remembering lets this browser create future handoffs.
          Only enable this on a trusted personal device.</span>
        </div>
      </div>
    </details>

    <div class="row">
      <button id="create">Create a context drop</button>
      <button id="reset" class="secondary">Reset</button>
    </div>
    <div id="msg" class="msg"></div>
  </div>

  <div id="result">
    <h1>✅ Handoff ready</h1>
    <div class="statusline"><span class="dot">●</span> <span id="statusText">Unclaimed</span></div>
    <p id="countdown"></p>
    <div class="k">URL (page for humans and agents)</div>
    <div class="copyline"><div id="rUrl" class="box"></div><button id="cUrl">Copy</button></div>
    <div class="k" style="margin-top:1rem">Password (send separately from the URL)</div>
    <div class="copyline"><div id="rPwd" class="box"></div><button id="cPwd">Copy</button></div>
    <div class="k" style="margin-top:1rem">Paste into ChatGPT / Claude</div>
    <div id="rSnippet" class="box"></div>
    <div class="copyline"><button id="cSnippet" style="flex:1">Copy for ChatGPT</button></div>
    <p class="sub" style="margin-top:1.5rem">Creating another one? <a href="/new">Start over</a></p>
  </div>

  <p class="footer">Burn after reading applies to this bridge — once delivered,
     the receiving AI handles the context according to its own data policy.
     <a href="/">Home</a></p>
</div>
<script>
const createLib = __CREATE_LIB__;
(function () {
  'use strict';
  var elDrop = document.getElementById('drop');
  var elFile = document.getElementById('file');
  var elFiles = document.getElementById('files');
  var elTotals = document.getElementById('totals');
  var elPrompt = document.getElementById('prompt');
  var elNotes = document.getElementById('notes');
  var elToken = document.getElementById('token');
  var elRemember = document.getElementById('remember');
  var elMsg = document.getElementById('msg');
  var elCreate = document.getElementById('create');
  var entries = [];   // { path, text }
  var pendingReads = 0;
  var blockedCount = 0;
  var timers = [];
  function refreshCreateState() {
    elCreate.disabled = pendingReads > 0 || blockedCount > 0;
  }

  function say(text, cls) {
    elMsg.textContent = text;
    elMsg.className = 'msg' + (cls ? ' ' + cls : '');
  }

  var saved = null;
  try { saved = localStorage.getItem('bridge_upload_token'); } catch (e) {}
  if (saved) { elToken.value = saved; elRemember.checked = true; }

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
    var files = Array.prototype.slice.call(elFile.files);
    elFile.value = '';
    addFiles(files);
  };

  function human(n) {
    n = Number(n);
    if (!Number.isFinite(n)) return '';
    return n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B';
  }
  function refreshTotals() {
    var total = entries.reduce(function (s, e) {
      return s + new TextEncoder().encode(e.text).length;
    }, 0);
    elTotals.textContent = entries.length > 0
      ? entries.length + (entries.length === 1 ? ' file · ' : ' files · ') + human(total)
      : '';
  }
  function removeEntry(path, row) {
    entries = entries.filter(function (e) { return e.path !== path; });
    row.remove();
    refreshTotals();
  }

  async function addFiles(fileList) {
    for (var i = 0; i < fileList.length; i++) {
      var f = fileList[i];
      if (entries.length >= createLib.LIMITS.maxFiles) { say('File limit reached (' + createLib.LIMITS.maxFiles + ').', 'err'); break; }
      var row = document.createElement('div');
      row.className = 'f';
      row.textContent = 'reading… ' + f.name;
      elFiles.appendChild(row);
      pendingReads++;
      elCreate.disabled = true;
      try {
        var buf = new Uint8Array(await f.arrayBuffer());
        var path = createLib.normalizeBundlePath(f.name);
        if (buf.length > createLib.LIMITS.maxFileBytes) throw new Error('exceeds per-file size limit');
        if (createLib.looksBinary(buf)) throw new Error('binary file (text only)');
        if (!createLib.isTextPath(path)) throw new Error('not a recognized text type');
        var text = new TextDecoder().decode(buf);
        var fw = createLib.firewallCheckFile(path, text);
        var blockFindings = fw.findings.filter(function (x) { return x.severity === 'block'; });
        if (fw.blocked) throw new Error('blocked by firewall: ' + blockFindings.map(function (x) { return x.rule + (x.line ? ' (line ' + x.line + ')' : ''); }).join('; '));
        entries.push({ path: path, text: text });
        var warns = fw.findings.filter(function (x) { return x.severity === 'warn'; }).length;
        row.className = 'f ok';
        row.textContent = '';
        var p = document.createElement('span');
        p.className = 'path';
        p.textContent = '✓ ' + path + (warns ? '  ⚠️ ' + warns + ' warning' + (warns > 1 ? 's' : '') : '');
        var sz = document.createElement('span');
        sz.className = 'sz'; sz.textContent = human(buf.length);
        var rm = document.createElement('button');
        rm.className = 'rm'; rm.textContent = '×'; rm.title = 'remove';
        rm.onclick = function () { removeEntry(path, row); };
        row.appendChild(p); row.appendChild(sz); row.appendChild(rm);
      } catch (err) {
        row.className = 'f bad';
        row.textContent = '✗ ' + f.name + ' — ' + (err && err.message ? err.message : 'could not read');
        blockedCount++;
      }
      pendingReads--;
      if (pendingReads === 0) refreshCreateState();
    }
    if (pendingReads === 0) elCreate.disabled = false;
  }

  elCreate.onclick = async function () {
    if (pendingReads > 0) { say('Still reading files — one moment.', 'err'); return; }
    if (blockedCount > 0) {
      say('🛑 Some files were blocked by the firewall. Remove them (×) before creating — the bridge never silently drops selected files.', 'err');
      return;
    }
    if (entries.length === 0) { say('Add at least one file first.', 'err'); return; }
    var token = elToken.value.trim();
    if (!token) { say('Upload token required (the same BRIDGE_UPLOAD_TOKEN the CLI uses).', 'err'); return; }
    if (elRemember.checked) { try { localStorage.setItem('bridge_upload_token', token); } catch (e) {} }
    else { try { localStorage.removeItem('bridge_upload_token'); } catch (e) {} }
    elCreate.disabled = true;
    say('🛡 Firewall passed → building bundle and encrypting locally…');
    try {
      var total = entries.reduce(function (s, e) { return s + new TextEncoder().encode(e.text).length; }, 0);
      if (total > createLib.LIMITS.maxTotalBytes) throw new Error('Total size exceeds ' + createLib.LIMITS.maxTotalBytes + ' bytes');
      var prompt = elPrompt.value.trim();
      var notes = elNotes.value.trim();
      var built = await createLib.buildSplitHandoff(entries, prompt, notes, location.origin);
      var res = await fetch('/v1/handoffs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify(Object.assign({}, built.body, { expires_in: 300 }))
      });
      if (res.status === 401) throw new Error('Upload token invalid (HTTP 401)');
      if (!res.ok) throw new Error('Upload failed: HTTP ' + res.status);
      var created = await res.json();
      showResult(created, built.secret, entries.length, prompt, total);
    } catch (err) {
      say('❌ ' + (err && err.message ? err.message : 'creation failed'), 'err');
      elCreate.disabled = false;
    }
  };

  function showResult(created, secret, fileCount, prompt, total) {
    document.getElementById('form').style.display = 'none';
    var box = document.getElementById('result');
    box.style.display = 'block';
    document.getElementById('rUrl').textContent = created.url;
    document.getElementById('rPwd').textContent = secret;
    var snippet = '继续这个项目：\\n' + created.url + '\\n密码：' + secret + '\\n（5 分钟内有效）';
    document.getElementById('rSnippet').textContent = snippet;
    var summary = '📦 Context Bundle：' + fileCount + ' 个文件，共 ' + human(total);
    if (prompt) summary += '\\n🎯 ' + prompt;
    document.getElementById('rSnippet').parentNode.insertBefore(
      (function () { var d = document.createElement('div'); d.className = 'box'; d.textContent = summary; return d; })(),
      document.getElementById('rSnippet'));
    document.getElementById('cUrl').onclick = function () { navigator.clipboard.writeText(created.url); };
    document.getElementById('cPwd').onclick = function () { navigator.clipboard.writeText(secret); };
    document.getElementById('cSnippet').onclick = function () {
      navigator.clipboard.writeText(snippet).then(function () {
        document.getElementById('cSnippet').textContent = 'Copied — go paste it';
      });
    };
    // lifecycle: unclaimed → claimed (read lease) → burned
    var poll = setInterval(async function () {
      try {
        var r = await fetch('/v1/handoffs/' + created.id + '/status');
        if (r.status === 410) {
          clearInterval(poll);
          document.getElementById('statusText').textContent = '🔥 Burned — this context no longer exists';
          return;
        }
        var st = await r.json();
        var now = Date.now();
        if (st.status === 'unclaimed') {
          var left = Math.max(0, st.expires_if_unread_in_seconds || 0);
          document.getElementById('statusText').textContent = '● Unclaimed — expires if unread in ' + Math.floor(left / 60) + ':' + (left % 60 < 10 ? '0' : '') + (left % 60);
        } else if (st.status === 'claimed') {
          var rem = Math.max(0, st.lease_remaining_seconds || 0);
          document.getElementById('statusText').textContent = '● Claimed — read window ' + Math.floor(rem / 60) + ':' + (rem % 60 < 10 ? '0' : '') + (rem % 60);
        } else if (st.status === 'expired') {
          clearInterval(poll);
          document.getElementById('statusText').textContent = '⏱ Expired unread — nothing was delivered';
        }
      } catch (e) { /* transient */ }
    }, 1500);
    timers.push(poll);
    var countdownLine = function () {
      var left = new Date(created.expires_at).getTime() - Date.now();
      document.getElementById('countdown').textContent = left > 0
        ? '⏱ Unread fallback expiry: ' + Math.ceil(left / 1000) + 's'
        : '';
    };
    countdownLine();
    timers.push(setInterval(countdownLine, 1000));
  }

  document.getElementById('reset').onclick = function () { location.reload(); };
})();
</script>
</body>
</html>`;

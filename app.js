'use strict';
// Brink & Marini, Inc. weekly freight invoices.
// Records are encrypted in the browser (AES-256-GCM) and saved to a private GitHub data repository.
// Every keystroke is saved automatically (debounced), like Google Docs / Office 365.

const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const TE = new TextEncoder(), TD = new TextDecoder();
const h = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const clone = o => JSON.parse(JSON.stringify(o));
const uid = () => crypto.randomUUID();
const TERMS = ['Due on receipt', 'Net 7', 'Net 15', 'Net 30'];       // same billing terms as the PTB CRM
const STATUSES = ['Draft', 'Submitted', 'Paid'];
const ITER = 600000, MIN_PW = 14, PENDING = 'bm-invoices-pending';
const VAULT_AAD = TE.encode('bm-invoices-vault-v1'), DATA_AAD = TE.encode('bm-invoices-data-v1');

// ---------- money / dates ----------
const money = n => (Number(n) || 0).toLocaleString('en-US', {style:'currency', currency:'USD'});
const round2 = n => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
const lineAmount = l => round2((parseFloat(l.qty) || 0) * (parseFloat(l.rate) || 0));   // amount = quantity x pay rate
const invTotal = inv => round2(inv.lines.reduce((s, l) => s + lineAmount(l), 0));
const pad = n => String(n).padStart(2, '0');
const iso = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const parseISO = s => { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || ''); return m ? new Date(+m[1], +m[2] - 1, +m[3]) : null; };
const fmtDate = s => { const d = parseISO(s); return d ? d.toLocaleDateString('en-US', {month:'2-digit', day:'2-digit', year:'numeric'}) : ''; };
const dayName = s => { const d = parseISO(s); return d ? d.toLocaleDateString('en-US', {weekday:'long'}) : ''; };
const isSubmitDay = s => { const d = parseISO(s); return !!d && (d.getDay() === 5 || d.getDay() === 6); };   // Friday or Saturday
function nextSubmitDay(from = new Date()){ const d = new Date(from.getFullYear(), from.getMonth(), from.getDate()); while (d.getDay() !== 5) d.setDate(d.getDate() + 1); return iso(d); }
function weekOf(s){      // billing week runs Sunday through Saturday
  const d = parseISO(s); if (!d) return null;
  const a = new Date(d.getFullYear(), d.getMonth(), d.getDate() - d.getDay()), b = new Date(a.getFullYear(), a.getMonth(), a.getDate() + 6);
  return {start:iso(a), end:iso(b)};
}
const weekText = s => { const w = weekOf(s); return w ? `Week: Sunday ${fmtDate(w.start)} to Saturday ${fmtDate(w.end)}` : ''; };
const outsideWeek = (inv, ld) => { const w = weekOf(inv.date); return !!(w && ld && (ld < w.start || ld > w.end)); };
function dueFrom(issued, terms){
  const d = parseISO(issued); if (!d) return '';
  if (terms === 'Due on receipt') return issued;
  const n = parseInt(String(terms || '').replace(/\D/g, ''), 10); if (!n) return '';
  d.setDate(d.getDate() + n); return iso(d);
}

// ---------- data ----------
let sess = null, db = null;
let remoteSha = null, dirty = false, pushing = false, pushAgain = false, pushTimer = null, lastPull = 0, idleTimer = null;
let lockNote = '', pendingSetup = null, syncState = {s:'idle', msg:''};
const ui = {q:'', status:''};

function freshDb(){ return {v:1, counter:0, invoices:[], customers:[], deleted:{}, settings:{company:'Brink & Marini, Inc.', addr1:'10270 Elder Creek Road', addr2:'Sacramento, CA 95829', phone:'916-416-5291', email:'cmanica@aol.com', defaultTerms:'Net 30', autoLock:30}, meta:{updated:0}}; }
function ensureShape(d){
  const f = freshDb(); d = d && typeof d === 'object' ? d : f;
  d.invoices = Array.isArray(d.invoices) ? d.invoices : []; d.customers = Array.isArray(d.customers) ? d.customers : []; d.deleted = d.deleted || {};
  d.settings = {...f.settings, ...(d.settings || {})}; d.meta = d.meta || {updated:0}; d.counter = +d.counter || 0;
  for (const i of d.invoices){ i.lines = Array.isArray(i.lines) ? i.lines : []; }
  return d;
}
function newLine(date = ''){ return {id:uid(), date, fb:'', desc:'', ticket:'', product:'', qty:'', rate:''}; }
function newInvoice(){
  db.counter += 1;
  const date = nextSubmitDay(), terms = db.settings.defaultTerms || 'Net 30';
  const inv = {id:uid(), number:'BM-' + String(db.counter).padStart(4, '0'), date, terms, due:dueFrom(date, terms), status:'Draft', customerId:'', notes:'', lines:[newLine(), newLine(), newLine()], updated:Date.now()};
  db.invoices.push(inv); save(); return inv;
}
const getInv = id => db.invoices.find(i => i.id === id);
const getCust = id => db.customers.find(c => c.id === id);
const custName = id => getCust(id)?.name || '';
const custOptions = cur => `<option value="">(none selected)</option>` + [...db.customers].sort((a, b) => a.name.localeCompare(b.name)).map(c => `<option value="${h(c.id)}" ${c.id === cur ? 'selected' : ''}>${h(c.name)}</option>`).join('');

// ---------- crypto ----------
const b64e = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function passKey(u, p, salt, iter){
  const base = await crypto.subtle.importKey('raw', TE.encode(u.trim().toLowerCase() + '\u0000' + p), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', hash:'SHA-256', salt, iterations:iter}, base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function sealVault(u, p, secret){
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await passKey(u, p, salt, ITER);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:VAULT_AAD}, k, TE.encode(JSON.stringify(secret))));
  return {v:1, kdf:'PBKDF2-SHA256', iter:ITER, salt:b64e(salt), iv:b64e(iv), ct:b64e(ct)};
}
async function openVault(v, u, p){
  const k = await passKey(u, p, b64d(v.salt), v.iter || ITER);
  return JSON.parse(TD.decode(await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d(v.iv), additionalData:VAULT_AAD}, k, b64d(v.ct))));
}
async function gz(u8, compress){
  const stream = new Blob([u8]).stream().pipeThrough(compress ? new CompressionStream('gzip') : new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function sealData(obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:DATA_AAD}, sess.key, await gz(TE.encode(JSON.stringify(obj)), true)));
  return JSON.stringify({v:1, z:'gzip', iv:b64e(iv), ct:b64e(ct)});
}
async function openData(text){
  const e = JSON.parse(text);
  const pt = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d(e.iv), additionalData:DATA_AAD}, sess.key, b64d(e.ct)));
  return JSON.parse(TD.decode(e.z === 'gzip' ? await gz(pt, false) : pt));
}

// ---------- GitHub sync + autosave ----------
async function gh(method, url, body, token){
  return fetch('https://api.github.com' + url, {method, cache:'no-store', referrerPolicy:'no-referrer',
    headers:{Authorization:'Bearer ' + (token || sess.token), Accept:'application/vnd.github+json', 'X-GitHub-Api-Version':'2022-11-28', ...(body ? {'Content-Type':'application/json'} : {})},
    body: body ? JSON.stringify(body) : undefined});
}
async function ghError(r){
  let m = ''; try { m = (await r.json()).message || ''; } catch(e) {}
  if (r.status === 401) return new Error('GitHub rejected the access token. It may have expired. Create a new login in Settings.');
  if (r.status === 403) return new Error(/rate limit/i.test(m) ? 'GitHub rate limit reached. Try again in a few minutes.' : 'The token is missing Contents read and write permission on the data repository.');
  if (r.status === 404) return new Error('GitHub could not find the data repository, or the token cannot see it.');
  return new Error(`GitHub error ${r.status}${m ? ': ' + m : ''}`);
}
const repoPath = s => `/repos/${encodeURIComponent(s.owner)}/${encodeURIComponent(s.repo)}`;
const filePath = s => repoPath(s) + '/contents/' + s.path.split('/').map(encodeURIComponent).join('/');
async function pull(){
  const r = await gh('GET', filePath(sess));
  if (r.status === 404) return null;
  if (!r.ok) throw await ghError(r);
  const j = await r.json(); let b = j.content;
  if (!b || j.encoding === 'none'){ const br = await gh('GET', repoPath(sess) + '/git/blobs/' + j.sha); if (!br.ok) throw await ghError(br); b = (await br.json()).content; }
  return {data: ensureShape(await openData(TD.decode(b64d(b.replace(/\s/g, ''))))), sha: j.sha};
}
function merge(local, remote){      // newest edit of each invoice wins; deletions are remembered
  const out = ensureShape(clone((remote.meta.updated || 0) > (local.meta.updated || 0) ? remote : local));
  out.deleted = {...remote.deleted};
  for (const [k, v] of Object.entries(local.deleted)) out.deleted[k] = Math.max(v, out.deleted[k] || 0);
  const m = new Map();
  for (const r of [...remote.invoices, ...local.invoices]){ const c = m.get(r.id); if (!c || (r.updated || 0) > (c.updated || 0)) m.set(r.id, r); }
  out.invoices = [...m.values()].filter(r => !(out.deleted[r.id] >= (r.updated || 0)));
  const cm = new Map();
  for (const r of [...remote.customers, ...local.customers]){ const c = cm.get(r.id); if (!c || (r.updated || 0) > (c.updated || 0)) cm.set(r.id, r); }
  out.customers = [...cm.values()].filter(r => !(out.deleted[r.id] >= (r.updated || 0)));
  out.counter = Math.max(local.counter, remote.counter);
  const cutoff = Date.now() - 180 * 864e5; for (const [k, v] of Object.entries(out.deleted)) if (v < cutoff) delete out.deleted[k];
  return out;
}
function setSync(s, msg = ''){
  syncState = {s, msg, at:new Date()};
  const el = $('#syncstat'); if (!el) return;
  el.textContent = {saved:'All changes saved ' + syncState.at.toLocaleTimeString([], {hour:'numeric', minute:'2-digit'}), saving:'Saving…', pending:'Saving…', error:'Not saved. Retrying…', idle:''}[s];
  el.dataset.s = s; el.title = msg;
}
function schedulePush(ms){ clearTimeout(pushTimer); pushTimer = setTimeout(push, ms); }
async function stashPending(){      // encrypted safety copy in this browser until GitHub confirms
  try { if (sess && db && dirty) localStorage.setItem(PENDING, JSON.stringify({u:sess.u, repo:sess.owner + '/' + sess.repo, blob:await sealData(db)})); } catch(e) {}
}
async function push(){
  if (!sess || !db) return;
  if (pushing){ pushAgain = true; return; }
  pushing = true; clearTimeout(pushTimer); setSync('saving');
  try {
    for (let attempt = 0; attempt < 4; attempt++){
      dirty = false;
      const sealed = await sealData(db);
      const r = await gh('PUT', filePath(sess), {message:'Invoice data update', content:b64e(TE.encode(sealed)), ...(remoteSha ? {sha:remoteSha} : {})});
      if (r.ok){ remoteSha = (await r.json()).content.sha; if (!dirty) { try { localStorage.removeItem(PENDING); } catch(e) {} } setSync(dirty ? 'pending' : 'saved'); break; }
      if (r.status === 409 || r.status === 422){      // changed on another device: merge, then retry
        const rem = await pull(); if (rem){ db = merge(db, rem.data); remoteSha = rem.sha; } else remoteSha = null; continue; }
      throw await ghError(r);
    }
  } catch(e){
    dirty = true; await stashPending(); setSync('error', e.message);
    if (/token|permission/.test(e.message)) toast(e.message);
    pushTimer = setTimeout(push, 15000);
  } finally {
    pushing = false; if (pushAgain){ pushAgain = false; schedulePush(300); }
  }
}
async function refresh(force){
  if (!sess || pushing || dirty || (!force && Date.now() - lastPull < 60000)) return;
  lastPull = Date.now();
  try {
    const rem = await pull(); if (!rem || rem.sha === remoteSha) return;
    db = rem.data; remoteSha = rem.sha; setSync('saved');
    if (!$('#invform')) route(); else toast('Newer data is on GitHub. Reopen the invoice to see it.');
  } catch(e){ setSync('error', e.message); }
}
function save(){    // called on every edit
  if (!db || !sess) return;
  db.meta.updated = Date.now(); dirty = true; setSync('pending');
  if (pushing) pushAgain = true; else schedulePush(900);
}

// ---------- session ----------
async function startSession(secret){
  sess = {...secret, key:await crypto.subtle.importKey('raw', b64d(secret.dataKey), 'AES-GCM', false, ['encrypt','decrypt'])};
  const rem = await pull();
  if (rem){ db = rem.data; remoteSha = rem.sha; } else { db = ensureShape(freshDb()); remoteSha = null; dirty = true; }
  try { const p = JSON.parse(localStorage.getItem(PENDING) || 'null');
    if (p && p.u === sess.u && p.repo === sess.owner + '/' + sess.repo){ db = merge(ensureShape(await openData(p.blob)), db); dirty = true; toast('Recovered changes that had not reached GitHub'); } } catch(e) {}
  lastPull = Date.now(); lockNote = '';
  if (dirty) schedulePush(200); else setSync('saved');
  armIdle(); if (!location.hash) location.hash = '#/'; route(); setSync(syncState.s, syncState.msg);
}
async function lock(note){
  if (!sess) return;
  if (dirty){ await push(); if (dirty) await stashPending(); }
  clearTimeout(pushTimer); clearTimeout(idleTimer);
  sess = null; db = null; remoteSha = null; dirty = false; lockNote = note || '';
  $('#print').innerHTML = ''; history.replaceState(null, '', location.pathname); route();
}
function armIdle(){
  clearTimeout(idleTimer); if (!sess || !db) return;
  const min = Math.max(5, +db.settings.autoLock || 30);
  idleTimer = setTimeout(() => lock(`Locked after ${min} minutes without activity.`), min * 60000);
}
['pointerdown','keydown','wheel'].forEach(ev => document.addEventListener(ev, () => { if (sess) armIdle(); }, {passive:true, capture:true}));
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refresh(); else if (dirty) { stashPending(); push(); } });
window.addEventListener('focus', () => refresh());
window.addEventListener('pagehide', () => { if (dirty) stashPending(); });
window.addEventListener('beforeunload', e => { if (dirty){ stashPending(); e.preventDefault(); e.returnValue = ''; } });

// ---------- login / setup ----------
function viewLogin(){
  return `<div class="gate"><form class="panel" id="loginform" autocomplete="on">
    <h1>Brink &amp; Marini, Inc.</h1><p>${lockNote ? h(lockNote) : 'Sign in to open your invoices.'}</p>
    <label class="f">Username<input name="u" autocomplete="username" required autofocus></label>
    <label class="f">Password<input name="p" type="password" autocomplete="current-password" required></label>
    <p class="err" role="alert"></p><button class="btn primary" type="submit">Sign in</button></form></div>`;
}
function viewSetup(){
  if (pendingSetup) return `<div class="gate"><div class="panel"><h1>Login created</h1>
    <p>Download <b>config.js</b> and commit it to the app repository, replacing the placeholder. Until then, this browser tab is the only way in.</p>
    <p class="meta">It holds your GitHub token, encrypted with your username and password. Without both, it is unreadable.</p>
    <div class="row"><button class="btn primary" data-act="dl-config">Download config.js</button><button class="btn" data-act="setup-open">Open invoices</button></div></div></div>`;
  return `<div class="gate wide"><form class="panel" id="setupform" autocomplete="off">
    <h1>Set up secure storage</h1>
    <p>Your invoices are encrypted in this browser and saved to a private GitHub repository. You only do this once.</p>
    <div class="formgrid" style="padding:0">
      <label class="f">GitHub account<input name="owner" required placeholder="your-username"></label>
      <label class="f">Private data repository<input name="repo" required value="brink-marini-data"></label>
      <label class="f wide">File inside that repository<input name="path" required value="data/invoices.enc.json"></label>
      <label class="f wide">Fine-grained access token<input name="token" type="password" required placeholder="github_pat_…"><small>Scoped to the data repository only, with Contents: Read and write.</small></label>
      <label class="f">Choose a username<input name="u" required autocomplete="off"></label><span></span>
      <label class="f">Choose a password<input name="p" type="password" required autocomplete="new-password"><small>At least ${MIN_PW} characters.</small></label>
      <label class="f">Repeat password<input name="p2" type="password" required autocomplete="new-password"></label>
    </div><p class="err" role="alert"></p>
    <button class="btn primary" type="submit">Test connection and create login</button></form></div>`;
}
const formErr = (form, msg) => { $('.err', form).textContent = msg; };
function busy(btn, on, text){ btn.disabled = on; if (on){ btn.dataset.t = btn.textContent; btn.textContent = text; } else if (btn.dataset.t) btn.textContent = btn.dataset.t; }
async function doLogin(form){
  const btn = $('button[type=submit]', form); busy(btn, true, 'Unlocking…'); formErr(form, '');
  let secret;
  try { secret = await openVault(window.BM_VAULT, form.u.value, form.p.value); }
  catch(e){ busy(btn, false); form.p.value = ''; await new Promise(r => setTimeout(r, 800)); formErr(form, 'Wrong username or password.'); form.p.focus(); return; }
  try { await startSession(secret); } catch(e){ sess = null; db = null; busy(btn, false); formErr(form, e.message); }
}
async function doSetup(form){
  const E = form.elements, btn = $('button[type=submit]', form); formErr(form, '');
  const v = k => E[k].value.trim();
  if (v('u').length < 3) return formErr(form, 'Pick a username of at least 3 characters.');
  if (E.p.value.length < MIN_PW) return formErr(form, `Use a password of at least ${MIN_PW} characters.`);
  if (E.p.value !== E.p2.value) return formErr(form, 'The passwords do not match.');
  busy(btn, true, 'Checking GitHub…');
  try {
    const rr = await gh('GET', `/repos/${encodeURIComponent(v('owner'))}/${encodeURIComponent(v('repo'))}`, null, v('token'));
    if (!rr.ok) throw await ghError(rr);
    if (!(await rr.json()).private) throw new Error('That repository is public. Make it private on GitHub before storing invoices in it.');
    const probe = await gh('GET', filePath({owner:v('owner'), repo:v('repo'), path:v('path')}), null, v('token'));
    if (probe.ok) throw new Error('A data file already exists at that path. Choose a new file name, or restore the original config.js.');
    const secret = {u:v('u'), owner:v('owner'), repo:v('repo'), path:v('path').replace(/^\/+/, ''), token:v('token'), dataKey:b64e(crypto.getRandomValues(new Uint8Array(32)))};
    btn.textContent = 'Encrypting…';
    const vault = await sealVault(secret.u, E.p.value, secret);
    pendingSetup = {secret, config:`// Brink & Marini login vault. Encrypted with your username and password (PBKDF2-SHA256, ${ITER.toLocaleString()} rounds, AES-256-GCM).\n// Safe to commit; useless without the password.\nwindow.BM_VAULT = ${JSON.stringify(vault)};\n`};
    route();
  } catch(e){ busy(btn, false); formErr(form, e.message); }
}

// ---------- views ----------
function toast(msg){ const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove('on'), 3500); }
function download(name, text, type = 'text/plain'){
  const a = document.createElement('a'), u = URL.createObjectURL(new Blob([text], {type}));
  a.href = u; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 2000);
}
function renderTop(active){
  const top = $('#top');
  if (!sess){ top.innerHTML = `<a class="brand">Brink &amp; Marini, Inc.<small>Weekly invoices</small></a>`; return; }
  top.innerHTML = `<a class="brand" href="#/">Brink &amp; Marini, Inc.<small>Weekly invoices</small></a>
    <nav aria-label="Main"><a href="#/" ${active === 'list' ? 'aria-current="page"' : ''}>Invoices</a><a href="#/customers" ${active === 'customers' ? 'aria-current="page"' : ''}>Customers</a><a href="#/settings" ${active === 'settings' ? 'aria-current="page"' : ''}>Settings</a></nav>
    <span class="grow"></span><span class="syncstat" id="syncstat" role="status"></span><button class="btn small" data-act="lock">Lock</button>`;
  setSync(syncState.s, syncState.msg);
}
function route(){
  const view = $('#view');
  if (!sess){ renderTop(); view.innerHTML = window.BM_VAULT ? viewLogin() : viewSetup(); return; }
  const parts = (location.hash || '#/').replace(/^#\/?/, '').split('/');
  if (parts[0] === 'inv' && getInv(parts[1])){ renderTop('list'); view.innerHTML = viewInvoice(getInv(parts[1])); recalc(); return; }
  if (parts[0] === 'customers' && parts[1] && (parts[1] === 'new' || getCust(parts[1]))){
    if (parts[1] === 'new'){ const c = {id:uid(), name:'', email:'', phone:'', address:'', notes:'', updated:Date.now()}; db.customers.push(c); location.replace('#/customers/' + c.id); return; }
    renderTop('customers'); view.innerHTML = viewCustomer(getCust(parts[1])); return; }
  if (parts[0] === 'customers'){ renderTop('customers'); view.innerHTML = viewCustomers(); return; }
  if (parts[0] === 'settings'){ renderTop('settings'); view.innerHTML = viewSettings(); return; }
  renderTop('list'); view.innerHTML = viewList(); fillRows();
}
const termsOptions = cur => TERMS.map(t => `<option ${t === cur ? 'selected' : ''}>${h(t)}</option>`).join('');

function viewList(){
  return `<div class="head"><div><h1>Invoices</h1><p>One invoice per week, submitted on a Friday or Saturday.</p></div>
    <button class="btn primary" data-act="new">New invoice</button></div>
    <div class="stats" id="stats"></div>
    <div class="toolbar"><input type="search" id="q" placeholder="Search invoice #, freight bill #, ticket #, item…" value="${h(ui.q)}" aria-label="Search">
      <select id="statusf" aria-label="Status"><option value="">All statuses</option>${STATUSES.map(s => `<option ${ui.status === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
      <button class="btn" data-act="csv-all">Export CSV</button></div>
    <div class="tablewrap"><table class="grid"><thead><tr><th>Invoice #</th><th>Customer</th><th>Date</th><th>Day</th><th>Lines</th><th class="num">Total tons</th><th class="num">Total</th><th>Terms</th><th>Due</th><th>Status</th></tr></thead><tbody id="rows"></tbody></table></div>`;
}
const totalTons = inv => round2(inv.lines.reduce((s, l) => s + (parseFloat(l.qty) || 0), 0));
function fillRows(){
  const q = ui.q.trim().toLowerCase();
  const rows = db.invoices.filter(i => (!ui.status || i.status === ui.status) &&
    (!q || [i.number, i.notes, custName(i.customerId), ...i.lines.flatMap(l => [l.fb, l.ticket, l.product, l.desc])].some(x => String(x || '').toLowerCase().includes(q)))).sort((a, b) => (b.date || '').localeCompare(a.date || ''));
  const body = $('#rows'); if (!body) return;
  body.innerHTML = rows.length ? rows.map(i => `<tr data-id="${h(i.id)}" tabindex="0"><td data-label="Invoice #"><b>${h(i.number)}</b></td><td data-label="Customer">${h(custName(i.customerId))}</td><td data-label="Date">${fmtDate(i.date)}</td><td data-label="Day">${dayName(i.date)}</td>
    <td data-label="Lines">${i.lines.filter(l => l.fb || l.ticket || l.qty).length}</td><td class="num" data-label="Total tons">${totalTons(i)}</td><td class="num" data-label="Total"><b>${money(invTotal(i))}</b></td>
    <td data-label="Terms">${h(i.terms)}</td><td data-label="Due">${fmtDate(i.due)}</td><td data-label="Status"><span class="pill" data-s="${h(i.status)}">${h(i.status)}</span></td></tr>`).join('')
    : `<tr><td colspan="10" class="empty" style="display:table-cell">${db.invoices.length ? 'No invoices match.' : 'No invoices yet. Press New invoice to start this week\'s.'}</td></tr>`;
  const open = db.invoices.filter(i => i.status === 'Submitted'), draft = db.invoices.filter(i => i.status === 'Draft');
  $('#stats').innerHTML = `<div><b>${money(open.reduce((s, i) => s + invTotal(i), 0))}</b>Submitted, unpaid</div><div><b>${draft.length}</b>Drafts</div><div><b>${db.invoices.length}</b>Invoices</div>`;
}

function lineRow(l){
  return `<tr class="li" data-line="${h(l.id)}">
    <td data-label="Date"><input type="date" data-l="date" value="${h(l.date)}" aria-label="Date"></td>
    <td data-label="Freight Bill #"><input data-l="fb" value="${h(l.fb)}" aria-label="Freight Bill #" autocomplete="off"></td>
    <td data-label="Description"><input data-l="desc" value="${h(l.desc)}" aria-label="Description" autocomplete="off"></td>
    <td data-label="Ticket #"><input data-l="ticket" value="${h(l.ticket)}" aria-label="Ticket #" autocomplete="off"></td>
    <td data-label="Product / Item"><input data-l="product" value="${h(l.product)}" aria-label="Product / Item" autocomplete="off"></td>
    <td class="num" data-label="Quantity (Tons)"><input type="number" step="any" min="0" inputmode="decimal" data-l="qty" value="${h(l.qty)}" aria-label="Quantity (Tons)"></td>
    <td class="num" data-label="Pay Rate"><input type="number" step="any" min="0" inputmode="decimal" data-l="rate" value="${h(l.rate)}" aria-label="Pay Rate"></td>
    <td class="num" data-label="Amount"><input class="calc" readonly tabindex="-1" data-amt aria-label="Amount" value="${money(lineAmount(l))}"></td>
    <td class="x"><button type="button" class="btn danger small" data-act="del-line" aria-label="Remove line" title="Remove line">✕</button></td></tr>`;
}
function viewInvoice(inv){
  return `<form id="invform" data-id="${h(inv.id)}" autocomplete="off">
    <div class="head"><div><h1>Invoice ${h(inv.number)}</h1><p>Changes save automatically as you type.</p></div>
      <div class="row"><a class="btn" href="#/">← All invoices</a><button type="button" class="btn" data-act="print">Print / PDF</button><button type="button" class="btn" data-act="csv-one">CSV</button><button type="button" class="btn" data-act="dup">Duplicate</button><button type="button" class="btn danger" data-act="del">Delete</button></div></div>
    <div class="panel"><div class="formgrid">
      <label class="f">Invoice #<input data-f="number" value="${h(inv.number)}"><span class="warn" id="numwarn"></span></label>
      <label class="f">Date (Friday or Saturday)<input type="date" data-f="date" value="${h(inv.date)}"><small id="weektxt"></small><span class="warn" id="daywarn"></span></label>
      <label class="f">Billing terms<select data-f="terms">${termsOptions(inv.terms)}</select></label>
      <label class="f">Due date<input type="date" data-f="due" value="${h(inv.due)}"><small>Fills in from the date and terms. You can still change it.</small></label>
      <label class="f">Status<select data-f="status">${STATUSES.map(s => `<option ${s === inv.status ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
      <label class="f wide">Customer (bill to)<select data-f="customerId">${custOptions(inv.customerId)}</select><small>Leave blank until you choose one. <a href="#/customers/new">Add a customer</a></small></label>
      <label class="f wide">Notes<textarea data-f="notes">${h(inv.notes)}</textarea></label>
    </div>
    <div class="sectionhead"><h2>Freight lines</h2><button type="button" class="btn small" data-act="add-line">Add line</button></div>
    <div class="lines"><div class="scroll"><table><thead><tr><th>Date</th><th>Freight Bill #</th><th>Description</th><th>Ticket #</th><th>Product / Item</th><th class="num">Quantity (Tons)</th><th class="num">Pay Rate</th><th class="num">Amount</th><th></th></tr></thead>
      <tbody id="lines">${inv.lines.map(lineRow).join('')}</tbody>
      <tfoot><tr><td colspan="5" style="text-align:right">Totals</td><td class="num" id="tot-tons"></td><td></td><td class="num" id="tot-amt"></td><td></td></tr></tfoot></table></div></div></div></form>`;
}
function recalc(){
  const form = $('#invform'); if (!form) return; const inv = getInv(form.dataset.id); if (!inv) return;
  $$('tr.li', form).forEach(tr => { const l = inv.lines.find(x => x.id === tr.dataset.line); if (l) $('[data-amt]', tr).value = money(lineAmount(l)); });
  $('#weektxt').textContent = weekText(inv.date);
  $('#numwarn').textContent = db.invoices.some(i => i.id !== inv.id && i.number === inv.number) ? 'Another invoice already uses this number.' : '';
  $$('tr.li', form).forEach(tr => { const l = inv.lines.find(x => x.id === tr.dataset.line), out = !!l && outsideWeek(inv, l.date), el = $('[data-l=date]', tr); el.style.borderColor = out ? 'var(--warn)' : ''; el.title = out ? 'This date is outside the invoice week (Sunday to Saturday).' : ''; });
  $('#tot-tons').textContent = totalTons(inv); $('#tot-amt').textContent = money(invTotal(inv));
  $('#daywarn').textContent = inv.date && !isSubmitDay(inv.date) ? `That is a ${dayName(inv.date)}. Invoices are submitted on Fridays or Saturdays.` : '';
}
function onEdit(t){
  const form = t.closest('#invform'); if (!form) return; const inv = getInv(form.dataset.id); if (!inv) return;
  if (t.dataset.f){
    inv[t.dataset.f] = t.value;
    if (t.dataset.f === 'date' || t.dataset.f === 'terms'){ inv.due = dueFrom(inv.date, inv.terms) || inv.due; $('[data-f=due]', form).value = inv.due; }
  } else if (t.dataset.l){
    const l = inv.lines.find(x => x.id === t.closest('tr').dataset.line); if (!l) return; l[t.dataset.l] = t.value;
  } else return;
  inv.updated = Date.now(); recalc(); save();
}

function viewSettings(){
  const S = db.settings;
  return `<div class="head"><h1>Settings</h1></div><div class="settings">
    <section class="panel"><h2>Company</h2><p>Printed at the top of every invoice.</p><div class="formgrid" style="padding:0">
      <label class="f wide">Company name<input data-s="company" value="${h(S.company)}"></label>
      <label class="f wide">Street address<input data-s="addr1" value="${h(S.addr1)}"></label>
      <label class="f wide">City, state, ZIP<input data-s="addr2" value="${h(S.addr2)}"></label>
      <label class="f">Phone<input type="tel" data-s="phone" value="${h(S.phone)}"></label>
      <label class="f">Email<input type="email" data-s="email" value="${h(S.email)}"></label></div></section>
    <section class="panel"><h2>Invoice numbering</h2><p>The next new invoice will be numbered <b id="nextnum">BM-${String(db.counter + 1).padStart(4, '0')}</b>. Delete any test invoices first so numbers do not repeat.</p>
      <div class="formgrid" style="padding:0"><label class="f">Next invoice number<input type="number" min="1" step="1" data-s="nextNum" value="${db.counter + 1}"></label></div>
      <div class="row" style="margin-top:.75rem"><button class="btn" data-act="reset-num">Restart at BM-0001</button></div></section>
    <section class="panel"><h2>Defaults</h2><p>Used when you start a new invoice.</p><div class="formgrid" style="padding:0">
      <label class="f">Default billing terms<select data-s="defaultTerms">${termsOptions(S.defaultTerms)}</select></label>
      <label class="f">Auto-lock after (minutes)<input type="number" min="5" data-s="autoLock" value="${h(S.autoLock)}"></label></div></section>
    <section class="panel"><h2>Backup</h2><p>Your data already lives in the private GitHub repository. This is an extra copy for your own files.</p>
      <div class="row"><button class="btn" data-act="backup">Download backup (JSON)</button><button class="btn" data-act="csv-all">Export all invoices (CSV)</button></div></section></div>`;
}

function viewCustomers(){
  const rows = [...db.customers].sort((a, b) => a.name.localeCompare(b.name));
  return `<div class="head"><div><h1>Customers</h1><p>Who your invoices are billed to.</p></div><a class="btn primary" href="#/customers/new">New customer</a></div>
    <div class="tablewrap"><table class="grid"><thead><tr><th>Name</th><th>Email</th><th>Phone</th><th class="num">Invoices</th></tr></thead><tbody>
    ${rows.length ? rows.map(c => `<tr data-href="#/customers/${h(c.id)}" tabindex="0"><td data-label="Name"><b>${h(c.name || '(unnamed)')}</b></td><td data-label="Email">${h(c.email)}</td><td data-label="Phone">${h(c.phone)}</td><td class="num" data-label="Invoices">${db.invoices.filter(i => i.customerId === c.id).length}</td></tr>`).join('')
      : `<tr><td colspan="4" class="empty" style="display:table-cell">No customers yet.</td></tr>`}</tbody></table></div>`;
}
function viewCustomer(c){
  const invs = db.invoices.filter(i => i.customerId === c.id);
  return `<form id="custform" data-id="${h(c.id)}"><div class="head"><div><h1>${h(c.name || 'New customer')}</h1><p>Changes save automatically as you type.</p></div>
    <div class="row"><a class="btn" href="#/customers">← All customers</a><button type="button" class="btn danger" data-act="del-cust">Delete</button></div></div>
    <div class="panel"><div class="formgrid"><label class="f wide">Name / company<input data-c="name" value="${h(c.name)}" autofocus></label>
      <label class="f">Email<input type="email" data-c="email" value="${h(c.email)}"></label><label class="f">Phone<input type="tel" data-c="phone" value="${h(c.phone)}"></label>
      <label class="f wide">Billing address<textarea data-c="address">${h(c.address)}</textarea></label><label class="f wide">Notes<textarea data-c="notes">${h(c.notes)}</textarea></label></div>
      <p class="meta" style="padding:0 1.1rem 1.1rem">${invs.length} invoice${invs.length === 1 ? '' : 's'} billed to this customer.</p></div></form>`;
}

// ---------- export / print ----------
const csvCell = v => { let s = String(v ?? ''); if (/^[=+\-@]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function csvFor(invs){
  const rows = [['Invoice #','Customer','Invoice Date','Billing Terms','Due Date','Status','Date','Freight Bill #','Description','Ticket #','Product / Item','Quantity (Tons)','Pay Rate','Amount']];
  for (const i of invs) for (const l of i.lines) if (l.fb || l.ticket || l.desc || l.product || l.qty || l.rate)
    rows.push([i.number, custName(i.customerId), i.date, i.terms, i.due, i.status, l.date, l.fb, l.desc, l.ticket, l.product, l.qty, l.rate, lineAmount(l).toFixed(2)]);
  return rows.map(r => r.map(csvCell).join(',')).join('\r\n');
}
function printInvoice(inv){
  const used = inv.lines.filter(l => l.date || l.fb || l.desc || l.ticket || l.product || l.qty || l.rate);
  const S = db.settings;
  $('#print').innerHTML = `<h1>${h(S.company)}</h1><p>${[S.addr1, S.addr2, S.phone, S.email].filter(Boolean).map(h).join('<br>')}</p>
    <p><b>Invoice ${h(inv.number)}</b> &nbsp; Date: ${fmtDate(inv.date)} (${dayName(inv.date)}) &nbsp; Terms: ${h(inv.terms)} &nbsp; Due: ${fmtDate(inv.due)}<br>${h(weekText(inv.date))}</p>
    ${(() => { const c = getCust(inv.customerId); return c ? `<p><b>Bill to:</b><br>${h(c.name)}${c.address ? '<br>' + h(c.address).replace(/\n/g, '<br>') : ''}${c.email ? '<br>' + h(c.email) : ''}${c.phone ? '<br>' + h(c.phone) : ''}</p>` : ''; })()}
    <table><thead><tr><th>Date</th><th>Freight Bill #</th><th>Description</th><th>Ticket #</th><th>Product / Item</th><th class="r">Quantity (Tons)</th><th class="r">Pay Rate</th><th class="r">Amount</th></tr></thead><tbody>
    ${used.map(l => `<tr><td>${fmtDate(l.date)}</td><td>${h(l.fb)}</td><td>${h(l.desc)}</td><td>${h(l.ticket)}</td><td>${h(l.product)}</td><td class="r">${h(l.qty)}</td><td class="r">${l.rate === '' ? '' : money(l.rate)}</td><td class="r">${money(lineAmount(l))}</td></tr>`).join('')}
    </tbody><tfoot><tr><th colspan="5" class="r">Totals</th><th class="r">${totalTons(inv)}</th><th></th><th class="r">${money(invTotal(inv))}</th></tr></tfoot></table>
    ${inv.notes ? `<p>${h(inv.notes)}</p>` : ''}`;
  window.print();
}

// ---------- events ----------
function setSetting(el){
  const k = el.dataset.s;
  if (k === 'nextNum'){ db.counter = Math.max(1, parseInt(el.value, 10) || 1) - 1; const n = $('#nextnum'); if (n) n.textContent = 'BM-' + String(db.counter + 1).padStart(4, '0'); }
  else db.settings[k] = k === 'autoLock' ? Math.max(5, +el.value || 30) : el.value;
  save();
}
document.addEventListener('input', e => {
  if (e.target.id === 'q'){ ui.q = e.target.value; fillRows(); return; }
  if (e.target.dataset?.s && db){ setSetting(e.target); return; }
  if (e.target.dataset?.c && db){ const c = getCust(e.target.closest('form').dataset.id); if (c){ c[e.target.dataset.c] = e.target.value; c.updated = Date.now(); save(); } return; }
  onEdit(e.target);
});
document.addEventListener('change', e => {
  if (e.target.id === 'statusf'){ ui.status = e.target.value; fillRows(); return; }
  if (['terms','status','customerId'].includes(e.target.dataset?.f)) onEdit(e.target);
  if (e.target.dataset?.s && db) setSetting(e.target);
});
document.addEventListener('submit', e => {
  e.preventDefault();
  if (e.target.id === 'loginform') doLogin(e.target); else if (e.target.id === 'setupform') doSetup(e.target);
});
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's'){ e.preventDefault(); if (dirty) push(); toast('Saving to GitHub…'); }
  if (e.key === 'Enter' && e.target.closest?.('tr[data-href]')) location.hash = e.target.closest('tr').dataset.href;
  if (e.key === 'Enter' && e.target.closest?.('tr[data-id]')) location.hash = '#/inv/' + e.target.closest('tr').dataset.id;
});
document.addEventListener('click', e => {
  const hr = e.target.closest('tr[data-href]'); if (hr){ location.hash = hr.dataset.href; return; }
  const row = e.target.closest('tr[data-id]'); if (row && !e.target.closest('button,a')){ location.hash = '#/inv/' + row.dataset.id; return; }
  const b = e.target.closest('[data-act]'); if (!b) return;
  const form = $('#invform'), inv = form ? getInv(form.dataset.id) : null;
  switch (b.dataset.act){
    case 'new': location.hash = '#/inv/' + newInvoice().id; break;
    case 'lock': lock(); break;
    case 'del-cust': { const c = getCust($('#custform').dataset.id); if (c && confirm(`Delete ${c.name || 'this customer'}? Invoices keep their data but show no customer.`)){ db.customers = db.customers.filter(x => x.id !== c.id); db.deleted[c.id] = Date.now(); db.invoices.forEach(i => { if (i.customerId === c.id){ i.customerId = ''; i.updated = Date.now(); } }); save(); location.hash = '#/customers'; } break; }
    case 'reset-num': if (confirm('Restart invoice numbering so the next invoice is BM-0001? Delete any test invoices first or numbers will repeat.')){ db.counter = 0; save(); route(); toast('Next invoice will be BM-0001'); } break;
    case 'dl-config': download('config.js', pendingSetup.config, 'text/javascript'); break;
    case 'setup-open': { const s = pendingSetup.secret; pendingSetup = null; startSession(s).catch(err => toast(err.message)); break; }
    case 'add-line': if (inv){ const l = newLine(); inv.lines.push(l); inv.updated = Date.now(); $('#lines').insertAdjacentHTML('beforeend', lineRow(l)); recalc(); save(); $('tr.li:last-child input', form).focus(); } break;
    case 'del-line': if (inv){ const tr = b.closest('tr'); inv.lines = inv.lines.filter(l => l.id !== tr.dataset.line); inv.updated = Date.now(); tr.remove(); recalc(); save(); } break;
    case 'dup': if (inv){ const c = clone(inv); db.counter += 1; Object.assign(c, {id:uid(), number:'BM-' + String(db.counter).padStart(4, '0'), status:'Draft', date:nextSubmitDay(), updated:Date.now()});
      c.due = dueFrom(c.date, c.terms); c.lines.forEach(l => { l.id = uid(); }); db.invoices.push(c); save(); location.hash = '#/inv/' + c.id; toast('Duplicated as ' + c.number); } break;
    case 'del': if (inv && confirm(`Delete invoice ${inv.number}? This cannot be undone.`)){ db.invoices = db.invoices.filter(i => i.id !== inv.id); db.deleted[inv.id] = Date.now(); save(); location.hash = '#/'; } break;
    case 'print': if (inv) printInvoice(inv); break;
    case 'csv-one': if (inv) download(`${inv.number}.csv`, csvFor([inv]), 'text/csv'); break;
    case 'csv-all': download('brink-marini-invoices.csv', csvFor(db.invoices), 'text/csv'); break;
    case 'backup': download(`brink-marini-backup-${iso(new Date())}.json`, JSON.stringify(db, null, 2), 'application/json'); break;
  }
});
window.addEventListener('hashchange', route);

route();
if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});

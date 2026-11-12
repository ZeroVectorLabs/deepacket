/* ===================== UI ===================== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cssv = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const SVGI = (d, w = 16) => `<svg width="${w}" height="${w}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const IC = {
  pk: '<path d="M21 8l-9-5-9 5 9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8"/>',
  data: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  speed: '<path d="M12 14l4-4"/><path d="M3.3 19a10 10 0 1 1 17.4 0"/>',
  hosts: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  flows: '<path d="M7 7h10l-3-3M17 17H7l3 3"/>',
  shield: '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  car: '<path d="M9 6l6 6-6 6"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>',
  stream: '<path d="M4 6h16M4 12h10M4 18h7"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  reset: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
  play: '<path d="M6 4l14 8-14 8z"/>', pause: '<path d="M7 4h4v16H7zM13 4h4v16h-4z"/>',
};
const SEV_ICON = {
  critical: '<path d="M8 2h8l6 6v8l-6 6H8l-6-6V8z" fill="currentColor" stroke="none"/><path d="M12 7v6M12 16.5v.5" stroke="#fff" stroke-width="2.4"/>',
  high: '<path d="M12 3l10 18H2z" fill="currentColor" stroke="none"/><path d="M12 10v5M12 18v.4" stroke="#fff" stroke-width="2.4"/>',
  medium: '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M12 7v6M12 16.5v.5" stroke="#111" stroke-width="2.4"/>',
  low: '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M12 11v6M12 7.5v.4" stroke="#fff" stroke-width="2.4"/>',
};
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const SEV_VAR = { critical: '--crit', high: '--high', medium: '--med', low: '--low' };
const sevBadge = (sev, n) => `<span class="sev ${sev}">${SVGI(SEV_ICON[sev], 14)}${SEV_LABEL[sev]}${n !== undefined ? ' <span class="n">' + n + '</span>' : ''}</span>`;
const ROLE_CLS = { 'At-risk host': 'r-compromised', 'Malware host': 'r-c2', 'Attacker': 'r-attacker', 'Botnet / spoofed': 'r-botnet', 'Rogue insider': 'r-insider', 'C2 server': 'r-c2', 'Compromised host': 'r-compromised', 'Victim': 'r-victim' };

const S = { cap: null, A: null, idx: null, idxNT: null, view: 'overview', sel: -1, tl: 'bytes', pm: 'p', hidden: new Set(), chips: { time: null, host: null, proto: null, ev: null }, expr: '', fn: null, dirty: {}, tsel: null, stage: null, sevF: null, colorOf: new Map(), order: [], roles: new Map(), openLayers: new Set(), graph: null };

/* ---------- helpers ---------- */
function tip(html, ev) { const t = $('#tooltip'); t.innerHTML = html; t.classList.add('on'); const w = t.offsetWidth, h = t.offsetHeight; let x = ev.clientX + 14, y = ev.clientY + 14; if (x + w > innerWidth - 8) x = ev.clientX - w - 14; if (y + h > innerHeight - 8) y = ev.clientY - h - 14; t.style.left = x + 'px'; t.style.top = y + 'px'; }
function untip() { $('#tooltip').classList.remove('on'); }
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('on'), 5000); }
function col(proto) { return S.colorOf.get(proto) || 'var(--s0)'; }
function relT(t) { return t - S.cap.t0; }
function fmtRel(s, span) { if (span < 2) return (s * 1000).toFixed(0) + 'ms'; if (span < 180) return (+s.toFixed(1)) + 's'; if (span < 7200) { const m = Math.floor(s / 60), x = Math.floor(s % 60); return m + ':' + String(x).padStart(2, '0'); } const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60); return h + 'h' + String(m).padStart(2, '0'); }
function clock(t) { const d = new Date(t * 1000); return d.toLocaleTimeString([], { hour12: false }) + '.' + String(Math.floor((t % 1) * 1000)).padStart(3, '0'); }
function niceStep(span, n) { const raw = span / n; const p = Math.pow(10, Math.floor(Math.log10(raw))); const f = raw / p; return (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * p; }
function protoPill(p) { return `<span class="pp"><i style="background:${col(p)}"></i>${esc(p)}</span>`; }
function techUrl(t) { return 'https://attack.mitre.org/techniques/' + t.replace('.', '/') + '/'; }
function hostRole(ip) { return S.roles.get(ip); }
function roleTag(ip) { const r = hostRole(ip); return r && ROLE_CLS[r] ? `<span class="role ${ROLE_CLS[r]}">${esc(r)}</span>` : ''; }

/* ---------- theme ---------- */
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('pl-theme', t); } catch (e) {}
  $('#themeBtn').innerHTML = SVGI(t === 'dark' ? IC.sun : IC.moon);
  if (S.cap) { S.dirty = { overview: 1, conversations: 1, insights: 1, threats: 1, packets: 1, artifacts: 1 }; render(); drawStrip(); if (S.graph) S.graph.kick(); }
  drawSpecimen();
}
(function initTheme() { let t = null; try { t = localStorage.getItem('pl-theme'); } catch (e) {} if (!t) t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'; setTheme(t); })();

/* ---------- loading ---------- */
async function readFile(f) {
  let u8 = new Uint8Array(await f.arrayBuffer());
  if (u8[0] === 0x1f && u8[1] === 0x8b) u8 = await gunzip(u8);
  return u8;
}
async function gunzip(u8) { const ds = new DecompressionStream('gzip'); const out = new Response(new Blob([u8]).stream().pipeThrough(ds)); return new Uint8Array(await out.arrayBuffer()); }
async function analyze(u8, name) {
  const L = $('#loading'); L.classList.add('on'); $('#lbar').style.width = '0%'; $('#ltitle').textContent = 'Analyzing ' + name; $('#ltext').textContent = 'Reading packets…';
  await new Promise(r => setTimeout(r, 30));
  try {
    const cap = await loadCapture(u8, name, (f, n) => { $('#lbar').style.width = (f * 92).toFixed(1) + '%'; $('#ltext').textContent = fmtNum(n) + ' packets decoded'; });
    $('#ltext').textContent = 'Detecting threats & building flows…'; $('#lbar').style.width = '100%';
    await new Promise(r => setTimeout(r, 20));
    setCapture(cap);
  } catch (e) { console.error(e); toast(e.message || String(e)); }
  L.classList.remove('on');
}
async function openFile(f) { if (!f) return; try { await analyze(await readFile(f), f.name); } catch (e) { toast('Could not read file: ' + e.message); } }
async function loadDemo() {
  if (S.demoCap) { setCapture(S.demoCap); return; }
  const b64 = $('#demo-data').textContent.trim();
  const bin = atob(b64); const u8 = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  await analyze(await gunzip(u8), 'attack_scenario.pcap');
}

function setCapture(cap) {
  S.cap = cap; S.sel = -1; S.hidden.clear(); S.tsel = null; S.stage = null; S.sevF = null; S.openLayers = new Set();
  S.chips = { time: null, host: null, proto: null, ev: null }; S.expr = ''; S.fn = null; $('#fin').value = '';
  // protocol colours: top 7 by packets get fixed slots for this capture
  const A = aggregate(cap, null);
  S.order = [...A.protos.values()].sort((a, b) => b.p - a.p).map(p => p.name);
  S.colorOf = new Map(); S.order.slice(0, 7).forEach((p, i) => S.colorOf.set(p, `var(--s${i + 1})`));
  // per-packet threat severity
  cap.pkSev = new Uint8Array(cap.pk.length); cap.pkDet = new Map();
  cap.threats.forEach(d => d.ev.forEach(i => { const r = SEV_RANK[d.sev]; if (r > cap.pkSev[i]) { cap.pkSev[i] = r; cap.pkDet.set(i, d.id); } }));
  S.art.urls.forEach(u => URL.revokeObjectURL(u)); S.art.urls.clear(); S.art.sel = null; S.art.reveal.clear(); S.art.revealAll = false;
  { const ab = $('#abadge'); ab.textContent = cap.art ? ab.textContent : '…'; ab.classList.add('ok'); }
  S.dirty = {}; setTimeout(ensureArt, 60);
  S.roles = new Map(); if (cap.flow) cap.flow.lanes.forEach(l => S.roles.set(l.id, l.role));
  $('#landing').classList.remove('on');
  ['#filemeta', '#tabs', '#filterbar', '#openBtn2', '#strip'].forEach(s => $(s).classList.remove('hidden'));
  $('#filemeta').innerHTML = `<span class="fname" title="${esc(cap.name)}">${esc(cap.name)}</span><span class="pill">${fmtNum(cap.pk.length)} packets, ${fmtBytes(cap.size)}, ${fmtDur(cap.dur)}</span>`;
  const n = cap.threats.length, crit = cap.threats.filter(d => d.sev === 'critical').length;
  const b = $('#tbadge'); b.textContent = n; b.className = 'badge' + (n ? '' : ' ok'); b.style.background = n && !crit ? 'var(--high)' : '';
  const h = location.hash.slice(1);
  S.view = ['overview', 'threats', 'conversations', 'packets', 'artifacts', 'insights'].includes(h) ? h : 'overview';
  $$('.view').forEach(x => x.classList.toggle('on', x.id === 'view-' + S.view));
  applyFilter();
  go(S.view);
}

/* ---------- routing ---------- */
function go(v) { if (location.hash.slice(1) !== v) { try { history.replaceState(null, '', '#' + v); } catch (e) { location.hash = v; } } route(v); }
function route(v) {
  if (!S.cap) return;
  S.view = v;
  $$('.tab').forEach(t => t.classList.toggle('on', t.dataset.view === v));
  $$('.view').forEach(x => x.classList.toggle('on', x.id === 'view-' + v));
  const noFilter = v === 'threats' || v === 'artifacts';
  $('#filterbar').style.display = $('#strip').style.display = noFilter ? 'none' : '';
  if (!noFilter) requestAnimationFrame(drawStrip);
  if (S.graph) S.graph.active = v === 'conversations';
  render();
  if (v === 'conversations' && S.graph) S.graph.kick();
}
window.addEventListener('hashchange', () => { const h = location.hash.slice(1); if (h && h !== S.view) route(h); });
function render() {
  const v = S.view;
  if (!S.dirty[v]) return;
  S.dirty[v] = 0;
  ({ overview: renderOverview, threats: renderThreats, conversations: renderConversations, packets: renderPackets, artifacts: renderArtifacts, insights: renderInsights })[v]();
}

/* ---------- filtering ---------- */
function ipInt(ip) { const p = ip.split('.'); if (p.length !== 4) return null; return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3]; }
function cmpFn(op, v) {
  const n = parseFloat(v);
  switch (op) { case '>': return x => x > n; case '<': return x => x < n; case '>=': return x => x >= n; case '<=': return x => x <= n; default: return x => x === n; }
}
const FLAG = { syn: s => (s.fl & 2) && !(s.fl & 16), synack: s => (s.fl & 18) === 18, rst: s => s.fl & 4, fin: s => s.fl & 1, psh: s => s.fl & 8, ack: s => s.fl & 16, urg: s => s.fl & 32 };
function hostMatch(v) {
  if (v.includes('/')) { const [b, m] = v.split('/'); const bi = ipInt(b), mm = +m; if (bi !== null && mm >= 0 && mm <= 32) { const mask = mm === 0 ? 0 : (0xffffffff << (32 - mm)) >>> 0; const net = (bi & mask) >>> 0; return ip => { const x = ipInt(ip); return x !== null && ((x & mask) >>> 0) === net; }; } }
  if (v.endsWith('*') || v.endsWith('.')) { const p = v.replace(/\*$/, ''); return ip => ip.startsWith(p); }
  return ip => ip === v;
}
function keyTerm(k, op, v) {
  const lv = v.toLowerCase(), num = op === '>' || op === '<' || op === '>=' || op === '<=';
  const c = cmpFn(op, v);
  const inc = (x) => (x || '').toLowerCase().includes(lv);
  switch (k) {
    case 'ip': case 'host': case 'addr': case 'ip.addr': case 'ipv6.addr': { const h = hostMatch(v); return r => h(r.s.src) || h(r.s.dst); }
    case 'src': case 'ip.src': { const h = hostMatch(v); return r => h(r.s.src); }
    case 'dst': case 'ip.dst': { const h = hostMatch(v); return r => h(r.s.dst); }
    case 'mac': case 'eth.addr': return r => r.s.smac === lv || r.s.dmac === lv;
    case 'port': case 'tcp.port': case 'udp.port': return r => r.s.sp >= 0 && (c(r.s.sp) || c(r.s.dp));
    case 'sport': case 'srcport': case 'tcp.srcport': case 'udp.srcport': return r => r.s.sp >= 0 && c(r.s.sp);
    case 'dport': case 'dstport': case 'tcp.dstport': case 'udp.dstport': return r => r.s.dp >= 0 && c(r.s.dp);
    case 'proto': case 'protocol': return r => r.s.proto.toLowerCase() === lv || r.s.l4.toLowerCase() === lv;
    case 'len': case 'size': case 'frame.len': return r => c(r.len);
    case 'frame': case 'no': case 'frame.number': return r => c(r.i + 1);
    case 'ttl': case 'ip.ttl': return r => r.s.ttl !== undefined && c(r.s.ttl);
    case 'stream': case 'tcp.stream': case 'udp.stream': return r => r.s.st === +v;
    case 'time': case 't': case 'frame.time_relative': return r => c(r.t - S.cap.t0);
    case 'sni': case 'tls.sni': return r => inc(r.s.sni);
    case 'dns': case 'domain': case 'dns.qry.name': return r => !!r.s.dns && r.s.dns.qs.some(q => q.name.toLowerCase().includes(lv));
    case 'http': case 'http.uri': return r => !!r.s.http && inc(r.s.http.uri || r.s.http.line);
    case 'http.host': return r => !!r.s.http && inc(r.s.http.host);
    case 'http.ua': case 'ua': return r => !!r.s.http && inc(r.s.http.ua);
    case 'status': case 'http.status': return r => !!r.s.http && r.s.http.resp && c(r.s.http.status);
    case 'flags': case 'tcp.flags': { const f = FLAG[lv]; return f ? r => r.s.l4 === 'TCP' && !!f(r.s) : () => false; }
    case 'info': return r => inc(r.s.info);
    case 'vlan': return r => r.s.vlan === +v;
    default: { const needle = (k + ':' + v).toLowerCase(); return r => r.s.info.toLowerCase().includes(needle); }
  }
  void num;
}
function bareTerm(t) {
  const l = t.toLowerCase();
  if (FLAG[l]) return r => r.s.l4 === 'TCP' && !!FLAG[l](r.s);
  if (l === 'threat' || l === 'threats') return r => S.cap.pkSev[r.i] > 0;
  if (l === 'ip' || l === 'ipv4') return r => r.s.ipv === 4;
  if (l === 'ipv6') return r => r.s.ipv === 6;
  if (l === 'malformed') return r => !!r.s.malformed;
  const protos = new Set(S.order.map(p => p.toLowerCase()).concat(['tcp', 'udp', 'icmp', 'icmpv6', 'arp', 'dns', 'http', 'tls', 'quic', 'ssh', 'dhcp', 'ntp', 'ftp', 'smb', 'rdp', 'telnet']));
  if (protos.has(l)) return r => r.s.proto.toLowerCase() === l || r.s.l4.toLowerCase() === l;
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?\*?$/.test(t) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(t) && t.split(':').length > 2) { const h = hostMatch(t); return r => h(r.s.src) || h(r.s.dst); }
  if (/^\d+$/.test(t)) { const n = +t; return r => r.s.sp === n || r.s.dp === n; }
  return r => r.s.info.toLowerCase().includes(l) || r.s.src.toLowerCase().includes(l) || r.s.dst.toLowerCase().includes(l) || r.s.proto.toLowerCase() === l;
}
function compileFilter(expr) {
  const toks = expr.match(/"[^"]*"|\S+/g) || [];
  const groups = [[]];
  for (let t of toks) {
    const l = t.toLowerCase();
    if (l === 'or' || l === '||') { groups.push([]); continue; }
    if (l === 'and' || l === '&&') continue;
    let neg = false;
    if ((t[0] === '!' || t[0] === '-') && t.length > 1) { neg = true; t = t.slice(1); }
    if (l.startsWith('not') && t.length === 3) continue;
    t = t.replace(/^"|"$/g, '');
    const m = t.match(/^([a-z][a-z0-9_.]*)\s*(==|!=|>=|<=|=|:|>|<)\s*(.+)$/i);
    let f;
    if (m) { f = keyTerm(m[1].toLowerCase(), m[2], m[3].replace(/^"|"$/g, '')); if (m[2] === '!=') { const g = f; f = r => !g(r); } }
    else f = bareTerm(t);
    groups[groups.length - 1].push(neg ? (g => r => !g(r))(f) : f);
  }
  const gs = groups.filter(g => g.length);
  if (!gs.length) return null;
  return r => gs.some(g => g.every(f => f(r)));
}
function applyFilter() {
  const cap = S.cap, C = S.chips;
  const preds = [];
  if (S.fn) preds.push(S.fn);
  if (C.host) { const h = C.host.v; preds.push(r => r.s.src === h || r.s.dst === h); }
  if (C.proto) { const p = C.proto.v; preds.push(r => r.s.proto === p); }
  if (C.ev) { const set = C.ev.set; preds.push(r => set.has(r.i)); }
  let idxNT = null;
  if (preds.length) { const out = []; for (const r of cap.pk) { let ok = true; for (const p of preds) if (!p(r)) { ok = false; break; } if (ok) out.push(r.i); } idxNT = out; }
  let idx = idxNT;
  if (C.time) { const a = cap.t0 + C.time.a, b = cap.t0 + C.time.b; const base = idxNT || cap.pk.map(r => r.i); idx = base.filter(i => cap.pk[i].t >= a && cap.pk[i].t <= b); }
  S.idxNT = idxNT; S.idx = idx;
  S.A = aggregate(cap, idx);
  const n = idx ? idx.length : cap.pk.length;
  $('#fcount').innerHTML = idx ? `<b>${fmtNum(n)}</b> of ${fmtNum(cap.pk.length)} packets` : `<b>${fmtNum(n)}</b> packets`;
  renderChips();
  drawStrip();
  S.dirty = { overview: 1, conversations: 1, packets: 1, insights: 1, threats: S.dirty.threats ?? 1, artifacts: S.dirty.artifacts ?? 1 };
  if (S.sel >= 0 && idx && !idx.includes(S.sel)) S.sel = -1;
  render();
}
function renderChips() {
  const C = S.chips, out = [];
  if (C.time) out.push(['time', `${SVGI(IC.clock, 12)} ${fmtRel(C.time.a, S.cap.dur)} – ${fmtRel(C.time.b, S.cap.dur)}`]);
  if (C.host) out.push(['host', 'host ' + esc(C.host.v)]);
  if (C.proto) out.push(['proto', 'protocol ' + esc(C.proto.v)]);
  if (C.ev) out.push(['ev', SVGI(IC.shield, 12) + ' ' + esc(C.ev.label)]);
  $('#chips').innerHTML = out.map(([k, h]) => `<span class="chip ${k === 'ev' ? 'ev' : ''}">${h}<button data-chip="${k}" title="Remove">${SVGI(IC.x, 13)}</button></span>`).join('');
}
$('#chips').addEventListener('click', e => { const b = e.target.closest('[data-chip]'); if (!b) return; S.chips[b.dataset.chip] = null; applyFilter(); });
function setChip(k, v) { S.chips[k] = v; applyFilter(); }
let finT;
$('#fin').addEventListener('input', e => {
  clearTimeout(finT);
  finT = setTimeout(() => {
    const v = e.target.value.trim();
    try { S.fn = v ? compileFilter(v) : null; S.expr = v; $('#fx').classList.remove('bad'); applyFilter(); }
    catch (err) { $('#fx').classList.add('bad'); }
  }, 220);
});
$('#fin').addEventListener('keydown', e => { if (e.key === 'Escape') { e.target.value = ''; e.target.dispatchEvent(new Event('input')); e.target.blur(); } });
function setExpr(v) { $('#fin').value = v; S.fn = compileFilter(v); S.expr = v; applyFilter(); }

/* ===================== OVERVIEW ===================== */
function renderOverview() {
  const A = S.A, cap = S.cap, el = $('#view-overview');
  const dur = Math.max(A.t1 - A.t0, 1e-6);
  const D = cap.threats, crit = D.filter(d => d.sev === 'critical').length, high = D.filter(d => d.sev === 'high').length;
  const kpi = (icon, l, v, s) => `<div class="kpi"><div class="l">${SVGI(icon)}${l}</div><div class="v">${v}</div><div class="s">${s}</div></div>`;
  const [bv, bu] = fmtBytes(A.bytes).split(' ');
  const [rv, ru] = fmtBits(A.bytes * 8 / dur).split(' ');
  const internal = [...A.hosts.keys()].filter(h => isIp(h) && isPrivate(h)).length;
  const banner = D.length ? `<div class="tbanner" id="tban"><div class="ic">${SVGI(SEV_ICON.critical, 26)}</div><div><h4>${D.length} security detection${D.length > 1 ? 's' : ''}: ${['critical', 'high', 'medium', 'low'].map(s => [s, D.filter(d => d.sev === s).length]).filter(x => x[1]).map(x => x[1] + ' ' + x[0]).join(', ')}</h4><p>${esc(cap.flow ? cap.flow.story : '')}</p></div><div class="mini">${cap.flow.stages.map(s => `<i title="${esc(s.name)}${s.n ? ': ' + s.n : ': not seen'}" style="${s.n ? 'background:var(' + SEV_VAR[Object.keys(SEV_RANK).find(k => SEV_RANK[k] === s.sev)] + ')' : ''}"></i>`).join('')}<span class="btn sm">Open attack flow</span></div></div>`
    : `<div class="tbanner clean"><div class="ic">${SVGI(IC.check, 22)}</div><div><h4>No threats detected</h4><p>Checked for scans, brute force, web exploits, shells, beaconing, tunneling, exfiltration, spoofing and floods.</p></div></div>`;
  el.innerHTML = `
  <div class="kpis">
    ${kpi(IC.pk, 'Packets', fmtNum(A.n), (A.n / dur).toFixed(A.n / dur < 10 ? 1 : 0) + ' packets/s avg')}
    ${kpi(IC.data, 'Data', bv + '<small>' + bu + '</small>', 'avg ' + Math.round(A.bytes / Math.max(A.n, 1)) + ' B per packet')}
    ${kpi(IC.clock, 'Duration', fmtDur(dur).replace(/ (\w+)$/, '<small>$1</small>'), clock(A.t0).slice(0, 8) + ' to ' + clock(A.t1).slice(0, 8))}
    ${kpi(IC.speed, 'Avg throughput', rv + '<small>' + ru + '</small>', 'average over the window')}
    ${kpi(IC.hosts, 'Hosts', fmtNum(A.hosts.size), internal + ' local, ' + (A.hosts.size - internal) + ' other')}
    ${kpi(IC.flows, 'Flows', fmtNum(A.streams.size), fmtNum(A.pairs.size) + ' host pairs')}
  </div>
  <div style="margin-top:16px">${banner}</div>
  <div class="grid" style="margin-top:16px">
    <div class="card c12"><div class="card-h"><h3>Traffic over time</h3><span class="sub" id="tlsub"></span><span class="sp"></span><span class="hint">Drag across the chart to filter by time. Double-click to clear.</span><div class="seg" id="tlseg"><button data-m="bytes">Throughput</button><button data-m="pkts">Packets/s</button></div></div>
      <div class="legend" id="tlleg"></div><div class="card-b"><div class="chart" id="tl"></div></div></div>
    <div class="card c6"><div class="card-h"><h3>Protocols</h3><span class="sub">${A.protos.size} detected</span><span class="sp"></span><div class="seg" id="pmseg"><button data-m="p">Packets</button><button data-m="b">Bytes</button></div></div><div class="card-b"><div class="bars" id="protobars"></div></div></div>
    <div class="card c6"><div class="card-h"><h3>Top talkers</h3><span class="sp"></span><span class="lg" style="cursor:default"><i style="background:var(--s1)"></i>Sent</span><span class="lg" style="cursor:default"><i style="background:var(--s2)"></i>Received</span></div><div class="card-b"><div class="bars" id="talkbars"></div></div></div>
    <div class="card c4"><div class="card-h"><h3>Services</h3><span class="sub">by server port</span></div><div class="card-b"><div class="bars" id="portbars"></div></div></div>
    <div class="card c4"><div class="card-h"><h3>Packet sizes</h3><span class="sub">bytes on the wire</span></div><div class="card-b"><div class="chart" id="sizes"></div></div></div>
    <div class="card c4"><div class="card-h"><h3>TCP control flags</h3><span class="sub">packets</span></div><div class="card-b"><div class="bars" id="flagbars"></div></div></div>
  </div>`;
  if (D.length) $('#tban').onclick = () => go('threats');
  $$('#tlseg button').forEach(b => { b.classList.toggle('on', b.dataset.m === S.tl); b.onclick = () => { S.tl = b.dataset.m; $$('#tlseg button').forEach(x => x.classList.toggle('on', x === b)); drawTimeline(); }; });
  $$('#pmseg button').forEach(b => { b.classList.toggle('on', b.dataset.m === S.pm); b.onclick = () => { S.pm = b.dataset.m; $$('#pmseg button').forEach(x => x.classList.toggle('on', x === b)); drawProtoBars(); }; });
  drawTimeline(); drawProtoBars(); drawTalkers(); drawPorts(); drawSizes(); drawFlags();
}

function barRow({ name, swatch, segs, max, value, sub, attr, extra }) {
  const segHtml = segs.map(s => `<b style="width:${Math.max(0, s.v / max * 100)}%;background:${s.c}" ${s.t ? `data-t="${esc(s.t)}"` : ''}></b>`).join('');
  return `<div class="bar${extra && extra.wide ? ' wide' : ''}" ${attr || ''}><div class="nm">${swatch ? `<i style="background:${swatch}"></i>` : ''}<span title="${esc(name)}" class="${extra && extra.mono ? 'mono' : ''}">${esc(name)}</span>${extra && extra.tag ? extra.tag : ''}</div><div class="tr">${segHtml}</div><div class="vl">${value}${sub ? `<em>${sub}</em>` : ''}</div></div>`;
}
function drawProtoBars() {
  const A = S.A, key = S.pm;
  const rows = [...A.protos.values()].sort((a, b) => b[key] - a[key]);
  const tot = key === 'p' ? A.n : A.bytes, max = rows.length ? rows[0][key] : 1;
  const top = rows.slice(0, 11), rest = rows.slice(11);
  let html = top.map(r => barRow({ name: r.name, swatch: col(r.name), segs: [{ v: r[key], c: col(r.name) }], max, value: key === 'p' ? fmtNum(r.p) : fmtBytes(r.b), sub: (r[key] / tot * 100).toFixed(1) + '%', attr: `data-proto="${esc(r.name)}"` })).join('');
  if (rest.length) { const v = rest.reduce((a, r) => a + r[key], 0); html += barRow({ name: rest.length + ' more', swatch: 'var(--s0)', segs: [{ v, c: 'var(--s0)' }], max, value: key === 'p' ? fmtNum(v) : fmtBytes(v), sub: (v / tot * 100).toFixed(1) + '%' }); }
  $('#protobars').innerHTML = html || '<div class="empty">No packets</div>';
  $$('#protobars [data-proto]').forEach(b => b.onclick = () => setChip('proto', { v: b.dataset.proto }));
}
function drawTalkers() {
  const rows = [...S.A.hosts.values()].sort((a, b) => (b.tx + b.rx) - (a.tx + a.rx)).slice(0, 10);
  const max = rows.length ? rows[0].tx + rows[0].rx : 1;
  $('#talkbars').innerHTML = rows.map(h => barRow({ name: h.ip, segs: [{ v: h.tx, c: 'var(--s1)', t: 'Sent ' + fmtBytes(h.tx) }, { v: h.rx, c: 'var(--s2)', t: 'Received ' + fmtBytes(h.rx) }], max, value: fmtBytes(h.tx + h.rx), attr: `data-host="${esc(h.ip)}"`, extra: { mono: 1, wide: 1, tag: roleTag(h.ip) } })).join('') || '<div class="empty">No IP traffic</div>';
  $$('#talkbars [data-host]').forEach(b => {
    b.onclick = () => setChip('host', { v: b.dataset.host });
    b.onmousemove = e => { const h = S.A.hosts.get(b.dataset.host); tip(`<div class="tt-h mono">${esc(h.ip)}</div><div class="tt-r"><span><i style="background:var(--s1)"></i>Sent</span><b>${fmtBytes(h.tx)} · ${fmtNum(h.ptx)} pkts</b></div><div class="tt-r"><span><i style="background:var(--s2)"></i>Received</span><b>${fmtBytes(h.rx)} · ${fmtNum(h.prx)} pkts</b></div>${hostRole(h.ip) ? `<div class="tt-r"><span>Role in attack</span><b>${esc(hostRole(h.ip))}</b></div>` : ''}`, e); };
    b.onmouseleave = untip;
  });
}
function drawPorts() {
  const rows = [...S.A.ports.values()].sort((a, b) => b.p - a.p).slice(0, 8);
  const max = rows.length ? rows[0].p : 1;
  $('#portbars').innerHTML = rows.map(p => barRow({ name: (p.name ? p.name + ' ' : '') + p.port + '/' + p.l4.toLowerCase(), segs: [{ v: p.p, c: 'var(--s1)' }], max, value: fmtNum(p.p), sub: fmtBytes(p.b), attr: `data-port="${p.port}"` })).join('') || '<div class="empty">No TCP/UDP traffic</div>';
  $$('#portbars [data-port]').forEach(b => b.onclick = () => setExpr(('port:' + b.dataset.port)));
}
function drawFlags() {
  let syn = 0, sa = 0, rst = 0, fin = 0, psh = 0, tot = 0;
  const pk = S.cap.pk, idx = S.idx, n = idx ? idx.length : pk.length;
  for (let k = 0; k < n; k++) { const s = pk[idx ? idx[k] : k].s; if (s.l4 !== 'TCP' || s.sp < 0) continue; tot++; const f = s.fl; if ((f & 18) === 2) syn++; else if ((f & 18) === 18) sa++; if (f & 4) rst++; if (f & 1) fin++; if (f & 8) psh++; }
  const rows = [['SYN', syn, 'syn'], ['SYN-ACK', sa, 'synack'], ['RST', rst, 'rst'], ['FIN', fin, 'fin'], ['PSH', psh, 'psh']];
  const max = Math.max(1, ...rows.map(r => r[1]));
  $('#flagbars').innerHTML = rows.map(r => barRow({ name: r[0], segs: [{ v: r[1], c: 'var(--s1)' }], max, value: fmtNum(r[1]), sub: tot ? (r[1] / tot * 100).toFixed(1) + '%' : '', attr: `data-flag="${r[2]}"` })).join('') + (syn > 3 * Math.max(sa, 1) && syn > 50 ? `<p class="hint" style="margin:8px 8px 0">SYNs far outnumber SYN-ACKs, a sign of scanning or a SYN flood.</p>` : '');
  $$('#flagbars [data-flag]').forEach(b => b.onclick = () => setExpr(b.dataset.flag));
}
function drawSizes() {
  const el = $('#sizes'), W = el.clientWidth || 400, H = 190, m = { l: 40, r: 6, t: 10, b: 26 };
  const labels = ['≤64', '65–128', '129–256', '257–512', '513–1K', '1K–1518', '>1518'];
  const v = S.A.sizes, max = Math.max(1, ...v), iw = W - m.l - m.r, ih = H - m.t - m.b, bw = iw / v.length;
  const step = niceStep(max, 3), ticks = []; for (let t = 0; t <= max * 1.001; t += step) ticks.push(t);
  const ymax = Math.max(max, ticks[ticks.length - 1]);
  const y = x => m.t + ih - x / ymax * ih;
  let s = `<svg viewBox="0 0 ${W} ${H}" height="${H}">`;
  ticks.forEach(t => s += `<line x1="${m.l}" x2="${W - m.r}" y1="${y(t)}" y2="${y(t)}" stroke="var(--grid)"/><text x="${m.l - 8}" y="${y(t) + 4}" text-anchor="end">${t >= 1000 ? (t / 1000) + 'k' : t}</text>`);
  v.forEach((c, i) => { const x = m.l + i * bw + 3, h = Math.max(c ? 2 : 0, ih - (y(c) - m.t)); s += `<path data-i="${i}" d="M${x},${m.t + ih} v${-Math.max(0, h - 4)} q0,-4 4,-4 h${bw - 14} q4,0 4,4 v${Math.max(0, h - 4)} z" fill="var(--s1)" class="szb"/><text x="${x + (bw - 6) / 2}" y="${H - 8}" text-anchor="middle">${labels[i]}</text>`; });
  s += `<line x1="${m.l}" x2="${W - m.r}" y1="${m.t + ih}" y2="${m.t + ih}" stroke="var(--axis)"/></svg>`;
  el.innerHTML = s;
  $$('.szb', el).forEach(p => { p.onmousemove = e => { const i = +p.dataset.i; tip(`<div class="tt-h">${labels[i]} bytes</div><div class="tt-r"><span>Packets</span><b>${fmtNum(v[i])}</b></div><div class="tt-r"><span>Share</span><b>${(v[i] / Math.max(S.A.n, 1) * 100).toFixed(1)}%</b></div>`, e); }; p.onmouseleave = untip; });
}

function drawTimeline() {
  const el = $('#tl'); if (!el) return;
  const cap = S.cap, pk = cap.pk, idx = S.idxNT, n = idx ? idx.length : pk.length;
  const W = el.clientWidth || 900, H = 230, m = { l: 58, r: 12, t: 18, b: 26 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const span = cap.dur, nb = Math.max(30, Math.min(240, Math.floor(iw / 5))), bw = span / nb;
  const keys = S.order.slice(0, 7); const other = S.order.length > 7;
  const series = keys.concat(other ? ['Other'] : []);
  const ki = new Map(keys.map((k, i) => [k, i]));
  const M = series.map(() => new Float64Array(nb));
  for (let k = 0; k < n; k++) { const r = pk[idx ? idx[k] : k]; let b = Math.floor((r.t - cap.t0) / bw); if (b >= nb) b = nb - 1; const si = ki.has(r.s.proto) ? ki.get(r.s.proto) : series.length - 1; M[si][b] += S.tl === 'bytes' ? r.len * 8 : 1; }
  const per = 1 / Math.max(bw, 1e-9);
  const vis = series.map((s, i) => !S.hidden.has(s));
  const tot = new Float64Array(nb); for (let b = 0; b < nb; b++) for (let i = 0; i < series.length; i++) if (vis[i]) tot[b] += M[i][b] * per;
  const peak = Math.max(1e-9, ...tot);
  const fmtV = v => S.tl === 'bytes' ? fmtBits(v) : (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + '/s';
  $('#tlsub').textContent = 'Peak ' + fmtV(peak) + ', ' + fmtDur(bw) + ' per column';
  const step = niceStep(peak, 4), ticks = []; for (let t = 0; t <= peak * 1.0001 + step * 0.01; t += step) ticks.push(t); if (ticks[ticks.length - 1] < peak) ticks.push(ticks[ticks.length - 1] + step);
  const ymax = ticks[ticks.length - 1];
  const X = t => m.l + t / span * iw, Y = v => m.t + ih - v / ymax * ih;
  let s = `<svg viewBox="0 0 ${W} ${H}" height="${H}">`;
  ticks.forEach(t => s += `<line x1="${m.l}" x2="${W - m.r}" y1="${Y(t)}" y2="${Y(t)}" stroke="var(--grid)"/><text x="${m.l - 8}" y="${Y(t) + 4}" text-anchor="end">${S.tl === 'bytes' ? fmtBits(t).replace('bps', '') : t >= 1000 ? (t / 1000).toFixed(t % 1000 ? 1 : 0) + 'k' : +t.toFixed(2)}</text>`);
  const xs = niceStep(span, Math.max(3, Math.floor(iw / 110)));
  for (let t = 0; t <= span + 1e-9; t += xs) s += `<text x="${X(t)}" y="${H - 6}" text-anchor="middle">${fmtRel(t, span)}</text><line x1="${X(t)}" x2="${X(t)}" y1="${m.t + ih}" y2="${m.t + ih + 4}" stroke="var(--axis)"/>`;
  // stacked areas
  const base = new Float64Array(nb);
  const cx = b => m.l + (b + 0.5) / nb * iw;
  series.forEach((name, i) => {
    if (!vis[i]) return;
    const top = new Float64Array(nb); for (let b = 0; b < nb; b++) top[b] = base[b] + M[i][b] * per;
    let d = `M${m.l},${Y(base[0])} L${m.l},${Y(top[0])}`;
    for (let b = 0; b < nb; b++) d += ` L${cx(b)},${Y(top[b])}`;
    d += ` L${m.l + iw},${Y(top[nb - 1])} L${m.l + iw},${Y(base[nb - 1])}`;
    for (let b = nb - 1; b >= 0; b--) d += ` L${cx(b)},${Y(base[b])}`;
    const c = name === 'Other' ? 'var(--s0)' : col(name);
    s += `<path d="${d}Z" fill="${c}" fill-opacity=".88" stroke="var(--panel)" stroke-width="1" stroke-linejoin="round"/>`;
    base.set(top);
  });
  s += `<line x1="${m.l}" x2="${W - m.r}" y1="${m.t + ih}" y2="${m.t + ih}" stroke="var(--axis)"/>`;
  // threat markers
  cap.threats.forEach(d => { const x = X(d.t0 - cap.t0); s += `<g class="tmark" data-d="${d.id}" style="cursor:pointer"><line x1="${x}" x2="${x}" y1="${m.t - 2}" y2="${m.t + ih}" stroke="var(${SEV_VAR[d.sev]})" stroke-opacity=".35" stroke-dasharray="2 3"/><path d="M${x - 5},${m.t - 12} h10 l-5,7z" fill="var(${SEV_VAR[d.sev]})" stroke="var(--panel)" stroke-width="1"/></g>`; });
  if (S.chips.time) { const a = X(S.chips.time.a), b = X(S.chips.time.b); s += `<rect class="brush" x="${a}" y="${m.t}" width="${Math.max(1, b - a)}" height="${ih}" rx="3"/>`; }
  s += `<line class="xh" id="tlx" x1="0" x2="0" y1="${m.t}" y2="${m.t + ih}" style="display:none"/><rect id="tlbr" class="brush" y="${m.t}" height="${ih}" width="0" style="display:none"/><rect id="tlov" x="${m.l}" y="${m.t}" width="${iw}" height="${ih}" fill="transparent" style="cursor:crosshair"/></svg>`;
  el.innerHTML = s;
  // legend
  $('#tlleg').innerHTML = series.map((nm, i) => `<button class="lg ${vis[i] ? '' : 'off'}" data-s="${esc(nm)}"><i style="background:${nm === 'Other' ? 'var(--s0)' : col(nm)}"></i>${esc(nm === 'Other' ? 'Other (' + (S.order.length - 7) + ')' : nm)}</button>`).join('');
  $$('#tlleg .lg').forEach(b => b.onclick = () => { const k = b.dataset.s; S.hidden.has(k) ? S.hidden.delete(k) : S.hidden.add(k); drawTimeline(); });
  // interactions
  const svg = $('svg', el), ov = $('#tlov'), xh = $('#tlx'), br = $('#tlbr');
  const toLocal = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) * (W / r.width); };
  let drag = null;
  ov.onmousemove = e => {
    const x = Math.max(m.l, Math.min(m.l + iw, toLocal(e)));
    if (drag !== null) { br.setAttribute('x', Math.min(drag, x)); br.setAttribute('width', Math.abs(x - drag)); br.style.display = ''; untip(); return; }
    const b = Math.min(nb - 1, Math.max(0, Math.floor((x - m.l) / iw * nb)));
    xh.setAttribute('x1', cx(b)); xh.setAttribute('x2', cx(b)); xh.style.display = '';
    let rows = series.map((nm, i) => ({ nm, v: M[i][b] * per, i })).filter(r => vis[r.i] && r.v > 0).sort((a, z) => z.v - a.v);
    tip(`<div class="tt-h">+${fmtRel(b * bw, span)} – ${fmtRel((b + 1) * bw, span)} <span class="hint">${clock(cap.t0 + b * bw)}</span></div>` + (rows.length ? rows.slice(0, 8).map(r => `<div class="tt-r"><span><i style="background:${r.nm === 'Other' ? 'var(--s0)' : col(r.nm)}"></i>${esc(r.nm)}</span><b>${fmtV(r.v)}</b></div>`).join('') + `<div class="tt-r" style="border-top:1px solid var(--line);margin-top:4px;padding-top:4px"><span>Total</span><b>${fmtV(tot[b])}</b></div>` : '<div class="tt-r">No traffic</div>'), e);
  };
  ov.onmouseleave = () => { xh.style.display = 'none'; untip(); };
  ov.onmousedown = e => { drag = Math.max(m.l, Math.min(m.l + iw, toLocal(e))); e.preventDefault(); };
  const up = e => {
    if (drag === null) return;
    const x = Math.max(m.l, Math.min(m.l + iw, toLocal(e))); const a = Math.min(drag, x), b = Math.max(drag, x); drag = null; br.style.display = 'none';
    if (b - a > 4) setChip('time', { a: (a - m.l) / iw * span, b: (b - m.l) / iw * span });
  };
  window.addEventListener('mouseup', up, { once: true });
  ov.addEventListener('mousedown', () => window.addEventListener('mouseup', up, { once: true }));
  ov.ondblclick = () => { if (S.chips.time) setChip('time', null); };
  $$('.tmark', el).forEach(g => { const d = cap.threats[+g.dataset.d]; g.onmousemove = e => tip(`<div class="tt-h">${esc(d.title)}</div><div class="tt-r"><span>${sevBadge(d.sev)}</span><b>+${fmtRel(d.t0 - cap.t0, span)}</b></div><div class="tt-r"><span class="mono">${esc(d.src)} → ${esc(d.dst)}</span></div><div class="hint" style="margin-top:4px">Click to open in attack flow</div>`, e); g.onmouseleave = untip; g.onclick = () => { S.tsel = d.id; S.dirty.threats = 1; go('threats'); }; });
}

/* ===================== PACKETS ===================== */
const RH = 28;
function renderPackets() {
  const el = $('#view-packets');
  if (!$('#pbody', el)) {
    el.innerHTML = `<div class="pk-wrap">
      <div class="card ptable"><div class="phead"><div>No.</div><div>Time</div><div>Source</div><div>Destination</div><div>Protocol</div><div>Length</div><div>Info</div></div><div class="pbody" id="pbody" tabindex="0"><div id="pspace"></div></div></div>
      <div class="detail"><div class="card"><div class="dhead" id="dhead"></div><div class="tree" id="tree"></div></div><div class="card"><div class="dhead"><h3>Bytes</h3><span class="sub hint" id="hexsub"></span><span style="flex:1"></span><button class="btn sm ghost" id="copyhex">${SVGI(IC.copy, 14)} Copy hex</button></div><div class="hex" id="hex"></div></div></div></div>`;
    const pb = $('#pbody');
    pb.addEventListener('scroll', () => requestAnimationFrame(drawRows));
    pb.addEventListener('click', e => { const r = e.target.closest('.prow'); if (r) selectPacket(+r.dataset.i); });
    pb.addEventListener('keydown', e => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'PageDown' && e.key !== 'PageUp') return;
      e.preventDefault();
      const list = S.idx, n = list ? list.length : S.cap.pk.length; if (!n) return;
      let pos = S.sel < 0 ? -1 : (list ? list.indexOf(S.sel) : S.sel);
      const d = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : e.key === 'PageDown' ? 20 : -20;
      pos = Math.max(0, Math.min(n - 1, pos + d));
      selectPacket(list ? list[pos] : pos, true);
    });
    $('#copyhex').onclick = () => { if (S.sel < 0) return; const b = pkBytes(S.cap, S.sel); const h = [...b].map(h2).join(''); navigator.clipboard.writeText(h).then(() => toast('Copied ' + b.length + ' bytes as hex'), () => toast('Clipboard unavailable')); };
  }
  const n = S.idx ? S.idx.length : S.cap.pk.length;
  $('#pspace').style.height = (n * RH) + 'px';
  drawRows();
  if (S.sel >= 0) showDetail(S.sel); else { $('#dhead').innerHTML = '<h3>Packet details</h3>'; $('#tree').innerHTML = '<div class="empty">Select a packet to inspect its layers</div>'; $('#hex').innerHTML = ''; $('#hexsub').textContent = ''; }
}
function drawRows() {
  const pb = $('#pbody'); if (!pb) return;
  const cap = S.cap, list = S.idx, n = list ? list.length : cap.pk.length;
  const top = pb.scrollTop, h = pb.clientHeight;
  const a = Math.max(0, Math.floor(top / RH) - 8), b = Math.min(n, Math.ceil((top + h) / RH) + 8);
  let html = '';
  const sevName = ['', 'low', 'medium', 'high', 'critical'];
  for (let k = a; k < b; k++) {
    const i = list ? list[k] : k, r = cap.pk[i], s = r.s, sv = cap.pkSev[i];
    html += `<div class="prow${i === S.sel ? ' sel' : ''}${sv ? ' th s-' + sevName[sv] : ''}" data-i="${i}" style="top:${k * RH}px"><div class="num dim">${i + 1}</div><div class="num">${(r.t - cap.t0).toFixed(6)}</div><div class="mono">${esc(s.src)}</div><div class="mono">${esc(s.dst)}</div><div>${protoPill(s.proto)}</div><div class="num">${r.len}</div><div title="${esc(s.info)}">${esc(s.info)}</div></div>`;
  }
  const sp = $('#pspace'); sp.innerHTML = html;
  if (!n) sp.innerHTML = '<div class="empty">No packets match the current filter</div>';
}
function selectPacket(i, scroll) {
  S.sel = i;
  const pb = $('#pbody');
  if (scroll && pb) { const list = S.idx, pos = list ? list.indexOf(i) : i; const y = pos * RH; if (y < pb.scrollTop || y > pb.scrollTop + pb.clientHeight - RH) pb.scrollTop = y - pb.clientHeight / 2; }
  drawRows(); showDetail(i);
}
function showDetail(i) {
  const cap = S.cap, r = cap.pk[i], s = r.s, bytes = pkBytes(cap, i);
  const T = new Tree(); dissect(bytes, r.lt, T);
  const det = cap.pkDet.get(i) !== undefined ? cap.threats[cap.pkDet.get(i)] : null;
  const st = s.st !== undefined ? cap.streams[s.st] : null;
  $('#dhead').innerHTML = `<h3>Frame ${i + 1}</h3><span class="pill">${r.len} bytes on wire${r.cap !== r.len ? ', ' + r.cap + ' captured' : ''}</span><span class="pill">${new Date(r.t * 1000).toISOString().replace('T', ' ').replace('Z', '')} UTC</span>${det ? `<span class="sev ${det.sev}" style="cursor:pointer" id="dthreat">${SVGI(SEV_ICON[det.sev], 14)}${esc(det.title)}</span>` : ''}<span style="flex:1"></span>${st ? `<button class="btn sm" id="dfollow">${SVGI(IC.stream, 14)}Follow ${st.l4} stream</button><button class="btn sm ghost" id="dconv">${SVGI(IC.filter, 14)}Conversation</button>` : ''}`;
  if (det) $('#dthreat').onclick = () => { S.tsel = det.id; S.dirty.threats = 1; go('threats'); };
  if (st) { $('#dfollow').onclick = () => followStream(st.id); $('#dconv').onclick = () => setExpr('stream:' + st.id); }
  const frame = { name: 'Frame ' + (i + 1) + ': ' + r.len + ' bytes on wire, ' + r.cap + ' bytes captured', s: 0, l: bytes.length, f: [{ n: 'Arrival time', v: new Date(r.t * 1000).toISOString(), s: 0, l: 0 }, { n: 'Time since first frame', v: (r.t - cap.t0).toFixed(6) + ' s', s: 0, l: 0 }, { n: 'Frame length', v: r.len + ' bytes', s: 0, l: 0 }, { n: 'Link type', v: r.lt, s: 0, l: 0 }, { n: 'Protocols', v: T.layers.map(l => l.name.split(/[ ,:(]/)[0]).join(' › '), s: 0, l: 0 }] };
  const layers = [frame].concat(T.layers);
  if (!S.openLayers.size) layers.slice(-2).forEach(l => S.openLayers.add(l.name.split(/[,:(]/)[0].trim()));
  $('#tree').innerHTML = layers.map((L, li) => {
    const key = L.name.split(/[,:(]/)[0].trim();
    return `<div class="layer ${S.openLayers.has(key) ? 'open' : ''}" data-k="${esc(key)}" data-s="${L.s}" data-l="${L.l}"><div class="lh">${SVGI(IC.car, 14).replace('<svg', '<svg class="car"')}<span>${esc(L.name)}</span><span class="bl">${li ? L.l + ' B' : ''}</span></div><div class="fs">${L.f.map(f => `<div class="fld d${f.d}" data-s="${f.s}" data-l="${f.l}"><span class="k">${esc(f.n)}</span><span class="v">${esc(f.v)}</span></div>`).join('')}</div></div>`;
  }).join('');
  // hex
  const lim = Math.min(bytes.length, 4096);
  let hx = '';
  for (let o = 0; o < lim; o += 16) {
    hx += `<span class="o">${o.toString(16).padStart(4, '0')}</span>`;
    let a = '';
    for (let j = 0; j < 16; j++) {
      const k = o + j;
      if (j === 8) hx += '<span class="g"></span>';
      if (k < lim) { const b = bytes[k]; hx += `<span class="b${b ? '' : ' z'}" data-i="${k}">${h2(b)}</span>`; a += `<span class="a" data-i="${k}">${b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : '·'}</span>`; }
      else hx += '<span class="b">  </span>';
    }
    hx += `<span class="asc">${a}</span>\n`;
  }
  $('#hex').innerHTML = hx;
  $('#hexsub').textContent = bytes.length > lim ? `showing first ${lim} of ${bytes.length} bytes` : bytes.length + ' bytes';
  const hexEls = $$('#hex [data-i]');
  const byIdx = new Map(); hexEls.forEach(e => { const k = +e.dataset.i; (byIdx.get(k) || byIdx.set(k, []).get(k)).push(e); });
  const clear = cls => $$('#hex .' + cls).forEach(e => e.classList.remove(cls));
  const mark = (s, l, cls) => { clear(cls); for (let k = s; k < s + l; k++) (byIdx.get(k) || []).forEach(e => e.classList.add(cls)); };
  $$('#tree .lh').forEach(h => { h.onclick = () => { const L = h.parentElement; L.classList.toggle('open'); const k = L.dataset.k; L.classList.contains('open') ? S.openLayers.add(k) : S.openLayers.delete(k); }; h.onmouseenter = () => { const L = h.parentElement; mark(+L.dataset.s, +L.dataset.l, 'ly'); }; h.onmouseleave = () => clear('ly'); });
  $$('#tree .fld').forEach(f => { f.onmouseenter = () => mark(+f.dataset.s, +f.dataset.l, 'on'); f.onmouseleave = () => clear('on'); });
  $('#hex').onclick = e => {
    const t = e.target.closest('[data-i]'); if (!t) return; const k = +t.dataset.i;
    let best = null; $$('#tree .fld').forEach(f => { const s0 = +f.dataset.s, l = +f.dataset.l; if (l > 0 && k >= s0 && k < s0 + l && (!best || l < +best.dataset.l)) best = f; });
    $$('#tree .fld.hl').forEach(f => f.classList.remove('hl'));
    if (best) { best.closest('.layer').classList.add('open'); best.classList.add('hl'); best.scrollIntoView({ block: 'nearest' }); mark(+best.dataset.s, +best.dataset.l, 'on'); }
  };
}
function followStream(id) {
  const cap = S.cap, st = cap.streams[id];
  let html = '', total = 0, cur = null, buf = '', cb = 0, sb = 0;
  const flush = () => { if (cur && buf) html += `<span class="${cur} blk">${esc(buf)}</span>`; buf = ''; };
  for (const i of st.pk) {
    const s = cap.pk[i].s; if (!s.pll) continue;
    const d = s.dirA ? 'c' : 's'; if (d === 'c') cb += s.pll; else sb += s.pll;
    if (total > 300000) continue;
    const t = payloadText(cap, i, 65536).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '·');
    total += t.length;
    if (d !== cur) { flush(); cur = d; }
    buf += t;
  }
  flush();
  $('#mtitle').innerHTML = `Follow ${st.l4} stream ${id} <span class="hint mono" style="font-weight:400;margin-left:8px">${esc(st.a)}:${st.ap} ⇄ ${esc(st.b)}:${st.bp}</span>`;
  $('#mbody').innerHTML = `<div class="filt" style="margin-bottom:12px"><span class="lg" style="cursor:default"><i style="background:var(--s1)"></i>Client to server, ${fmtBytes(cb)}</span><span class="lg" style="cursor:default"><i style="background:var(--s2)"></i>Server to client, ${fmtBytes(sb)}</span><span class="pill">${st.pk.length} packets</span><span class="pill">${fmtDur(st.t1 - st.t0)}</span>${st.proto === 'TLS' ? '<span class="pill">Encrypted with TLS, so bytes are shown raw</span>' : ''}${total > 300000 ? '<span class="pill">truncated to 300 KB</span>' : ''}</div><div class="stream">${html || '<div class="empty">This stream carries no payload</div>'}</div>`;
  $('#modal').classList.add('on');
}

/* ===================== CONVERSATIONS ===================== */
function renderConversations() {
  const el = $('#view-conversations'), A = S.A, cap = S.cap;
  el.innerHTML = `<div class="grid">
    <div class="card c8 graphcard"><div class="gtools"><button class="btn sm" id="gfit">${SVGI(IC.reset, 14)}Tidy layout</button></div>
      <div class="gmap" id="gmap"></div>
      <div class="glegend">${[['workstation', 'var(--s1)', 'Workstation'], ['server', 'var(--s3)', 'Server'], ['router', 'var(--teal)', 'Gateway'], ['globe', 'var(--s7)', 'Internet host'], ['cloud', 'var(--s7)', 'Group of hosts']].map(([i, c, l]) => `<span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${MAP_ICON[i]}</svg>${l}</span>`).join('')}<span><svg width="24" height="10"><path d="M1 5h16" stroke="var(--crit)" stroke-width="2"/><path d="M16 1l6 4-6 4z" fill="var(--crit)"/></svg>Attack path, numbered by step</span><span class="hint">Drag boxes to rearrange. Scroll to zoom.</span></div></div>
    <div class="c4 side"><div class="card" id="gside"></div></div>
    <div class="card c12"><div class="card-h"><h3>Flows</h3><span class="sub">${fmtNum(A.streams.size)} TCP and UDP streams, largest 300 shown</span></div><div class="card-b"><div class="scroll" style="max-height:480px"><table class="tbl" id="flowtbl"></table></div></div></div>
  </div>`;
  const flows = [...A.streams].map(i => cap.streams[i]).sort((a, b) => b.bytes - a.bytes).slice(0, 300);
  const flowDet = new Map(); cap.threats.forEach(d => { if (d.stream !== undefined) flowDet.set(d.stream, d); });
  $('#flowtbl').innerHTML = `<thead><tr><th>#</th><th>Client</th><th>Server</th><th>Protocol</th><th class="r">Packets</th><th class="r">Client→Server</th><th class="r">Server→Client</th><th class="r">Duration</th><th></th></tr></thead><tbody>${flows.map(f => `<tr data-st="${f.id}"><td class="num dim">${f.id}</td><td class="mono">${esc(f.a)}:${f.ap}</td><td class="mono">${esc(f.b)}:${f.bp}</td><td>${protoPill(f.proto)} ${flowDet.has(f.id) ? sevBadge(flowDet.get(f.id).sev) : ''}</td><td class="r">${fmtNum(f.pk.length)}</td><td class="r">${fmtBytes(f.ab)}</td><td class="r">${fmtBytes(f.ba)}</td><td class="r">${fmtDur(f.t1 - f.t0)}</td><td><button class="btn sm ghost" data-follow="${f.id}">${SVGI(IC.stream, 13)}Follow</button></td></tr>`).join('')}</tbody>`;
  $('#flowtbl').onclick = e => { const b = e.target.closest('[data-follow]'); if (b) { followStream(+b.dataset.follow); return; } const tr = e.target.closest('tr[data-st]'); if (tr) { setExpr('stream:' + tr.dataset.st); go('packets'); } };
  sideDefault();
  if (S.graph) S.graph.destroy();
  S.graph = makeGraph($('#gmap'));
  S.graph.active = S.view === 'conversations';
  $('#gfit').onclick = () => S.graph.relayout();
}
function sideDefault() {
  const A = S.A;
  const pairs = [...A.pairs.values()].sort((a, b) => (b.ab + b.ba) - (a.ab + a.ba)).slice(0, 14);
  $('#gside').innerHTML = `<div class="card-h"><h3>Busiest host pairs</h3></div><div class="card-b"><table class="tbl"><thead><tr><th>Hosts</th><th class="r">Bytes</th></tr></thead><tbody>${pairs.map(p => { const top = [...p.protos.entries()].sort((a, b) => b[1] - a[1])[0]; return `<tr data-a="${esc(p.a)}" data-b="${esc(p.b)}"><td><div class="mono" style="font-size:12px">${esc(p.a)}</div><div class="mono dim" style="font-size:12px;color:var(--muted)">⇄ ${esc(p.b)}</div></td><td class="r">${fmtBytes(p.ab + p.ba)}<div>${top ? protoPill(top[0]) : ''}</div></td></tr>`; }).join('')}</tbody></table></div>`;
  $$('#gside tr[data-a]').forEach(tr => tr.onclick = () => setExpr('ip:' + tr.dataset.a + ' ip:' + tr.dataset.b));
}
function sideHost(ip) {
  const A = S.A, h = A.hosts.get(ip); if (!h) return sideDefault();
  const peers = [...A.pairs.values()].filter(p => p.a === ip || p.b === ip).map(p => ({ ip: p.a === ip ? p.b : p.a, b: p.ab + p.ba })).sort((a, b) => b.b - a.b);
  const protos = [...h.protos.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const dets = S.cap.threats.filter(d => d.src === ip || d.dst === ip || (d.targets || []).includes(ip));
  const macs = [...(S.cap.macIp || new Map()).entries()].filter(([m, s]) => s.has(ip)).map(e => e[0]);
  $('#gside').innerHTML = `<div class="card-h"><h3 class="mono">${esc(ip)}</h3>${roleTag(ip)}<span class="sp"></span><button class="btn sm ghost" id="gback">${SVGI(IC.x, 13)}</button></div><div class="card-b">
    <dl class="kv"><dt>Scope</dt><dd>${isIp(ip) ? (isPrivate(ip) ? 'Internal / private' : 'External / public') : 'Link layer'}</dd>${macs.length ? `<dt>MAC</dt><dd class="mono">${macs.map(esc).join('<br>')}</dd>` : ''}<dt>Sent</dt><dd>${fmtBytes(h.tx)} · ${fmtNum(h.ptx)} pkts</dd><dt>Received</dt><dd>${fmtBytes(h.rx)} · ${fmtNum(h.prx)} pkts</dd><dt>Peers</dt><dd>${peers.length}</dd></dl>
    <div style="margin-top:14px" class="bars">${protos.map(([p, b]) => barRow({ name: p, swatch: col(p), segs: [{ v: b, c: col(p) }], max: protos[0][1], value: fmtBytes(b) })).join('')}</div>
    ${dets.length ? `<div style="margin-top:14px;display:flex;flex-direction:column;gap:6px">${dets.slice(0, 8).map(d => `<div class="sev ${d.sev}" style="cursor:pointer;white-space:normal" data-d="${d.id}">${SVGI(SEV_ICON[d.sev], 14)}${esc(d.title)}</div>`).join('')}</div>` : ''}
    <div style="margin-top:14px;font-size:12px;color:var(--muted)">Top peers</div>
    <table class="tbl"><tbody>${peers.slice(0, 8).map(p => `<tr data-ip="${esc(p.ip)}"><td class="mono">${esc(p.ip)} ${roleTag(p.ip)}</td><td class="r">${fmtBytes(p.b)}</td></tr>`).join('')}</tbody></table>
    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn sm" id="gfilt">${SVGI(IC.filter, 13)}Filter to host</button></div></div>`;
  $('#gback').onclick = () => { S.graph.select(null); };
  $('#gfilt').onclick = () => setChip('host', { v: ip });
  $$('#gside [data-d]').forEach(x => x.onclick = () => { S.tsel = +x.dataset.d; S.dirty.threats = 1; go('threats'); });
  $$('#gside tr[data-ip]').forEach(tr => tr.onclick = () => S.graph.select(tr.dataset.ip));
}

/* ===================== INSIGHTS ===================== */
function renderInsights() {
  const el = $('#view-insights'), A = S.A, cap = S.cap;
  const flagged = new Set(cap.threats.filter(d => d.type === 'dnstunnel').map(d => d.dst));
  const dns = [...A.dns.values()].sort((a, b) => (b.q + b.r) - (a.q + a.r));
  const groupDns = new Map(); dns.forEach(d => { const b = baseDomain(d.name); let g = groupDns.get(b); if (!g) { g = { name: b, q: 0, subs: 0, types: new Set(), ans: new Set(), nx: 0, first: d.first }; groupDns.set(b, g); } g.q += d.q; g.subs++; d.types.forEach(t => g.types.add(t)); d.ans.forEach(a => g.ans.add(a)); g.nx += d.nx; });
  const dnsRows = [...groupDns.values()].sort((a, b) => b.q - a.q).slice(0, 150);
  const sni = [...A.sni.values()].sort((a, b) => b.n - a.n).slice(0, 150);
  const http = A.http.slice(0, 400).map(i => cap.pk[i]);
  const hosts = [...A.hosts.values()].sort((a, b) => (b.tx + b.rx) - (a.tx + a.rx)).slice(0, 200);
  const macOf = new Map(); (cap.macIp || new Map()).forEach((ips, m) => ips.forEach(ip => macOf.set(ip, (macOf.get(ip) || []).concat(m))));
  el.innerHTML = `<div class="grid">
    <div class="card c6"><div class="card-h"><h3>DNS domains</h3><span class="sub">${fmtNum(A.dns.size)} names, grouped by registered domain</span></div><div class="card-b"><div class="scroll"><table class="tbl" id="dnstbl"><thead><tr><th>Domain</th><th class="r">Queries</th><th class="r">Names</th><th>Types</th><th>Resolved to</th></tr></thead><tbody>${dnsRows.map(d => `<tr data-q="${esc(d.name)}"><td class="mono">${esc(d.name)} ${flagged.has(d.name) ? sevBadge('high') : ''}${d.nx ? ' <span class="pill">NXDOMAIN ×' + d.nx + '</span>' : ''}</td><td class="r">${fmtNum(d.q)}</td><td class="r">${d.subs}</td><td>${[...d.types].map(esc).join(', ')}</td><td class="mono ell" style="max-width:180px" title="${esc([...d.ans].join(', '))}">${esc([...d.ans].slice(0, 3).join(', '))}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No DNS traffic</td></tr>'}</tbody></table></div></div></div>
    <div class="card c6"><div class="card-h"><h3>TLS server names (SNI)</h3><span class="sub">${fmtNum(A.sni.size)} names</span></div><div class="card-b"><div class="scroll"><table class="tbl" id="snitbl"><thead><tr><th>Server name</th><th class="r">Handshakes</th><th class="r">Clients</th><th>ALPN</th><th class="r">Bytes</th></tr></thead><tbody>${sni.map(t => `<tr data-sni="${esc(t.name)}"><td class="mono">${esc(t.name)}</td><td class="r">${t.n}</td><td class="r">${t.clients.size}</td><td>${esc(t.alpn)}</td><td class="r">${fmtBytes(t.bytes)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No TLS Client Hellos</td></tr>'}</tbody></table></div></div></div>
    <div class="card c12"><div class="card-h"><h3>HTTP requests</h3><span class="sub">${fmtNum(A.http.length)} cleartext requests</span></div><div class="card-b"><div class="scroll"><table class="tbl" id="httptbl"><thead><tr><th>#</th><th>Client</th><th>Method</th><th>Host</th><th>URI</th><th class="r">Status</th><th>User-Agent</th></tr></thead><tbody>${http.map(r => { const h = r.s.http; const sv = cap.pkSev[r.i]; return `<tr data-i="${r.i}"><td class="num dim">${r.i + 1}</td><td class="mono">${esc(r.s.src)}</td><td><b style="font-weight:600">${esc(h.method)}</b></td><td class="mono">${esc(h.host)}</td><td class="mono ell" title="${esc(safeDecode(h.uri))}">${sv ? sevBadge(['', 'low', 'medium', 'high', 'critical'][sv]) + ' ' : ''}${esc(h.uri)}</td><td class="r">${h.status ? `<span class="pill" style="${h.status >= 500 ? 'color:var(--crit)' : h.status >= 400 ? 'color:var(--high)' : ''}">${h.status}</span>` : '—'}</td><td class="ell" style="max-width:240px" title="${esc(h.ua)}">${esc(h.ua)}</td></tr>`; }).join('') || '<tr><td colspan="7" class="empty">No cleartext HTTP requests</td></tr>'}</tbody></table></div></div></div>
    <div class="card c12"><div class="card-h"><h3>Endpoints</h3><span class="sub">${fmtNum(A.hosts.size)} addresses</span></div><div class="card-b"><div class="scroll"><table class="tbl" id="hosttbl"><thead><tr><th>Address</th><th>Scope</th><th>MAC</th><th class="r">Sent</th><th class="r">Received</th><th class="r">Packets</th><th>Top protocol</th><th>Role</th></tr></thead><tbody>${hosts.map(h => { const tp = [...h.protos.entries()].sort((a, b) => b[1] - a[1])[0]; return `<tr data-h="${esc(h.ip)}"><td class="mono">${esc(h.ip)}</td><td>${isIp(h.ip) ? (isPrivate(h.ip) ? 'Internal' : 'External') : 'L2'}</td><td class="mono dim">${esc((macOf.get(h.ip) || []).join(', '))}</td><td class="r">${fmtBytes(h.tx)}</td><td class="r">${fmtBytes(h.rx)}</td><td class="r">${fmtNum(h.ptx + h.prx)}</td><td>${tp ? protoPill(tp[0]) : ''}</td><td>${roleTag(h.ip)}</td></tr>`; }).join('')}</tbody></table></div></div></div>
  </div>`;
  $('#dnstbl').onclick = e => { const tr = e.target.closest('tr[data-q]'); if (tr) { setExpr('dns:' + tr.dataset.q); go('packets'); } };
  $('#snitbl').onclick = e => { const tr = e.target.closest('tr[data-sni]'); if (tr) { setExpr('sni:' + tr.dataset.sni); go('packets'); } };
  $('#httptbl').onclick = e => { const tr = e.target.closest('tr[data-i]'); if (tr) { go('packets'); selectPacket(+tr.dataset.i, true); } };
  $('#hosttbl').onclick = e => { const tr = e.target.closest('tr[data-h]'); if (tr) setChip('host', { v: tr.dataset.h }); };
}

/* ===================== THREATS ===================== */
function renderThreats() {
  const el = $('#view-threats'), cap = S.cap, D = cap.threats, F = cap.flow;
  if (!D.length) {
    el.innerHTML = `<div class="clean-state"><div class="ic">${SVGI(IC.check, 30)}</div><h2>No threats detected</h2><p>DeepPacket checked ${fmtNum(cap.pk.length)} packets for port scans, host sweeps, brute force, web exploits (SQLi, XSS, traversal, command injection, Log4Shell, Shellshock), cleartext credentials, ARP spoofing, rogue DHCP, reverse shells, beaconing, DNS tunneling, DGA, exfiltration and floods. Nothing matched.</p><p class="hint" style="margin-top:12px">Detection is heuristic. A clean result does not prove the traffic is benign.</p></div>`;
    return;
  }
  const cnt = s => D.filter(d => d.sev === s).length;
  const story = esc(F.story).replace(/(\d{1,3}(?:\.\d{1,3}){3})/g, '<b class="mono" style="font-size:12.5px">$1</b>');
  el.innerHTML = `
  <div class="thero">
    <div><div class="big">${D.length}</div><div class="lbl">detections</div></div>
    <div class="story"><h2>What happened</h2>${story}
      <div class="sevs">${['critical', 'high', 'medium', 'low'].filter(cnt).map(s => `<button class="fbtn ${S.sevF === s ? 'on' : ''}" data-sev="${s}" style="padding:0;border:0;background:none">${sevBadge(s, cnt(s))}</button>`).join('')}</div></div>
  </div>
  <div style="margin-top:22px"><div class="card-h" style="padding:0 0 10px"><h3>Kill chain</h3><span class="sub">MITRE ATT&amp;CK tactics in attack order. Select one to narrow the list.</span></div>
    <div class="chain">${F.stages.map((s, i) => { const sev = Object.keys(SEV_RANK).find(k => SEV_RANK[k] === s.sev); return `<div class="stage ${s.n ? 'hit' : 'miss'} ${S.stage === s.k ? 'sel' : ''}" data-st="${s.k}" style="${s.n ? '--sc:var(' + SEV_VAR[sev] + ')' : ''}"><div class="ix">${i + 1}&ensp;${s.ta}</div><div class="nm">${s.name}</div><div class="ct">${s.n ? s.n + ' detection' + (s.n > 1 ? 's' : '') + ', from +' + fmtRel(s.t0 - cap.t0, cap.dur) : 'Not seen'}</div></div>`; }).join('')}</div></div>
  <div class="card" style="margin-top:22px"><div class="card-h"><h3>Attack flow</h3><span class="sub">Who did what to whom, in time order. Select a step for its evidence.</span></div><div class="seq" id="seq"></div></div>
  <div style="margin-top:26px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding-bottom:10px"><h3 style="margin:0;font-size:18px;font-weight:650">Detections</h3><span class="hint" id="detcount"></span><span style="flex:1"></span>${S.stage || S.sevF ? `<button class="btn sm ghost" id="clrf">${SVGI(IC.x, 13)}Clear filters</button>` : ''}</div>
  <div class="dets" id="dets" style="margin-top:10px"></div>`;
  $$('#view-threats [data-st]').forEach(x => x.onclick = () => { S.stage = S.stage === x.dataset.st ? null : x.dataset.st; renderThreats(); });
  $$('#view-threats [data-sev]').forEach(x => x.onclick = () => { S.sevF = S.sevF === x.dataset.sev ? null : x.dataset.sev; renderThreats(); });
  if ($('#clrf')) $('#clrf').onclick = () => { S.stage = null; S.sevF = null; renderThreats(); };
  drawSequence();
  drawDetections();
  if (S.tsel !== null) { const t = S.tsel; setTimeout(() => selectThreat(t, true), 60); }
}
function drawSequence() {
  const cap = S.cap, F = cap.flow, el = $('#seq');
  const lanes = F.lanes, steps = F.steps;
  const avail = el.clientWidth || 1100, gut = 78, n = lanes.length;
  const lw = Math.max(132, Math.min(230, (avail - gut - 20) / n));
  const W = gut + lw * n + 20, top = 78, rh = 50, H = top + steps.length * rh + 24;
  const lx = i => gut + lw * i + lw / 2;
  const li = new Map(lanes.map((l, i) => [l.id, i]));
  const roleColor = r => ({ 'Attacker': 'var(--crit)', 'Botnet / spoofed': 'var(--crit)', 'Rogue insider': 'var(--crit)', 'C2 server': 'var(--high)', 'Malware host': 'var(--high)', 'Compromised host': 'var(--med)', 'At-risk host': 'var(--med)' }[r] || 'var(--muted)');
  let s = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><defs>${['critical', 'high', 'medium', 'low'].map(k => `<marker id="ah-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(${SEV_VAR[k]})"/></marker>`).join('')}</defs>`;
  lanes.forEach((l, i) => {
    const x = lx(i), id = l.id.length > 22 ? l.id.slice(0, 21) + '…' : l.id;
    s += `<line x1="${x}" x2="${x}" y1="${top - 6}" y2="${H - 10}" stroke="var(--line-2)" stroke-dasharray="3 4"/>`;
    s += `<rect x="${x - lw / 2 + 8}" y="10" width="${lw - 16}" height="${top - 22}" rx="4" fill="var(--panel-2)"/>`;
    s += `<rect x="${x - lw / 2 + 8}" y="10" width="${lw - 16}" height="3" fill="${roleColor(l.role)}"/>`;
    s += `<text x="${x}" y="33" text-anchor="middle" font-size="12.5" font-weight="650" fill="${roleColor(l.role)}">${esc(l.role)}</text>`;
    s += `<text x="${x}" y="51" text-anchor="middle" font-size="12" font-weight="550" fill="var(--text)" font-family="IBM Plex Mono, monospace"><title>${esc(l.id)}</title>${esc(id)}</text>`;
  });
  steps.forEach((st, k) => {
    const d = st.d, y = top + k * rh + rh / 2, a = li.get(st.src), b = li.get(st.dst);
    const xa = lx(a), xb = lx(b), sev = d.sev;
    const vis = (!S.stage || d.stage === S.stage) && (!S.sevF || d.sev === S.sevF);
    s += `<g class="row ${S.tsel === d.id ? 'sel' : ''}" data-d="${d.id}" opacity="${vis ? 1 : 0.22}"><rect class="band" x="0" y="${y - rh / 2 + 2}" width="${W}" height="${rh - 4}" rx="8" fill="transparent"/>`;
    s += `<text x="12" y="${y + 4}" font-size="11" fill="var(--muted)" style="font-variant-numeric:tabular-nums">+${fmtRel(d.t0 - cap.t0, cap.dur)}</text>`;
    if (a === b) s += `<path d="M${xa + 12},${y - 8} h36 v16 h-30" fill="none" stroke="var(${SEV_VAR[sev]})" stroke-width="2" marker-end="url(#ah-${sev})"/>`;
    else s += `<line x1="${xa + (xb > xa ? 12 : -12)}" x2="${xb + (xb > xa ? -6 : 6)}" y1="${y}" y2="${y}" stroke="var(${SEV_VAR[sev]})" stroke-width="2" marker-end="url(#ah-${sev})"/>`;
    s += `<circle cx="${xa}" cy="${y}" r="11" fill="var(${SEV_VAR[sev]})" stroke="var(--panel)" stroke-width="2"/><text x="${xa}" y="${y + 4}" text-anchor="middle" font-size="10.5" font-weight="700" fill="${sev === 'medium' ? '#111' : '#fff'}">${k + 1}</text>`;
    const lx0 = Math.min(xa, xb) + 18, rightward = xb >= xa;
    const label = d.title.length > 58 ? d.title.slice(0, 56) + '…' : d.title;
    const anchorX = a === b ? xa + 56 : (Math.abs(xb - xa) < label.length * 7.2 + 40 ? Math.max(xa, xb) + 16 : lx0);
    s += `<text x="${anchorX}" y="${y - 7}" font-size="13" font-weight="650" fill="var(--text)">${esc(label)}</text>`;
    s += `<text x="${anchorX}" y="${y + 15}" font-size="11.5" fill="var(--muted)">${SEV_LABEL[sev]}, ${esc(STAGES.find(x => x.k === d.stage).name)}, ${d.tech}</text>`;
    void rightward;
    s += `</g>`;
  });
  s += `</svg>`;
  el.innerHTML = s;
  $$('#seq .row').forEach(g => { g.onclick = () => selectThreat(+g.dataset.d, true); g.onmousemove = e => { const d = cap.threats[+g.dataset.d]; tip(`<div class="tt-h">${esc(d.title)}</div><div style="color:var(--text-2);max-width:320px">${esc(d.summary)}</div>`, e); }; g.onmouseleave = untip; });
}
function drawDetections() {
  const cap = S.cap, D = cap.threats.filter(d => (!S.stage || d.stage === S.stage) && (!S.sevF || d.sev === S.sevF));
  $('#detcount').textContent = D.length + ' shown' + (S.stage ? ' · ' + STAGES.find(s => s.k === S.stage).name : '') + (S.sevF ? ' · ' + SEV_LABEL[S.sevF] : '');
  const stepNo = new Map(cap.flow.steps.map((s, i) => [s.d.id, i + 1]));
  $('#dets').innerHTML = D.map(d => `<div class="det" id="det-${d.id}" data-d="${d.id}">
    <span class="stepn">${stepNo.get(d.id)}</span><div class="tline">${sevBadge(d.sev)}<h4>${esc(d.title)}</h4><span class="hint num">+${fmtRel(d.t0 - cap.t0, cap.dur)}${d.t1 > d.t0 + 0.5 ? ' to +' + fmtRel(d.t1 - cap.t0, cap.dur) : ''}, ${clock(d.t0).slice(0, 8)}</span></div>
    <div class="meta"><span class="flow">${esc(d.src)} ${roleTag(d.src)} ${SVGI(IC.arrow, 14)} ${esc(d.dst)}${d.dport ? ':' + d.dport : ''} ${roleTag(d.dst)}</span><span class="tag">${esc(STAGES.find(s => s.k === d.stage).name)}</span><a class="tag" href="${techUrl(d.tech)}" target="_blank" rel="noopener"><b style="font-weight:650">${esc(d.tech)}</b> ${esc(d.techName)} ${SVGI(IC.ext, 11)}</a></div>
    <p>${esc(d.summary)}</p>
    <dl>${d.details.map(([k, v]) => `<dt>${esc(k)}</dt><dd ${k === 'Password' && d.secret ? 'data-secret' : ''}>${esc(v)}</dd>`).join('')}</dl>
    <div class="acts"><button class="btn sm" data-ev="${d.id}">${SVGI(IC.filter, 13)}Show ${fmtNum(d.ev.length)} packet${d.ev.length > 1 ? 's' : ''}</button>${d.stream !== undefined ? `<button class="btn sm" data-fs="${d.stream}">${SVGI(IC.stream, 13)}Follow stream</button>` : ''}${d.secret ? `<button class="btn sm ghost" data-rev="${d.id}">${SVGI(IC.eye, 13)}Reveal password</button>` : ''}</div>
  </div>`).join('') || '<div class="empty">No detections match these filters</div>';
  $('#dets').onclick = e => {
    const b = e.target.closest('button');
    const card = e.target.closest('.det');
    if (b && b.dataset.ev !== undefined) { const d = cap.threats[+b.dataset.ev]; S.chips.ev = { set: new Set(d.ev), label: d.title }; S.chips.time = null; S.sel = d.ev[0]; applyFilter(); go('packets'); setTimeout(() => selectPacket(d.ev[0], true), 30); return; }
    if (b && b.dataset.fs !== undefined) { followStream(+b.dataset.fs); return; }
    if (b && b.dataset.rev !== undefined) { const d = cap.threats[+b.dataset.rev]; const dd = $('[data-secret]', card); const shown = dd.dataset.shown === '1'; dd.textContent = shown ? mask(d.secret) : d.secret; dd.dataset.shown = shown ? '0' : '1'; b.innerHTML = SVGI(IC.eye, 13) + (shown ? 'Reveal password' : 'Hide password'); return; }
    if (card && !e.target.closest('a')) selectThreat(+card.dataset.d, false);
  };
}
function selectThreat(id, scroll) {
  S.tsel = id;
  $$('#seq .row').forEach(g => g.classList.toggle('sel', +g.dataset.d === id));
  $$('.det').forEach(c => c.classList.toggle('sel', +c.dataset.d === id));
  const c = $('#det-' + id);
  if (scroll && c) c.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/* ===================== wiring ===================== */
$('#openBtn').onclick = $('#openBtn2').onclick = () => $('#file').click();
$('#file').onchange = e => { openFile(e.target.files[0]); e.target.value = ''; };
$('#demoBtn').onclick = loadDemo;
$('#themeBtn').onclick = () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
$('#brand').onclick = () => { if (S.cap) go('overview'); };
$$('.tab').forEach(t => t.onclick = () => go(t.dataset.view));
$('#mclose').onclick = () => $('#modal').classList.remove('on');
$('#modal').onclick = e => { if (e.target.id === 'modal') $('#modal').classList.remove('on'); };
$('#helpBtn').onclick = () => {
  $('#mtitle').textContent = 'Filter syntax';
  $('#mbody').innerHTML = `<div class="help"><p>Terms are combined with AND. Use <code>or</code> between groups. Prefix a term with <code>!</code> to negate it. Operators: <code>:</code> <code>==</code> <code>!=</code> <code>&gt;</code> <code>&lt;</code> <code>&gt;=</code> <code>&lt;=</code>.</p><table>
  <tr><td><code>tcp</code> <code>dns</code> <code>tls</code> <code>arp</code> …</td><td>Protocol name</td></tr>
  <tr><td><code>ip:10.0.0.5</code> <code>ip:10.0.0.0/24</code></td><td>Either address (also <code>src:</code> <code>dst:</code>)</td></tr>
  <tr><td><code>port:443</code> <code>dport&lt;1024</code></td><td>Ports (also <code>sport:</code>)</td></tr>
  <tr><td><code>len&gt;1000</code> <code>ttl&lt;10</code> <code>frame&gt;=500</code> <code>time&gt;30</code></td><td>Numeric comparisons</td></tr>
  <tr><td><code>syn</code> <code>synack</code> <code>rst</code> <code>fin</code></td><td>TCP flags</td></tr>
  <tr><td><code>stream:12</code></td><td>One TCP/UDP conversation</td></tr>
  <tr><td><code>dns:example.com</code> <code>sni:github</code> <code>http:login</code> <code>ua:sqlmap</code> <code>status&gt;=400</code></td><td>Application fields (substring)</td></tr>
  <tr><td><code>threat</code></td><td>Packets that are evidence in a detection</td></tr>
  <tr><td><code>mac:aa:bb:cc:dd:ee:ff</code> <code>vlan:10</code></td><td>Link layer</td></tr>
  <tr><td>anything else</td><td>Text search in addresses and the Info column</td></tr></table>
  <p style="margin-top:12px">Example: <code>ip:10.0.0.20 !tls port:80 or dns</code></p></div>`;
  $('#modal').classList.add('on');
};
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { $('#modal').classList.remove('on'); }
  if (e.key === '/' && S.cap && document.activeElement.tagName !== 'INPUT') { e.preventDefault(); if (S.view === 'threats') go('packets'); $('#fin').focus(); }
});
// drag & drop
let dragN = 0;
window.addEventListener('dragenter', e => { if (![...e.dataTransfer.types].includes('Files')) return; dragN++; if (S.cap) $('#dzf').classList.add('on'); else $('#drop').classList.add('over'); e.preventDefault(); });
window.addEventListener('dragleave', () => { if (--dragN <= 0) { dragN = 0; $('#dzf').classList.remove('on'); $('#drop').classList.remove('over'); } });
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('drop', e => { e.preventDefault(); dragN = 0; $('#dzf').classList.remove('on'); $('#drop').classList.remove('over'); const f = e.dataTransfer.files[0]; if (f) openFile(f); });
let rzT; window.addEventListener('resize', () => { clearTimeout(rzT); rzT = setTimeout(() => { drawSpecimen(); if (!S.cap) return; drawStrip(); drawSpecimen(); if (S.view === 'overview') { drawTimeline(); drawSizes(); } if (S.view === 'threats') drawSequence(); if (S.view === 'packets') drawRows(); }, 150); });

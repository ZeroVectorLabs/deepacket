function makeGraph(cv) {
  const A = S.A, cap = S.cap, ctx = cv.getContext('2d');
  const G = { active: true, autofit: true, alpha: 1, sel: null, hover: null, k: 1, ox: 0, oy: 0, raf: 0 };
  const scope = ip => (!isIp(ip) || /^(22[4-9]|23\d)\./.test(ip) || ip === '255.255.255.255' || ip === '0.0.0.0' || ip.toLowerCase().startsWith('ff')) ? 'l2' : isPrivate(ip) ? 'lan' : 'wan';
  // threat paths between hosts, strongest severity wins
  const tEdge = new Map(), tHosts = new Set();
  cap.threats.forEach(d => (d.targets || [d.dst]).forEach(t => {
    if (!A.hosts.has(d.src) || !A.hosts.has(t)) return;
    const k = d.src < t ? d.src + '|' + t : t + '|' + d.src, prev = tEdge.get(k);
    if (!prev || SEV_RANK[d.sev] > SEV_RANK[prev.sev]) tEdge.set(k, { sev: d.sev, from: d.src, to: t });
    tHosts.add(d.src); tHosts.add(t);
  }));
  const peers = new Map();
  for (const p of A.pairs.values()) { if (p.a === p.b) continue; for (const x of [p.a, p.b]) { if (!peers.has(x)) peers.set(x, []); peers.get(x).push(p); } }
  const hostsSorted = [...A.hosts.values()].sort((a, b) => (b.tx + b.rx) - (a.tx + a.rx));
  const keepTop = new Set(hostsSorted.slice(0, 12).map(h => h.ip));
  // fold single-peer hosts into "+N hosts" clusters
  const clusterOf = new Map(), clusters = new Map();
  for (const h of hostsSorted) {
    if (keepTop.has(h.ip) || tHosts.has(h.ip) || S.roles.has(h.ip)) continue;
    const ps = peers.get(h.ip) || []; if (ps.length !== 1) continue;
    const peer = ps[0].a === h.ip ? ps[0].b : ps[0].a, sc = scope(h.ip), key = 'cluster:' + peer + ':' + sc;
    let c = clusters.get(key); if (!c) { c = { key, peer, scope: sc, members: [], tx: 0, rx: 0 }; clusters.set(key, c); }
    c.members.push(h.ip); c.tx += h.tx; c.rx += h.rx; clusterOf.set(h.ip, key);
  }
  for (const [k, c] of clusters) if (c.members.length < 3) { c.members.forEach(m => clusterOf.delete(m)); clusters.delete(k); }
  let items = [];
  for (const h of hostsSorted) if (!clusterOf.has(h.ip)) items.push({ id: h.ip, label: h.ip, h, bytes: h.tx + h.rx, scope: scope(h.ip), role: S.roles.get(h.ip) });
  for (const c of clusters.values()) items.push({ id: c.key, label: '+' + c.members.length + ' hosts', cluster: c, bytes: c.tx + c.rx, scope: c.scope, h: { ip: c.key, tx: c.tx, rx: c.rx } });
  items.sort((a, b) => (tHosts.has(b.id) - tHosts.has(a.id)) || b.bytes - a.bytes);
  const hiddenN = Math.max(0, items.length - 60);
  items = items.slice(0, 60);
  const byId = new Map(items.map(n => [n.id, n]));
  const maxB = Math.max(1, ...items.filter(n => !n.cluster).map(n => n.bytes));
  const ZX = 300;
  items.forEach((n, i) => {
    n.r = n.cluster ? Math.min(20, 9 + Math.sqrt(n.cluster.members.length) * 1.6) : 4 + Math.sqrt(n.bytes / maxB) * 19;
    n.tx = n.scope === 'wan' ? ZX : -ZX; n.ty = n.scope === 'l2' ? 200 : 0;
    n.x = n.tx + (Math.random() - .5) * 200; n.y = n.ty + (Math.random() - .5) * 300; n.vx = n.vy = 0;
  });
  const resolve = ip => byId.has(ip) ? ip : (clusterOf.has(ip) && byId.has(clusterOf.get(ip)) ? clusterOf.get(ip) : null);
  const emap = new Map();
  for (const p of A.pairs.values()) {
    const a = resolve(p.a), b = resolve(p.b); if (!a || !b || a === b) continue;
    const k = a < b ? a + '|' + b : b + '|' + a;
    let e = emap.get(k); if (!e) { e = { a: byId.get(a < b ? a : b), b: byId.get(a < b ? b : a), bytes: 0, ab: 0, ba: 0, threat: null }; emap.set(k, e); }
    e.bytes += p.ab + p.ba; if (e.a.id === a) { e.ab += p.ab; e.ba += p.ba; } else { e.ab += p.ba; e.ba += p.ab; }
  }
  for (const t of tEdge.values()) {
    const a = resolve(t.from), b = resolve(t.to); if (!a || !b || a === b) continue;
    const e = emap.get(a < b ? a + '|' + b : b + '|' + a); if (e) e.threat = { sev: t.sev, from: byId.get(a) };
  }
  const edges = [...emap.values()];
  const maxE = Math.max(1, ...edges.map(e => e.bytes));
  edges.forEach(e => e.w = 0.8 + Math.log1p(e.bytes) / Math.log1p(maxE) * 2.6);
  const parts = [];
  edges.forEach(e => { const n = 2 + Math.round(Math.log1p(e.bytes) / Math.log1p(maxE) * 3); for (let i = 0; i < n; i++) parts.push({ e, t: Math.random(), dir: Math.random() < e.ab / Math.max(1, e.bytes) ? 1 : -1, sp: 0.003 + Math.random() * 0.004 }); });

  let W = 0, H = 0, dpr = 1, C = {};
  const resize = () => { const r = cv.getBoundingClientRect(); dpr = window.devicePixelRatio || 1; W = r.width; H = r.height; cv.width = Math.max(1, W * dpr); cv.height = Math.max(1, H * dpr); };
  const readColors = () => { ['s1', 's7', 's0', 'crit', 'high', 'med', 'low', 'text', 'text-2', 'muted', 'line', 'line-2', 'axis', 'panel', 'panel-2', 'plate', 'accent', 'bg'].forEach(k => C[k] = cssv('--' + k)); };
  resize(); readColors();
  const ro = new ResizeObserver(resize); ro.observe(cv);
  const sevCol = s => C[{ critical: 'crit', high: 'high', medium: 'med', low: 'low' }[s]];
  const roleCol = r => ({ 'Attacker': C.crit, 'Botnet / spoofed': C.crit, 'Rogue insider': C.crit, 'C2 server': C.high, 'Malware host': C.high, 'Compromised host': C.med, 'At-risk host': C.med }[r] || C.muted);

  const tick = () => {
    if (G.alpha < 0.005) return;
    const n = items.length, al = G.alpha;
    for (let i = 0; i < n; i++) {
      const a = items[i];
      for (let j = i + 1; j < n; j++) {
        const b = items[j]; let dx = b.x - a.x, dy = b.y - a.y; const d2 = dx * dx + dy * dy + 0.01, d = Math.sqrt(d2);
        let f = 2800 / d2; const minD = a.r + b.r + 26; if (d < minD) f += (minD - d) * 0.25;
        dx /= d; dy /= d; a.vx -= dx * f * al; a.vy -= dy * f * al; b.vx += dx * f * al; b.vy += dy * f * al;
      }
    }
    for (const e of edges) { const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y, d = Math.sqrt(dx * dx + dy * dy) + 0.01; const f = (d - (90 + e.a.r + e.b.r)) * 0.006 * al; e.a.vx += dx / d * f; e.a.vy += dy / d * f * 1.6; e.b.vx -= dx / d * f; e.b.vy -= dy / d * f * 1.6; }
    for (const a of items) {
      a.vx += (a.tx - a.x) * 0.03 * al; a.vy += (a.ty - a.y) * 0.006 * al;
      if (a === G.drag) { a.vx = a.vy = 0; continue; }
      a.vx *= 0.78; a.vy *= 0.78; a.x += a.vx; a.y += a.vy;
      if (a.scope === 'wan' && a.x < 110 + a.r) a.x = 110 + a.r;
      if (a.scope !== 'wan' && a.x > -110 - a.r) a.x = -110 - a.r;
    }
    G.alpha *= 0.982;
  };
  for (let i = 0; i < 260; i++) tick();
  const bounds = () => { let x0 = -ZX - 60, x1 = ZX + 60, y0 = Infinity, y1 = -Infinity; items.forEach(n => { x0 = Math.min(x0, n.x - n.r - 30); x1 = Math.max(x1, n.x + n.r + 30); y0 = Math.min(y0, n.y - n.r - 20); y1 = Math.max(y1, n.y + n.r + 34); }); return { x0, x1, y0, y1 }; };
  const fit = () => { if (!items.length || !W) return; const b = bounds(); G.k = Math.min(1.6, (W - 40) / (b.x1 - b.x0), (H - 120) / (b.y1 - b.y0)); G.ox = W / 2 - (b.x0 + b.x1) / 2 * G.k; G.oy = 66 + (H - 120) / 2 - (b.y0 + b.y1) / 2 * G.k; };
  fit();

  const curve = (e) => { const mx = (e.a.x + e.b.x) / 2, my = (e.a.y + e.b.y) / 2, dx = e.b.x - e.a.x, dy = e.b.y - e.a.y; return { cx: mx - dy * 0.12, cy: my + dx * 0.12 }; };
  const qpt = (e, c, t) => { const u = 1 - t; return { x: u * u * e.a.x + 2 * u * t * c.cx + t * t * e.b.x, y: u * u * e.a.y + 2 * u * t * c.cy + t * t * e.b.y }; };
  const draw = () => {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
    // zone headers + perimeter
    const sx = x => G.ox + x * G.k;
    ctx.font = '600 13px Archivo, sans-serif'; ctx.fillStyle = C['text-2']; ctx.textAlign = 'center';
    ctx.fillText('Local network', sx(-ZX), 28); ctx.fillText('Internet', sx(ZX), 28);
    ctx.font = '400 12px Archivo, sans-serif'; ctx.fillStyle = C.muted;
    const nl = items.filter(n => n.scope !== 'wan').length, nw = items.length - nl;
    ctx.fillText(nl + ' hosts', sx(-ZX), 44); ctx.fillText(nw + ' hosts' + (hiddenN ? ', ' + hiddenN + ' smaller not shown' : ''), sx(ZX), 44);
    ctx.strokeStyle = C['line-2']; ctx.lineWidth = 1; ctx.setLineDash([2, 5]); ctx.beginPath(); ctx.moveTo(sx(0), 18); ctx.lineTo(sx(0), H - 40); ctx.stroke(); ctx.setLineDash([]);
    ctx.save(); ctx.translate(G.ox, G.oy); ctx.scale(G.k, G.k);
    const focus = G.hover || G.sel;
    const nb = focus ? new Set(edges.filter(e => e.a === focus || e.b === focus).flatMap(e => [e.a, e.b])) : null;
    const lw = 1 / G.k;
    for (const e of edges) {
      if (e.threat) continue;
      const on = focus && (e.a === focus || e.b === focus);
      ctx.globalAlpha = nb ? (on ? 1 : 0.12) : 0.75;
      ctx.strokeStyle = on ? C['text-2'] : C.axis; ctx.lineWidth = e.w * lw * (on ? 1.2 : 1);
      const c = curve(e); ctx.beginPath(); ctx.moveTo(e.a.x, e.a.y); ctx.quadraticCurveTo(c.cx, c.cy, e.b.x, e.b.y); ctx.stroke();
    }
    for (const e of edges) {
      if (!e.threat) continue;
      const on = !focus || e.a === focus || e.b === focus;
      ctx.globalAlpha = on ? 1 : 0.2; const col = sevCol(e.threat.sev);
      ctx.strokeStyle = col; ctx.lineWidth = 2.2 * lw;
      const from = e.threat.from, to = from === e.a ? e.b : e.a;
      const ee = { a: from, b: to }; const c = curve(ee);
      ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.quadraticCurveTo(c.cx, c.cy, to.x, to.y); ctx.stroke();
      // arrowhead just outside target node
      const t = Math.max(0.5, 1 - (to.r + 6) / Math.max(1, Math.hypot(to.x - from.x, to.y - from.y)));
      const p = qpt(ee, c, t), q = qpt(ee, c, t - 0.02); const ang = Math.atan2(p.y - q.y, p.x - q.x), s = 9 * lw;
      ctx.fillStyle = col; ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(p.x - Math.cos(ang - 0.45) * s, p.y - Math.sin(ang - 0.45) * s); ctx.lineTo(p.x - Math.cos(ang + 0.45) * s, p.y - Math.sin(ang + 0.45) * s); ctx.closePath(); ctx.fill();
    }
    // traffic particles only along the focused host's links
    if (focus) for (const pt of parts) {
      const e = pt.e; if (e.a !== focus && e.b !== focus) continue;
      pt.t += pt.sp; if (pt.t > 1) pt.t -= 1;
      const p = qpt(e, curve(e), pt.dir > 0 ? pt.t : 1 - pt.t);
      ctx.globalAlpha = 1; ctx.fillStyle = e.threat ? sevCol(e.threat.sev) : C.text; ctx.beginPath(); ctx.arc(p.x, p.y, 2 * lw, 0, 7); ctx.fill();
    }
    for (const n of items) {
      const dim = nb && !nb.has(n);
      ctx.globalAlpha = dim ? 0.25 : 1;
      if (n.role && ROLE_CLS[n.role]) { ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 5 * lw + 2, 0, 7); ctx.strokeStyle = roleCol(n.role); ctx.lineWidth = 2.5 * lw; ctx.stroke(); }
      const base = n.scope === 'lan' ? C.s1 : n.scope === 'wan' ? C.s7 : C.s0;
      ctx.lineWidth = 2 * lw;
      if (n.cluster) {
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 7); ctx.fillStyle = C['panel-2']; ctx.fill();
        ctx.setLineDash([3 * lw, 3 * lw]); ctx.strokeStyle = base; ctx.stroke(); ctx.setLineDash([]);
        ctx.fillStyle = C.text; ctx.font = `600 ${11 * lw}px Archivo, sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        ctx.fillText('+' + n.cluster.members.length, n.x, n.y + 0.5 * lw); ctx.textBaseline = 'alphabetic';
      } else if (n.scope === 'l2') {
        ctx.fillStyle = base; ctx.fillRect(n.x - n.r * .85, n.y - n.r * .85, n.r * 1.7, n.r * 1.7);
      } else if (n.scope === 'wan') {
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 7); ctx.fillStyle = C.panel; ctx.fill(); ctx.strokeStyle = base; ctx.lineWidth = Math.max(2, n.r * 0.28) * (G.k < 1 ? 1 : lw * G.k); ctx.stroke();
      } else { ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 7); ctx.fillStyle = base; ctx.fill(); }
      if (n === G.sel) { ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 10 * lw + 3, 0, 7); ctx.strokeStyle = C.text; ctx.lineWidth = 1.5 * lw; ctx.stroke(); }
    }
    ctx.restore(); ctx.globalAlpha = 1;
    // labels in screen space, placed by priority and never overlapping
    const rank = n => (n === focus ? 1e6 : 0) + (nb && nb.has(n) ? 5e5 : 0) + (n.role && ROLE_CLS[n.role] ? 2e5 : 0) + (n.cluster ? 1e4 : 0) + n.bytes / maxB * 1e4;
    const placed = [{ x: sx(-ZX) - 70, y: 12, w: 140, h: 38 }, { x: sx(ZX) - 120, y: 12, w: 240, h: 38 }];
    const nodeRects = items.map(m => { const X = G.ox + m.x * G.k, Y = G.oy + m.y * G.k, R = m.r * G.k + 3; return { x: X - R, y: Y - R, w: 2 * R, h: 2 * R, n: m }; });
    const ov = (r, q) => r.x < q.x + q.w && r.x + r.w > q.x && r.y < q.y + q.h && r.y + r.h > q.y;
    let self = null;
    const hitRect = r => placed.some(q => ov(r, q)) || nodeRects.some(q => q.n !== self && ov(r, q));
    const order = items.slice().sort((a, b) => rank(b) - rank(a));
    let budget = 26;
    for (const n of order) {
      if (budget-- <= 0 && rank(n) < 2e5) break;
      if (nb && !nb.has(n)) continue;
      const X = G.ox + n.x * G.k, Y = G.oy + n.y * G.k, R = n.r * G.k; self = n;
      ctx.font = '500 12px "IBM Plex Mono", monospace'; const t1 = n.cluster ? n.label : n.label; const w1 = ctx.measureText(t1).width;
      const t2 = n.role && ROLE_CLS[n.role] ? n.role : n.cluster ? 'via ' + n.cluster.peer : '';
      ctx.font = '600 11.5px Archivo, sans-serif'; const w2 = t2 ? ctx.measureText(t2).width : 0;
      const w = Math.max(w1, w2) + 10, h = t2 ? 32 : 18;
      const cands = [[X - w / 2, Y + R + 7], [X - w / 2, Y - R - 7 - h], [X + R + 6, Y - h / 2], [X - R - 6 - w, Y - h / 2], [X + R * .7, Y + R * .7], [X - R * .7 - w, Y + R * .7], [X + R * .7, Y - R * .7 - h], [X - R * .7 - w, Y - R * .7 - h]];
      let rect = null;
      for (const [cx, cy] of cands) { const r = { x: cx, y: cy, w, h }; if (!hitRect(r)) { rect = r; break; } }
      if (!rect) { if (rank(n) >= 2e5) rect = { x: cands[0][0], y: cands[0][1], w, h }; else continue; }
      placed.push(rect);
      ctx.fillStyle = C.plate; ctx.beginPath(); ctx.roundRect ? ctx.roundRect(rect.x, rect.y, rect.w, rect.h, 3) : ctx.rect(rect.x, rect.y, rect.w, rect.h); ctx.fill();
      ctx.textAlign = 'center'; ctx.fillStyle = C.text; ctx.font = '500 12px "IBM Plex Mono", monospace'; ctx.fillText(t1, rect.x + w / 2, rect.y + 13);
      if (t2) { ctx.font = '600 11.5px Archivo, sans-serif'; ctx.fillStyle = n.cluster ? C.muted : roleCol(n.role); ctx.fillText(t2, rect.x + w / 2, rect.y + 27); }
    }
  };
  const loop = () => { G.raf = requestAnimationFrame(loop); if (!G.active || !cv.isConnected) return; tick(); if (G.autofit && G.alpha > 0.01) fit(); draw(); };
  loop();
  const toW = e => { const r = cv.getBoundingClientRect(); return { x: (e.clientX - r.left - G.ox) / G.k, y: (e.clientY - r.top - G.oy) / G.k }; };
  const hit = p => { for (let i = items.length - 1; i >= 0; i--) { const n = items[i]; if ((p.x - n.x) ** 2 + (p.y - n.y) ** 2 <= (n.r + 5 / G.k) ** 2) return n; } return null; };
  let pan = null, moved = false;
  cv.onmousedown = e => { const n = hit(toW(e)); moved = false; G.autofit = false; if (n) { G.drag = n; } else pan = { x: e.clientX, y: e.clientY, ox: G.ox, oy: G.oy }; cv.classList.add('drag'); };
  cv.onmousemove = e => {
    const p = toW(e);
    if (G.drag) { G.drag.x = p.x; G.drag.y = p.y; moved = true; G.alpha = Math.max(G.alpha, 0.08); untip(); return; }
    if (pan) { G.ox = pan.ox + e.clientX - pan.x; G.oy = pan.oy + e.clientY - pan.y; moved = true; return; }
    const n = hit(p); G.hover = n; cv.style.cursor = n ? 'pointer' : '';
    if (n) tip(`<div class="tt-h ${n.cluster ? '' : 'mono'}">${esc(n.label)}</div>${n.role ? `<div class="tt-r"><span>Role in attack</span><b>${esc(n.role)}</b></div>` : ''}${n.cluster ? `<div class="tt-r"><span>All talk only to</span><b class="mono">${esc(n.cluster.peer)}</b></div>` : ''}<div class="tt-r"><span><i style="background:var(--s1)"></i>Sent</span><b>${fmtBytes(n.h.tx)}</b></div><div class="tt-r"><span><i style="background:var(--s2)"></i>Received</span><b>${fmtBytes(n.h.rx)}</b></div>`, e); else untip();
  };
  const end = () => { if (G.drag && !moved) select(G.drag.id); else if (pan && !moved) select(null); G.drag = null; pan = null; cv.classList.remove('drag'); };
  cv.onmouseup = end; cv.onmouseleave = () => { G.hover = null; untip(); if (G.drag || pan) end(); };
  cv.ondblclick = e => { const n = hit(toW(e)); if (n && !n.cluster) setChip('host', { v: n.id }); };
  cv.onwheel = e => { e.preventDefault(); G.autofit = false; const r = cv.getBoundingClientRect(); const mx = e.clientX - r.left, my = e.clientY - r.top; const k = Math.max(0.25, Math.min(5, G.k * Math.exp(-e.deltaY * 0.0015))); G.ox = mx - (mx - G.ox) * k / G.k; G.oy = my - (my - G.oy) * k / G.k; G.k = k; };
  function select(id) { const n = id ? byId.get(id) || null : null; G.sel = n; if (!n) sideDefault(); else if (n.cluster) sideCluster(n.cluster); else sideHost(id); }
  G.select = id => { if (id && !byId.has(id) && clusterOf.has(id)) id = clusterOf.get(id); select(id); };
  G.kick = () => { resize(); readColors(); if (G.autofit) fit(); };
  G.relayout = () => { items.forEach(n => { n.x = n.tx + (Math.random() - .5) * 200; n.y = n.ty + (Math.random() - .5) * 300; n.vx = n.vy = 0; }); G.alpha = 1; G.autofit = true; for (let i = 0; i < 260; i++) tick(); fit(); };
  G.destroy = () => { cancelAnimationFrame(G.raf); ro.disconnect(); };
  return G;
}
function sideCluster(c) {
  $('#gside').innerHTML = `<div class="card-h"><h3>${c.members.length} ${c.scope === 'wan' ? 'internet' : c.scope === 'lan' ? 'local' : 'link-layer'} hosts</h3><span class="sp"></span><button class="btn sm ghost" id="gback">${SVGI(IC.x, 13)}</button></div><div class="card-b">
    <p class="hint" style="margin:0 0 10px">Each of these hosts talked only to <span class="mono">${esc(c.peer)}</span>, so they are drawn as one group.</p>
    <dl class="kv"><dt>Sent</dt><dd>${fmtBytes(c.tx)}</dd><dt>Received</dt><dd>${fmtBytes(c.rx)}</dd></dl>
    <div class="scroll" style="max-height:420px;margin-top:10px"><table class="tbl"><tbody>${c.members.slice(0, 400).map(m => { const h = S.A.hosts.get(m); return `<tr data-ip="${esc(m)}"><td class="mono">${esc(m)}</td><td class="r">${fmtBytes(h.tx + h.rx)}</td></tr>`; }).join('')}</tbody></table></div></div>`;
  $('#gback').onclick = () => S.graph.select(null);
  $$('#gside tr[data-ip]').forEach(tr => tr.onclick = () => setChip('host', { v: tr.dataset.ip }));
}

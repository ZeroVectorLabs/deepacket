/* ===================== Network map (diagram style: containers, device boxes, orthogonal connectors) ===================== */
const MAP_ICON = {
  workstation: '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>',
  server: '<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M7.5 6.5h.01M7.5 17.5h.01M11 6.5h6M11 17.5h6"/>',
  router: '<rect x="3" y="12" width="18" height="8" rx="1.5"/><path d="M7 16h.01M11 16h.01M8 12V9M16 12V9M5.5 6.5a9 9 0 0 1 13 0"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  attacker: '<circle cx="12" cy="11" r="7"/><path d="M9 10h.01M15 10h.01M9.5 14.5h5M9 18v3M15 18v3M12 18v3"/>',
  c2: '<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M7.5 6.5h.01M7.5 17.5h.01M14 5l3 3M17 5l-3 3"/>',
  device: '<rect x="6" y="3" width="12" height="18" rx="2"/><path d="M11 18h2"/>',
  group: '<rect x="3" y="4" width="8" height="6" rx="1"/><rect x="13" y="4" width="8" height="6" rx="1"/><rect x="8" y="14" width="8" height="6" rx="1"/>',
  cloud: '<path d="M7 18h10a4 4 0 0 0 .6-7.96A6 6 0 0 0 6.2 11.2 3.4 3.4 0 0 0 7 18z"/>',
};
const NW = 196, NH = 56;

function makeGraph(host) {
  const A = S.A, cap = S.cap;
  const G = { active: true, sel: null, hover: null, vx: 0, vy: 0, k: 1 };
  const scope = ip => (!isIp(ip) || /^(22[4-9]|23\d)\./.test(ip) || ip === '255.255.255.255' || ip === '0.0.0.0' || ip.toLowerCase().startsWith('ff')) ? 'l2' : isPrivate(ip) ? 'lan' : 'wan';
  // ---------- facts ----------
  const tEdge = new Map(), tHosts = new Set(), steps = new Map();
  (cap.flow ? cap.flow.steps : []).forEach((s, i) => steps.set(s.d.id, i + 1));
  cap.threats.forEach(d => (d.targets || [d.dst]).forEach(t => {
    if (!A.hosts.has(d.src) || !A.hosts.has(t)) return;
    const k = d.src < t ? d.src + '|' + t : t + '|' + d.src; let e = tEdge.get(k);
    if (!e) { e = { sev: d.sev, from: d.src, to: t, ids: [] }; tEdge.set(k, e); }
    if (SEV_RANK[d.sev] > SEV_RANK[e.sev]) { e.sev = d.sev; e.from = d.src; e.to = t; }
    e.ids.push(d.id); tHosts.add(d.src); tHosts.add(t);
  }));
  const peers = new Map();
  for (const p of A.pairs.values()) { if (p.a === p.b) continue; for (const x of [p.a, p.b]) { if (!peers.has(x)) peers.set(x, []); peers.get(x).push(p); } }
  // services offered, names and gateway
  const svc = new Map();
  for (const i of A.streams) { const st = cap.streams[i]; if (st.ba > 0 && st.bp < 49152) { if (!svc.has(st.b)) svc.set(st.b, new Map()); const nm = (st.l4 === 'TCP' ? TCP_PORTS : UDP_PORTS)[st.bp] || (st.l4.toLowerCase() + '/' + st.bp); svc.get(st.b).set(nm, (svc.get(st.b).get(nm) || 0) + st.bytes); } }
  const names = new Map();
  for (const r of cap.pk) { const s = r.s; if (s.dhcp && s.dhcp.host && s.dhcp.yiaddr && s.dhcp.yiaddr !== '0.0.0.0') names.set(s.dhcp.yiaddr, s.dhcp.host); if (s.dns && s.dns.qr && s.proto === 'DNS') for (const a of s.dns.ans) if (a.type === 'A' && !names.has(a.val)) names.set(a.val, s.dns.qs[0] ? s.dns.qs[0].name : a.name); if (s.sni && s.tlsHello === 'client') names.set(s.dst, s.sni); if (s.http && !s.http.resp && s.http.host && !isIp(s.http.host.split(':')[0]) && scope(s.dst) === 'wan') names.set(s.dst, s.http.host.split(':')[0]); }
  if (cap.macIp) { const dhcpMac = new Map(); cap.pk.forEach(r => { if (r.s.dhcp && r.s.dhcp.host) dhcpMac.set(r.s.dhcp.mac, r.s.dhcp.host); }); cap.macIp.forEach((ips, m) => { if (dhcpMac.has(m)) ips.forEach(ip => { if (!names.has(ip)) names.set(ip, dhcpMac.get(m)); }); }); }
  const gwMacCount = new Map(); for (const r of cap.pk) { const s = r.s; if (s.smac && scope(s.src) === 'wan') gwMacCount.set(s.smac, (gwMacCount.get(s.smac) || 0) + 1); }
  const gwMac = [...gwMacCount.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  const gwIps = new Set(gwMac && cap.macIp && cap.macIp.get(gwMac) ? [...cap.macIp.get(gwMac)] : []);

  // ---------- choose nodes ----------
  const hostsSorted = [...A.hosts.values()].sort((a, b) => (b.tx + b.rx) - (a.tx + a.rx));
  const important = h => tHosts.has(h.ip) || S.roles.has(h.ip);
  const shown = new Set(), groupOf = new Map(), groups = new Map();
  const lanAll = hostsSorted.filter(h => scope(h.ip) === 'lan' || (scope(h.ip) === 'l2' && S.roles.has(h.ip)));
  const wanAll = hostsSorted.filter(h => scope(h.ip) === 'wan');
  const addGroup = (h, peer, zone, why) => { const key = 'group:' + zone + ':' + peer; let g = groups.get(key); if (!g) { g = { key, peer, scope: zone, zone, members: [], tx: 0, rx: 0, why }; groups.set(key, g); } g.members.push(h.ip); g.tx += h.tx; g.rx += h.rx; groupOf.set(h.ip, key); };
  const mainPeer = ip => { const ps = peers.get(ip) || []; let best = null, bb = -1; for (const p of ps) { const o = p.a === ip ? p.b : p.a; const b = p.ab + p.ba; if (b > bb) { bb = b; best = o; } } return best; };
  lanAll.forEach((h, i) => { const ps = peers.get(h.ip) || []; if (!important(h) && i > 3 && ps.length <= 1 && h.tx + h.rx < 20000) addGroup(h, mainPeer(h.ip) || '?', 'lan', 'all with'); else shown.add(h.ip); });
  let wanShown = 0;
  wanAll.forEach(h => { if (important(h) || (wanShown < 6 && (peers.get(h.ip) || []).length >= 1 && h.tx + h.rx > 4000)) { shown.add(h.ip); wanShown++; } else addGroup(h, mainPeer(h.ip) || '?', 'wan', 'all with'); });
  for (const [k, g] of groups) if (g.members.length === 1 && g.zone === 'lan') { shown.add(g.members[0]); groupOf.delete(g.members[0]); groups.delete(k); }
  const nodes = [], byId = new Map();
  const mk = n => { n.w = NW; n.h = NH; nodes.push(n); byId.set(n.id, n); };
  for (const ip of shown) {
    const h = A.hosts.get(ip), role = S.roles.get(ip), zone = scope(ip) === 'wan' ? 'wan' : 'lan';
    const sv = svc.get(ip) ? [...svc.get(ip).entries()].sort((a, b) => b[1] - a[1]).map(x => x[0]) : [];
    let icon = zone === 'wan' ? 'globe' : sv.length ? 'server' : 'workstation';
    if (gwIps.has(ip)) icon = 'router'; if (!isIp(ip)) icon = 'device';
    if (role === 'Attacker' || role === 'Rogue insider') icon = 'attacker'; if (role === 'C2 server' || role === 'Malware host') icon = 'c2';
    let sub = names.get(ip) || '';
    if (!sub) sub = gwIps.has(ip) ? 'Gateway' + (sv.length ? ', ' + sv.slice(0, 2).join(', ') : '') : sv.length ? sv.slice(0, 3).join(', ') + ' server' : zone === 'lan' ? (isIp(ip) ? 'Workstation' : 'Unknown device') : 'Internet host';
    mk({ id: ip, label: ip, sub, icon, zone, role, host: h, bytes: h.tx + h.rx, isServer: sv.length > 0 });
  }
  for (const g of groups.values()) mk({ id: g.key, label: '+' + g.members.length + (g.zone === 'wan' ? ' internet hosts' : ' local hosts'), sub: (g.why || 'via') + ' ' + g.peer, icon: g.zone === 'wan' ? 'cloud' : 'group', zone: g.zone, group: g, host: { ip: g.key, tx: g.tx, rx: g.rx }, bytes: g.tx + g.rx });
  const resolve = ip => byId.has(ip) ? ip : (groupOf.has(ip) && byId.has(groupOf.get(ip)) ? groupOf.get(ip) : null);
  const emap = new Map();
  for (const p of A.pairs.values()) {
    const a = resolve(p.a), b = resolve(p.b); if (!a || !b || a === b) continue;
    const k = a < b ? a + '|' + b : b + '|' + a;
    let e = emap.get(k); if (!e) { e = { a: byId.get(a < b ? a : b), b: byId.get(a < b ? b : a), bytes: 0, protos: new Map(), t: null }; emap.set(k, e); }
    e.bytes += p.ab + p.ba; p.protos.forEach((v, pr) => e.protos.set(pr, (e.protos.get(pr) || 0) + v));
  }
  for (const t of tEdge.values()) {
    const a = resolve(t.from), b = resolve(t.to); if (!a || !b || a === b) continue;
    const e = emap.get(a < b ? a + '|' + b : b + '|' + a); if (!e) continue;
    if (!e.t || SEV_RANK[t.sev] > SEV_RANK[e.t.sev]) e.t = { sev: t.sev, from: byId.get(a), ids: [] };
    e.t.ids.push(...t.ids);
  }
  const edges = [...emap.values()];
  const maxE = Math.max(1, ...edges.map(e => e.bytes));
  edges.forEach(e => { e.w = 1 + Math.log1p(e.bytes) / Math.log1p(maxE) * 2.2; if (e.t) e.t.ids = [...new Set(e.t.ids)].sort((x, y) => (steps.get(x) || 0) - (steps.get(y) || 0)); });

  // ---------- layout ----------
  const wan = nodes.filter(n => n.zone === 'wan'), lan = nodes.filter(n => n.zone === 'lan');
  const roleRank = n => ({ 'Attacker': 0, 'Botnet / spoofed': 1, 'Malware host': 2, 'C2 server': 3 }[n.role] ?? 5);
  wan.sort((a, b) => (a.group ? 1 : 0) - (b.group ? 1 : 0) || roleRank(a) - roleRank(b) || b.bytes - a.bytes);
  const lanRank = n => n.icon === 'router' ? 0 : n.isServer ? 1 : n.role ? 2 : n.group ? 4 : 3;
  lan.sort((a, b) => lanRank(a) - lanRank(b) || b.bytes - a.bytes);
  const PX = 236, PY = 92, GX = PX - NW, GY = PY - NH;
  const wcols = Math.max(1, Math.min(4, wan.length)), lcols = Math.max(1, Math.min(4, lan.length));
  const wrows = Math.ceil(wan.length / wcols), lrows = Math.ceil(lan.length / lcols);
  const crossN = edges.filter(e => e.a.zone !== e.b.zone).length;
  const BAND = Math.max(90, Math.min(200, 40 + crossN * 6));
  const totalW = Math.max(wcols, lcols) * PX;
  const wanY = 76, lanY = wanY + wrows * PY + 70 + BAND;
  const layout = () => {
    const wx = (totalW - wcols * PX) / 2, lx = (totalW - lcols * PX) / 2;
    wan.forEach((n, i) => { n.col = i % wcols; n.row = Math.floor(i / wcols); n.x = wx + n.col * PX + GX / 2; n.y = wanY + n.row * PY; });
    lan.forEach((n, i) => { n.col = i % lcols; n.row = Math.floor(i / lcols); n.x = lx + n.col * PX + GX / 2; n.y = lanY + n.row * PY; });
  };
  layout();
  const zoneBox = list => { let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity; list.forEach(n => { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x + n.w); y1 = Math.max(y1, n.y + n.h); }); return list.length ? { x: x0 - 24, y: y0 - 66, w: x1 - x0 + 48, h: y1 - y0 + 90 } : null; };

  // ---------- routing: every connector runs in the free corridors between boxes ----------
  const rounded = pts => {
    const p = pts.filter((q, i) => i === 0 || q[0] !== pts[i - 1][0] || q[1] !== pts[i - 1][1]);
    const c = p.filter((q, i) => i === 0 || i === p.length - 1 || !((p[i - 1][0] === q[0] && q[0] === p[i + 1][0]) || (p[i - 1][1] === q[1] && q[1] === p[i + 1][1])));
    let d = 'M' + c[0][0] + ',' + c[0][1];
    for (let i = 1; i < c.length; i++) {
      const [x, y] = c[i];
      if (i < c.length - 1) { const [px, py] = c[i - 1], [nx, ny] = c[i + 1]; const r = Math.min(7, Math.abs(x - px) / 2 + Math.abs(y - py) / 2, Math.abs(nx - x) / 2 + Math.abs(ny - y) / 2); d += ' L' + (x - Math.sign(x - px) * r) + ',' + (y - Math.sign(y - py) * r) + ' Q' + x + ',' + y + ' ' + (x + Math.sign(nx - x) * r) + ',' + (y + Math.sign(ny - y) * r); }
      else d += ' L' + x + ',' + y;
    }
    return d;
  };
  const route = () => {
    const wanBottom = Math.max(...wan.map(n => n.y + n.h), wanY), lanTop = Math.min(...lan.map(n => n.y), lanY);
    const bandA = wanBottom + 42, bandB = lanTop - 80;
    // spread attachment points along each box edge
    const att = new Map(); const slot = (n, side) => { const k = n.id + side; att.set(k, (att.get(k) || 0) + 1); return att.get(k); };
    const order = edges.slice().sort((x, y) => ((x.a.zone === x.b.zone) - (y.a.zone === y.b.zone)) || (Math.min(x.a.x, x.b.x) - Math.min(y.a.x, y.b.x)));
    const counts = new Map(); order.forEach(e => { for (const n of [e.a, e.b]) counts.set(n.id, (counts.get(n.id) || 0) + 1); });
    const px = (n, k) => { const m = counts.get(n.id) || 1; return Math.round(n.x + n.w * (k / (m + 1))); };
    order.forEach((e, i) => {
      let s = e.a, t = e.b;
      if (e.t && e.t.from === t) [s, t] = [t, s];
      else if (s.zone === 'lan' && t.zone === 'wan') [s, t] = [t, s];
      e.from = s;
      const off = ((i % 7) - 3) * 3;
      const sDown = !(s.zone === 'lan' && t.zone === 'lan' && t.row < s.row) && !(s.zone === 'lan' && t.zone === 'wan');
      const sx = px(s, slot(s, 'x')), tx = px(t, slot(t, 'x'));
      const sy = sDown ? s.y + s.h : s.y;
      const tUp = s.zone === t.zone ? t.row > s.row || (t.row === s.row) : t.zone === 'lan';
      const ty = tUp ? t.y : t.y + t.h;
      const pts = [[sx, sy]];
      const corridorX = (n, towardX) => (towardX < n.x + n.w / 2 ? n.x - GX / 2 : n.x + n.w + GX / 2) + off;
      if (s.zone !== t.zone) {
        const lane = Math.round(bandA + (bandB - bandA) * ((i % Math.max(1, crossN)) + 0.5) / Math.max(1, crossN));
        const lastW = s.row === wrows - 1, firstL = t.row === 0;
        if (lastW) pts.push([sx, lane]);
        else { const hy = s.y + s.h + GY / 2 + off; const vx = corridorX(s, tx); pts.push([sx, hy], [vx, hy], [vx, lane]); }
        if (firstL) pts.push([tx, lane], [tx, ty]);
        else { const vx2 = corridorX(t, pts[pts.length - 1][0]); const hy2 = t.y - GY / 2 + off; pts.push([vx2, lane], [vx2, hy2], [tx, hy2], [tx, ty]); }
      } else {
        const hy = sDown ? s.y + s.h + GY / 2 + off : s.y - GY / 2 + off;
        const hy2 = tUp ? t.y - GY / 2 + off : t.y + t.h + GY / 2 + off;
        if (Math.abs(hy - hy2) < 1) pts.push([sx, hy], [tx, hy], [tx, ty]);
        else { const vx = corridorX(s, tx); pts.push([sx, hy], [vx, hy], [vx, hy2], [tx, hy2], [tx, ty]); }
      }
      e.pts = pts;
      e.lane = s.zone !== t.zone ? pts.find((p, j) => j > 0 && p[1] === pts[j - 1][1] && Math.abs(p[1] - (bandA + bandB) / 2) <= (bandB - bandA) / 2 + 1) : null;
    });
  };

  // ---------- render ----------
  host.innerHTML = '';
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'mapsvg'); host.appendChild(svg);
  const sevVar = s => 'var(' + SEV_VAR[s] + ')';
  const roleVar = r => ({ 'Attacker': 'var(--crit)', 'Botnet / spoofed': 'var(--crit)', 'Rogue insider': 'var(--crit)', 'C2 server': 'var(--high)', 'Malware host': 'var(--high)', 'Compromised host': 'var(--med)', 'At-risk host': 'var(--med)', 'Victim': 'var(--low)' }[r]);
  const tile = n => n.role && roleVar(n.role) ? roleVar(n.role) : n.zone === 'wan' ? 'var(--s7)' : n.icon === 'router' ? 'var(--teal)' : n.isServer ? 'var(--s3)' : 'var(--s1)';
  const draw = () => {
    route();
    const wb = zoneBox(wan), lb = zoneBox(lan);
    const focus = G.hover || G.sel;
    const on = e => !focus || e.a === focus || e.b === focus;
    let s = `<defs><pattern id="mdots" width="18" height="18" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="var(--dot)"/></pattern>
      ${['critical', 'high', 'medium', 'low'].map(k => `<marker id="mah-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="${sevVar(k)}"/></marker>`).join('')}</defs>
      <rect x="-5000" y="-5000" width="10000" height="10000" fill="url(#mdots)"/><g id="vp" transform="translate(${G.vx},${G.vy}) scale(${G.k})">`;
    const zone = (b, title, sub, icon, dashed) => b ? `<g class="zone"><rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="10" fill="var(--panel)" fill-opacity=".72" stroke="var(--line-2)" ${dashed ? 'stroke-dasharray="6 5"' : ''}/><g transform="translate(${b.x + 14},${b.y + 13})" stroke="var(--text-2)" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><g transform="scale(.75)">${MAP_ICON[icon]}</g></g><text x="${b.x + 40}" y="${b.y + 27}" font-size="14" font-weight="650" fill="var(--text)">${esc(title)}</text><text x="${b.x + b.w - 14}" y="${b.y + 27}" font-size="12" text-anchor="end" fill="var(--muted)">${esc(sub)}</text></g>` : '';
    const subnet = (() => { const l = lan.map(n => n.id).filter(isIp).filter(x => !x.includes(':')); if (!l.length) return ''; const p = l.map(x => x.split('.')); const same = k => p.every(q => q[k] === p[0][k]); return same(0) && same(1) && same(2) ? p[0].slice(0, 3).join('.') + '.0/24' : same(0) && same(1) ? p[0].slice(0, 2).join('.') + '.0.0/16' : ''; })();
    s += zone(wb, 'Internet', wan.reduce((a, n) => a + (n.group ? n.group.members.length : 1), 0) + ' hosts', 'cloud', true);
    s += zone(lb, 'Local network', subnet || lan.length + ' hosts', 'router', false);
    // connectors
    const ordered = edges.slice().sort((x, y) => (x.t ? 1 : 0) - (y.t ? 1 : 0) || (on(x) ? 1 : 0) - (on(y) ? 1 : 0));
    for (const e of ordered) {
      const d = rounded(e.pts); const vis = on(e);
      if (e.t) {
        const rev = e.t.from !== e.from;
        const path = rev ? rounded(e.pts.slice().reverse()) : d;
        s += `<path class="edge" data-e="${edges.indexOf(e)}" d="${path}" fill="none" stroke="${sevVar(e.t.sev)}" stroke-width="2.4" marker-end="url(#mah-${e.t.sev})" opacity="${vis ? 1 : 0.15}"/>`;
      } else s += `<path class="edge" data-e="${edges.indexOf(e)}" d="${d}" fill="none" stroke="${focus && vis ? 'var(--accent)' : 'var(--axis)'}" stroke-width="${e.w}" opacity="${vis ? (focus ? 1 : 0.85) : 0.12}"/>`;
      s += `<path class="ehit" data-e="${edges.indexOf(e)}" d="${d}" fill="none" stroke="transparent" stroke-width="10"/>`;
    }
    // step badges on attack connectors
    for (const e of edges) {
      if (!e.t || !on(e)) continue;
      const nums = e.t.ids.map(id => steps.get(id)).filter(Boolean);
      if (!nums.length) continue;
      const txt = nums.length > 4 ? nums.slice(0, 3).join(' ') + ' +' + (nums.length - 3) : nums.join(' ');
      const p = e.pts; let mid;
      const li = p.findIndex((q, j) => j > 0 && q[1] === p[j - 1][1] && Math.abs(q[0] - p[j - 1][0]) > 40);
      mid = li > 0 ? [(p[li][0] + p[li - 1][0]) / 2, p[li][1]] : [(p[0][0] + p[1][0]) / 2, (p[0][1] + p[1][1]) / 2];
      const w = 14 + txt.length * 6.4;
      s += `<g class="badge" data-ids="${e.t.ids.join(',')}" style="cursor:pointer"><rect x="${mid[0] - w / 2}" y="${mid[1] - 10}" width="${w}" height="20" rx="10" fill="var(--panel)" stroke="${sevVar(e.t.sev)}" stroke-width="1.5"/><text x="${mid[0]}" y="${mid[1] + 4}" font-size="11" font-weight="700" text-anchor="middle" fill="${sevVar(e.t.sev)}">${esc(txt)}</text></g>`;
    }
    // device boxes
    for (const n of nodes) {
      const dim = focus && n !== focus && !edges.some(e => (e.a === focus && e.b === n) || (e.b === focus && e.a === n));
      const rc = n.role && roleVar(n.role);
      s += `<g class="mnode${n === G.sel ? ' sel' : ''}" data-n="${esc(n.id)}" transform="translate(${n.x},${n.y})" opacity="${dim ? 0.35 : 1}">
        <rect width="${n.w}" height="${n.h}" rx="7" fill="var(--panel)" stroke="${n === G.sel ? 'var(--accent)' : rc || 'var(--line-2)'}" stroke-width="${n === G.sel || rc ? 2 : 1.2}" ${n.group ? 'stroke-dasharray="5 4"' : ''}/>
        <rect x="8" y="8" width="40" height="40" rx="6" fill="${tile(n)}" fill-opacity=".16"/>
        <g transform="translate(16,16)" fill="none" stroke="${tile(n)}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${MAP_ICON[n.icon]}</g>
        <text x="58" y="24" font-size="12.5" font-weight="500" fill="var(--text)" font-family="IBM Plex Mono, monospace">${esc(n.label.length > 19 ? n.label.slice(0, 18) + '…' : n.label)}</text>
        <text x="58" y="41" font-size="12" fill="var(--muted)">${esc(n.sub.length > 24 ? n.sub.slice(0, 23) + '…' : n.sub)}</text>
        ${rc && n.role ? `<g transform="translate(${n.w - 8},-9)"><rect x="${-(n.role.length * 6.3 + 14)}" width="${n.role.length * 6.3 + 14}" height="18" rx="9" fill="${rc}"/><text x="${-(n.role.length * 6.3 + 14) / 2}" y="12.5" font-size="11" font-weight="700" text-anchor="middle" fill="${n.role === 'Compromised host' || n.role === 'At-risk host' ? '#111' : '#fff'}">${esc(n.role)}</text></g>` : ''}
      </g>`;
    }
    s += '</g>';
    svg.innerHTML = s;
  };
  const fit = () => {
    const r = host.getBoundingClientRect(); if (!r.width) return;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    nodes.forEach(n => { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x + n.w); y1 = Math.max(y1, n.y + n.h); });
    x0 -= 30; y0 -= 66; x1 += 30; y1 += 30;
    G.k = Math.min(1.2, (r.width - 20) / (x1 - x0), (r.height - 60) / (y1 - y0));
    G.vx = (r.width - (x1 - x0) * G.k) / 2 - x0 * G.k; G.vy = 10 - y0 * G.k;
  };
  fit(); draw();

  // ---------- interaction ----------
  const toW = e => { const r = svg.getBoundingClientRect(); return { x: (e.clientX - r.left - G.vx) / G.k, y: (e.clientY - r.top - G.vy) / G.k }; };
  let drag = null, pan = null, moved = false, raf = 0;
  const redraw = () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; draw(); }); };
  svg.addEventListener('mousedown', e => {
    moved = false; const g = e.target.closest('.mnode');
    if (g) { const n = byId.get(g.dataset.n), p = toW(e); drag = { n, dx: p.x - n.x, dy: p.y - n.y }; }
    else if (!e.target.closest('.badge')) pan = { x: e.clientX, y: e.clientY, vx: G.vx, vy: G.vy };
    host.classList.add('drag'); e.preventDefault();
  });
  window.addEventListener('mousemove', G._mm = e => {
    if (drag) { const p = toW(e); drag.n.x = Math.round((p.x - drag.dx) / 6) * 6; drag.n.y = Math.round((p.y - drag.dy) / 6) * 6; moved = true; redraw(); return; }
    if (pan) { G.vx = pan.vx + e.clientX - pan.x; G.vy = pan.vy + e.clientY - pan.y; moved = true; svg.querySelector('#vp').setAttribute('transform', `translate(${G.vx},${G.vy}) scale(${G.k})`); }
  });
  window.addEventListener('mouseup', G._mu = () => {
    if (drag && !moved) select(drag.n.id); else if (pan && !moved) select(null);
    drag = null; pan = null; host.classList.remove('drag');
  });
  svg.addEventListener('mousemove', e => {
    if (drag || pan) return;
    const g = e.target.closest('.mnode'), ed = e.target.closest('.ehit'), b = e.target.closest('.badge');
    const n = g ? byId.get(g.dataset.n) : null;
    if (n !== G.hover) { G.hover = n; redraw(); }
    if (n) tip(`<div class="tt-h ${n.group ? '' : 'mono'}">${esc(n.label)}</div><div class="tt-r"><span>${esc(n.sub)}</span></div>${n.role ? `<div class="tt-r"><span>Role in attack</span><b>${esc(n.role)}</b></div>` : ''}<div class="tt-r"><span><i style="background:var(--s1)"></i>Sent</span><b>${fmtBytes(n.host.tx)}</b></div><div class="tt-r"><span><i style="background:var(--s2)"></i>Received</span><b>${fmtBytes(n.host.rx)}</b></div><div class="hint" style="margin-top:4px">Drag to move. Double-click to filter.</div>`, e);
    else if (b) tip(b.dataset.ids.split(',').map(id => { const d = cap.threats[+id]; return `<div style="margin:2px 0">${sevBadge(d.sev)} <b>${steps.get(d.id)}.</b> ${esc(d.title)}</div>`; }).join('') + '<div class="hint" style="margin-top:4px">Click to open in the attack flow</div>', e);
    else if (ed) { const x = edges[+ed.dataset.e]; const pr = [...x.protos.entries()].sort((a, c) => c[1] - a[1]).slice(0, 4); tip(`<div class="tt-h mono">${esc(x.a.label)} ⇄ ${esc(x.b.label)}</div>${pr.map(([p, v]) => `<div class="tt-r"><span><i style="background:${col(p)}"></i>${esc(p)}</span><b>${fmtBytes(v)}</b></div>`).join('')}${x.t ? `<div class="tt-r"><span>${sevBadge(x.t.sev)}</span><b>${x.t.ids.length} detection${x.t.ids.length > 1 ? 's' : ''}</b></div>` : ''}`, e); }
    else untip();
  });
  svg.addEventListener('mouseleave', () => { untip(); if (G.hover) { G.hover = null; redraw(); } });
  svg.addEventListener('click', e => { const b = e.target.closest('.badge'); if (b) { S.tsel = +b.dataset.ids.split(',')[0]; S.dirty.threats = 1; go('threats'); } });
  svg.addEventListener('dblclick', e => { const g = e.target.closest('.mnode'); if (g) { const n = byId.get(g.dataset.n); if (!n.group) setChip('host', { v: n.id }); } });
  svg.addEventListener('wheel', e => { e.preventDefault(); const r = svg.getBoundingClientRect(); const mx = e.clientX - r.left, my = e.clientY - r.top; const k = Math.max(0.25, Math.min(3, G.k * Math.exp(-e.deltaY * 0.0015))); G.vx = mx - (mx - G.vx) * k / G.k; G.vy = my - (my - G.vy) * k / G.k; G.k = k; svg.querySelector('#vp').setAttribute('transform', `translate(${G.vx},${G.vy}) scale(${G.k})`); }, { passive: false });
  function select(id) { const n = id ? byId.get(id) || null : null; G.sel = n; draw(); if (!n) sideDefault(); else if (n.group) sideCluster(n.group); else sideHost(id); }
  G.select = id => { if (id && !byId.has(id) && groupOf.has(id)) id = groupOf.get(id); select(id); };
  G.kick = () => { fit(); draw(); };
  G.relayout = () => { layout(); fit(); draw(); };
  G.destroy = () => { window.removeEventListener('mousemove', G._mm); window.removeEventListener('mouseup', G._mu); };
  return G;
}
function sideCluster(c) {
  $('#gside').innerHTML = `<div class="card-h"><h3>${c.members.length} ${c.scope === 'wan' ? 'internet' : 'local'} hosts</h3><span class="sp"></span><button class="btn sm ghost" id="gback">${SVGI(IC.x, 13)}</button></div><div class="card-b">
    <p class="hint" style="margin:0 0 10px">These hosts mostly talked to <span class="mono">${esc(c.peer)}</span>, so the map draws them as one group.</p>
    <dl class="kv"><dt>Sent</dt><dd>${fmtBytes(c.tx)}</dd><dt>Received</dt><dd>${fmtBytes(c.rx)}</dd></dl>
    <div class="scroll" style="max-height:420px;margin-top:10px"><table class="tbl"><tbody>${c.members.slice(0, 400).map(m => { const h = S.A.hosts.get(m); return `<tr data-ip="${esc(m)}"><td class="mono">${esc(m)}</td><td class="r">${fmtBytes(h.tx + h.rx)}</td></tr>`; }).join('')}</tbody></table></div></div>`;
  $('#gback').onclick = () => S.graph.select(null);
  $$('#gside tr[data-ip]').forEach(tr => tr.onclick = () => setChip('host', { v: tr.dataset.ip }));
}

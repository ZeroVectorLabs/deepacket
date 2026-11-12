/* ===================== Loading & post-processing ===================== */
async function loadCapture(u8, name, onProgress) {
  const fmt = captureFormat(u8);
  if (!fmt) throw new Error('Not a pcap or pcapng file (unrecognised magic number). Try exporting from Wireshark as .pcap or .pcapng.');
  const it = fmt === 'pcap' ? readPcap(u8) : readPcapng(u8);
  const pk = [];
  let last = performance.now();
  for (const r of it) {
    r.i = pk.length;
    r.s = dissect(u8.subarray(r.off, r.off + r.cap), r.lt, null);
    pk.push(r);
    if ((pk.length & 2047) === 0 && performance.now() - last > 60) {
      onProgress && onProgress(r.off / u8.length, pk.length);
      await new Promise(res => setTimeout(res, 0));
      last = performance.now();
    }
  }
  if (!pk.length) throw new Error('The capture contains no packets.');
  onProgress && onProgress(1, pk.length);
  const cap = { name, fmt, u8, pk, size: u8.length };
  postProcess(cap);
  return cap;
}

function pkBytes(cap, i) { const r = cap.pk[i]; return cap.u8.subarray(r.off, r.off + r.cap); }
function payloadText(cap, i, max) { const r = cap.pk[i], s = r.s; if (!s.pll) return ''; return latin(cap.u8, r.off + s.plo, r.off + s.plo + s.pll, max || 4096); }

function postProcess(cap) {
  const pk = cap.pk;
  let t0 = Infinity, t1 = -Infinity, bytes = 0;
  for (const r of pk) { if (r.t < t0) t0 = r.t; if (r.t > t1) t1 = r.t; bytes += r.len; }
  cap.t0 = t0; cap.t1 = t1; cap.bytes = bytes; cap.dur = Math.max(t1 - t0, 1e-6);
  // streams
  const map = new Map(), streams = [];
  for (const r of pk) {
    const s = r.s;
    if (s.sp < 0 || !s.src) continue;
    const a = s.src + '|' + s.sp, b = s.dst + '|' + s.dp;
    const fwd = a < b;
    const key = s.l4 + '|' + (fwd ? a + '|' + b : b + '|' + a);
    let st = map.get(key);
    if (!st) {
      st = { id: streams.length, l4: s.l4, a: s.src, ap: s.sp, b: s.dst, bp: s.dp, pk: [], bytes: 0, ab: 0, ba: 0, t0: r.t, t1: r.t, isn: {}, proto: s.proto, syn: false, client: null, payload: 0 };
      map.set(key, st); streams.push(st);
    }
    const dirA = s.src === st.a && s.sp === st.ap;
    s.st = st.id; s.dirA = dirA;
    st.pk.push(r.i); st.bytes += r.len; if (dirA) st.ab += r.len; else st.ba += r.len;
    st.t1 = r.t; st.payload += s.pll;
    if (s.proto !== 'TCP' && s.proto !== 'UDP' && (st.proto === 'TCP' || st.proto === 'UDP')) st.proto = s.proto;
    if (s.l4 === 'TCP') {
      const side = dirA ? 'a' : 'b', other = dirA ? 'b' : 'a';
      if ((s.fl & 2) && !(s.fl & 16)) { st.syn = true; st.client = st.client || (dirA ? 'a' : 'b'); st.isn[side] = s.seq; }
      else if ((s.fl & 2) && (s.fl & 16)) st.isn[side] = s.seq;
      if (st.isn[side] === undefined) st.isn[side] = s.seq;
      if (s.ti) {
        const rel = (s.seq - st.isn[side] + 4294967296) % 4294967296;
        const ra = st.isn[other] !== undefined ? (s.ack - st.isn[other] + 4294967296) % 4294967296 : s.ack;
        s.info = s.sp + ' → ' + s.dp + ' [' + tcpFlagStr(s.fl) + '] Seq=' + rel + (s.fl & 16 ? ' Ack=' + ra : '') + ' Win=' + s.win + ' Len=' + s.pll;
      }
    } else if (!st.client) st.client = 'a';
    // HTTP request/response pairing
    if (s.http) {
      if (!s.http.resp) { (st.pend || (st.pend = [])).push(r.i); }
      else if (st.pend && st.pend.length) { const q = st.pend.shift(); pk[q].s.http.status = s.http.status; pk[q].s.http.respIdx = r.i; s.http.reqIdx = q; }
    }
  }
  for (const st of streams) {
    if (st.client === 'b') { // normalise so a = client
      [st.a, st.b] = [st.b, st.a]; [st.ap, st.bp] = [st.bp, st.ap]; [st.ab, st.ba] = [st.ba, st.ab];
      st.isn = { a: st.isn.b, b: st.isn.a };
      for (const i of st.pk) pk[i].s.dirA = !pk[i].s.dirA;
    }
    if (!st.client && st.l4 === 'TCP' && st.ap < st.bp && st.ap < 1024) { // guess client by port
      [st.a, st.b] = [st.b, st.a]; [st.ap, st.bp] = [st.bp, st.ap]; [st.ab, st.ba] = [st.ba, st.ab];
      for (const i of st.pk) pk[i].s.dirA = !pk[i].s.dirA;
    }
    delete st.pend;
  }
  cap.streams = streams;
  // MAC → IP map for labelling
  const macIp = new Map();
  for (const r of pk) { const s = r.s; if (s.smac && s.ipv === 4 && isPrivate(s.src)) { if (!macIp.has(s.smac)) macIp.set(s.smac, new Set()); macIp.get(s.smac).add(s.src); } }
  cap.macIp = macIp;
  cap.threats = detectThreats(cap);
  cap.flow = buildAttackFlow(cap, cap.threats);
}

/* ===================== Aggregation (respects filters) ===================== */
function aggregate(cap, idx) {
  const pk = cap.pk;
  const A = { n: 0, bytes: 0, t0: Infinity, t1: -Infinity, protos: new Map(), hosts: new Map(), pairs: new Map(), ports: new Map(), sizes: new Array(7).fill(0), dns: new Map(), sni: new Map(), http: [], streams: new Set() };
  const SZ = [64, 128, 256, 512, 1024, 1518];
  const host = ip => { let h = A.hosts.get(ip); if (!h) { h = { ip, tx: 0, rx: 0, ptx: 0, prx: 0, protos: new Map() }; A.hosts.set(ip, h); } return h; };
  const n = idx ? idx.length : pk.length;
  for (let k = 0; k < n; k++) {
    const r = pk[idx ? idx[k] : k], s = r.s, L = r.len;
    A.n++; A.bytes += L; if (r.t < A.t0) A.t0 = r.t; if (r.t > A.t1) A.t1 = r.t;
    let pr = A.protos.get(s.proto); if (!pr) { pr = { name: s.proto, p: 0, b: 0 }; A.protos.set(s.proto, pr); } pr.p++; pr.b += L;
    let b = 0; while (b < SZ.length && L > SZ[b]) b++; A.sizes[b]++;
    if (s.src && s.dst) {
      const hs = host(s.src), hd = host(s.dst);
      hs.tx += L; hs.ptx++; hd.rx += L; hd.prx++;
      hs.protos.set(s.proto, (hs.protos.get(s.proto) || 0) + L);
      const fwd = s.src < s.dst, key = fwd ? s.src + '|' + s.dst : s.dst + '|' + s.src;
      let c = A.pairs.get(key);
      if (!c) { c = { a: fwd ? s.src : s.dst, b: fwd ? s.dst : s.src, ab: 0, ba: 0, p: 0, protos: new Map(), t0: r.t, t1: r.t }; A.pairs.set(key, c); }
      if (fwd) c.ab += L; else c.ba += L; c.p++; c.t1 = r.t;
      c.protos.set(s.proto, (c.protos.get(s.proto) || 0) + L);
    }
    if (s.st !== undefined) A.streams.add(s.st);
    if (s.dp >= 0) {
      const st = s.st !== undefined ? cap.streams[s.st] : null;
      const port = st ? st.bp : Math.min(s.sp, s.dp);
      const key = s.l4 + '/' + port;
      let po = A.ports.get(key); if (!po) { po = { key, l4: s.l4, port, p: 0, b: 0, name: (s.l4 === 'TCP' ? TCP_PORTS : UDP_PORTS)[port] || '' }; A.ports.set(key, po); }
      po.p++; po.b += L;
    }
    if (s.dns) {
      const q = s.dns.qs[0];
      if (q) {
        const nm = q.name.toLowerCase();
        let d = A.dns.get(nm); if (!d) { d = { name: nm, q: 0, r: 0, types: new Set(), ans: new Set(), nx: 0, clients: new Set(), first: r.i }; A.dns.set(nm, d); }
        d.types.add(q.type);
        if (s.dns.qr) { d.r++; if (s.dns.rcode === 3) d.nx++; s.dns.ans.forEach(a => { if (a.type === 'A' || a.type === 'AAAA' || a.type === 'CNAME') d.ans.add(a.val); }); }
        else { d.q++; d.clients.add(s.src); }
      }
    }
    if (s.sni && s.tlsHello === 'client') {
      let t = A.sni.get(s.sni); if (!t) { t = { name: s.sni, n: 0, clients: new Set(), servers: new Set(), first: r.i, alpn: s.alpn || '', bytes: 0 }; A.sni.set(s.sni, t); }
      t.n++; t.clients.add(s.src); t.servers.add(s.dst);
      if (s.st !== undefined) t.bytes += cap.streams[s.st].bytes;
    }
    if (s.http && !s.http.resp) A.http.push(r.i);
  }
  if (!isFinite(A.t0)) { A.t0 = cap.t0; A.t1 = cap.t0; }
  return A;
}

/* ===================== Threat detection ===================== */
function isPrivate(ip) {
  if (!ip) return false;
  if (ip.includes(':')) { const l = ip.toLowerCase(); return l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('ff'); }
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return true; // MAC addresses etc.
  return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] < 32) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] >= 224 || p[0] === 0 || ip === '255.255.255.255';
}
function isMac(x) { return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(x); }
function isIp(x) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(x) || (x.includes(':') && !isMac(x) && /^[0-9a-f:.]+$/i.test(x)); }
function entropy(str) { const m = {}; for (const c of str) m[c] = (m[c] || 0) + 1; let e = 0; const n = str.length; for (const k in m) { const p = m[k] / n; e -= p * Math.log2(p); } return e; }
function baseDomain(n) { const p = n.toLowerCase().replace(/\.$/, '').split('.'); if (p.length <= 2) return p.join('.'); const sl = p[p.length - 2]; if (['co', 'com', 'net', 'org', 'gov', 'ac', 'edu'].includes(sl) && p[p.length - 1].length === 2) return p.slice(-3).join('.'); return p.slice(-2).join('.'); }
function safeDecode(x) { try { return decodeURIComponent(x.replace(/\+/g, ' ')); } catch (e) { return x; } }
function mask(pw) { if (!pw) return ''; return pw.length <= 2 ? '••' : pw[0] + '•'.repeat(Math.min(10, pw.length - 2)) + pw[pw.length - 1]; }

const STAGES = [
  { k: 'recon', name: 'Reconnaissance', ta: 'TA0043' },
  { k: 'access', name: 'Initial Access', ta: 'TA0001' },
  { k: 'exec', name: 'Execution', ta: 'TA0002' },
  { k: 'cred', name: 'Credential Access', ta: 'TA0006' },
  { k: 'disc', name: 'Discovery', ta: 'TA0007' },
  { k: 'lateral', name: 'Lateral Movement', ta: 'TA0008' },
  { k: 'c2', name: 'Command & Control', ta: 'TA0011' },
  { k: 'exfil', name: 'Exfiltration', ta: 'TA0010' },
  { k: 'impact', name: 'Impact', ta: 'TA0040' },
];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const AUTH_PORTS = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP', 445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis' };
const ADMIN_PORTS = { 22: 'SSH', 23: 'Telnet', 135: 'MSRPC', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM', 5900: 'VNC' };
const BAD_PORTS = { 4444: 'Metasploit default', 1337: 'leet', 31337: 'Back Orifice / elite', 6666: 'IRC/backdoor', 6667: 'IRC', 12345: 'NetBus', 5555: 'common RAT / ADB', 9001: 'Tor ORPort', 4445: 'Metasploit alt', 1234: 'common backdoor' };
const WEB_RULES = [
  { k: 'cmdi', name: 'Command injection', sev: 'critical', re: /((;|\|\|?|`|&&)\s*(cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python\d?|perl|powershell|ping|rm|chmod)\b|\$\((cat|id|whoami|curl|wget)|\/bin\/(ba)?sh\b|cmd\.exe|nc\s+-e)/i },
  { k: 'log4j', name: 'Log4Shell (JNDI injection)', sev: 'critical', re: /\$\{(jndi|\$\{lower:j|\$\{::-j|\$\{env:)/i, hdr: true },
  { k: 'shellshock', name: 'Shellshock (CVE-2014-6271)', sev: 'critical', re: /\(\)\s*\{\s*:?\s*;?\s*\}\s*;/, hdr: true },
  { k: 'sqli', name: 'SQL injection', sev: 'high', re: /(=[\w-]*'(\s|&|$)|\bunion\b[\s\S]{0,40}\bselect\b|information_schema|'\s*or\s*'?\w*'?\s*=\s*'?\w*|\bor\s+1\s*=\s*1\b|\band\s+\d+\s*=\s*\d+|\bsleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay|order\s+by\s+\d+\s*--|;\s*drop\s+table|xp_cmdshell|load_file\s*\(|into\s+outfile|'\s*--)/i },
  { k: 'lfi', name: 'Path traversal / LFI', sev: 'high', re: /(\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini|\/proc\/self\/)/i },
  { k: 'xss', name: 'Cross-site scripting', sev: 'medium', re: /(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*\son\w+=|document\.cookie|alert\s*\()/i },
];
const TOOL_UA = /(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|\bdirb\b|wfuzz|ffuf|feroxbuster|nuclei|acunetix|nessus|openvas|hydra|metasploit|wpscan|havij|w3af|arachni|skipfish|commix|xsstrike)/i;

function detectThreats(cap) {
  const pk = cap.pk, streams = cap.streams, D = [];
  const add = d => { d.id = D.length; d.ev = d.ev || []; d.t0 = d.t0 ?? pk[d.ev[0]]?.t; d.t1 = d.t1 ?? pk[d.ev[d.ev.length - 1]]?.t; D.push(d); };
  const pairKey = (a, b) => a + '→' + b;

  // ---------- gather TCP/UDP/ICMP/ARP facts in one pass ----------
  const synBy = new Map();     // src→dst : {ports:Set, ev:[], t0,t1, kinds}
  const synAns = new Map();    // dst→src : {open:Set, closed:Set, ev:[]}
  const synToPort = new Map(); // dst|port : {n, srcs:Set, ev:[], times:[]}
  const echoBy = new Map();    // src : {dsts:Set, ev:[]}
  const echoRep = new Map();   // replier→src
  const udpProbe = new Map();  // src→dst : ports
  const unreach = new Map();
  const arpReq = new Map();    // smac : Set targets, ev
  const arpClaims = new Map(); // ip : Map mac→{n, ev:[], unsolicited}
  const arpAsked = new Set();
  const icmpBig = new Map();
  const dhcpServers = new Map(), dhcpDisc = new Map();
  const heart = [];
  for (const r of pk) {
    const s = r.s;
    if (s.l4 === 'TCP' && s.sp >= 0) {
      const f = s.fl;
      const probe = ((f & 2) && !(f & 16)) || f === 0 || f === 1 || (f & 0x29) === 0x29 && !(f & 16);
      if (probe) {
        const k = pairKey(s.src, s.dst);
        let o = synBy.get(k); if (!o) { o = { src: s.src, dst: s.dst, ports: new Set(), ev: [], kinds: new Set() }; synBy.set(k, o); }
        if (!o.ports.has(s.dp)) { o.ports.add(s.dp); o.ev.push(r.i); } o.kinds.add(f === 0 ? 'NULL' : f === 1 ? 'FIN' : (f & 0x29) === 0x29 ? 'Xmas' : 'SYN');
        if (f & 2) {
          const pk2 = s.dst + '|' + s.dp;
          let q = synToPort.get(pk2); if (!q) { q = { dst: s.dst, port: s.dp, n: 0, srcs: new Set(), ev: [], acked: 0 }; synToPort.set(pk2, q); }
          q.n++; q.srcs.add(s.src); q.ev.push(r.i);
        }
      } else if ((f & 2) && (f & 16) || (f & 4)) {
        const k = pairKey(s.dst, s.src);
        let o = synAns.get(k); if (!o) { o = { open: new Set(), closed: new Set(), ev: [] }; synAns.set(k, o); }
        if (f & 2) o.open.add(s.sp); else o.closed.add(s.sp);
        o.ev.push(r.i);
      }
    }
    if (s.l4 === 'UDP' && s.sp >= 0 && s.pll < 64 && !s.dns) {
      const k = pairKey(s.src, s.dst);
      let o = udpProbe.get(k); if (!o) { o = { src: s.src, dst: s.dst, ports: new Set(), ev: [] }; udpProbe.set(k, o); }
      o.ports.add(s.dp); o.ev.push(r.i);
    }
    if (s.icmp) {
      const ty = s.icmp.type;
      if ((ty === 8 && !s.icmp.v6) || (ty === 128 && s.icmp.v6)) {
        let o = echoBy.get(s.src); if (!o) { o = { dsts: new Set(), ev: [] }; echoBy.set(s.src, o); }
        o.dsts.add(s.dst); o.ev.push(r.i);
        if (s.pll >= 120) { const k = pairKey(s.src, s.dst); let b = icmpBig.get(k); if (!b) { b = { src: s.src, dst: s.dst, ev: [], bytes: 0 }; icmpBig.set(k, b); } b.ev.push(r.i); b.bytes += s.pll; }
      }
      if ((ty === 0 && !s.icmp.v6) || (ty === 129 && s.icmp.v6)) { let o = echoRep.get(s.dst); if (!o) { o = new Set(); echoRep.set(s.dst, o); } o.add(s.src); }
      if (ty === 3 && s.icmp.code === 3 && s.icmp.inner) { const k = pairKey(s.icmp.inner.src, s.icmp.inner.dst); unreach.set(k, (unreach.get(k) || 0) + 1); }
    }
    if (s.arp) {
      const a = s.arp;
      if (a.op === 1) {
        arpAsked.add(a.tpa);
        if (a.spa !== a.tpa) { let o = arpReq.get(a.sha); if (!o) { o = { tg: new Set(), ev: [], ip: a.spa }; arpReq.set(a.sha, o); } o.tg.add(a.tpa); o.ev.push(r.i); }
      }
      if (a.spa !== '0.0.0.0') {
        let m = arpClaims.get(a.spa); if (!m) { m = new Map(); arpClaims.set(a.spa, m); }
        let c = m.get(a.sha); if (!c) { c = { n: 0, ev: [], unsol: 0, first: r.t }; m.set(a.sha, c); }
        c.n++; c.ev.push(r.i);
        if (a.op === 2 && !arpAsked.has(a.spa)) c.unsol++;
        if (a.op === 2) arpAsked.delete(a.spa);
      }
    }
    if (s.dhcp) {
      if (s.dhcp.type === 2 || s.dhcp.type === 5) { const sv = s.dhcp.server || s.src; let o = dhcpServers.get(sv); if (!o) { o = { ev: [], mac: s.smac }; dhcpServers.set(sv, o); } o.ev.push(r.i); }
      if (s.dhcp.type === 1) { let o = dhcpDisc.get('all'); if (!o) { o = { macs: new Set(), ev: [] }; dhcpDisc.set('all', o); } o.macs.add(s.dhcp.mac); o.ev.push(r.i); }
    }
    if (s.heartbeat && s.heartbeat.payloadLen > s.heartbeat.len) heart.push(r.i);
  }

  // ---------- 1. Port scans ----------
  for (const o of synBy.values()) {
    if (o.ports.size < 15) continue;
    const ans = synAns.get(pairKey(o.src, o.dst)) || { open: new Set(), closed: new Set(), ev: [] };
    const ext = !isPrivate(o.src);
    const ta = pk[o.ev[0]].t, tb = pk[o.ev[o.ev.length - 1]].t + 2;
    const ansEv = ans.ev.filter(i => pk[i].t >= ta && pk[i].t <= tb);
    const openS = new Set(), closedS = new Set();
    ansEv.forEach(i => { const s = pk[i].s; if (s.fl & 2) openS.add(s.sp); else closedS.add(s.sp); });
    ans.open = openS; ans.closed = closedS; ans.ev = ansEv;
    const open = [...openS].sort((a, b) => a - b);
    const kinds = [...o.kinds].join('/');
    add({
      type: 'portscan', title: 'TCP ' + kinds + ' port scan', sev: open.length ? 'high' : 'medium',
      stage: ext ? 'recon' : 'disc', tech: ext ? 'T1595.001' : 'T1046', techName: ext ? 'Active Scanning: Scanning IP Blocks' : 'Network Service Discovery',
      src: o.src, dst: o.dst, count: o.ports.size,
      summary: o.src + ' probed ' + o.ports.size + ' TCP ports on ' + o.dst + (open.length ? ' and found ' + open.length + ' open: ' + open.slice(0, 12).join(', ') : ' (no open ports answered)') + '.',
      details: [['Ports probed', o.ports.size], ['Scan type', kinds], ['Open ports', open.join(', ') || '—'], ['Closed (RST)', ans.closed.size], ['Probe packets', o.ev.length]],
      ev: o.ev.concat(ans.ev).sort((a, b) => a - b), tags: open.map(p => p + '/' + (TCP_PORTS[p] || 'tcp')),
    });
  }
  for (const o of udpProbe.values()) {
    if (o.ports.size < 20) continue;
    const un = unreach.get(pairKey(o.src, o.dst)) || 0;
    if (un < 5) continue;
    add({ type: 'udpscan', title: 'UDP port scan', sev: 'medium', stage: isPrivate(o.src) ? 'disc' : 'recon', tech: 'T1046', techName: 'Network Service Discovery', src: o.src, dst: o.dst, count: o.ports.size, summary: o.src + ' sent empty/small UDP probes to ' + o.ports.size + ' ports on ' + o.dst + ' (' + un + ' ICMP port-unreachable replies).', details: [['Ports probed', o.ports.size], ['ICMP unreachable', un]], ev: o.ev });
  }
  // horizontal SYN scan (same port, many hosts, mostly unanswered)
  const horiz = new Map();
  for (const [k, q] of synToPort) for (const src of q.srcs) { const hk = src + '|' + q.port; let h = horiz.get(hk); if (!h) { h = { src, port: q.port, dsts: new Set(), ev: [] }; horiz.set(hk, h); } h.dsts.add(q.dst); }
  for (const h of horiz.values()) {
    if (h.dsts.size < 10) continue;
    let answered = 0; for (const d of h.dsts) { const a = synAns.get(pairKey(h.src, d)); if (a && a.open.has(h.port)) answered++; }
    if (answered / h.dsts.size > 0.5) continue;
    for (const d of h.dsts) { const q = synToPort.get(d + '|' + h.port); if (q) q.ev.forEach(i => { if (pk[i].s.src === h.src) h.ev.push(i); }); }
    h.ev.sort((a, b) => a - b);
    add({ type: 'hscan', title: 'Horizontal scan on port ' + h.port, sev: 'medium', stage: isPrivate(h.src) ? 'disc' : 'recon', tech: 'T1046', techName: 'Network Service Discovery', src: h.src, dst: h.dsts.size + ' hosts', count: h.dsts.size, summary: h.src + ' probed port ' + h.port + ' on ' + h.dsts.size + ' hosts; ' + answered + ' answered.', details: [['Port', h.port + ' (' + (TCP_PORTS[h.port] || 'tcp') + ')'], ['Targets', h.dsts.size], ['Answered', answered]], ev: h.ev });
  }
  // ping sweep
  for (const [src, o] of echoBy) {
    if (o.dsts.size < 10) continue;
    const alive = [...(echoRep.get(src) || [])];
    add({ type: 'sweep', title: 'ICMP ping sweep', sev: 'medium', stage: isPrivate(src) ? 'disc' : 'recon', tech: 'T1018', techName: 'Remote System Discovery', src, dst: o.dsts.size + ' hosts', count: o.dsts.size, summary: src + ' pinged ' + o.dsts.size + ' addresses; ' + alive.length + ' responded (' + alive.slice(0, 6).join(', ') + (alive.length > 6 ? ', …' : '') + ').', details: [['Addresses pinged', o.dsts.size], ['Live hosts', alive.length], ['Responders', alive.join(', ') || '—']], ev: o.ev, tags: alive.slice(0, 10) });
  }
  // ARP sweep
  for (const [m, o] of arpReq) {
    if (o.tg.size < 25) continue;
    add({ type: 'arpsweep', title: 'ARP scan', sev: 'medium', stage: 'disc', tech: 'T1018', techName: 'Remote System Discovery', src: o.ip || m, dst: o.tg.size + ' hosts', count: o.tg.size, summary: m + ' (' + o.ip + ') sent ARP requests for ' + o.tg.size + ' different addresses.', details: [['MAC', m], ['Addresses requested', o.tg.size]], ev: o.ev });
  }

  // ---------- 2. Lateral movement attempts ----------
  const lat = new Map();
  for (const q of synToPort.values()) {
    if (!ADMIN_PORTS[q.port] || !isPrivate(q.dst)) continue;
    for (const src of q.srcs) { if (!isPrivate(src)) continue; let o = lat.get(src); if (!o) { o = { src, dsts: new Set(), ports: new Set(), ev: [] }; lat.set(src, o); } o.dsts.add(q.dst); o.ports.add(q.port); q.ev.forEach(i => { if (pk[i].s.src === src) o.ev.push(i); }); }
  }
  for (const o of lat.values()) {
    if (o.dsts.size < 3) continue;
    let ok = []; for (const d of o.dsts) { const a = synAns.get(pairKey(o.src, d)); if (a) for (const p of a.open) if (ADMIN_PORTS[p]) ok.push(d + ':' + p); }
    o.ev.sort((a, b) => a - b);
    add({ type: 'lateral', title: 'Lateral movement attempts (' + [...o.ports].map(p => ADMIN_PORTS[p]).filter((v, i, a) => a.indexOf(v) === i).join('/') + ')', sev: 'high', stage: 'lateral', tech: 'T1021', techName: 'Remote Services', src: o.src, dst: o.dsts.size + ' internal hosts', targets: [...o.dsts], count: o.dsts.size, summary: o.src + ' tried remote-admin services on ' + o.dsts.size + ' internal hosts' + (ok.length ? '; reachable: ' + ok.join(', ') : '') + '.', details: [['Targets', [...o.dsts].join(', ')], ['Services', [...o.ports].map(p => p + '/' + ADMIN_PORTS[p]).join(', ')], ['Reachable', ok.join(', ') || 'none']], ev: o.ev });
  }

  // ---------- 3. Brute force ----------
  const bf = new Map();
  for (const st of streams) {
    if (st.l4 !== 'TCP' || !AUTH_PORTS[st.bp] || !st.syn) continue;
    const k = st.a + '|' + st.b + '|' + st.bp;
    let o = bf.get(k); if (!o) { o = { src: st.a, dst: st.b, port: st.bp, n: 0, withData: 0, ev: [], t0: st.t0, t1: st.t1, banner: '' }; bf.set(k, o); }
    o.n++; if (st.payload > 0) o.withData++; o.t1 = Math.max(o.t1, st.t1);
    o.ev.push(st.pk[0]);
    if (!o.banner) for (const i of st.pk) { const s = pk[i].s; if (s.banner && s.dirA) { o.banner = s.banner; break; } }
  }
  for (const o of bf.values()) {
    if (o.n < 10 || o.withData < 5) continue;
    const dur = Math.max(o.t1 - o.t0, 0.001);
    add({ type: 'bruteforce', title: AUTH_PORTS[o.port] + ' brute force', sev: 'high', stage: 'cred', tech: 'T1110.001', techName: 'Brute Force: Password Guessing', src: o.src, dst: o.dst, dport: o.port, count: o.n, t0: o.t0, t1: o.t1, summary: o.src + ' opened ' + o.n + ' ' + AUTH_PORTS[o.port] + ' sessions to ' + o.dst + ' in ' + fmtDur(dur) + ' (' + (o.n / dur * 60).toFixed(0) + '/min)' + (o.banner ? ', client "' + o.banner + '"' : '') + '.', details: [['Service', o.port + '/' + AUTH_PORTS[o.port]], ['Connections', o.n], ['Rate', (o.n / dur * 60).toFixed(1) + ' per minute'], ['Client banner', o.banner || '—']], ev: o.ev });
  }
  // FTP failed logins
  const ftpFail = new Map();
  for (const r of pk) { const s = r.s; if (s.proto === 'FTP' && s.txt && /^530 /m.test(s.txt)) { const k = s.dst + '|' + s.src; let o = ftpFail.get(k); if (!o) { o = { src: s.dst, dst: s.src, ev: [] }; ftpFail.set(k, o); } o.ev.push(r.i); } }
  for (const o of ftpFail.values()) if (o.ev.length >= 5 && !bf.has(o.src + '|' + o.dst + '|21')) add({ type: 'bruteforce', title: 'FTP login failures', sev: 'high', stage: 'cred', tech: 'T1110', techName: 'Brute Force', src: o.src, dst: o.dst, count: o.ev.length, summary: o.ev.length + ' failed FTP logins from ' + o.src + '.', details: [['Failures', o.ev.length]], ev: o.ev });

  // ---------- 4. Web attacks ----------
  const web = new Map(), tools = new Map(), notFound = new Map(), httpLogin = new Map();
  for (const r of pk) {
    const s = r.s, h = s.http; if (!h) continue;
    if (h.resp) {
      if (h.status === 404) { const k = s.dst + '|' + s.src; let o = notFound.get(k); if (!o) { o = { src: s.dst, dst: s.src, ev: [] }; notFound.set(k, o); } o.ev.push(r.i); }
      continue;
    }
    const uri = safeDecode(h.uri || ''), body = safeDecode(h.body || ''), hdr = h.raw || '';
    for (const rule of WEB_RULES) {
      const target = rule.hdr ? hdr : uri + ' ' + body;
      const m = target.match(rule.re);
      if (!m) continue;
      const k = s.src + '|' + s.dst + '|' + rule.k;
      let o = web.get(k); if (!o) { o = { rule, src: s.src, dst: s.dst, ev: [], samples: [], success: '', statuses: {} }; web.set(k, o); }
      o.ev.push(r.i); if (h.respIdx !== undefined) o.ev.push(h.respIdx);
      if (o.samples.length < 4) o.samples.push(h.method + ' ' + (h.uri.length > 140 ? h.uri.slice(0, 140) + '…' : h.uri) + (rule.hdr ? '  [header: ' + (hdr.split('\r\n').find(l => rule.re.test(l)) || '').slice(0, 100) + ']' : ''));
      if (h.status) o.statuses[h.status] = (o.statuses[h.status] || 0) + 1;
      if (h.respIdx !== undefined) {
        const rt = payloadText(cap, h.respIdx, 4096);
        if (rule.k === 'lfi' && /root:.*:0:0:/.test(rt)) o.success = '/etc/passwd contents returned in the response';
        if (rule.k === 'sqli' && /(SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE|sqlite3?\.|PostgreSQL.*ERROR|Unclosed quotation)/i.test(rt)) o.success = o.success || 'Database error message leaked (injectable parameter)';
        if (rule.k === 'cmdi' && h.status === 200) o.success = o.success || 'Server answered 200 OK to the injected command';
        if (rule.k === 'xss' && /<script/i.test(rt)) o.success = o.success || 'Payload reflected unencoded in the response';
      }
    }
    const ua = h.ua || '';
    const tm = ua.match(TOOL_UA);
    if (tm) { const k = s.src + '|' + tm[1].toLowerCase(); let o = tools.get(k); if (!o) { o = { src: s.src, dst: s.dst, tool: tm[1], ua, ev: [], dsts: new Set() }; tools.set(k, o); } o.ev.push(r.i); o.dsts.add(s.dst); }
    if (h.method === 'POST' && /(login|signin|sign-in|auth|wp-login|session|logon)/i.test(h.uri)) { const k = s.src + '|' + s.dst + '|' + h.uri.split('?')[0]; let o = httpLogin.get(k); if (!o) { o = { src: s.src, dst: s.dst, uri: h.uri.split('?')[0], ev: [] }; httpLogin.set(k, o); } o.ev.push(r.i); }
  }
  for (const o of tools.values()) add({ type: 'tool', title: 'Attack tool fingerprint: ' + o.tool, sev: 'medium', stage: 'recon', tech: 'T1595.002', techName: 'Active Scanning: Vulnerability Scanning', src: o.src, dst: [...o.dsts].join(', '), count: o.ev.length, summary: o.src + ' sent ' + o.ev.length + ' HTTP requests with the User-Agent of ' + o.tool + '.', details: [['User-Agent', o.ua], ['Requests', o.ev.length]], ev: o.ev });
  for (const o of notFound.values()) {
    if (o.ev.length < 20) continue;
    add({ type: 'dirbrute', title: 'Web content discovery (forced browsing)', sev: 'medium', stage: 'recon', tech: 'T1595.003', techName: 'Active Scanning: Wordlist Scanning', src: o.src, dst: o.dst, count: o.ev.length, summary: o.src + ' requested ' + o.ev.length + ' paths on ' + o.dst + ' that returned 404 Not Found.', details: [['404 responses', o.ev.length]], ev: o.ev.map(i => pk[i].s.http.reqIdx ?? i).concat(o.ev).sort((a, b) => a - b) });
  }
  for (const o of web.values()) {
    const st = Object.entries(o.statuses).map(([k, v]) => k + '×' + v).join(', ');
    add({ type: 'web-' + o.rule.k, title: o.rule.name + (o.success ? ' (likely successful)' : ' attempts'), sev: o.success && o.rule.sev === 'high' ? 'critical' : o.rule.sev, stage: 'access', tech: 'T1190', techName: 'Exploit Public-Facing Application', src: o.src, dst: o.dst, count: o.ev.filter(i => !pk[i].s.http.resp).length,
      summary: o.src + ' sent ' + o.ev.filter(i => !pk[i].s.http.resp).length + ' ' + o.rule.name.toLowerCase() + ' payload(s) to ' + o.dst + '.' + (o.success ? ' Evidence of success: ' + o.success + '.' : ''),
      details: [['Sample requests', o.samples.join('\n')], ['Response codes', st || '—'], ['Outcome', o.success || 'No clear sign of success']], ev: o.ev.sort((a, b) => a - b) });
  }
  for (const o of httpLogin.values()) if (o.ev.length >= 10) add({ type: 'bruteforce', title: 'HTTP login brute force', sev: 'high', stage: 'cred', tech: 'T1110', techName: 'Brute Force', src: o.src, dst: o.dst, count: o.ev.length, summary: o.src + ' sent ' + o.ev.length + ' POSTs to ' + o.uri + ' on ' + o.dst + '.', details: [['Endpoint', o.uri], ['Attempts', o.ev.length]], ev: o.ev });

  // ---------- 5. Tool / payload downloads ----------
  for (const r of pk) {
    const h = r.s.http; if (!h || !h.resp) continue;
    const ct = (h.headers['content-type'] || '').toLowerCase();
    const req = h.reqIdx !== undefined ? pk[h.reqIdx].s.http : null;
    const uri = req ? req.uri : '';
    const path = safeDecode(uri.split('?')[0]);
    const body = payloadText(cap, r.i, 600);
    const scripty = /(x-sh|x-shellscript|x-executable|x-msdownload|x-elf|x-dosexec|x-powershell)/.test(ct) || /\.(sh|ps1|exe|elf|bin|dll|bat|vbs|hta|py)$/i.test(path) || /\r\n\r\n(#!\/bin\/|MZ|\x7fELF)/.test(body);
    if (!scripty || h.status !== 200) continue;
    const dl = r.s.dst, from = r.s.src;
    const shell = /\/dev\/tcp\/|bash -i|nc -e|powershell.*-enc|IEX\s*\(/i.test(body);
    const disguised = /^image\/|^text\/plain/.test(ct) && /\r\n\r\n(MZ|\x7fELF)/.test(body);
    add({ type: 'download', title: disguised ? 'Executable disguised as ' + ct : 'Suspicious file download' + (shell ? ' (reverse-shell stager)' : ''), sev: disguised || shell ? 'critical' : 'high', stage: 'c2', tech: disguised ? 'T1036.008' : 'T1105', techName: disguised ? 'Masquerading: Masquerade File Type' : 'Ingress Tool Transfer', src: dl, dst: from, count: 1, summary: dl + ' downloaded ' + (uri || 'a file') + ' from ' + from + ' (' + (ct || 'unknown type') + ').' + (shell ? ' The script opens a reverse shell.' : ''), details: [['URL', 'http://' + (req ? req.host : from) + uri], ['Content-Type', ct || '—'], ['User-Agent', req ? req.ua : '—'], ['Preview', body.split('\r\n\r\n').slice(1).join('').slice(0, 200)]], ev: [h.reqIdx, r.i].filter(x => x !== undefined) });
  }

  // ---------- 6. Reverse shells / suspicious ports ----------
  const SHELL_RE = /(uid=\d+\([\w-]+\)|\/bin\/(ba)?sh|bash -i|Microsoft Windows \[Version|PS [A-Z]:\\>|root@[\w.-]+:|www-data@|\bwhoami\b|cmd\.exe|\/dev\/tcp\/|cat \/etc\/(passwd|shadow))/;
  const shellStreams = new Set();
  for (const st of streams) {
    if (st.l4 !== 'TCP' || st.payload === 0 || st.payload > 2e6) continue;
    let txt = '', hit = null, cmds = [];
    for (const i of st.pk) {
      const s = pk[i].s; if (!s.pll || s.proto === 'HTTP' || s.proto === 'TLS' || s.proto === 'SSH') continue;
      const t = payloadText(cap, i, 2048);
      if (!isText(cap.u8, cap.pk[i].off + s.plo, cap.pk[i].off + s.plo + s.pll, 64)) continue;
      txt += t;
      if (!s.dirA) t.split('\n').map(x => x.trim()).filter(x => x && x.length < 120).forEach(x => cmds.push(x));
      if (!hit) { const m = t.match(SHELL_RE); if (m) hit = m[0]; }
    }
    if (!hit) continue;
    shellStreams.add(st.id);
    const reverse = isPrivate(st.a) && !isPrivate(st.b);
    add({ type: 'shell', title: (reverse ? 'Reverse shell' : 'Interactive shell') + ' over TCP/' + st.bp, sev: 'critical', stage: 'exec', tech: 'T1059.004', techName: 'Command and Scripting Interpreter: Unix Shell', src: st.a, dst: st.b, dport: st.bp, stream: st.id, count: cmds.length, summary: st.a + ' connected out to ' + st.b + ':' + st.bp + ' and served a command shell. Commands issued by the remote side: ' + cmds.slice(0, 6).map(c => '"' + c + '"').join(', ') + (cmds.length > 6 ? ', …' : '') + '.', details: [['Indicator', hit], ['Commands', cmds.slice(0, 20).join('\n') || '—'], ['Duration', fmtDur(st.t1 - st.t0)]], ev: st.pk.slice() });
  }
  for (const st of streams) {
    if (st.l4 !== 'TCP' || shellStreams.has(st.id)) continue;
    const bad = BAD_PORTS[st.bp];
    if (!bad || st.payload === 0) continue;
    add({ type: 'badport', title: 'Session on suspicious port ' + st.bp, sev: 'medium', stage: 'c2', tech: 'T1571', techName: 'Non-Standard Port', src: st.a, dst: st.b, dport: st.bp, stream: st.id, count: st.pk.length, summary: st.a + ' exchanged ' + fmtBytes(st.bytes) + ' with ' + st.b + ' on port ' + st.bp + ' (' + bad + ').', details: [['Port', st.bp + ' — ' + bad], ['Bytes', fmtBytes(st.bytes)]], ev: st.pk.slice() });
  }

  // ---------- 7. Beaconing ----------
  const conns = new Map();
  for (const st of streams) {
    if (st.l4 !== 'TCP' || !st.syn) continue;
    const k = st.a + '|' + st.b + '|' + st.bp;
    let o = conns.get(k); if (!o) { o = { src: st.a, dst: st.b, port: st.bp, t: [], ev: [], bytes: 0 }; conns.set(k, o); }
    o.t.push(st.t0); o.ev.push(...st.pk); o.bytes += st.bytes;
  }
  for (const o of conns.values()) {
    if (o.t.length < 6) continue;
    o.t.sort((a, b) => a - b);
    const iv = []; for (let i = 1; i < o.t.length; i++) iv.push(o.t[i] - o.t[i - 1]);
    const mean = iv.reduce((a, b) => a + b, 0) / iv.length;
    if (mean < 2) continue;
    const sd = Math.sqrt(iv.reduce((a, b) => a + (b - mean) ** 2, 0) / iv.length);
    const cv = sd / mean;
    if (cv > 0.2) continue;
    add({ type: 'beacon', title: 'Periodic beaconing every ~' + fmtDur(mean), sev: isPrivate(o.dst) ? 'medium' : 'high', stage: 'c2', tech: o.port === 80 || o.port === 8080 || o.port === 443 ? 'T1071.001' : 'T1071', techName: 'Application Layer Protocol' + (o.port === 80 || o.port === 8080 || o.port === 443 ? ': Web Protocols' : ''), src: o.src, dst: o.dst, dport: o.port, count: o.t.length, t0: o.t[0], t1: o.t[o.t.length - 1], summary: o.src + ' connected to ' + o.dst + ':' + o.port + ' ' + o.t.length + ' times at a regular ' + fmtDur(mean) + ' interval (jitter ' + (cv * 100).toFixed(1) + '%), a typical C2 check-in pattern.', details: [['Connections', o.t.length], ['Mean interval', fmtDur(mean)], ['Jitter (CV)', (cv * 100).toFixed(1) + '%'], ['Total bytes', fmtBytes(o.bytes)]], ev: o.ev.sort((a, b) => a - b) });
  }

  // ---------- 8. DNS tunneling & DGA ----------
  const dq = new Map(), nx = new Map();
  for (const r of pk) {
    const d = r.s.dns; if (!d || !d.qs[0]) continue;
    const nm = d.qs[0].name.toLowerCase();
    if (r.s.proto !== 'DNS') continue;
    if (!d.qr) {
      const bd = baseDomain(nm); const sub = nm.slice(0, Math.max(0, nm.length - bd.length - 1));
      const k = r.s.src + '|' + bd;
      let o = dq.get(k); if (!o) { o = { src: r.s.src, dst: r.s.dst, bd, subs: new Set(), len: 0, ent: 0, txt: 0, ev: [], longest: '' }; dq.set(k, o); }
      if (!o.subs.has(sub)) { o.subs.add(sub); o.len += sub.replace(/\./g, '').length; o.ent += entropy(sub.replace(/\./g, '')); }
      if (d.qs[0].type === 'TXT' || d.qs[0].type === 'NULL') o.txt++;
      if (nm.length > o.longest.length) o.longest = nm;
      o.ev.push(r.i);
    } else if (d.rcode === 3) {
      let o = nx.get(r.s.dst); if (!o) { o = { src: r.s.dst, names: new Set(), ev: [] }; nx.set(r.s.dst, o); }
      o.names.add(nm); o.ev.push(r.i);
    }
  }
  for (const o of dq.values()) {
    const u = o.subs.size; if (u < 15) continue;
    const avgLen = o.len / u, avgEnt = o.ent / u;
    if (!(avgLen >= 25 || (avgEnt >= 3.6 && avgLen >= 12) || (o.txt >= 15 && avgLen >= 12))) continue;
    // include responses
    const ids = new Set(o.ev.map(i => pk[i].s.dns.id));
    for (const r of pk) { const d = r.s.dns; if (d && d.qr && r.s.dst === o.src && ids.has(d.id) && baseDomain(d.qs[0]?.name || '') === o.bd) o.ev.push(r.i); }
    o.ev.sort((a, b) => a - b);
    const est = Math.round(o.len * 5 / 8);
    add({ type: 'dnstunnel', title: 'DNS tunneling to ' + o.bd, sev: 'high', stage: 'exfil', tech: 'T1048.003', techName: 'Exfiltration Over Unencrypted Non-C2 Protocol (DNS)', src: o.src, dst: o.bd, viaDns: o.dst, count: u, summary: o.src + ' sent ' + u + ' unique, high-entropy subdomains of ' + o.bd + ' (avg ' + avgLen.toFixed(0) + ' chars, entropy ' + avgEnt.toFixed(2) + ' bits/char' + (o.txt ? ', ' + o.txt + ' TXT queries' : '') + '), encoding roughly ' + fmtBytes(est) + ' of data.', details: [['Base domain', o.bd], ['Unique subdomains', u], ['Avg label length', avgLen.toFixed(1)], ['Avg entropy', avgEnt.toFixed(2) + ' bits/char'], ['TXT queries', o.txt], ['Est. data encoded', fmtBytes(est)], ['Longest query', o.longest]], ev: o.ev });
  }
  for (const o of nx.values()) if (o.names.size >= 15) add({ type: 'dga', title: 'Burst of NXDOMAIN responses (possible DGA)', sev: 'medium', stage: 'c2', tech: 'T1568.002', techName: 'Dynamic Resolution: Domain Generation Algorithms', src: o.src, dst: 'DNS', count: o.names.size, summary: o.src + ' looked up ' + o.names.size + ' names that do not exist, e.g. ' + [...o.names].slice(0, 3).join(', ') + '.', details: [['Failed names', o.names.size], ['Examples', [...o.names].slice(0, 8).join('\n')]], ev: o.ev });

  // ---------- 9. ARP spoofing ----------
  for (const [ip, m] of arpClaims) {
    if (m.size < 2) continue;
    const arr = [...m.entries()].sort((a, b) => a[1].first - b[1].first);
    const legit = arr[0][0];
    for (const [mc, c] of arr.slice(1)) {
      const owner = cap.macIp?.get(mc);
      const who = owner && owner.size ? [...owner][0] : mc;
      add({ type: 'arpspoof', title: 'ARP spoofing of ' + ip, sev: 'high', stage: 'cred', tech: 'T1557.002', techName: 'Adversary-in-the-Middle: ARP Cache Poisoning', src: who, srcMac: mc, dst: ip, count: c.n, summary: 'MAC ' + mc + ' claimed to own ' + ip + ' (' + c.n + ' ARP packets, ' + c.unsol + ' unsolicited replies), which belongs to ' + legit + '. Traffic for ' + ip + ' can be intercepted.', details: [['Spoofed IP', ip], ['Legitimate MAC', legit], ['Attacker MAC', mc], ['ARP packets', c.n], ['Unsolicited replies', c.unsol]], ev: c.ev });
    }
  }

  // ---------- 10. Rogue DHCP / starvation ----------
  if (dhcpServers.size >= 2) {
    const arr = [...dhcpServers.entries()];
    add({ type: 'rogue-dhcp', title: 'Multiple DHCP servers (possible rogue DHCP)', sev: 'high', stage: 'cred', tech: 'T1557.003', techName: 'Adversary-in-the-Middle: DHCP Spoofing', src: arr[1][0], dst: 'clients', count: arr.length, summary: arr.length + ' different DHCP servers answered clients: ' + arr.map(a => a[0]).join(', ') + '.', details: [['Servers', arr.map(a => a[0] + ' (' + (a[1].mac || '?') + ')').join('\n')]], ev: arr.flatMap(a => a[1].ev) });
  }
  const dd = dhcpDisc.get('all');
  if (dd && dd.macs.size >= 30) add({ type: 'dhcp-starve', title: 'DHCP starvation', sev: 'medium', stage: 'impact', tech: 'T1499', techName: 'Endpoint Denial of Service', src: 'multiple MACs', dst: 'DHCP', count: dd.macs.size, summary: dd.macs.size + ' different client MACs sent DHCP Discover messages.', details: [['Distinct MACs', dd.macs.size]], ev: dd.ev });

  // ---------- 11. Exfiltration (large outbound) ----------
  const out = new Map();
  for (const st of streams) {
    const inside = isPrivate(st.a), outside = !isPrivate(st.b);
    if (!inside || !outside) continue;
    const k = st.a + '|' + st.b; let o = out.get(k); if (!o) { o = { src: st.a, dst: st.b, up: 0, down: 0, ev: [], ports: new Set(), sni: '' }; out.set(k, o); }
    o.up += st.ab; o.down += st.ba; o.ev.push(...st.pk); o.ports.add(st.bp);
    if (!o.sni) for (const i of st.pk.slice(0, 6)) if (pk[i].s.sni) { o.sni = pk[i].s.sni; break; }
  }
  for (const o of out.values()) {
    if (o.up < 1e6 || o.up < o.down * 4) continue;
    o.ev.sort((a, b) => a - b);
    const big = streams.filter(st => st.a === o.src && st.b === o.dst).sort((x, y) => y.ab - x.ab)[0];
    add({ t0: big.t0, t1: big.t1, type: 'exfil', title: 'Large outbound transfer (' + fmtBytes(o.up) + ')', sev: 'high', stage: 'exfil', tech: 'T1041', techName: 'Exfiltration Over C2 Channel', src: o.src, dst: o.dst, count: o.ev.length, summary: o.src + ' uploaded ' + fmtBytes(o.up) + ' to external host ' + o.dst + (o.sni ? ' (' + o.sni + ')' : '') + ' while receiving only ' + fmtBytes(o.down) + ' (ratio ' + (o.up / Math.max(o.down, 1)).toFixed(0) + ':1).', details: [['Uploaded', fmtBytes(o.up)], ['Downloaded', fmtBytes(o.down)], ['Ports', [...o.ports].join(', ')], ['TLS server name', o.sni || '—']], ev: o.ev });
  }

  // ---------- 12. Floods ----------
  const burst = (ev, minWin) => {
    const ts = ev.map(i => pk[i].t); let lo = 0, peak = 0, first = -1, last = -1;
    for (let j = 0; j < ts.length; j++) { while (ts[j] - ts[lo] > 1) lo++; const c = j - lo + 1; if (c > peak) peak = c; if (c >= minWin) { if (first < 0) first = lo; last = j; } }
    if (first < 0) return null;
    return { peak, ev: ev.slice(first, last + 1), span: Math.max(ts[last] - ts[first], 0.001) };
  };
  for (const q of synToPort.values()) {
    if (q.n < 300) continue;
    const b = burst(q.ev, 100); if (!b || b.ev.length < 300) continue;
    const srcs = new Set(b.ev.map(i => pk[i].s.src));
    const spoofed = srcs.size > 50;
    add({ type: 'synflood', title: 'SYN flood on ' + q.dst + ':' + q.port, sev: 'critical', stage: 'impact', tech: 'T1498.001', techName: 'Network Denial of Service: Direct Network Flood', src: spoofed ? srcs.size + ' spoofed sources' : [...srcs].join(', '), spoofed, dst: q.dst, dport: q.port, count: b.ev.length, summary: b.ev.length + ' SYN packets hit ' + q.dst + ':' + q.port + ' in ' + fmtDur(b.span) + ' (peak ' + b.peak + ' pkt/s) from ' + srcs.size + ' source address' + (srcs.size > 1 ? 'es' : '') + (spoofed ? ' (randomised — likely spoofed)' : '') + '.', details: [['SYN packets', b.ev.length], ['Peak rate', b.peak + ' pkt/s'], ['Distinct sources', srcs.size], ['Duration', fmtDur(b.span)]], ev: b.ev });
  }
  for (const [src, o] of echoBy) {
    const byDst = new Map(); o.ev.forEach(i => { const d = pk[i].s.dst; byDst.set(d, (byDst.get(d) || []).concat(i)); });
    for (const [d, ev] of byDst) { if (ev.length < 300) continue; const b = burst(ev, 100); if (!b || b.ev.length < 300) continue; add({ type: 'icmpflood', title: 'ICMP flood', sev: 'high', stage: 'impact', tech: 'T1498.001', techName: 'Network Denial of Service: Direct Network Flood', src, dst: d, count: b.ev.length, summary: src + ' sent ' + b.ev.length + ' echo requests to ' + d + ' (peak ' + b.peak + '/s).', details: [['Packets', b.ev.length], ['Peak rate', b.peak + '/s']], ev: b.ev }); }
  }
  for (const b of icmpBig.values()) if (b.ev.length >= 10) add({ type: 'icmptunnel', title: 'Possible ICMP tunnel', sev: 'medium', stage: 'c2', tech: 'T1095', techName: 'Non-Application Layer Protocol', src: b.src, dst: b.dst, count: b.ev.length, summary: b.src + ' sent ' + b.ev.length + ' oversized echo requests (' + fmtBytes(b.bytes) + ' of payload) to ' + b.dst + '.', details: [['Packets', b.ev.length], ['Payload', fmtBytes(b.bytes)]], ev: b.ev });
  if (heart.length) add({ type: 'heartbleed', title: 'TLS Heartbleed exploitation', sev: 'critical', stage: 'cred', tech: 'T1190', techName: 'Exploit Public-Facing Application', src: pk[heart[0]].s.src, dst: pk[heart[0]].s.dst, count: heart.length, summary: 'TLS heartbeat requests claim a payload larger than the record (CVE-2014-0160).', details: [['Packets', heart.length]], ev: heart });

  // ---------- 13. Cleartext credentials ----------
  const creds = new Map();
  const addCred = (r, proto, user, pw, extra) => {
    const s = r.s; const k = s.src + '|' + s.dst + '|' + proto + '|' + user;
    let o = creds.get(k); if (!o) { o = { src: s.src, dst: s.dst, proto, user: user || '', pw: '', ev: [] }; creds.set(k, o); }
    if (pw) o.pw = pw; o.ev.push(r.i); if (extra) o.extra = extra;
  };
  const pending = new Map();
  for (const r of pk) {
    const s = r.s;
    if ((s.proto === 'FTP' || s.proto === 'POP3' || s.proto === 'IMAP' || s.proto === 'SMTP') && s.txt && s.dirA) {
      const k = s.st; const t = s.txt;
      let m;
      if ((m = t.match(/^USER\s+(\S+)/im))) pending.set(k, m[1]);
      if ((m = t.match(/^PASS\s+(\S+)/im))) addCred(r, s.proto, pending.get(k) || '?', m[1]);
      if ((m = t.match(/^\S+\s+LOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?/im))) addCred(r, 'IMAP', m[1], m[2]);
      if ((m = t.match(/^AUTH PLAIN\s+(\S+)/im))) { try { const d = atob(m[1]).split('\0'); addCred(r, 'SMTP', d[1], d[2]); } catch (e) {} }
    }
    if (s.http && !s.http.resp) {
      const au = s.http.headers.authorization || '';
      if (/^basic\s+/i.test(au)) { try { const d = atob(au.split(/\s+/)[1]); const c = d.indexOf(':'); addCred(r, 'HTTP Basic', d.slice(0, c), d.slice(c + 1), s.http.uri); } catch (e) {} }
      if (s.http.method === 'POST' && s.http.body) {
        const b = safeDecode(s.http.body);
        const pm = b.match(/(?:^|&)(pass|password|passwd|pwd)=([^&]*)/i), um = b.match(/(?:^|&)(user|username|login|email|uname)=([^&]*)/i);
        if (pm) addCred(r, 'HTTP form', um ? um[2] : '?', pm[2], s.http.uri);
      }
    }
    if (s.proto === 'Telnet' && s.pll) { const k = s.src + '|' + s.dst + '|Telnet|'; if (!creds.has(k)) creds.set(k, { src: s.dirA ? s.src : s.dst, dst: s.dirA ? s.dst : s.src, proto: 'Telnet', user: '(interactive)', pw: '', ev: [] }); creds.get(k).ev.push(r.i); }
  }
  cap.credList = [...creds.values()];
  for (const o of creds.values()) {
    add({ type: 'cleartext', title: 'Cleartext ' + o.proto + ' credentials', sev: o.proto === 'Telnet' ? 'medium' : 'medium', stage: 'cred', tech: 'T1040', techName: 'Network Sniffing (exposed credentials)', src: o.src, dst: o.dst, count: o.ev.length, secret: o.pw, summary: o.src + ' sent ' + o.proto + ' credentials' + (o.user ? ' for user "' + o.user + '"' : '') + ' to ' + o.dst + ' without encryption. Anyone on the path can read them.', details: [['Protocol', o.proto], ['Username', o.user || '—'], ['Password', o.pw ? mask(o.pw) : '—'], ['Resource', o.extra || '—']], ev: o.ev });
  }

  D.sort((a, b) => a.t0 - b.t0 || SEV_RANK[b.sev] - SEV_RANK[a.sev]);
  D.forEach((d, i) => { d.id = i; d.evSet = null; });
  return D;
}

/* ===================== Attack flow model ===================== */
function buildAttackFlow(cap, D) {
  if (!D.length) return null;
  const actors = new Map();
  const actor = (id, kind) => { if (!id) return; let a = actors.get(id); if (!a) { a = { id, roles: new Set(), first: Infinity, sev: 0 }; actors.set(id, a); } if (kind) a.roles.add(kind); return a; };
  const steps = [];
  const c2s = new Set();
  D.forEach(d => { if (['beacon', 'shell', 'badport', 'exfil'].includes(d.type) && isIp(d.dst) && !isPrivate(d.dst)) c2s.add(d.dst); });
  const malSrc = new Set(D.filter(d => d.type === 'download' && isIp(d.dst) && !isPrivate(d.dst) && !c2s.has(d.dst)).map(d => d.dst));
  for (const d of D) {
    if (d.type === 'cleartext' && SEV_RANK[d.sev] < 3) { /* still include */ }
    let src = d.src, dst = d.dst;
    if (d.type === 'synflood' && d.spoofed) src = 'Spoofed sources';
    if (d.type === 'dnstunnel') dst = d.dst;
    if (/hosts$/.test(dst)) dst = 'LAN hosts';
    const sa = actor(src), da = actor(dst);
    sa.first = Math.min(sa.first, d.t0); da.first = Math.min(da.first, d.t0);
    sa.sev = Math.max(sa.sev, SEV_RANK[d.sev]); da.sev = Math.max(da.sev, SEV_RANK[d.sev]);
    steps.push({ d, src, dst });
  }
  for (const [id, a] of actors) {
    const asSrc = steps.filter(s => s.src === id), asDst = steps.filter(s => s.dst === id);
    const mac = isMac(id), priv = mac || (isIp(id) && isPrivate(id));
    if (c2s.has(id)) a.role = 'C2 server';
    else if (malSrc.has(id)) a.role = 'Malware host';
    else if (id === 'Spoofed sources') a.role = 'Botnet / spoofed';
    else if (id === 'LAN hosts') a.role = 'Internal network';
    else if (!mac && !isIp(id)) a.role = 'External domain';
    else if (!priv && asSrc.length) a.role = 'Attacker';
    else if (priv && asSrc.some(s => ['lateral', 'beacon', 'shell', 'exfil', 'dnstunnel', 'sweep', 'hscan'].includes(s.d.type)) || (asSrc.some(s => s.d.type === 'download') && asSrc.length > 1 && asSrc.some(s => s.d.type !== 'download' && s.d.type !== 'cleartext'))) a.role = 'Compromised host';
    else if (priv && asSrc.some(s => s.d.type === 'download')) a.role = 'At-risk host';
    else if (priv && asSrc.some(s => s.d.type === 'arpspoof')) a.role = 'Rogue insider';
    else if (asDst.length && priv) a.role = 'Victim';
    else if (asSrc.length && asSrc.every(s => s.d.type === 'cleartext')) a.role = 'Internal client';
    else a.role = priv ? 'Internal host' : 'External host';
  }
  const order = { 'At-risk host': 4.5, 'Malware host': 9.5, 'Attacker': 0, 'Botnet / spoofed': 1, 'Rogue insider': 2, 'Internal client': 3, 'Compromised host': 4, 'Victim': 5, 'Internal network': 6, 'Internal host': 7, 'External host': 8, 'External domain': 9, 'C2 server': 10 };
  const lanes = [...actors.values()].sort((a, b) => order[a.role] - order[b.role] || a.first - b.first);
  const stages = STAGES.map(s => { const ds = D.filter(d => d.stage === s.k); return { ...s, n: ds.length, t0: ds.length ? Math.min(...ds.map(d => d.t0)) : null, sev: ds.reduce((m, d) => Math.max(m, SEV_RANK[d.sev]), 0) }; });
  // narrative
  const att = lanes.filter(l => l.role === 'Attacker').map(l => l.id);
  const comp = lanes.filter(l => l.role === 'Compromised host').map(l => l.id);
  const c2 = lanes.filter(l => l.role === 'C2 server').map(l => l.id);
  let story = '';
  const seen = stages.filter(s => s.n);
  if (att.length) story += 'Activity from external attacker' + (att.length > 1 ? 's ' : ' ') + att.join(', ') + ' ';
  if (seen.length) story += (att.length ? 'spans ' : 'Activity spans ') + seen.length + ' ATT&CK tactic' + (seen.length > 1 ? 's' : '') + ' (' + seen.map(s => s.name).join(' → ') + ').';
  if (comp.length) story += ' ' + comp.join(', ') + (comp.length > 1 ? ' appear' : ' appears') + ' compromised';
  if (comp.length && c2.length) story += ' and talks to C2 ' + c2.join(', ');
  if (comp.length) story += '.';
  return { lanes, steps, stages, story };
}

/* ===================== Formatting ===================== */
function fmtBytes(b) { if (b < 1024) return b + ' B'; const u = ['KB', 'MB', 'GB', 'TB']; let i = -1; do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1); return (b < 10 ? b.toFixed(2) : b < 100 ? b.toFixed(1) : b.toFixed(0)) + ' ' + u[i]; }
function fmtBits(b) { const u = ['bps', 'Kbps', 'Mbps', 'Gbps']; let i = 0; while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; } return (b < 10 ? b.toFixed(2) : b < 100 ? b.toFixed(1) : b.toFixed(0)) + ' ' + u[i]; }
function fmtNum(n) { return n.toLocaleString('en-US'); }
function fmtDur(s) { if (s < 1e-3) return (s * 1e6).toFixed(0) + ' µs'; if (s < 1) return (s * 1000).toFixed(s < 0.01 ? 2 : 0) + ' ms'; if (s < 60) return s.toFixed(s < 10 ? 2 : 1) + ' s'; if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's'; return Math.floor(s / 3600) + 'h ' + Math.round((s % 3600) / 60) + 'm'; }

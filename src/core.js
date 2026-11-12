/* ===================== Capture reading ===================== */
'use strict';
const be16 = (u, p) => (u[p] << 8) | u[p + 1];
const be32 = (u, p) => u[p] * 16777216 + (u[p + 1] << 16) + (u[p + 2] << 8) + u[p + 3];
const le16 = (u, p) => u[p] | (u[p + 1] << 8);
const h2 = b => (b < 16 ? '0' : '') + b.toString(16);
const hex4 = v => '0x' + v.toString(16).padStart(4, '0');
const mac = (u, p) => h2(u[p]) + ':' + h2(u[p + 1]) + ':' + h2(u[p + 2]) + ':' + h2(u[p + 3]) + ':' + h2(u[p + 4]) + ':' + h2(u[p + 5]);
const ip4 = (u, p) => u[p] + '.' + u[p + 1] + '.' + u[p + 2] + '.' + u[p + 3];
function ip6(u, p) {
  const g = [];
  for (let i = 0; i < 8; i++) g.push(be16(u, p + i * 2));
  let bs = -1, bl = 0;
  for (let i = 0; i < 8;) {
    if (g[i] === 0) { let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > bl && j - i > 1) { bs = i; bl = j - i; } i = j; } else i++;
  }
  const hx = g.map(x => x.toString(16));
  if (bs < 0) return hx.join(':');
  return hx.slice(0, bs).join(':') + '::' + hx.slice(bs + bl).join(':');
}
function latin(u, s, e, max) {
  e = Math.min(e, u.length, max ? s + max : Infinity);
  let out = '';
  for (let i = s; i < e; i++) out += String.fromCharCode(u[i]);
  return out;
}

function captureFormat(u8) {
  if (u8.length < 24) return null;
  const m = be32(u8, 0);
  if (m === 0xa1b2c3d4 || m === 0xd4c3b2a1 || m === 0xa1b23c4d || m === 0x4d3cb2a1) return 'pcap';
  if (m === 0x0a0d0d0a) return 'pcapng';
  return null;
}

function* readPcap(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const m = dv.getUint32(0, false);
  const le = m === 0xd4c3b2a1 || m === 0x4d3cb2a1;
  const nano = m === 0xa1b23c4d || m === 0x4d3cb2a1;
  const lt = dv.getUint32(20, le) & 0x0fffffff;
  const div = nano ? 1e-9 : 1e-6;
  let p = 24;
  while (p + 16 <= u8.length) {
    const s = dv.getUint32(p, le), f = dv.getUint32(p + 4, le);
    let cap = dv.getUint32(p + 8, le);
    const len = dv.getUint32(p + 12, le);
    p += 16;
    if (cap > 0x4000000) break;               // corrupt record
    if (cap > u8.length - p) { cap = u8.length - p; if (cap <= 0) break; }
    yield { t: s + f * div, off: p, cap, len: len || cap, lt };
    p += cap;
  }
}

function* readPcapng(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  let p = 0, le = true, ifs = [], lastT = 0;
  while (p + 12 <= u8.length) {
    let type = dv.getUint32(p, le);
    if (type === 0x0a0d0d0a || dv.getUint32(p, true) === 0x0a0d0d0a) {
      type = 0x0a0d0d0a;
      le = dv.getUint32(p + 8, true) === 0x1a2b3c4d;
      ifs = [];
    }
    const blen = dv.getUint32(p + 4, le);
    if (blen < 12 || p + blen > u8.length) break;
    const b = p + 8, end = p + blen - 4;
    if (type === 1) {
      const lt = dv.getUint16(b, le);
      let res = 1e-6, o = b + 8;
      while (o + 4 <= end) {
        const code = dv.getUint16(o, le), l = dv.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && l >= 1) { const v = u8[o + 4]; res = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v); }
        o += 4 + ((l + 3) & ~3);
      }
      ifs.push({ lt, res });
    } else if (type === 6 || type === 2) {
      const id = type === 6 ? dv.getUint32(b, le) : dv.getUint16(b, le);
      const hi = dv.getUint32(b + 4, le), lo = dv.getUint32(b + 8, le);
      const cap = Math.min(dv.getUint32(b + 12, le), end - (b + 20));
      const len = dv.getUint32(b + 16, le);
      const itf = ifs[id] || { lt: 1, res: 1e-6 };
      lastT = hi * 4294967296 * itf.res + lo * itf.res;
      if (cap > 0) yield { t: lastT, off: b + 20, cap, len: len || cap, lt: itf.lt };
    } else if (type === 3) {
      const len = dv.getUint32(b, le);
      const cap = Math.min(len, end - (b + 4));
      const itf = ifs[0] || { lt: 1 };
      if (cap > 0) yield { t: lastT, off: b + 4, cap, len, lt: itf.lt };
    }
    p += blen;
  }
}

/* ===================== Dissection ===================== */
const ETH_TYPES = { 0x0800: 'IPv4', 0x86dd: 'IPv6', 0x0806: 'ARP', 0x8100: '802.1Q', 0x88a8: '802.1ad', 0x88cc: 'LLDP', 0x888e: 'EAPOL', 0x8863: 'PPPoE-D', 0x8864: 'PPPoE-S', 0x8847: 'MPLS', 0x8035: 'RARP', 0x88e5: 'MACsec', 0x9000: 'Loopback' };
const IP_PROTOS = { 0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 4: 'IPIP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP' };
const TCP_PORTS = { 20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 179: 'BGP', 389: 'LDAP', 443: 'TLS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 636: 'LDAPS', 853: 'DoT', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 1883: 'MQTT', 2049: 'NFS', 3306: 'MySQL', 3389: 'RDP', 5060: 'SIP', 5222: 'XMPP', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 6667: 'IRC', 8080: 'HTTP', 8443: 'TLS', 9200: 'Elasticsearch', 27017: 'MongoDB' };
const UDP_PORTS = { 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 123: 'NTP', 137: 'NBNS', 138: 'NetBIOS', 161: 'SNMP', 162: 'SNMP', 443: 'QUIC', 500: 'ISAKMP', 514: 'Syslog', 546: 'DHCPv6', 547: 'DHCPv6', 1194: 'OpenVPN', 1900: 'SSDP', 3478: 'STUN', 4500: 'IPsec', 4789: 'VXLAN', 5060: 'SIP', 5353: 'mDNS', 5355: 'LLMNR', 51820: 'WireGuard' };
const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY' };
const DNS_RCODES = { 0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name', 4: 'Not implemented', 5: 'Refused' };
const ICMP_TYPES = { 0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo (ping) request', 9: 'Router advertisement', 10: 'Router solicitation', 11: 'Time-to-live exceeded', 12: 'Parameter problem', 13: 'Timestamp request', 14: 'Timestamp reply' };
const ICMP_UNREACH = { 0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable', 4: 'Fragmentation needed', 9: 'Network prohibited', 10: 'Host prohibited', 13: 'Communication administratively prohibited' };
const ICMP6_TYPES = { 1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply', 130: 'Multicast listener query', 131: 'Multicast listener report', 133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation', 136: 'Neighbor advertisement', 137: 'Redirect', 143: 'Multicast listener report v2' };
const DHCP_TYPES = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
const TLS_HS = { 0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished' };
const TLS_VER = { 0x0300: 'SSLv3', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'HEAD ', 'DELETE ', 'OPTIONS ', 'PATCH ', 'CONNECT ', 'TRACE ', 'PROPFIND '];

function Tree() { this.layers = []; }
Tree.prototype.layer = function (name, s, l) { const L = { name, s, l, f: [] }; this.layers.push(L); return L; };
function F(L, n, v, s, l, d) { L.f.push({ n, v: String(v), s, l, d: d || 0 }); }

function tcpFlagStr(f) {
  const a = [];
  if (f & 2) a.push('SYN'); if (f & 16) a.push('ACK'); if (f & 1) a.push('FIN'); if (f & 4) a.push('RST');
  if (f & 8) a.push('PSH'); if (f & 32) a.push('URG'); if (f & 64) a.push('ECE'); if (f & 128) a.push('CWR'); if (f & 256) a.push('NS');
  return a.length ? a.join(', ') : '<none>';
}

function dissect(u8, lt, T) {
  const s = { src: '', dst: '', sp: -1, dp: -1, proto: 'Unknown', l4: '', info: '', fl: 0, plo: 0, pll: 0 };
  const n = u8.length;
  try {
    let p = 0, et = -1, L;
    switch (lt) {
      case 1: {
        if (n < 14) { s.proto = 'Ethernet'; s.info = 'Truncated frame'; return s; }
        s.dmac = mac(u8, 0); s.smac = mac(u8, 6); et = be16(u8, 12);
        if (T) { L = T.layer('Ethernet II', 0, 14); F(L, 'Destination', s.dmac, 0, 6); F(L, 'Source', s.smac, 6, 6); F(L, 'Type', hex4(et) + ' (' + (ETH_TYPES[et] || 'unknown') + ')', 12, 2); }
        p = 14;
        while ((et === 0x8100 || et === 0x88a8) && p + 4 <= n) {
          const tci = be16(u8, p); s.vlan = tci & 0xfff; et = be16(u8, p + 2);
          if (T) { L = T.layer('802.1Q Virtual LAN, ID: ' + s.vlan, p, 4); F(L, 'Priority', tci >> 13, p, 2); F(L, 'VLAN ID', s.vlan, p, 2); F(L, 'Type', hex4(et), p + 2, 2); }
          p += 4;
        }
        if (et < 0x0600) {
          s.src = s.smac; s.dst = s.dmac;
          if (u8[p] === 0x42 && u8[p + 1] === 0x42) { s.proto = 'STP'; s.info = 'Spanning Tree BPDU'; }
          else { s.proto = 'LLC'; s.info = 'IEEE 802.3 LLC frame, length ' + et; }
          if (T) { L = T.layer(s.proto === 'STP' ? 'Spanning Tree Protocol' : 'Logical-Link Control', p, n - p); F(L, 'Length', et, 12, 2); }
          return s;
        }
        break;
      }
      case 0: case 108: {
        let fam = u8[0] | (u8[1] << 8) | (u8[2] << 16) | (u8[3] << 24);
        if (fam > 255 || fam < 0) fam = be32(u8, 0);
        et = fam === 2 ? 0x0800 : (fam === 24 || fam === 28 || fam === 30) ? 0x86dd : -1; p = 4;
        if (T) { L = T.layer('Null/Loopback', 0, 4); F(L, 'Family', fam + (et === 0x800 ? ' (IPv4)' : et === 0x86dd ? ' (IPv6)' : ''), 0, 4); }
        break;
      }
      case 101: case 12: case 14: { const v = u8[0] >> 4; et = v === 4 ? 0x0800 : v === 6 ? 0x86dd : -1; break; }
      case 228: et = 0x0800; break;
      case 229: et = 0x86dd; break;
      case 113: {
        if (n < 16) { s.proto = 'SLL'; s.info = 'Truncated'; return s; }
        et = be16(u8, 14); p = 16;
        const al = be16(u8, 4); if (al === 6) s.smac = mac(u8, 6);
        if (T) { L = T.layer('Linux cooked capture v1', 0, 16); F(L, 'Packet type', be16(u8, 0), 0, 2); if (s.smac) F(L, 'Source', s.smac, 6, 6); F(L, 'Protocol', hex4(et), 14, 2); }
        break;
      }
      case 276: {
        if (n < 20) { s.proto = 'SLL2'; s.info = 'Truncated'; return s; }
        et = be16(u8, 0); p = 20; if (u8[11] === 6) s.smac = mac(u8, 12);
        if (T) { L = T.layer('Linux cooked capture v2', 0, 20); F(L, 'Protocol', hex4(et), 0, 2); F(L, 'Interface index', be32(u8, 4), 4, 4); if (s.smac) F(L, 'Source', s.smac, 12, 6); }
        break;
      }
      default:
        s.proto = 'DLT ' + lt; s.info = 'Link type ' + lt + ' not decoded (' + n + ' bytes)';
        return s;
    }
    l3(u8, p, et, s, T);
  } catch (e) {
    s.malformed = true;
    if (!s.info) s.info = 'Malformed packet';
  }
  return s;
}

function l3(u8, p, et, s, T) {
  const n = u8.length; let L;
  if (et === 0x0800) {
    if (p + 20 > n) { s.proto = 'IPv4'; s.info = 'Truncated IPv4 header'; return; }
    const ihl = (u8[p] & 15) * 4, tot = be16(u8, p + 2), id = be16(u8, p + 4), ff = be16(u8, p + 6), ttl = u8[p + 8], pr = u8[p + 9];
    s.src = ip4(u8, p + 12); s.dst = ip4(u8, p + 16); s.ttl = ttl; s.ipv = 4; s.ipid = id;
    const end = tot >= ihl ? Math.min(n, p + tot) : n;
    const fo = (ff & 0x1fff) * 8;
    if (T) {
      L = T.layer('Internet Protocol Version 4, Src: ' + s.src + ', Dst: ' + s.dst, p, ihl);
      F(L, 'Version', 4, p, 1); F(L, 'Header length', ihl + ' bytes', p, 1); F(L, 'DSCP / ECN', '0x' + h2(u8[p + 1]), p + 1, 1);
      F(L, 'Total length', tot, p + 2, 2); F(L, 'Identification', hex4(id) + ' (' + id + ')', p + 4, 2);
      F(L, 'Flags', (ff & 0x4000 ? "Don't fragment" : '') + (ff & 0x2000 ? ' More fragments' : '') || 'none', p + 6, 1);
      F(L, 'Fragment offset', fo, p + 6, 2); F(L, 'Time to live', ttl, p + 8, 1); F(L, 'Protocol', (IP_PROTOS[pr] || 'Unknown') + ' (' + pr + ')', p + 9, 1);
      F(L, 'Header checksum', hex4(be16(u8, p + 10)), p + 10, 2); F(L, 'Source address', s.src, p + 12, 4); F(L, 'Destination address', s.dst, p + 16, 4);
    }
    if (ff & 0x2000 || fo) s.frag = true;
    if (fo > 0) { s.proto = 'IPv4'; s.l4 = IP_PROTOS[pr] || String(pr); s.info = 'Fragmented IP protocol (proto=' + s.l4 + ', off=' + fo + ', ID=' + hex4(id) + ')'; return; }
    return l4(u8, p + ihl, end, pr, s, T);
  }
  if (et === 0x86dd) {
    if (p + 40 > n) { s.proto = 'IPv6'; s.info = 'Truncated IPv6 header'; return; }
    const plen = be16(u8, p + 4); let nh = u8[p + 6]; const hl = u8[p + 7];
    s.src = ip6(u8, p + 8); s.dst = ip6(u8, p + 24); s.ttl = hl; s.ipv = 6;
    if (T) {
      L = T.layer('Internet Protocol Version 6, Src: ' + s.src + ', Dst: ' + s.dst, p, 40);
      F(L, 'Version', 6, p, 1); F(L, 'Flow label', '0x' + ((be32(u8, p) & 0xfffff) >>> 0).toString(16), p, 4); F(L, 'Payload length', plen, p + 4, 2);
      F(L, 'Next header', (IP_PROTOS[nh] || nh) + ' (' + nh + ')', p + 6, 1); F(L, 'Hop limit', hl, p + 7, 1);
      F(L, 'Source address', s.src, p + 8, 16); F(L, 'Destination address', s.dst, p + 24, 16);
    }
    let q = p + 40; const end = plen ? Math.min(n, q + plen) : n;
    let guard = 0;
    while ((nh === 0 || nh === 43 || nh === 60 || nh === 44 || nh === 51) && q + 8 <= end && guard++ < 8) {
      if (nh === 44) {
        const off = be16(u8, q + 2) >> 3; const nx = u8[q];
        if (T) { L = T.layer('IPv6 Fragment header', q, 8); F(L, 'Offset', off * 8, q + 2, 2); }
        s.frag = true; q += 8; nh = nx;
        if (off > 0) { s.proto = 'IPv6'; s.l4 = IP_PROTOS[nh] || String(nh); s.info = 'IPv6 fragment (offset ' + off * 8 + ')'; return; }
        continue;
      }
      const len = nh === 51 ? (u8[q + 1] + 2) * 4 : (u8[q + 1] + 1) * 8;
      if (T) { L = T.layer({ 0: 'Hop-by-Hop Options', 43: 'Routing Header', 60: 'Destination Options', 51: 'Authentication Header' }[nh], q, len); F(L, 'Next header', u8[q], q, 1); F(L, 'Length', len, q + 1, 1); }
      nh = u8[q]; q += len;
    }
    return l4(u8, q, end, nh, s, T);
  }
  s.src = s.smac || ''; s.dst = s.dmac || '';
  if (et === 0x0806 || et === 0x8035) return arp(u8, p, s, T);
  s.proto = ETH_TYPES[et] || ('EtherType ' + hex4(et));
  const names = { LLDP: 'Link Layer Discovery Protocol', EAPOL: '802.1X Authentication', 'PPPoE-D': 'PPPoE Discovery', 'PPPoE-S': 'PPPoE Session', MPLS: 'MPLS label switched packet' };
  s.info = names[s.proto] || (s.proto + ' frame, ' + (n - p) + ' bytes');
  if (T) { L = T.layer(names[s.proto] || s.proto, p, n - p); F(L, 'Payload', (n - p) + ' bytes', p, n - p); }
}

function arp(u8, p, s, T) {
  const op = be16(u8, p + 6), hl = u8[p + 4], pl = u8[p + 5];
  s.proto = 'ARP';
  if (hl !== 6 || pl !== 4) { s.info = 'ARP (non-Ethernet/IPv4)'; return; }
  const sha = mac(u8, p + 8), spa = ip4(u8, p + 14), tha = mac(u8, p + 18), tpa = ip4(u8, p + 24);
  s.arp = { op, sha, spa, tha, tpa };
  if (op === 1) s.info = spa === tpa ? 'Gratuitous ARP for ' + spa + ' (Request)' : (spa === '0.0.0.0' ? 'ARP Probe for ' + tpa : 'Who has ' + tpa + '? Tell ' + spa);
  else if (op === 2) s.info = (spa === tpa ? 'Gratuitous ARP: ' : '') + spa + ' is at ' + sha;
  else s.info = 'ARP opcode ' + op;
  if (!s.src) s.src = sha;
  if (!s.dst) s.dst = op === 1 ? 'ff:ff:ff:ff:ff:ff' : tha;
  if (T) {
    const L = T.layer('Address Resolution Protocol (' + (op === 1 ? 'request' : op === 2 ? 'reply' : op) + ')', p, 28);
    F(L, 'Hardware type', be16(u8, p), p, 2); F(L, 'Protocol type', hex4(be16(u8, p + 2)), p + 2, 2); F(L, 'Opcode', op + (op === 1 ? ' (request)' : op === 2 ? ' (reply)' : ''), p + 6, 2);
    F(L, 'Sender MAC address', sha, p + 8, 6); F(L, 'Sender IP address', spa, p + 14, 4); F(L, 'Target MAC address', tha, p + 18, 6); F(L, 'Target IP address', tpa, p + 24, 4);
  }
}

function l4(u8, p, end, pr, s, T) {
  s.l4 = IP_PROTOS[pr] || ('IP proto ' + pr);
  if (pr === 6) return tcp(u8, p, end, s, T);
  if (pr === 17) return udp(u8, p, end, s, T);
  if (pr === 1) return icmp(u8, p, end, s, T);
  if (pr === 58) return icmp6(u8, p, end, s, T);
  s.proto = s.l4;
  s.info = { IGMP: 'Internet Group Management Protocol', GRE: 'Generic Routing Encapsulation', ESP: 'Encapsulating Security Payload, SPI ' + hex8(be32(u8, p)), OSPF: 'OSPF routing', VRRP: 'VRRP announcement', PIM: 'PIM', SCTP: 'SCTP' }[s.l4] || (s.l4 + ', ' + (end - p) + ' bytes');
  s.plo = p; s.pll = Math.max(0, end - p);
  if (T) { const L = T.layer(s.l4, p, end - p); F(L, 'Length', end - p, p, end - p); }
}
const hex8 = v => '0x' + (v >>> 0).toString(16).padStart(8, '0');

function tcp(u8, p, end, s, T) {
  s.proto = 'TCP';
  if (p + 20 > end) { s.info = 'Truncated TCP header'; return; }
  const sp = be16(u8, p), dp = be16(u8, p + 2), seq = be32(u8, p + 4), ack = be32(u8, p + 8);
  const off = (u8[p + 12] >> 4) * 4, fl = ((u8[p + 12] & 1) << 8) | u8[p + 13], win = be16(u8, p + 14);
  Object.assign(s, { sp, dp, seq, ack, fl, win });
  s.plo = p + off; s.pll = Math.max(0, end - s.plo);
  s.ti = 1;
  s.info = sp + ' → ' + dp + ' [' + tcpFlagStr(fl) + '] Seq=' + seq + (fl & 16 ? ' Ack=' + ack : '') + ' Win=' + win + ' Len=' + s.pll;
  if (T) {
    const L = T.layer('Transmission Control Protocol, Src Port: ' + sp + ', Dst Port: ' + dp + ', Len: ' + s.pll, p, off);
    F(L, 'Source port', sp, p, 2); F(L, 'Destination port', dp, p + 2, 2); F(L, 'Sequence number (raw)', seq, p + 4, 4); F(L, 'Acknowledgment number (raw)', ack, p + 8, 4);
    F(L, 'Header length', off + ' bytes', p + 12, 1); F(L, 'Flags', '0x' + fl.toString(16).padStart(3, '0') + ' (' + tcpFlagStr(fl) + ')', p + 12, 2);
    const fn = [[256, 'Nonce'], [128, 'CWR'], [64, 'ECE'], [32, 'Urgent'], [16, 'Acknowledgment'], [8, 'Push'], [4, 'Reset'], [2, 'Syn'], [1, 'Fin']];
    fn.forEach(([b, nm]) => F(L, nm, fl & b ? 'Set' : 'Not set', p + 13, 1, 1));
    F(L, 'Window', win, p + 14, 2); F(L, 'Checksum', hex4(be16(u8, p + 16)), p + 16, 2); F(L, 'Urgent pointer', be16(u8, p + 18), p + 18, 2);
    let o = p + 20; const oe = p + off;
    while (o < oe) {
      const k = u8[o];
      if (k === 0) { F(L, 'Option: End of list', '', o, 1, 1); break; }
      if (k === 1) { F(L, 'Option: No-Operation', '', o, 1, 1); o++; continue; }
      const l = u8[o + 1]; if (!l || l < 2) break;
      const nm = { 2: 'Maximum segment size', 3: 'Window scale', 4: 'SACK permitted', 5: 'SACK', 8: 'Timestamps', 30: 'Multipath TCP', 34: 'TCP Fast Open' }[k] || ('Kind ' + k);
      const v = k === 2 ? be16(u8, o + 2) + ' bytes' : k === 3 ? 'shift ' + u8[o + 2] + ' (×' + (1 << u8[o + 2]) + ')' : k === 8 ? 'TSval ' + be32(u8, o + 2) + ', TSecr ' + be32(u8, o + 6) : '';
      F(L, 'Option: ' + nm, v, o, l, 1); o += l;
    }
  }
  if (s.pll > 0) tcpApp(u8, s.plo, end, s, T);
}

function svcName(map, sp, dp) {
  const a = map[sp], b = map[dp];
  if (a && b) return sp < dp ? a : b;
  return b || a || null;
}

function isText(u8, p, e, n) {
  e = Math.min(e, p + (n || 64));
  for (let i = p; i < e; i++) { const c = u8[i]; if (!(c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127))) return false; }
  return e > p;
}

function tcpApp(u8, p, end, s, T) {
  const b0 = u8[p], b1 = u8[p + 1];
  // TLS
  if (b0 >= 20 && b0 <= 24 && b1 === 3 && u8[p + 2] <= 4) return tls(u8, p, end, s, T);
  const head = latin(u8, p, end, 12);
  // HTTP
  if (HTTP_METHODS.some(m => head.startsWith(m)) || head.startsWith('HTTP/1.') || head.startsWith('HTTP/2')) return httpParse(u8, p, end, s, T);
  if (head.startsWith('SSH-')) {
    s.proto = 'SSH'; const line = latin(u8, p, end, 255).split(/\r?\n/)[0];
    s.info = (s.sp === 22 ? 'Server' : 'Client') + ': Protocol (' + line + ')'; s.banner = line;
    if (T) { const L = T.layer('SSH Protocol', p, end - p); F(L, 'Protocol', line, p, line.length); }
    return;
  }
  // DNS over TCP
  if ((s.sp === 53 || s.dp === 53) && end - p > 14) { dnsParse(u8, p + 2, end, s, T, 'DNS'); return; }
  const svc = svcName(TCP_PORTS, s.sp, s.dp);
  const txtProtos = { FTP: 1, SMTP: 1, POP3: 1, IMAP: 1, Telnet: 1, IRC: 1, Redis: 1 };
  if (svc && txtProtos[svc] && (svc === 'Telnet' || isText(u8, p, end, 32))) {
    s.proto = svc;
    const text = latin(u8, p, end, 512);
    const line = svc === 'Telnet' ? text.replace(/[^\x20-\x7e]/g, '·').slice(0, 80) : text.split(/\r?\n/)[0];
    s.info = (svc === 'Telnet' ? 'Telnet data: ' : (s.dp === TCP_KEY(svc) ? 'Request: ' : 'Response: ')) + line;
    s.txt = text;
    if (T) { const L = T.layer(svc, p, end - p); text.split(/\r?\n/).filter(Boolean).slice(0, 20).forEach((ln, i) => F(L, i ? '' : 'Line', ln, p, end - p)); }
    return;
  }
  if (svc) {
    s.proto = svc === 'TLS' ? 'TLS' : svc;
    s.info = (svc === 'TLS' ? 'Continuation Data' : svc + ' payload') + ', ' + (end - p) + ' bytes  (' + s.sp + ' → ' + s.dp + ')';
    s.ti = 0;
  }
  if (T) { const L = T.layer(svc ? svc + ' (by port)' : 'Data (' + (end - p) + ' bytes)', p, end - p); F(L, 'Data', (end - p) + ' bytes', p, end - p); }
}
function TCP_KEY(svc) { for (const k in TCP_PORTS) if (TCP_PORTS[k] === svc) return +k; return -1; }

function tls(u8, p, end, s, T) {
  s.proto = 'TLS'; s.ti = 0;
  const parts = []; let r = p, guard = 0;
  while (r + 5 <= end && guard++ < 32) {
    const ct = u8[r], ver = be16(u8, r + 1), len = be16(u8, r + 3);
    if (ct < 20 || ct > 24 || u8[r + 1] !== 3) break;
    let L;
    const name = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat' }[ct];
    if (T) { L = T.layer('TLS Record: ' + name + (TLS_VER[ver] ? ' (' + TLS_VER[ver] + ')' : ''), r, Math.min(5 + len, end - r)); F(L, 'Content type', name + ' (' + ct + ')', r, 1); F(L, 'Version', (TLS_VER[ver] || hex4(ver)), r + 1, 2); F(L, 'Length', len, r + 3, 2); }
    if (ct === 22 && r + 9 <= end) {
      const ht = u8[r + 5];
      if (TLS_HS[ht] === undefined || len < 4) { parts.push('Encrypted Handshake Message'); }
      else {
        parts.push(TLS_HS[ht]);
        if (T) F(L, 'Handshake type', TLS_HS[ht] + ' (' + ht + ')', r + 5, 1, 1);
        if (ht === 1) clientHello(u8, r + 9, Math.min(end, r + 5 + len), s, L);
        if (ht === 2) serverHello(u8, r + 9, Math.min(end, r + 5 + len), s, L);
      }
    } else if (ct === 21) parts.push(len === 2 && r + 7 <= end ? 'Alert (' + (u8[r + 5] === 2 ? 'Fatal' : 'Warning') + ', ' + u8[r + 6] + ')' : 'Encrypted Alert');
    else if (ct === 24) { parts.push('Heartbeat'); s.heartbeat = { len, payloadLen: r + 8 <= end ? be16(u8, r + 6) : 0 }; }
    else parts.push(name);
    r += 5 + len;
  }
  const uniq = []; parts.forEach(x => { if (uniq[uniq.length - 1] !== x) uniq.push(x); });
  s.info = (uniq.join(', ') || 'TLS segment') + (s.sni ? ' (SNI=' + s.sni + ')' : '');
}

function clientHello(u8, q, e, s, L) {
  const base = q;
  s.tlsHello = 'client';
  q += 2 + 32;                    // version + random
  q += 1 + u8[q];                 // session id
  const csl = be16(u8, q); if (L) F(L, 'Cipher suites', (csl / 2) + ' suites', q, csl + 2, 1); q += 2 + csl;
  q += 1 + u8[q];                 // compression
  if (q + 2 > e) return;
  const el = be16(u8, q); q += 2; const ee = Math.min(e, q + el);
  while (q + 4 <= ee) {
    const et = be16(u8, q), l = be16(u8, q + 2), d = q + 4;
    if (et === 0 && l > 5) { const nl = be16(u8, d + 3); s.sni = latin(u8, d + 5, d + 5 + nl); if (L) F(L, 'Server Name Indication', s.sni, d + 5, nl, 1); }
    else if (et === 16 && l > 2) {
      const out = []; let a = d + 2; while (a < d + l) { const al = u8[a]; out.push(latin(u8, a + 1, a + 1 + al)); a += 1 + al; }
      s.alpn = out.join(','); if (L) F(L, 'ALPN', s.alpn, d, l, 1);
    } else if (et === 43 && l > 1) {
      const vs = []; for (let a = d + 1; a < d + 1 + u8[d]; a += 2) { const v = be16(u8, a); if (TLS_VER[v]) vs.push(TLS_VER[v]); }
      if (L) F(L, 'Supported versions', vs.join(', '), d, l, 1); if (vs.includes('TLS 1.3')) s.tlsv = 'TLS 1.3';
    } else if (L) F(L, 'Extension', ({ 10: 'supported_groups', 11: 'ec_point_formats', 13: 'signature_algorithms', 23: 'extended_master_secret', 35: 'session_ticket', 45: 'psk_key_exchange_modes', 51: 'key_share', 65281: 'renegotiation_info', 21: 'padding', 27: 'compress_certificate', 17513: 'application_settings' }[et] || 'type ' + et) + ' (' + l + ' bytes)', q, l + 4, 1);
    q = d + l;
  }
  void base;
}
function serverHello(u8, q, e, s, L) {
  s.tlsHello = 'server';
  const ver = be16(u8, q); q += 2 + 32; q += 1 + u8[q];
  const cs = be16(u8, q); if (L) F(L, 'Cipher suite', hex4(cs), q, 2, 1); q += 3;
  s.tlsv = TLS_VER[ver];
  if (q + 2 > e) return; const ee = Math.min(e, q + 2 + be16(u8, q)); q += 2;
  while (q + 4 <= ee) { const et = be16(u8, q), l = be16(u8, q + 2); if (et === 43 && l === 2) s.tlsv = TLS_VER[be16(u8, q + 4)] || s.tlsv; q += 4 + l; }
  if (L && s.tlsv) F(L, 'Negotiated version', s.tlsv, q, 0, 1);
}

function httpParse(u8, p, end, s, T) {
  s.proto = 'HTTP'; s.ti = 0;
  const text = latin(u8, p, end, 8192);
  const he = text.indexOf('\r\n\r\n');
  const head = he >= 0 ? text.slice(0, he) : text;
  const lines = head.split('\r\n');
  const first = lines[0];
  const h = { line: first, headers: {} };
  for (let i = 1; i < lines.length; i++) { const c = lines[i].indexOf(':'); if (c > 0) h.headers[lines[i].slice(0, c).trim().toLowerCase()] = lines[i].slice(c + 1).trim(); }
  if (first.startsWith('HTTP/')) { const m = first.split(' '); h.status = +m[1]; h.reason = m.slice(2).join(' '); h.resp = true; }
  else { const m = first.split(' '); h.method = m[0]; h.uri = m[1] || ''; h.host = h.headers.host || ''; h.ua = h.headers['user-agent'] || ''; }
  if (he >= 0) h.body = text.slice(he + 4, he + 4 + 1024);
  h.raw = head.slice(0, 2048);
  s.http = h;
  s.info = first.length > 160 ? first.slice(0, 160) + '…' : first;
  if (T) {
    const L = T.layer('Hypertext Transfer Protocol', p, end - p);
    let o = p;
    lines.forEach((ln, i) => { F(L, i === 0 ? (h.resp ? 'Status line' : 'Request line') : ln.split(':')[0], i === 0 ? ln : ln.slice(ln.indexOf(':') + 1).trim(), o, ln.length + 2, i ? 1 : 0); o += ln.length + 2; });
    if (he >= 0 && end - (p + he + 4) > 0) F(L, 'Body', (end - (p + he + 4)) + ' bytes', p + he + 4, end - (p + he + 4));
  }
}

function udp(u8, p, end, s, T) {
  s.proto = 'UDP';
  if (p + 8 > end) { s.info = 'Truncated UDP header'; return; }
  const sp = be16(u8, p), dp = be16(u8, p + 2), ul = be16(u8, p + 4);
  s.sp = sp; s.dp = dp; s.plo = p + 8; s.pll = Math.max(0, Math.min(end, p + (ul || end - p)) - s.plo);
  s.info = sp + ' → ' + dp + ' Len=' + s.pll;
  if (T) { const L = T.layer('User Datagram Protocol, Src Port: ' + sp + ', Dst Port: ' + dp, p, 8); F(L, 'Source port', sp, p, 2); F(L, 'Destination port', dp, p + 2, 2); F(L, 'Length', ul, p + 4, 2); F(L, 'Checksum', hex4(be16(u8, p + 6)), p + 6, 2); }
  const q = s.plo, e = s.plo + s.pll;
  if (s.pll === 0) return;
  const has = x => sp === x || dp === x;
  if (has(53) || has(5353) || has(5355) || has(137)) return dnsParse(u8, q, e, s, T, has(5353) ? 'mDNS' : has(5355) ? 'LLMNR' : has(137) ? 'NBNS' : 'DNS');
  if (has(67) || has(68)) return dhcp(u8, q, e, s, T);
  if (has(123) && s.pll >= 48) {
    const li = u8[q], mode = li & 7, ver = (li >> 3) & 7;
    s.proto = 'NTP'; s.info = 'NTP Version ' + ver + ', ' + ({ 1: 'symmetric active', 2: 'symmetric passive', 3: 'client', 4: 'server', 5: 'broadcast', 6: 'control', 7: 'private' }[mode] || 'mode ' + mode);
    s.ntpMode = mode;
    if (T) { const L = T.layer('Network Time Protocol', q, e - q); F(L, 'Version', ver, q, 1); F(L, 'Mode', mode, q, 1); F(L, 'Stratum', u8[q + 1], q + 1, 1); }
    return;
  }
  if (has(443) || has(80) || has(8443)) {
    const b = u8[q];
    if (b & 0x40 || b & 0x80) {
      s.proto = 'QUIC';
      if (b & 0x80) {
        const ver = be32(u8, q + 1), ty = (b >> 4) & 3, dl = u8[q + 5];
        let dcid = ''; for (let i = 0; i < dl && i < 20; i++) dcid += h2(u8[q + 6 + i]);
        s.info = (ver === 0 ? 'Version Negotiation' : ['Initial', '0-RTT', 'Handshake', 'Retry'][ty]) + ', DCID=' + dcid;
        if (T) { const L = T.layer('QUIC IETF', q, e - q); F(L, 'Header form', 'Long header', q, 1); F(L, 'Version', hex8(ver), q + 1, 4); F(L, 'DCID', dcid, q + 6, dl); }
      } else { s.info = 'Protected Payload (short header), ' + s.pll + ' bytes'; if (T) { const L = T.layer('QUIC IETF', q, e - q); F(L, 'Header form', 'Short header', q, 1); } }
      return;
    }
  }
  if ((has(161) || has(162)) && u8[q] === 0x30) {
    const bl = p => { const b = u8[p]; if (b < 0x80) return [b, p + 1]; const k = b & 0x7f; let v = 0; for (let i = 0; i < k; i++) v = v * 256 + u8[p + 1 + i]; return [v, p + 1 + k]; };
    let [, p1] = bl(q + 1);
    if (u8[p1] === 0x02) { const [vl, pv] = bl(p1 + 1); const ver = u8[pv]; p1 = pv + vl;
      if (u8[p1] === 0x04) { const [cl, pc] = bl(p1 + 1); const comm = latin(u8, pc, pc + cl); const tag = u8[pc + cl];
        const pdu = { 0xa0: 'get-request', 0xa1: 'get-next-request', 0xa2: 'response', 0xa3: 'set-request', 0xa4: 'trap', 0xa5: 'get-bulk-request', 0xa6: 'inform', 0xa7: 'trap' }[tag] || 'pdu';
        s.proto = 'SNMP'; s.snmp = { ver: ver === 0 ? '1' : ver === 1 ? '2c' : '3', community: ver < 2 ? comm : '', pdu };
        s.info = pdu + (ver < 2 ? ' (community "' + comm + '")' : ' (SNMPv3)');
        if (T) { const L = T.layer('Simple Network Management Protocol', q, e - q); F(L, 'Version', s.snmp.ver, pv, 1); if (ver < 2) F(L, 'Community', comm, pc, cl); F(L, 'PDU', pdu, pc + cl, 1); }
        return; } } }
  if (has(1900) && isText(u8, q, e, 16)) { s.proto = 'SSDP'; s.info = latin(u8, q, e, 200).split('\r\n')[0]; if (T) { const L = T.layer('Simple Service Discovery Protocol', q, e - q); latin(u8, q, e, 1024).split('\r\n').filter(Boolean).forEach(x => F(L, '', x, q, e - q)); } return; }
  if (has(3478) && s.pll >= 20 && be32(u8, q + 4) === 0x2112a442) { s.proto = 'STUN'; s.info = 'STUN ' + hex4(be16(u8, q)); return; }
  const svc = svcName(UDP_PORTS, sp, dp);
  if (svc) { s.proto = svc; s.info = svc + ', ' + s.pll + ' bytes  (' + sp + ' → ' + dp + ')'; }
  if (T) { const L = T.layer(svc ? svc + ' (by port)' : 'Data (' + s.pll + ' bytes)', q, e - q); F(L, 'Data', s.pll + ' bytes', q, e - q); }
}

function dnsName(u8, p, base, end) {
  const parts = []; let jumped = false, next = -1, guard = 0;
  while (p < end && guard++ < 64) {
    const l = u8[p];
    if (l === 0) { p++; break; }
    if ((l & 0xc0) === 0xc0) { if (!jumped) next = p + 2; jumped = true; p = base + (((l & 0x3f) << 8) | u8[p + 1]); continue; }
    if (l > 63) break;
    parts.push(latin(u8, p + 1, p + 1 + l)); p += 1 + l;
  }
  return [parts.join('.') || '<Root>', jumped ? next : p];
}

function dnsParse(u8, p, end, s, T, label) {
  s.proto = label;
  if (end - p < 12) { s.info = label + ' (truncated)'; return; }
  const id = be16(u8, p), fl = be16(u8, p + 2), qd = be16(u8, p + 4), an = be16(u8, p + 6), ns = be16(u8, p + 8), ar = be16(u8, p + 10);
  const qr = fl >> 15, rcode = fl & 15, opcode = (fl >> 11) & 15;
  const d = { id, qr, rcode, qs: [], ans: [] };
  let L;
  if (T) {
    L = T.layer((label === 'DNS' ? 'Domain Name System' : label) + ' (' + (qr ? 'response' : 'query') + ')', p, end - p);
    F(L, 'Transaction ID', hex4(id), p, 2); F(L, 'Flags', hex4(fl) + (qr ? ' Standard query response' : ' Standard query') + (rcode ? ', ' + (DNS_RCODES[rcode] || rcode) : ''), p + 2, 2);
    F(L, 'Questions', qd, p + 4, 2); F(L, 'Answer RRs', an, p + 6, 2); F(L, 'Authority RRs', ns, p + 8, 2); F(L, 'Additional RRs', ar, p + 10, 2);
  }
  let q = p + 12;
  for (let i = 0; i < qd && i < 16 && q < end; i++) {
    const st = q; const [nm, q2] = dnsName(u8, q, p, end); const ty = be16(u8, q2);
    d.qs.push({ name: nm, type: DNS_TYPES[ty] || String(ty) }); q = q2 + 4;
    if (L) F(L, 'Query', nm + ': type ' + (DNS_TYPES[ty] || ty) + ', class ' + (be16(u8, q2 + 2) & 0x7fff), st, q - st, 1);
  }
  for (let i = 0; i < an && i < 64 && q + 10 < end; i++) {
    const st = q; const [nm, q2] = dnsName(u8, q, p, end); const ty = be16(u8, q2), ttl = be32(u8, q2 + 4), rl = be16(u8, q2 + 8), rd = q2 + 10;
    let v = '';
    if (ty === 1 && rl === 4) v = ip4(u8, rd);
    else if (ty === 28 && rl === 16) v = ip6(u8, rd);
    else if (ty === 5 || ty === 2 || ty === 12) v = dnsName(u8, rd, p, end)[0];
    else if (ty === 15) v = dnsName(u8, rd + 2, p, end)[0];
    else if (ty === 16) { let a = rd; const out = []; while (a < rd + rl) { out.push(latin(u8, a + 1, a + 1 + u8[a])); a += 1 + u8[a]; } v = out.join(''); }
    else v = rl + ' bytes';
    d.ans.push({ name: nm, type: DNS_TYPES[ty] || String(ty), val: v, ttl });
    q = rd + rl;
    if (L) F(L, 'Answer', nm + ': type ' + (DNS_TYPES[ty] || ty) + ', TTL ' + ttl + ', ' + v, st, q - st, 1);
  }
  s.dns = d;
  const q0 = d.qs[0];
  let info = (opcode === 5 ? 'Dynamic update' : 'Standard query') + (qr ? ' response' : '') + ' ' + hex4(id);
  if (rcode) info += ' ' + (DNS_RCODES[rcode] || 'rcode ' + rcode);
  if (q0) info += ' ' + q0.type + ' ' + q0.name;
  if (qr && d.ans.length) info += ' ' + d.ans.slice(0, 3).map(a => a.type + ' ' + (a.val.length > 40 ? a.val.slice(0, 40) + '…' : a.val)).join(' ') + (d.ans.length > 3 ? ' …' : '');
  s.info = info;
}

function dhcp(u8, p, end, s, T) {
  s.proto = 'DHCP';
  if (end - p < 240) { s.info = 'DHCP (truncated)'; return; }
  const op = u8[p], xid = be32(u8, p + 4), yi = ip4(u8, p + 16), ch = mac(u8, p + 28);
  const d = { op, xid, mac: ch, yiaddr: yi, type: 0 };
  let L;
  if (T) { L = T.layer('Dynamic Host Configuration Protocol', p, end - p); F(L, 'Message type', op === 1 ? 'Boot Request' : 'Boot Reply', p, 1); F(L, 'Transaction ID', hex8(xid), p + 4, 4); F(L, 'Your (client) IP', yi, p + 16, 4); F(L, 'Client MAC address', ch, p + 28, 6); }
  let q = p + 240;
  while (q < end) {
    const c = u8[q]; if (c === 255) break; if (c === 0) { q++; continue; }
    const l = u8[q + 1], v = q + 2;
    if (c === 53) d.type = u8[v];
    else if (c === 12) d.host = latin(u8, v, v + l);
    else if (c === 50) d.req = ip4(u8, v);
    else if (c === 54) d.server = ip4(u8, v);
    if (L) F(L, 'Option (' + c + ')', { 53: 'DHCP Message Type: ' + (DHCP_TYPES[u8[v]] || u8[v]), 12: 'Host Name: ' + latin(u8, v, v + l), 50: 'Requested IP: ' + ip4(u8, v), 54: 'Server Identifier: ' + ip4(u8, v), 51: 'Lease time: ' + be32(u8, v) + 's', 3: 'Router: ' + ip4(u8, v), 6: 'DNS: ' + ip4(u8, v), 1: 'Subnet mask: ' + ip4(u8, v) }[c] || (l + ' bytes'), q, l + 2, 1);
    q = v + l;
  }
  s.dhcp = d;
  s.info = 'DHCP ' + (DHCP_TYPES[d.type] || (op === 1 ? 'Request' : 'Reply')) + ' - Transaction ID ' + hex8(xid) + (d.host ? ' (' + d.host + ')' : '');
}

function icmp(u8, p, end, s, T) {
  s.proto = 'ICMP';
  const ty = u8[p], code = u8[p + 1];
  s.icmp = { type: ty, code };
  s.plo = p + 8; s.pll = Math.max(0, end - p - 8);
  let info = ICMP_TYPES[ty] || ('Type ' + ty);
  if (ty === 0 || ty === 8) { const id = be16(u8, p + 4), sq = be16(u8, p + 6); info += ' id=' + hex4(id) + ', seq=' + sq + ', ttl=' + s.ttl; s.icmp.id = id; s.icmp.seq = sq; }
  if (ty === 3) info += ' (' + (ICMP_UNREACH[code] || 'code ' + code) + ')';
  s.info = info;
  if (T) {
    const L = T.layer('Internet Control Message Protocol', p, end - p);
    F(L, 'Type', ty + ' (' + (ICMP_TYPES[ty] || '?') + ')', p, 1); F(L, 'Code', code, p + 1, 1); F(L, 'Checksum', hex4(be16(u8, p + 2)), p + 2, 2);
    if (ty === 0 || ty === 8) { F(L, 'Identifier', hex4(be16(u8, p + 4)), p + 4, 2); F(L, 'Sequence number', be16(u8, p + 6), p + 6, 2); }
    if (end - p > 8) F(L, 'Data', (end - p - 8) + ' bytes', p + 8, end - p - 8);
  }
  if ((ty === 3 || ty === 11) && end - p >= 28) {
    const ip = p + 8; if ((u8[ip] >> 4) === 4) { s.icmp.inner = { src: ip4(u8, ip + 12), dst: ip4(u8, ip + 16), proto: u8[ip + 9], dp: be16(u8, ip + (u8[ip] & 15) * 4 + 2) }; }
  }
}

function icmp6(u8, p, end, s, T) {
  s.proto = 'ICMPv6';
  const ty = u8[p], code = u8[p + 1];
  s.icmp = { type: ty, code, v6: true };
  let info = ICMP6_TYPES[ty] || ('Type ' + ty);
  if (ty === 128 || ty === 129) info += ' id=' + hex4(be16(u8, p + 4)) + ', seq=' + be16(u8, p + 6);
  if ((ty === 135 || ty === 136) && end - p >= 24) info += ' for ' + ip6(u8, p + 8);
  s.info = info;
  if (T) { const L = T.layer('Internet Control Message Protocol v6', p, end - p); F(L, 'Type', ty + ' (' + (ICMP6_TYPES[ty] || '?') + ')', p, 1); F(L, 'Code', code, p + 1, 1); F(L, 'Checksum', hex4(be16(u8, p + 2)), p + 2, 2); if ((ty === 135 || ty === 136) && end - p >= 24) F(L, 'Target address', ip6(u8, p + 8), p + 8, 16); }
}

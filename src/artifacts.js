/* ===================== Artifact extraction: files, credentials, indicators, host inventory ===================== */
function bytesIndexOf(buf, pat, from, limit) {
  const n = Math.min(buf.length, limit || buf.length) - pat.length;
  outer: for (let i = from || 0; i <= n; i++) { for (let j = 0; j < pat.length; j++) if (buf[i + j] !== pat[j]) continue outer; return i; }
  return -1;
}
const CRLF2 = [13, 10, 13, 10];
const u8str = (u, s, e) => latin(u, s, e);

function reassemble(cap, st) {
  const segs = { a: [], b: [] };
  for (const i of st.pk) {
    const s = cap.pk[i].s; if (!s.pll || s.seq === undefined) continue;
    const d = s.dirA ? 'a' : 'b';
    const base = st.isn[d] !== undefined ? st.isn[d] : s.seq;
    segs[d].push({ off: (s.seq - base + 4294967296) % 4294967296, i, len: s.pll, at: cap.pk[i].off + s.plo });
  }
  const build = list => {
    list.sort((x, y) => x.off - y.off || x.i - y.i);
    let total = 0; const parts = [], map = []; let next = list.length ? list[0].off : 0;
    for (const g of list) {
      if (g.off + g.len <= next) continue;
      if (g.off > next) { const gap = Math.min(g.off - next, 65536); parts.push(new Uint8Array(gap)); total += gap; next = g.off; }
      const skip = next - g.off;
      const piece = cap.u8.subarray(g.at + skip, g.at + g.len);
      map.push({ o: total, i: g.i }); parts.push(piece); total += piece.length; next = g.off + g.len;
      if (total > 64 * 1048576) break;
    }
    const out = new Uint8Array(total); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    return { buf: out, map };
  };
  return { a: build(segs.a), b: build(segs.b) };
}
function pktAt(side, off) { let lo = 0, hi = side.map.length - 1, r = side.map.length ? side.map[0].i : -1; while (lo <= hi) { const m = (lo + hi) >> 1; if (side.map[m].o <= off) { r = side.map[m].i; lo = m + 1; } else hi = m - 1; } return r; }

function parseHttpStream(buf, isReq, methods) {
  const out = []; let pos = 0, k = 0;
  while (pos < buf.length && out.length < 500) {
    const he = bytesIndexOf(buf, CRLF2, pos, pos + 65536);
    if (he < 0) break;
    const head = u8str(buf, pos, he), lines = head.split('\r\n'), first = lines[0];
    const ok = isReq ? /^[A-Z]{3,10} \S+ HTTP\/1\.[01]$/.test(first) : /^HTTP\/1\.[01] \d{3}/.test(first);
    if (!ok) { const nx = bytesIndexOf(buf, isReq ? [32, 72, 84, 84, 80, 47] : [72, 84, 84, 80, 47, 49], pos + 1); if (nx < 0) break; pos = isReq ? Math.max(pos + 1, u8str(buf, Math.max(0, nx - 2048), nx).lastIndexOf('\n') + Math.max(0, nx - 2048) + 1) : nx; if (pos <= 0) break; continue; }
    const h = {}; for (let i = 1; i < lines.length; i++) { const c = lines[i].indexOf(':'); if (c > 0) h[lines[i].slice(0, c).trim().toLowerCase()] = lines[i].slice(c + 1).trim(); }
    const m = { start: pos, line: first, headers: h, bodyStart: he + 4 };
    if (isReq) { const p = first.split(' '); m.method = p[0]; m.uri = p[1]; } else { m.status = +first.split(' ')[1]; }
    let body = new Uint8Array(0), end = he + 4;
    const noBody = !isReq && (m.status < 200 || m.status === 204 || m.status === 304 || (methods && methods[k] === 'HEAD'));
    if (!noBody) {
      if (/chunked/i.test(h['transfer-encoding'] || '')) {
        const parts = []; let p = he + 4, tot = 0;
        for (let guard = 0; guard < 100000; guard++) {
          const le = bytesIndexOf(buf, [13, 10], p, p + 64); if (le < 0) break;
          const n = parseInt(u8str(buf, p, le), 16); if (!(n >= 0)) break;
          p = le + 2; if (n === 0) { const t = bytesIndexOf(buf, CRLF2, p - 2, p + 8192); p = t >= 0 ? t + 4 : p + 2; break; }
          parts.push(buf.subarray(p, Math.min(buf.length, p + n))); tot += n; p += n + 2;
        }
        body = new Uint8Array(tot); let o = 0; parts.forEach(x => { body.set(x, o); o += x.length; }); end = p; m.chunked = true;
      } else if (h['content-length'] !== undefined) { const n = parseInt(h['content-length'], 10) || 0; body = buf.subarray(he + 4, Math.min(buf.length, he + 4 + n)); end = he + 4 + n; m.truncated = body.length < n; }
      else if (!isReq) { body = buf.subarray(he + 4); end = buf.length; }
    }
    m.body = body; m.end = end; out.push(m); pos = end; k++;
  }
  return out;
}

async function inflate(data, enc) {
  const kind = /gzip/i.test(enc) ? 'gzip' : /deflate/i.test(enc) ? 'deflate' : null;
  if (!kind || typeof DecompressionStream === 'undefined') return null;
  try { return new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream(kind))).arrayBuffer()); } catch (e) { return null; }
}

const KIND_LABEL = { exe: 'Executable', script: 'Script', image: 'Image', archive: 'Archive', doc: 'Document', html: 'Web page', text: 'Text', data: 'Data', media: 'Media' };
function sniff(d, mime, name) {
  const b = i => d[i], s4 = latin(d, 0, Math.min(d.length, 16));
  const r = (label, ext, kind, mimeOut) => ({ label, ext, kind, mime: mimeOut || mime || 'application/octet-stream' });
  if (b(0) === 0x4d && b(1) === 0x5a) return r('Windows PE executable', 'exe', 'exe', 'application/x-msdownload');
  if (b(0) === 0x7f && s4.startsWith('\x7fELF')) return r('ELF executable', 'elf', 'exe', 'application/x-executable');
  if (b(0) === 0xca && b(1) === 0xfe && b(2) === 0xba && b(3) === 0xbe) return r('Mach-O / Java class', 'bin', 'exe');
  if (b(0) === 0xcf && b(1) === 0xfa && b(2) === 0xed && b(3) === 0xfe) return r('Mach-O executable', 'macho', 'exe');
  if (s4.startsWith('\x89PNG')) return r('PNG image', 'png', 'image', 'image/png');
  if (b(0) === 0xff && b(1) === 0xd8 && b(2) === 0xff) return r('JPEG image', 'jpg', 'image', 'image/jpeg');
  if (s4.startsWith('GIF8')) return r('GIF image', 'gif', 'image', 'image/gif');
  if (s4.startsWith('RIFF') && latin(d, 8, 12) === 'WEBP') return r('WebP image', 'webp', 'image', 'image/webp');
  if (s4.startsWith('BM') && d.length > 26 && /\.bmp$/i.test(name || '')) return r('BMP image', 'bmp', 'image', 'image/bmp');
  if (s4.startsWith('<svg') || (/svg/.test(mime || '') && s4.includes('<'))) return r('SVG image', 'svg', 'image', 'image/svg+xml');
  if (s4.startsWith('\x00\x00\x01\x00') && /icon/.test(mime || '')) return r('Icon', 'ico', 'image', 'image/x-icon');
  if (s4.startsWith('%PDF')) return r('PDF document', 'pdf', 'doc', 'application/pdf');
  if (s4.startsWith('PK\x03\x04')) { const t = latin(d, 30, 30 + Math.min(80, d.length)); const ext = /^word\//.test(t) ? 'docx' : /^xl\//.test(t) ? 'xlsx' : /^ppt\//.test(t) ? 'pptx' : /^META-INF/.test(t) ? 'jar' : /AndroidManifest/.test(t) ? 'apk' : 'zip'; return r(ext === 'zip' ? 'ZIP archive' : ext.toUpperCase() + ' (ZIP container)', ext, ext === 'zip' ? 'archive' : ext === 'jar' || ext === 'apk' ? 'exe' : 'doc', ext === 'zip' ? 'application/zip' : undefined); }
  if (b(0) === 0xd0 && b(1) === 0xcf && b(2) === 0x11 && b(3) === 0xe0) return r('OLE document (doc/xls/msi)', /\.msi$/i.test(name || '') ? 'msi' : 'ole', /\.msi$/i.test(name || '') ? 'exe' : 'doc');
  if (b(0) === 0x1f && b(1) === 0x8b) return r('gzip archive', 'gz', 'archive', 'application/gzip');
  if (s4.startsWith('7z\xbc\xaf')) return r('7-Zip archive', '7z', 'archive');
  if (s4.startsWith('Rar!')) return r('RAR archive', 'rar', 'archive');
  if (latin(d, 257, 262) === 'ustar') return r('TAR archive', 'tar', 'archive');
  if (s4.startsWith('SQLite format')) return r('SQLite database', 'sqlite', 'data');
  if (s4.startsWith('ID3') || (b(0) === 0xff && (b(1) & 0xe0) === 0xe0 && /audio/.test(mime || ''))) return r('MP3 audio', 'mp3', 'media', 'audio/mpeg');
  if (latin(d, 4, 8) === 'ftyp') return r('MP4 video', 'mp4', 'media', 'video/mp4');
  if (s4.startsWith('#!')) return r('Shell script', 'sh', 'script', 'text/x-shellscript');
  const head = latin(d, 0, Math.min(d.length, 512));
  if (/\.(ps1|bat|cmd|vbs|hta|js|sh|py|pl)$/i.test(name || '') && isText(d, 0, d.length, 256)) return r('Script', (name.match(/\.(\w+)$/) || [])[1].toLowerCase(), 'script');
  if (/^\s*<\?php/i.test(head)) return r('PHP script', 'php', 'script');
  if (/^\s*(<!doctype html|<html|<head|<body)/i.test(head) || /html/.test(mime || '')) return r('HTML page', 'html', 'html', 'text/html');
  if (/json/.test(mime || '') || /^\s*[\[{]/.test(head) && isText(d, 0, d.length, 256)) return r('JSON', 'json', 'text', 'application/json');
  if (/^\s*<\?xml/.test(head) || /xml/.test(mime || '')) return r('XML', 'xml', 'text', 'application/xml');
  if (/css/.test(mime || '')) return r('Stylesheet', 'css', 'text', 'text/css');
  if (/javascript/.test(mime || '')) return r('JavaScript', 'js', 'script', 'text/javascript');
  if (isText(d, 0, d.length, 512)) { const csv = /^[^\n]*,[^\n]*\n[^\n]*,/.test(head); return r(csv ? 'CSV text' : 'Text', csv ? 'csv' : 'txt', 'text', csv ? 'text/csv' : 'text/plain'); }
  return r('Binary data', 'bin', 'data');
}
function baseName(p) { p = safeDecode((p || '').split('?')[0].split('#')[0]); const x = p.split(/[\\/]/).pop(); return x || ''; }

/* MD5 (for lookups in threat-intel tools that still key on it) */
function md5(u8) {
  const K = new Uint32Array(64), S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  const n = u8.length, nb = ((n + 8) >> 6) + 1, M = new Uint32Array(nb * 16);
  for (let i = 0; i < n; i++) M[i >> 2] |= u8[i] << ((i % 4) * 8);
  M[n >> 2] |= 0x80 << ((n % 4) * 8); M[nb * 16 - 2] = (n * 8) >>> 0; M[nb * 16 - 1] = Math.floor(n / 536870912);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let j = 0; j < nb; j++) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; } else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; } else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; } else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[j * 16 + g]) >>> 0; A = D; D = C; C = B;
      const sh = S[(i >> 4) * 4 + (i % 4)]; B = (B + ((F << sh) | (F >>> (32 - sh)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  return [a0, b0, c0, d0].map(v => [0, 8, 16, 24].map(s => h2((v >>> s) & 255)).join('')).join('');
}
async function sha256(u8) { try { const h = await crypto.subtle.digest('SHA-256', u8); return [...new Uint8Array(h)].map(h2).join(''); } catch (e) { return ''; } }

async function extractArtifacts(cap) {
  const files = [], emails = [], creds = (cap.credList || []).map(c => ({ ...c, kind: c.proto }));
  const pk = cap.pk, streams = cap.streams;
  const used = new Set();
  const evMap = new Map(); cap.threats.forEach(d => d.ev.forEach(i => { if (!evMap.has(i)) evMap.set(i, []); evMap.get(i).push(d); }));
  const linkDet = (st) => { let best = null; for (const i of st.pk) for (const d of evMap.get(i) || []) { const score = (d.type === 'download' ? 1e9 : 0) - d.ev.length; if (!best || score > best.score) best = { d, score }; } return best ? best.d : null; };
  const addFile = async (f) => {
    if (!f.data || !f.data.length) return;
    const sn = sniff(f.data, f.mime, f.name);
    f.type = sn; f.kind = sn.kind; f.size = f.data.length;
    if (!f.name) f.name = 'file_' + (files.length + 1) + '.' + sn.ext;
    else if (!/\.\w{1,5}$/.test(f.name)) f.name += '.' + sn.ext;
    f.flags = [];
    const nameExt = (f.name.match(/\.(\w+)$/) || [])[1] || '';
    const claimsSafe = /^(jpe?g|png|gif|webp|bmp|pdf|txt|csv|doc|docx|xls|xlsx|mp3|mp4|html?)$/i.test(nameExt) || /^(image|text|audio|video)\//.test(f.mime || '');
    if ((sn.kind === 'exe' || sn.kind === 'script') && claimsSafe) f.flags.push({ sev: 'critical', t: 'Executable disguised as ' + (nameExt ? '.' + nameExt : f.mime) });
    else if (sn.kind === 'exe') f.flags.push({ sev: 'high', t: 'Executable file' });
    else if (sn.kind === 'script') f.flags.push({ sev: 'high', t: 'Script' });
    if (sn.kind === 'archive' && f.src && isIp(f.src) && !isPrivate(f.src)) f.flags.push({ sev: 'low', t: 'Archive from the internet' });
    const det = f.stream !== undefined ? linkDet(streams[f.stream]) : null;
    if (det) f.det = det;
    f.id = files.length; files.push(f);
  };
  for (const st of streams) {
    if (st.l4 !== 'TCP' || st.payload === 0) continue;
    const proto = st.proto;
    const isHttp = proto === 'HTTP' || pk[st.pk[0]].s.http || st.pk.some(i => pk[i].s.http);
    if (isHttp) {
      const R = reassemble(cap, st);
      const reqs = parseHttpStream(R.a.buf, true), resps = parseHttpStream(R.b.buf, false, reqs.map(q => q.method));
      used.add(st.id);
      for (let k = 0; k < Math.max(reqs.length, resps.length); k++) {
        const q = reqs[k], p = resps[k];
        const url = q ? 'http://' + (q.headers.host || st.b) + q.uri : '';
        // Bearer tokens and API keys
        if (q) {
          const au = q.headers.authorization || '';
          if (/^bearer\s+/i.test(au)) creds.push({ src: st.a, dst: st.b, proto: 'HTTP Bearer token', user: '', pw: au.split(/\s+/)[1], extra: q.uri, ev: [pktAt(R.a, q.start)] });
          for (const hk of ['x-api-key', 'x-auth-token', 'api-key']) if (q.headers[hk]) creds.push({ src: st.a, dst: st.b, proto: 'HTTP ' + hk, user: '', pw: q.headers[hk], extra: q.uri, ev: [pktAt(R.a, q.start)] });
        }
        if (q && q.body.length && (q.method === 'POST' || q.method === 'PUT')) {
          const ct = q.headers['content-type'] || '';
          if (/multipart\/form-data/i.test(ct)) {
            for (const part of mimeParts(latin(q.body, 0, q.body.length), ct)) if (part.filename) await addFile({ name: part.filename, data: part.data, mime: part.ctype, src: st.a, dst: st.b, dir: 'upload', proto: 'HTTP', via: 'HTTP upload', url, stream: st.id, pkt: pktAt(R.a, q.start), t: pk[pktAt(R.a, q.start)].t });
          } else if (q.body.length > 256 && !/x-www-form-urlencoded/i.test(ct)) {
            await addFile({ name: baseName(q.uri) || 'upload_body', data: q.body, mime: ct, src: st.a, dst: st.b, dir: 'upload', proto: 'HTTP', via: 'HTTP ' + q.method, url, stream: st.id, pkt: pktAt(R.a, q.start), t: pk[pktAt(R.a, q.start)].t });
          }
        }
        if (!p || !p.body.length) continue;
        let data = p.body, enc = p.headers['content-encoding'] || '';
        if (enc && !/identity/i.test(enc)) { const d = await inflate(data, enc); if (d) data = d; }
        const cd = p.headers['content-disposition'] || '';
        const fn = (cd.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i) || [])[1];
        const nm = fn ? baseName(fn) : (q ? (baseName(q.uri) || 'index') : '');
        const pkt = pktAt(R.b, p.start);
        await addFile({ name: nm, data, mime: (p.headers['content-type'] || '').split(';')[0].trim(), src: st.b, dst: st.a, dir: 'download', proto: 'HTTP', via: 'HTTP ' + (q ? q.method : 'response') + ' ' + p.status, url, status: p.status, encoding: enc, stream: st.id, pkt, t: pk[pkt] ? pk[pkt].t : st.t0, truncated: p.truncated });
      }
      continue;
    }
    if (st.bp === 21) {
      used.add(st.id);
      const R = reassemble(cap, st), cli = latin(R.a.buf, 0, R.a.buf.length), srv = latin(R.b.buf, 0, R.b.buf.length);
      const ports = [...srv.matchAll(/227 [^(]*\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)|229 [^(]*\(\|\|\|(\d+)\|\)/g)].map(m => m[7] ? +m[7] : (+m[5]) * 256 + (+m[6]));
      const actives = [...cli.matchAll(/^PORT (\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/gm)].map(m => (+m[5]) * 256 + (+m[6]));
      const cmds = [...cli.matchAll(/^(RETR|STOR|STOU|APPE|LIST|NLST|MLSD) ?([^\r\n]*)/gm)].map(m => ({ c: m[1], arg: m[2] }));
      const dataStreams = streams.filter(x => x.l4 === 'TCP' && x.t0 >= st.t0 && x.t0 <= st.t1 + 5 && x.id !== st.id && ((x.b === st.b && ports.includes(x.bp)) || (x.a === st.b && x.ap === 20) || (x.a === st.a && actives.includes(x.ap)) || (x.b === st.a && actives.includes(x.bp))));
      dataStreams.sort((x, y) => x.t0 - y.t0);
      for (let k = 0; k < dataStreams.length; k++) {
        const ds = dataStreams[k], cmd = cmds[k] || { c: 'RETR', arg: '' }; used.add(ds.id);
        if (/LIST|NLST|MLSD/.test(cmd.c)) continue;
        const Rd = reassemble(cap, ds), upload = /STOR|STOU|APPE/.test(cmd.c);
        const side = upload ? (ds.a === st.a ? Rd.a : Rd.b) : (ds.b === st.b ? Rd.b : Rd.a);
        await addFile({ name: baseName(cmd.arg), data: side.buf, src: upload ? st.a : st.b, dst: upload ? st.b : st.a, dir: upload ? 'upload' : 'download', proto: 'FTP', via: 'FTP ' + cmd.c, url: 'ftp://' + st.b + '/' + cmd.arg, stream: ds.id, pkt: side.map.length ? side.map[0].i : ds.pk[0], t: ds.t0 });
      }
      continue;
    }
    if (st.bp === 25 || st.bp === 587 || st.bp === 2525) {
      used.add(st.id);
      const R = reassemble(cap, st), cli = latin(R.a.buf, 0, R.a.buf.length);
      const mailFrom = (cli.match(/^MAIL FROM:\s*<([^>]*)>/im) || [])[1] || '', rcpts = [...cli.matchAll(/^RCPT TO:\s*<([^>]*)>/gim)].map(m => m[1]);
      let p = 0;
      while (true) {
        const d = cli.indexOf('\r\nDATA\r\n', p) >= 0 ? cli.indexOf('\r\nDATA\r\n', p) + 8 : (cli.startsWith('DATA\r\n', p) ? p + 6 : -1); if (d < 0) break;
        const e = cli.indexOf('\r\n.\r\n', d); const msg = cli.slice(d, e < 0 ? cli.length : e);
        const hdrEnd = msg.indexOf('\r\n\r\n'); const hdr = msg.slice(0, hdrEnd);
        const hv = k => (hdr.match(new RegExp('^' + k + ':\\s*(.+)$', 'im')) || [])[1] || '';
        const em = { from: hv('From') || mailFrom, to: hv('To') || rcpts.join(', '), subject: hv('Subject'), src: st.a, dst: st.b, pkt: st.pk[0], t: st.t0, stream: st.id, attachments: [] };
        for (const part of mimeParts(msg.slice(hdrEnd + 4), hv('Content-Type'))) if (part.filename) { em.attachments.push(part.filename); await addFile({ name: part.filename, data: part.data, mime: part.ctype, src: st.a, dst: st.b, dir: 'upload', proto: 'SMTP', via: 'Email attachment', url: 'mailto:' + em.to, stream: st.id, pkt: pktAt(R.a, d), t: pk[pktAt(R.a, d)].t, email: em.subject }); }
        emails.push(em);
        p = e < 0 ? cli.length : e + 5;
      }
      continue;
    }
  }
  // raw carving from other cleartext TCP streams (e.g. files pushed over netcat)
  for (const st of streams) {
    if (st.l4 !== 'TCP' || used.has(st.id) || st.payload < 64 || ['TLS', 'SSH', 'QUIC', 'RDP', 'SMB'].includes(st.proto)) continue;
    const R = reassemble(cap, st);
    for (const [sideKey, side] of [['a', R.a], ['b', R.b]]) {
      if (side.buf.length < 64) continue;
      const sn = sniff(side.buf.subarray(0, 600), '', '');
      if (!['exe', 'archive', 'image', 'doc', 'media'].includes(sn.kind)) continue;
      await addFile({ name: 'carved_stream' + st.id + '_' + (sideKey === 'a' ? 'from_client' : 'from_server'), data: side.buf, src: sideKey === 'a' ? st.a : st.b, dst: sideKey === 'a' ? st.b : st.a, dir: 'transfer', proto: 'TCP/' + st.bp, via: 'Raw TCP (carved)', stream: st.id, pkt: side.map[0].i, t: pk[side.map[0].i].t });
    }
  }
  for (const f of files) { f.md5 = md5(f.data); f.sha256 = await sha256(f.data) || f.md5; }
  const groups = new Map(), uniq = [];
  for (const f of files) { const k = f.sha256 + '|' + f.name; const g = groups.get(k); if (g) { g.occ.push({ src: f.src, dst: f.dst, t: f.t, pkt: f.pkt, stream: f.stream }); continue; } f.occ = [{ src: f.src, dst: f.dst, t: f.t, pkt: f.pkt, stream: f.stream }]; groups.set(k, f); uniq.push(f); }
  uniq.forEach((f, i) => { f.id = i; f.interesting = f.flags.length > 0 || (f.kind !== 'html' && !(f.status >= 400) && f.size >= 64); });
  files.length = 0; files.push(...uniq);
  // SNMP communities
  const snmpSeen = new Set();
  for (const r of pk) { const sn = r.s.snmp; if (!sn || !sn.community) continue; const k = r.s.src + '|' + r.s.dst + '|' + sn.community; if (snmpSeen.has(k)) continue; snmpSeen.add(k); if (sn.pdu === 'response') continue; creds.push({ src: r.s.src, dst: r.s.dst, proto: 'SNMP v' + sn.ver + ' community', user: '', pw: sn.community, extra: sn.pdu, ev: [r.i] }); }
  // secrets in cleartext payloads (config dumps, shells, scripts)
  const SECRET_RE = /(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)['"]?\s*(?:=>|=|:)\s*['"]([^'"\s]{4,80})['"]/gi;
  const seenSec = new Set(creds.map(c => c.pw));
  for (const st of streams) {
    if (st.l4 !== 'TCP' || st.payload === 0 || st.payload > 4e6 || ['TLS', 'SSH', 'QUIC'].includes(st.proto)) continue;
    for (const i of st.pk) {
      const s = pk[i].s; if (!s.pll || s.http && /POST/.test(s.http.method || '')) continue;
      const t = payloadText(cap, i, 8192);
      for (const m of t.matchAll(SECRET_RE)) if (!seenSec.has(m[1])) { seenSec.add(m[1]); creds.push({ src: s.src, dst: s.dst, proto: 'Secret in cleartext', user: m[0].split(/\s*(?:=>|=|:)/)[0].replace(/^[\s$'"]+|['"]$/g, ''), pw: m[1], extra: 'stream ' + st.id, ev: [i] }); }
      for (const m of t.matchAll(/\bAKIA[0-9A-Z]{16}\b/g)) if (!seenSec.has(m[0])) { seenSec.add(m[0]); creds.push({ src: s.src, dst: s.dst, proto: 'AWS access key ID', user: '', pw: m[0], extra: 'stream ' + st.id, ev: [i] }); }
      if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(t) && !seenSec.has('pk' + st.id)) { seenSec.add('pk' + st.id); creds.push({ src: s.src, dst: s.dst, proto: 'Private key', user: '', pw: '(PEM block)', extra: 'stream ' + st.id, ev: [i] }); }
    }
  }
  creds.forEach((c, i) => { c.id = i; c.t = c.ev && c.ev.length && pk[c.ev[0]] ? pk[c.ev[0]].t : cap.t0; });
  creds.sort((a, b) => a.t - b.t);
  cap.art = { files, creds, emails, iocs: buildIocs(cap, files, emails), inv: buildInventory(cap) };
  return cap.art;
}
function mimeParts(text, ctype) {
  const bm = (ctype || '').match(/boundary="?([^";\r\n]+)"?/i); if (!bm) return [];
  const out = [];
  for (const chunk of text.split('--' + bm[1]).slice(1)) {
    if (chunk.startsWith('--')) break;
    const he = chunk.indexOf('\r\n\r\n'); if (he < 0) continue;
    const hdr = chunk.slice(0, he), body = chunk.slice(he + 4).replace(/\r\n$/, '');
    const fn = (hdr.match(/filename\*?="?([^";\r\n]+)"?/i) || hdr.match(/name="?([^";\r\n]+)"?/i) || [])[1];
    const ctp = ((hdr.match(/content-type:\s*([^;\r\n]+)/i) || [])[1] || '').trim();
    const cte = ((hdr.match(/content-transfer-encoding:\s*([^\r\n]+)/i) || [])[1] || '').trim().toLowerCase();
    let data;
    if (cte === 'base64') { try { const bin = atob(body.replace(/[^A-Za-z0-9+/=]/g, '')); data = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i); } catch (e) { continue; } }
    else { data = new Uint8Array(body.length); for (let i = 0; i < body.length; i++) data[i] = body.charCodeAt(i) & 255; }
    if (/multipart\//i.test(ctp)) { out.push(...mimeParts(body, hdr)); continue; }
    out.push({ filename: fn && /filename|name=/i.test(hdr) && (/attachment|filename/i.test(hdr) || !/text\/plain/i.test(ctp)) ? baseName(fn) : null, ctype: ctp, data });
  }
  return out;
}

function buildIocs(cap, files, emails) {
  const pk = cap.pk, flagged = new Set();
  cap.threats.forEach(d => { [d.src, d.dst].forEach(x => flagged.add(x)); });
  const ips = new Map(), domains = new Map(), urls = new Map(), uas = new Map(), mails = new Map();
  const dom = (name, src, i) => { name = name.toLowerCase().replace(/\.$/, ''); if (!name || /\.(local|arpa|lan|internal|corp\.local)$/.test(name) || !name.includes('.')) return; let d = domains.get(name); if (!d) { d = { v: name, src: new Set(), n: 0, i }; domains.set(name, d); } d.src.add(src); d.n++; };
  for (const r of pk) {
    const s = r.s;
    for (const ip of [s.src, s.dst]) if (isIp(ip) && !isPrivate(ip)) { let o = ips.get(ip); if (!o) { o = { v: ip, n: 0, bytes: 0, i: r.i }; ips.set(ip, o); } o.n++; o.bytes += r.len; }
    if (s.dns && !s.dns.qr && s.dns.qs[0] && s.proto === 'DNS') dom(s.dns.qs[0].name, 'DNS', r.i);
    if (s.sni && s.tlsHello === 'client') dom(s.sni, 'TLS SNI', r.i);
    if (s.http && !s.http.resp) {
      const h = s.http; if (h.host && !isIp(h.host.split(':')[0])) dom(h.host.split(':')[0], 'HTTP Host', r.i);
      const u = 'http://' + (h.host || s.dst) + h.uri; let o = urls.get(u); if (!o) { o = { v: u, n: 0, method: h.method, status: h.status, i: r.i, client: s.src }; urls.set(u, o); } o.n++;
      if (h.ua) { let a = uas.get(h.ua); if (!a) { a = { v: h.ua, n: 0, clients: new Set(), i: r.i, tool: TOOL_UA.test(h.ua) }; uas.set(h.ua, a); } a.n++; a.clients.add(s.src); }
    }
  }
  emails.forEach(e => [e.from, ...String(e.to).split(',')].forEach(x => { const m = (x.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/) || [])[0]; if (m) { let o = mails.get(m); if (!o) { o = { v: m, n: 0, i: e.pkt }; mails.set(m, o); } o.n++; } }));
  const tunnel = new Set(cap.threats.filter(d => d.type === 'dnstunnel').map(d => d.dst));
  const domList = [...domains.values()].map(d => ({ ...d, src: [...d.src].join(', '), bad: tunnel.has(baseDomain(d.v)) || flagged.has(d.v) }));
  // collapse tunnel subdomains into the base domain
  const dl = []; const seenBase = new Set();
  domList.sort((a, b) => b.bad - a.bad || b.n - a.n).forEach(d => { const b = baseDomain(d.v); if (tunnel.has(b)) { if (seenBase.has(b)) { dl.find(x => x.v === b).n += d.n; return; } seenBase.add(b); dl.push({ ...d, v: b, note: 'tunnel subdomains collapsed' }); } else dl.push(d); });
  return {
    ips: [...ips.values()].sort((a, b) => (flagged.has(b.v) - flagged.has(a.v)) || b.bytes - a.bytes).map(o => ({ ...o, bad: flagged.has(o.v) })),
    domains: dl, urls: [...urls.values()].sort((a, b) => a.i - b.i), uas: [...uas.values()].map(a => ({ ...a, clients: [...a.clients] })).sort((a, b) => b.tool - a.tool || b.n - a.n),
    emails: [...mails.values()], hashes: files.map(f => ({ v: f.sha256, md5: f.md5, name: f.name, bad: f.flags.some(x => x.sev !== 'low') })),
  };
}

function buildInventory(cap) {
  const pk = cap.pk, H = new Map();
  const host = ip => { let h = H.get(ip); if (!h) { h = { ip, macs: new Set(), names: new Set(), ttl: new Map(), sw: new Map(), ports: new Map(), tx: 0, rx: 0 }; H.set(ip, h); } return h; };
  const macName = new Map();
  for (const r of pk) {
    const s = r.s;
    if (s.dhcp && s.dhcp.host) macName.set(s.dhcp.mac, s.dhcp.host);
    if (s.dns && s.proto === 'mDNS' && s.dns.qr) s.dns.ans.forEach(a => { if (a.type === 'A' && /\.local$/.test(a.name)) host(a.val).names.add(a.name); });
    if (!isIp(s.src)) continue;
    const h = host(s.src); h.tx += r.len; if (isIp(s.dst)) host(s.dst).rx += r.len;
    if (s.smac && isPrivate(s.src)) h.macs.add(s.smac);
    if (s.ttl !== undefined && s.ipv === 4) h.ttl.set(s.ttl, (h.ttl.get(s.ttl) || 0) + 1);
    const sw = (k, v) => { if (v) h.sw.set(k + ': ' + v, k); };
    if (s.banner) sw(s.dirA ? 'SSH client' : 'SSH server', s.banner);
    if (s.http) { if (s.http.resp && s.http.headers.server) sw('Web server', s.http.headers.server); if (s.http.headers['x-powered-by']) sw('Powered by', s.http.headers['x-powered-by']); if (!s.http.resp && s.http.ua) sw('HTTP client', s.http.ua); }
    if (s.txt && /^220[ -]/.test(s.txt) && !s.dirA) sw(s.proto + ' server', s.txt.split('\r\n')[0].replace(/^220[ -]/, ''));
    if (s.l4 === 'TCP' && (s.fl & 18) === 18) h.ports.set('tcp/' + s.sp, TCP_PORTS[s.sp] || '');
    if (s.l4 === 'UDP' && s.dp > 0 && !s.dirA && s.st !== undefined) { const st = cap.streams[s.st]; if (st.b === s.src && st.bp < 49152) h.ports.set('udp/' + st.bp, UDP_PORTS[st.bp] || ''); }
  }
  for (const h of H.values()) for (const m of h.macs) if (macName.has(m)) h.names.add(macName.get(m));
  const os = h => { if (!h.ttl.size) return ''; const top = [...h.ttl.entries()].sort((a, b) => b[1] - a[1])[0][0]; const init = top <= 64 ? 64 : top <= 128 ? 128 : 255; const hops = init - top; return (init === 64 ? 'Linux, macOS or other Unix' : init === 128 ? 'Windows' : 'Network device / Solaris') + ' (TTL ' + top + (hops ? ', ~' + hops + ' hops away' : '') + ')'; };
  return [...H.values()].filter(h => h.tx > 0 && h.ip !== '0.0.0.0' && h.ip !== '255.255.255.255' && !/^2(2[4-9]|3\d)\./.test(h.ip)).map(h => ({ ip: h.ip, internal: isPrivate(h.ip), macs: [...h.macs], names: [...h.names], os: os(h), sw: [...h.sw.keys()], ports: [...h.ports.entries()].map(([p, n]) => p + (n ? ' ' + n : '')), tx: h.tx, rx: h.rx }))
    .sort((a, b) => (b.internal - a.internal) || (b.sw.length + b.ports.length) - (a.sw.length + a.ports.length) || (b.tx + b.rx) - (a.tx + a.rx));
}

/* minimal ZIP writer (stored entries) so any extracted file can be saved safely */
const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(u8) { let c = 0xffffffff; for (let i = 0; i < u8.length; i++) c = CRC_T[(c ^ u8[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function makeZip(entries) {
  const enc = new TextEncoder(), locals = [], central = []; let off = 0;
  const seen = new Map();
  for (const e of entries) {
    let name = e.name.replace(/[\\:*?"<>|]/g, '_'); const c = seen.get(name) || 0; seen.set(name, c + 1); if (c) name = name.replace(/(\.\w+)?$/, '_' + c + '$1');
    const nb = enc.encode(name), crc = crc32(e.data), sz = e.data.length;
    const lh = new DataView(new ArrayBuffer(30)); lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true); lh.setUint32(14, crc, true); lh.setUint32(18, sz, true); lh.setUint32(22, sz, true); lh.setUint16(26, nb.length, true);
    locals.push(new Uint8Array(lh.buffer), nb, e.data);
    const ch = new DataView(new ArrayBuffer(46)); ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true); ch.setUint16(8, 0x0800, true); ch.setUint32(16, crc, true); ch.setUint32(20, sz, true); ch.setUint32(24, sz, true); ch.setUint16(28, nb.length, true); ch.setUint32(42, off, true);
    central.push(new Uint8Array(ch.buffer), nb);
    off += 30 + nb.length + sz;
  }
  const cdSize = central.reduce((a, b) => a + b.length, 0);
  const end = new DataView(new ArrayBuffer(22)); end.setUint32(0, 0x06054b50, true); end.setUint16(8, entries.length, true); end.setUint16(10, entries.length, true); end.setUint32(12, cdSize, true); end.setUint32(16, off, true);
  return new Blob([...locals, ...central, new Uint8Array(end.buffer)], { type: 'application/zip' });
}

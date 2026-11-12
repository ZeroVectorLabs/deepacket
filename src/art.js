/* ===================== ARTIFACTS tab ===================== */
const KIND_FILTERS = [
  ['interesting', 'Notable files', f => f.interesting],
  ['exe', 'Executables & scripts', f => f.kind === 'exe' || f.kind === 'script'],
  ['image', 'Images', f => f.kind === 'image'],
  ['doc', 'Documents', f => f.kind === 'doc'],
  ['archive', 'Archives', f => f.kind === 'archive'],
  ['text', 'Text & data', f => f.kind === 'text' || f.kind === 'data' || f.kind === 'media'],
  ['html', 'Web pages', f => f.kind === 'html'],
  ['all', 'Everything', () => true],
];
const DIRECT_EXT = /^(png|jpe?g|gif|webp|txt|json|csv|pdf|zip|svg|docx|xlsx|pptx|md)$/i;
S.art = { sub: 'files', kf: 'interesting', view: 'list', sel: null, reveal: new Set(), urls: new Map() };

function ensureArt() {
  const cap = S.cap; if (!cap || cap.artP) return;
  cap.artP = extractArtifacts(cap).then(() => {
    if (S.cap !== cap) return;
    const n = cap.art.files.filter(f => f.interesting).length + cap.art.creds.length;
    const b = $('#abadge'); b.textContent = n; b.classList.toggle('ok', !n);
    S.dirty.artifacts = 1; if (S.view === 'artifacts') render();
  }).catch(e => { console.error(e); toast('Could not extract artifacts: ' + e.message); });
}
(async () => { try { S.dl = window.claude && typeof window.claude.use === 'function' ? await window.claude.use('downloads') : null; } catch (e) { S.dl = null; } if (S.cap && S.view === 'artifacts') { S.dirty.artifacts = 1; render(); } })();

const NATIVE_DL = (() => { try { return window.top === window.self; } catch (e) { return false; } })();
const canSave = () => !!S.dl || NATIVE_DL;
async function offerSave(filename, data) {
  if (!S.dl && NATIVE_DL) { // a normal top-level page (GitHub Pages, opened from disk): use the browser's own download
    const url = URL.createObjectURL(data instanceof Blob ? data : new Blob([data]));
    const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000); return;
  }
  if (!S.dl) { toast('Saving files is not available in this view.'); return; }
  try { await S.dl.save({ filename, data }); }
  catch (e) { if (e && e.code === 'declined') return; toast(e && e.code === 'rejected_extension' ? 'That file type cannot be saved here.' : 'Could not save: ' + ((e && (e.message || e.code)) || e)); }
}
function saveFileArt(f) {
  const ext = (f.name.match(/\.(\w+)$/) || [])[1] || '';
  if (DIRECT_EXT.test(ext) && f.kind !== 'exe' && f.kind !== 'script') return offerSave(f.name, new Blob([f.data]));
  return offerSave(f.name + '.zip', makeZip([{ name: f.name, data: f.data }]));
}
function blobUrl(f) { let u = S.art.urls.get(f.id); if (!u) { u = URL.createObjectURL(new Blob([f.data], { type: f.type.mime })); S.art.urls.set(f.id, u); } return u; }
function fileIcon(f) {
  if (f.kind === 'image') return `<img class="thumb" src="${blobUrl(f)}" alt="">`;
  const glyph = { exe: '<path d="M4 4h16v16H4z"/><path d="M8 9l3 3-3 3M13 15h3"/>', script: '<path d="M8 7l-5 5 5 5M16 7l5 5-5 5"/>', archive: '<path d="M4 4h16v16H4z"/><path d="M12 4v4M12 10v2M12 14v2"/>', doc: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>', html: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>', text: '<path d="M6 3h8l4 4v14H6z"/><path d="M9 12h6M9 16h4"/>', data: '<path d="M4 6h16M4 12h16M4 18h16"/>', media: '<path d="M6 4l14 8-14 8z"/>' }[f.kind] || '';
  return `<span class="ficon k-${f.kind}">${SVGI(glyph, 18)}</span>`;
}

function renderArtifacts() {
  const el = $('#view-artifacts'), cap = S.cap;
  if (!cap.art) { el.innerHTML = '<div class="empty">Reassembling streams and extracting files…</div>'; ensureArt(); return; }
  const A = cap.art, st = S.art;
  const counts = { files: A.files.filter(f => f.interesting).length, creds: A.creds.length, iocs: A.iocs.domains.length + A.iocs.urls.length + A.iocs.hashes.length, hosts: A.inv.filter(h => h.internal).length };
  el.innerHTML = `<div class="subnav">${[['files', 'Files'], ['creds', 'Credentials'], ['iocs', 'Indicators'], ['hosts', 'Hosts & software']].map(([k, l]) => `<button class="${st.sub === k ? 'on' : ''}" data-sub="${k}">${l}<span class="num">${counts[k]}</span></button>`).join('')}<span class="sp"></span><span class="hint">Covers the whole capture, regardless of filters</span></div><div id="artbody"></div>`;
  $$('.subnav [data-sub]', el).forEach(b => b.onclick = () => { st.sub = b.dataset.sub; renderArtifacts(); });
  ({ files: artFiles, creds: artCreds, iocs: artIocs, hosts: artHosts })[st.sub]();
}

function artFiles() {
  const A = S.cap.art, st = S.art, body = $('#artbody');
  const flt = KIND_FILTERS.find(k => k[0] === st.kf) || KIND_FILTERS[0];
  const list = A.files.filter(flt[2]);
  if (st.sel === null || !list.some(f => f.id === st.sel)) st.sel = list.length ? (list.find(f => f.flags.some(x => x.sev === 'critical')) || list.find(f => f.flags.length) || list[0]).id : null;
  body.innerHTML = `<div class="atools"><div class="kchips">${KIND_FILTERS.map(([k, l, fn]) => { const n = A.files.filter(fn).length; return n || k === 'interesting' ? `<button class="${st.kf === k ? 'on' : ''}" data-kf="${k}">${l} <span class="num">${n}</span></button>` : ''; }).join('')}</div><span class="sp"></span>
    <div class="seg"><button data-v="list" class="${st.view === 'list' ? 'on' : ''}">List</button><button data-v="gallery" class="${st.view === 'gallery' ? 'on' : ''}">Image gallery</button></div>
    ${canSave() && list.length ? `<button class="btn sm" id="dlall">Save these ${list.length} as .zip</button>` : ''}</div>
    <div class="artgrid"><div id="flist"></div><div class="card fprev" id="fprev"></div></div>`;
  $$('[data-kf]', body).forEach(b => b.onclick = () => { st.kf = b.dataset.kf; artFiles(); });
  $$('.seg [data-v]', body).forEach(b => b.onclick = () => { st.view = b.dataset.v; if (st.view === 'gallery') st.kf = 'image'; artFiles(); });
  if ($('#dlall')) $('#dlall').onclick = () => offerSave('deepacket_' + st.kf + '_files.zip', makeZip(list.map(f => ({ name: f.name, data: f.data }))));
  const fl = $('#flist');
  if (!list.length) fl.innerHTML = '<div class="empty">No files of this kind were found in the capture. Files can only be recovered from unencrypted transfers such as HTTP, FTP and SMTP.</div>';
  else if (st.view === 'gallery') {
    const imgs = list.filter(f => f.kind === 'image');
    fl.innerHTML = imgs.length ? `<div class="gallery">${imgs.map(f => `<button class="gcard ${f.id === st.sel ? 'sel' : ''}" data-f="${f.id}"><img src="${blobUrl(f)}" alt="${esc(f.name)}"><span class="gname">${esc(f.name)}</span><span class="gmeta mono">${esc(f.src)}</span></button>`).join('')}</div>` : '<div class="empty">No images were recovered.</div>';
  } else {
    fl.innerHTML = `<div class="card"><table class="tbl ftbl"><thead><tr><th></th><th>Name</th><th>Type</th><th class="r">Size</th><th>From</th><th>To</th><th class="r">Time</th></tr></thead><tbody>${list.map(f => `<tr data-f="${f.id}" class="${f.id === st.sel ? 'sel' : ''}"><td style="width:46px">${fileIcon(f)}</td><td><div class="fname2">${esc(f.name)}${f.occ.length > 1 ? ` <span class="pill">×${f.occ.length}</span>` : ''}</div><div class="hint">${esc(f.via)}</div>${f.flags.length ? `<div style="margin-top:4px;display:flex;gap:6px;flex-wrap:wrap">${f.flags.map(x => sevBadge(x.sev).replace(SEV_LABEL[x.sev] + '</span>', esc(x.t) + '</span>')).join('')}</div>` : ''}</td><td>${esc(f.type.label)}</td><td class="r">${fmtBytes(f.size)}</td><td class="mono">${esc(f.src)}</td><td class="mono">${esc(f.dst)}</td><td class="r">+${fmtRel(f.t - S.cap.t0, S.cap.dur)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  $$('#flist [data-f]').forEach(r => r.onclick = () => { st.sel = +r.dataset.f; $$('#flist [data-f]').forEach(x => x.classList.toggle('sel', x === r)); filePreview(); });
  filePreview();
}

function filePreview() {
  const A = S.cap.art, f = A.files.find(x => x.id === S.art.sel), el = $('#fprev');
  if (!el) return;
  if (!f) { el.innerHTML = '<div class="empty">Select a file to preview it</div>'; return; }
  let prev = '';
  if (f.kind === 'image' && f.type.ext !== 'svg') prev = `<div class="pimg"><img src="${blobUrl(f)}" alt="${esc(f.name)}"></div>`;
  else if (f.kind === 'exe') prev = `<div class="pwarn">${SVGI(SEV_ICON.high, 18)}<div><b>Executable content.</b> Deepacket never runs or renders it. Saving wraps it in a .zip so it cannot be opened by accident. Check the hash with your threat-intel tools first.</div></div>` + hexPreview(f.data, 128);
  else if (['text', 'html', 'script'].includes(f.kind) || f.type.ext === 'json') prev = `<pre class="ptext">${esc(new TextDecoder('utf-8', { fatal: false }).decode(f.data.subarray(0, 12000)))}${f.size > 12000 ? '\n…' : ''}</pre>`;
  else if (f.type.ext === 'pdf') { const t = latin(f.data, 0, Math.min(f.size, 200000)); const txt = [...t.matchAll(/\(([^()]{2,200})\)\s*Tj/g)].map(m => m[1]).slice(0, 40).join('\n'); prev = (txt ? `<pre class="ptext">${esc(txt)}</pre><p class="hint" style="margin:6px 0 0">Text strings found in the PDF.</p>` : '') + hexPreview(f.data, 128); }
  else if (f.type.ext === 'zip') { const names = zipNames(f.data); prev = names.length ? `<div class="hint" style="margin-bottom:6px">${names.length} entries</div><pre class="ptext">${esc(names.join('\n'))}</pre>` : hexPreview(f.data, 256); }
  else prev = hexPreview(f.data, 256);
  const o = f.occ[0];
  el.innerHTML = `<div class="card-h"><h3 class="mono" style="font-size:14px;word-break:break-all">${esc(f.name)}</h3></div><div class="card-b">
    ${f.flags.length || f.det ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">${f.flags.map(x => sevBadge(x.sev).replace(SEV_LABEL[x.sev] + '</span>', esc(x.t) + '</span>')).join('')}${f.det ? `<button class="tag" id="fdet" style="border:0;cursor:pointer">Part of: ${esc(f.det.title)}</button>` : ''}</div>` : ''}
    ${prev}
    <dl class="fmeta"><dt>Type</dt><dd>${esc(f.type.label)}${f.mime && f.mime !== f.type.mime ? ` <span class="hint">(sent as ${esc(f.mime)})</span>` : ''}</dd><dt>Size</dt><dd>${fmtNum(f.size)} bytes${f.truncated ? ' <span class="hint">(capture incomplete)</span>' : ''}</dd>
    <dt>Transfer</dt><dd>${esc(f.via)}${f.encoding ? ', ' + esc(f.encoding) + ' decoded' : ''}</dd>${f.url ? `<dt>Source</dt><dd class="mono" style="word-break:break-all">${esc(f.url)}</dd>` : ''}${f.email ? `<dt>Email</dt><dd>${esc(f.email)}</dd>` : ''}
    <dt>From → to</dt><dd class="mono">${esc(o.src)} → ${esc(o.dst)}</dd><dt>Seen</dt><dd>${f.occ.length > 1 ? f.occ.length + ' times, first ' : ''}+${fmtRel(o.t - S.cap.t0, S.cap.dur)} (${clock(o.t).slice(0, 8)})</dd>
    <dt>MD5</dt><dd class="mono hash">${f.md5}</dd><dt>SHA-256</dt><dd class="mono hash">${f.sha256}</dd></dl>
    <div class="acts">${canSave() ? `<button class="btn sm primary" id="fsave">${f.kind === 'exe' || f.kind === 'script' || !DIRECT_EXT.test((f.name.match(/\.(\w+)$/) || [])[1] || '') ? 'Save as .zip' : 'Save file'}</button>` : ''}<button class="btn sm" id="fcopy">Copy SHA-256</button><a class="btn sm" href="https://www.virustotal.com/gui/file/${f.sha256}" target="_blank" rel="noopener">Look up hash on VirusTotal ${SVGI(IC.ext, 12)}</a>${o.stream !== undefined ? `<button class="btn sm ghost" id="ffollow">Follow stream</button><button class="btn sm ghost" id="fpk">Show packets</button>` : ''}</div>
    ${!canSave() ? '<p class="hint" style="margin:10px 0 0">Saving files is not available in this view.</p>' : ''}</div>`;
  if ($('#fsave')) $('#fsave').onclick = () => saveFileArt(f);
  $('#fcopy').onclick = () => navigator.clipboard.writeText(f.sha256).then(() => toast('SHA-256 copied'), () => toast('Clipboard unavailable'));
  if ($('#ffollow')) { $('#ffollow').onclick = () => followStream(o.stream); $('#fpk').onclick = () => { setExpr('stream:' + o.stream); go('packets'); }; }
  if ($('#fdet')) $('#fdet').onclick = () => { S.tsel = f.det.id; S.dirty.threats = 1; go('threats'); };
}
function hexPreview(d, n) {
  let s = ''; const lim = Math.min(d.length, n);
  for (let o = 0; o < lim; o += 16) { let hx = '', as = ''; for (let j = 0; j < 16 && o + j < lim; j++) { const b = d[o + j]; hx += h2(b) + (j === 7 ? '  ' : ' '); as += b >= 32 && b < 127 ? String.fromCharCode(b) : '·'; } s += o.toString(16).padStart(4, '0') + '  ' + hx.padEnd(49) + ' ' + as + '\n'; }
  return `<pre class="ptext hexp">${esc(s)}${d.length > lim ? '…' : ''}</pre>`;
}
function zipNames(d) { const out = []; let p = 0; while (p + 30 < d.length && out.length < 200) { if (!(d[p] === 0x50 && d[p + 1] === 0x4b && d[p + 2] === 3 && d[p + 3] === 4)) break; const cs = d[p + 18] | d[p + 19] << 8 | d[p + 20] << 16 | d[p + 21] << 24, nl = d[p + 26] | d[p + 27] << 8, el = d[p + 28] | d[p + 29] << 8, us = d[p + 22] | d[p + 23] << 8 | d[p + 24] << 16 | d[p + 25] << 24; out.push(latin(d, p + 30, p + 30 + nl) + '  (' + fmtBytes(us >>> 0) + ')'); if (d[p + 6] & 8) break; p += 30 + nl + el + (cs >>> 0); } return out; }

function artCreds() {
  const A = S.cap.art, st = S.art, body = $('#artbody');
  const csv = () => 'time,protocol,client,server,username,secret,where\n' + A.creds.map(c => [clock(c.t), c.proto, c.src, c.dst, c.user, c.pw, c.extra || ''].map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
  body.innerHTML = `<div class="atools"><p class="hint" style="margin:0;max-width:90ch">Credentials and secrets that crossed the network without encryption. Anyone on the path could read them, so treat each one as compromised.</p><span class="sp"></span><button class="btn sm" id="crev">${st.revealAll ? 'Hide' : 'Reveal'} all secrets</button>${canSave() ? '<button class="btn sm" id="ccsv">Save as .csv</button>' : '<button class="btn sm" id="ccsv">Copy as CSV</button>'}</div>
  ${A.creds.length ? `<div class="card"><table class="tbl"><thead><tr><th class="r">Time</th><th>Protocol</th><th>Client</th><th>Server</th><th>Username</th><th>Password or secret</th><th>Where</th><th></th></tr></thead><tbody>${A.creds.map(c => { const shown = st.revealAll || st.reveal.has(c.id); return `<tr data-c="${c.id}"><td class="r">+${fmtRel(c.t - S.cap.t0, S.cap.dur)}</td><td><b style="font-weight:600">${esc(c.proto)}</b></td><td class="mono">${esc(c.src)}</td><td class="mono">${esc(c.dst)}</td><td class="mono">${esc(c.user || '—')}</td><td class="mono secret">${esc(shown ? c.pw : mask(c.pw))} <button class="btn sm ghost" data-rv="${c.id}">${shown ? 'Hide' : 'Reveal'}</button></td><td class="mono ell" style="max-width:220px">${esc(c.extra || '')}</td><td><button class="btn sm ghost" data-pk="${c.id}">Packet</button></td></tr>`; }).join('')}</tbody></table></div>` : '<div class="empty">No cleartext credentials were found. Logins over TLS, SSH and other encrypted protocols cannot be read from a capture.</div>'}`;
  $('#crev').onclick = () => { st.revealAll = !st.revealAll; artCreds(); };
  $('#ccsv').onclick = () => canSave() ? offerSave('deepacket_credentials.csv', csv()) : navigator.clipboard.writeText(csv()).then(() => toast('Copied ' + A.creds.length + ' rows as CSV'), () => toast('Clipboard unavailable'));
  $$('[data-rv]', body).forEach(b => b.onclick = e => { e.stopPropagation(); const id = +b.dataset.rv; st.reveal.has(id) ? st.reveal.delete(id) : st.reveal.add(id); artCreds(); });
  $$('[data-pk]', body).forEach(b => b.onclick = () => { const c = A.creds.find(x => x.id === +b.dataset.pk); if (c && c.ev && c.ev[0] !== undefined) { go('packets'); selectPacket(c.ev[0], true); } });
}

function artIocs() {
  const I = S.cap.art.iocs, body = $('#artbody');
  const txt = () => ['# Deepacket indicators — ' + S.cap.name, '', '## External IP addresses', ...I.ips.map(o => o.v), '', '## Domains', ...I.domains.map(o => o.v), '', '## URLs', ...I.urls.map(o => o.v), '', '## User agents', ...I.uas.map(o => o.v), '', '## Email addresses', ...I.emails.map(o => o.v), '', '## File hashes (SHA-256)', ...I.hashes.map(o => o.v + '  ' + o.name)].join('\n');
  const bad = b => b ? ' <span class="sev high" style="padding:0 6px">' + SVGI(SEV_ICON.high, 12) + 'Linked to a detection</span>' : '';
  const card = (title, sub, head, rows) => `<div class="card c6"><div class="card-h"><h3>${title}</h3><span class="sub">${sub}</span></div><div class="card-b"><div class="scroll" style="max-height:360px"><table class="tbl"><thead><tr>${head}</tr></thead><tbody>${rows || '<tr><td class="empty" colspan="4">None found</td></tr>'}</tbody></table></div></div></div>`;
  body.innerHTML = `<div class="atools"><p class="hint" style="margin:0;max-width:90ch">Everything external this capture touched, ready to paste into a blocklist, SIEM search or threat-intel lookup.</p><span class="sp"></span><button class="btn sm" id="icopy">Copy all as text</button>${canSave() ? '<button class="btn sm" id="isave">Save as .txt</button>' : ''}</div>
  <div class="grid">
  ${card('External IP addresses', I.ips.length + ' addresses', '<th>Address</th><th class="r">Packets</th><th class="r">Bytes</th>', I.ips.slice(0, 300).map(o => `<tr data-ip="${esc(o.v)}"><td class="mono">${esc(o.v)} ${roleTag(o.v)}</td><td class="r">${fmtNum(o.n)}</td><td class="r">${fmtBytes(o.bytes)}</td></tr>`).join('') + (I.ips.length > 300 ? `<tr><td colspan="3" class="hint">${I.ips.length - 300} more in the text export</td></tr>` : ''))}
  ${card('Domains', I.domains.length + ' names from DNS, TLS and HTTP', '<th>Domain</th><th>Seen in</th><th class="r">Times</th>', I.domains.map(o => `<tr><td class="mono">${esc(o.v)}${bad(o.bad)}${o.note ? `<div class="hint">${esc(o.note)}</div>` : ''}</td><td>${esc(o.src)}</td><td class="r">${fmtNum(o.n)}</td></tr>`).join(''))}
  ${card('URLs', I.urls.length + ' cleartext requests', '<th>URL</th><th>Method</th><th class="r">Status</th>', I.urls.map(o => `<tr data-pi="${o.i}"><td class="mono ell" style="max-width:420px" title="${esc(o.v)}">${esc(o.v)}</td><td>${esc(o.method)}</td><td class="r">${o.status || '—'}</td></tr>`).join(''))}
  ${card('User agents', I.uas.length + ' distinct', '<th>User agent</th><th>Clients</th><th class="r">Requests</th>', I.uas.map(o => `<tr><td class="ell" style="max-width:360px" title="${esc(o.v)}">${esc(o.v)}${o.tool ? ' <span class="sev critical" style="padding:0 6px">' + SVGI(SEV_ICON.critical, 12) + 'Attack tool</span>' : ''}</td><td class="mono">${o.clients.map(esc).join(', ')}</td><td class="r">${o.n}</td></tr>`).join(''))}
  ${card('Email addresses', I.emails.length + ' found in mail traffic', '<th>Address</th><th class="r">Times</th>', I.emails.map(o => `<tr><td class="mono">${esc(o.v)}</td><td class="r">${o.n}</td></tr>`).join(''))}
  ${card('File hashes', I.hashes.length + ' recovered files', '<th>SHA-256</th><th>File</th>', I.hashes.map(o => `<tr><td class="mono hash" style="max-width:300px">${o.v}</td><td>${esc(o.name)}${o.bad ? bad(true) : ''}</td></tr>`).join(''))}
  </div>`;
  $('#icopy').onclick = () => navigator.clipboard.writeText(txt()).then(() => toast('Indicators copied'), () => toast('Clipboard unavailable'));
  if ($('#isave')) $('#isave').onclick = () => offerSave('deepacket_indicators.txt', txt());
  $$('[data-ip]', body).forEach(r => r.onclick = () => { setChip('host', { v: r.dataset.ip }); go('packets'); });
  $$('[data-pi]', body).forEach(r => r.onclick = () => { go('packets'); selectPacket(+r.dataset.pi, true); });
}

function artHosts() {
  const inv = S.cap.art.inv, st = S.art, body = $('#artbody');
  const list = st.allHosts ? inv : inv.filter(h => h.internal || h.sw.length || S.roles.has(h.ip));
  body.innerHTML = `<div class="atools"><p class="hint" style="margin:0;max-width:90ch">What each machine appears to be, from DHCP names, MAC addresses, TTL values, banners and the services it answered on. Operating systems are educated guesses.</p><span class="sp"></span><label class="hint" style="display:flex;gap:6px;align-items:center;cursor:pointer"><input type="checkbox" id="hall" ${st.allHosts ? 'checked' : ''}> Include every external address (${inv.length})</label></div>
  <div class="card"><table class="tbl"><thead><tr><th>Address</th><th>Name</th><th>MAC</th><th>Likely OS</th><th>Services offered</th><th>Software and banners</th><th class="r">Sent</th><th class="r">Received</th></tr></thead><tbody>${list.slice(0, 400).map(h => `<tr data-h="${esc(h.ip)}"><td class="mono">${esc(h.ip)}<div>${roleTag(h.ip) || `<span class="hint">${h.internal ? 'Local' : 'Internet'}</span>`}</div></td><td>${esc(h.names.join(', ') || '—')}</td><td class="mono">${esc(h.macs.join(', ') || '—')}</td><td>${esc(h.os || '—')}</td><td class="mono" style="max-width:200px">${h.ports.map(esc).join('<br>') || '—'}</td><td style="max-width:420px">${h.sw.map(x => `<div class="swl">${esc(x)}</div>`).join('') || '—'}</td><td class="r">${fmtBytes(h.tx)}</td><td class="r">${fmtBytes(h.rx)}</td></tr>`).join('')}</tbody></table></div>`;
  $('#hall').onchange = e => { st.allHosts = e.target.checked; artHosts(); };
  $$('tr[data-h]', body).forEach(r => r.onclick = () => { go('conversations'); setTimeout(() => S.graph && S.graph.select(r.dataset.h), 400); });
}

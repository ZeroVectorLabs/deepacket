/* ===================== Capture strip (header navigator + landing specimen) ===================== */
function paintStrip(cv, cap, idx, order, opt) {
  const r = cv.getBoundingClientRect(); const W = r.width, H = r.height; if (!W) return null;
  const dpr = window.devicePixelRatio || 1; cv.width = W * dpr; cv.height = H * dpr;
  const ctx = cv.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
  const colW = opt.colW || 3, ncol = Math.max(10, Math.floor(W / colW)), K = 8;
  const pi = new Map(order.slice(0, 7).map((p, i) => [p, i]));
  const counts = new Uint32Array(ncol * K), tot = new Uint32Array(ncol);
  const pk = cap.pk, n = idx ? idx.length : pk.length, span = cap.dur;
  for (let k = 0; k < n; k++) { const p = pk[idx ? idx[k] : k]; let c = Math.floor((p.t - cap.t0) / span * ncol); if (c >= ncol) c = ncol - 1; if (c < 0) c = 0; const j = pi.has(p.s.proto) ? pi.get(p.s.proto) : 7; counts[c * K + j]++; tot[c]++; }
  let max = 1; for (let c = 0; c < ncol; c++) if (tot[c] > max) max = tot[c];
  const cols = []; for (let i = 1; i <= 7; i++) cols.push(cssv('--s' + i)); cols.push(cssv('--s0'));
  const top = opt.flags ? 10 : 0, ih = H - top;
  ctx.fillStyle = cssv('--panel-2'); ctx.fillRect(0, top + ih - 1, W, 1);
  const cw = W / ncol, gap = cw >= 3 ? 1 : 0;
  const dom = new Int8Array(ncol).fill(-1);
  for (let c = 0; c < ncol; c++) {
    if (!tot[c]) continue;
    let best = 0, bj = 0; for (let j = 0; j < K; j++) if (counts[c * K + j] > best) { best = counts[c * K + j]; bj = j; }
    dom[c] = bj;
    const h = Math.max(2, Math.log1p(tot[c]) / Math.log1p(max) * ih);
    ctx.fillStyle = cols[bj]; ctx.fillRect(c * cw, top + ih - h, cw - gap, h);
  }
  if (opt.flags) {
    cap.threats.forEach(d => {
      const x = (d.t0 - cap.t0) / span * W, col = cssv(SEV_VAR[d.sev]);
      ctx.globalAlpha = 0.5; ctx.fillStyle = col; ctx.fillRect(Math.round(x), top, 1, ih); ctx.globalAlpha = 1;
      ctx.beginPath(); ctx.moveTo(x - 4, 0); ctx.lineTo(x + 4, 0); ctx.lineTo(x, top - 2); ctx.closePath(); ctx.fill();
    });
  }
  if (opt.time) {
    const a = opt.time.a / span * W, b = opt.time.b / span * W;
    ctx.fillStyle = cssv('--bg'); ctx.globalAlpha = 0.72; ctx.fillRect(0, 0, a, H); ctx.fillRect(b, 0, W - b, H); ctx.globalAlpha = 1;
    ctx.fillStyle = cssv('--text'); ctx.fillRect(Math.round(a), 0, 1.5, H); ctx.fillRect(Math.round(b), 0, 1.5, H);
  }
  return { W, H, ncol, tot, dom, cw, span };
}

let stripState = null;
function drawStrip() {
  const cv = $('#stripcv'); if (!cv || !S.cap || $('#strip').classList.contains('hidden')) return;
  stripState = paintStrip(cv, S.cap, S.idxNT, S.order, { flags: true, time: S.chips.time, colW: 3 });
  $('#strip0').textContent = clock(S.cap.t0).slice(0, 8);
  $('#strip1').textContent = clock(S.cap.t1).slice(0, 8) + ', ' + fmtDur(S.cap.dur);
  $('#stripmid').textContent = S.chips.time ? 'Showing +' + fmtRel(S.chips.time.a, S.cap.dur) + ' to +' + fmtRel(S.chips.time.b, S.cap.dur) + '. Double-click to show everything.' : 'Drag across the capture to focus on a time window';
}
(function wireStrip() {
  const cv = $('#stripcv'); let drag = null;
  const fx = e => { const r = cv.getBoundingClientRect(); return Math.max(0, Math.min(r.width, e.clientX - r.left)); };
  cv.addEventListener('mousedown', e => { drag = fx(e); e.preventDefault(); });
  cv.addEventListener('mousemove', e => {
    if (!stripState || !S.cap) return;
    const x = fx(e), st = stripState;
    if (drag !== null) {
      drawStrip(); const ctx = cv.getContext('2d'); ctx.fillStyle = cssv('--accent'); ctx.globalAlpha = 0.25; ctx.fillRect(Math.min(drag, x), 0, Math.abs(x - drag), st.H); ctx.globalAlpha = 1; untip(); return;
    }
    const c = Math.min(st.ncol - 1, Math.floor(x / st.cw)), t = c / st.ncol * st.span;
    const dets = S.cap.threats.filter(d => Math.abs((d.t0 - S.cap.t0) / st.span * st.W - x) < 4);
    tip(`<div class="tt-h">+${fmtRel(t, st.span)}, ${clock(S.cap.t0 + t).slice(0, 8)}</div><div class="tt-r"><span>Packets</span><b>${fmtNum(st.tot[c])}</b></div>${st.dom[c] >= 0 ? `<div class="tt-r"><span>Busiest protocol</span><b>${esc(st.dom[c] < 7 ? S.order[st.dom[c]] : 'Other')}</b></div>` : ''}${dets.map(d => `<div style="margin-top:4px">${sevBadge(d.sev)} ${esc(d.title)}</div>`).join('')}`, e);
  });
  cv.addEventListener('mouseleave', untip);
  window.addEventListener('mouseup', e => {
    if (drag === null || !stripState) { drag = null; return; }
    const x = fx(e), a = Math.min(drag, x), b = Math.max(drag, x); drag = null;
    if (b - a > 3) setChip('time', { a: a / stripState.W * stripState.span, b: b / stripState.W * stripState.span }); else drawStrip();
  });
  cv.addEventListener('dblclick', () => { if (S.chips.time) setChip('time', null); });
})();

/* landing specimen: the bundled sample capture drawn as a strip */
async function prepSpecimen() {
  try {
    const b64 = $('#demo-data').textContent.trim();
    const bin = atob(b64); const u8 = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    S.demoCap = await loadCapture(await gunzip(u8), 'attack_scenario.pcap');
    drawSpecimen();
  } catch (e) { $('#specld').textContent = 'Could not decode the sample: ' + e.message; }
}
function drawSpecimen() {
  const cap = S.demoCap; if (!cap || !$('#landing').classList.contains('on')) return;
  const A = aggregate(cap, null);
  const order = [...A.protos.values()].sort((a, b) => b.p - a.p).map(p => p.name);
  $('#specld').style.display = 'none';
  paintStrip($('#speccv'), cap, null, order, { flags: true, colW: 5 });
  const step = cap.dur / Math.max(10, Math.floor($('#speccv').getBoundingClientRect().width / 5));
  $('#speccap').innerHTML = `<b>The sample capture.</b> ${fmtNum(cap.pk.length)} packets over ${fmtDur(cap.dur)}. Each column is ${fmtDur(step)} of traffic, coloured by its busiest protocol. Red markers are the ${cap.threats.length} attack steps Deepacket finds in it.`;
  $('#speclg').innerHTML = order.slice(0, 5).map((p, i) => `<span class="lg" style="cursor:default"><i style="background:var(--s${i + 1})"></i>${esc(p)}</span>`).join('');
}
$('#specimen').addEventListener('click', loadDemo);
prepSpecimen();

// Engine tests: run with `node --test tests/` (Node 20+). No dependencies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const root = fileURLToPath(new URL('..', import.meta.url));
const src = ['core', 'analysis', 'artifacts'].map(f => readFileSync(root + 'src/' + f + '.js', 'utf8')).join('\n');
const ctx = { performance, setTimeout, atob, console, Blob, Response, DecompressionStream, crypto, TextEncoder, TextDecoder };
vm.createContext(ctx);
vm.runInContext(src + '\nthis.E = { loadCapture, extractArtifacts, dissect, Tree, captureFormat };', ctx);
const { E } = ctx;

const sample = new Uint8Array(readFileSync(root + 'samples/attack_scenario.pcap'));
const capP = E.loadCapture(sample, 'attack_scenario.pcap');

test('parses the sample capture', async () => {
  const cap = await capP;
  assert.equal(cap.fmt, 'pcap');
  assert.equal(cap.pk.length, 4916);
  assert.ok(cap.streams.length > 1000);
  const protos = new Set(cap.pk.map(r => r.s.proto));
  for (const p of ['TLS', 'HTTP', 'DNS', 'SSH', 'FTP', 'SMTP', 'ARP', 'DHCP', 'NTP', 'QUIC', 'SNMP']) assert.ok(protos.has(p), 'missing ' + p);
});

test('detects every stage of the scripted intrusion', async () => {
  const cap = await capP;
  const types = new Set(cap.threats.map(d => d.type));
  for (const t of ['portscan', 'bruteforce', 'web-sqli', 'web-lfi', 'web-cmdi', 'web-log4j', 'download', 'shell', 'beacon', 'sweep', 'lateral', 'dnstunnel', 'exfil', 'arpspoof', 'synflood', 'cleartext'])
    assert.ok(types.has(t), 'missing detection ' + t);
  const stages = cap.flow.stages.filter(s => s.n).map(s => s.k);
  assert.equal(stages.length, 9);
  const role = id => cap.flow.lanes.find(l => l.id === id)?.role;
  assert.equal(role('203.0.113.66'), 'Attacker');
  assert.equal(role('10.0.0.20'), 'Compromised host');
  assert.equal(role('198.51.100.23'), 'C2 server');
});

test('recovers files, credentials and indicators', async () => {
  const cap = await capP;
  const A = await E.extractArtifacts(cap);
  const byName = n => A.files.find(f => f.name === n);
  assert.equal(byName('invoice_viewer_setup.exe')?.kind, 'exe');
  assert.equal(byName('kworker.jpg')?.flags[0]?.sev, 'critical');
  assert.equal(byName('team-offsite.jpg')?.kind, 'image');
  assert.equal(byName('customers_export.csv')?.via, 'FTP RETR');
  assert.equal(byName('invoice_88213.pdf')?.via, 'Email attachment');
  const sales = byName('sales.html');
  assert.equal(sales?.encoding, 'gzip');
  assert.match(new TextDecoder().decode(sales.data.subarray(0, 40)), /^<html>/, 'gzip-encoded page decoded');
  const creds = A.creds.map(c => c.proto + ':' + c.pw);
  for (const c of ['FTP:Backup#2026', 'HTTP Basic:S3cret!2026', 'HTTP form:Summer2026!', 'SMTP:Summer2026!', 'SNMP v2c community:corp-private', "Secret in cleartext:Pr0duct10n!DB"])
    assert.ok(creds.includes(c), 'missing credential ' + c);
  assert.ok(A.iocs.domains.some(d => d.v === 'exfil-tunnel.net' && d.bad));
  assert.ok(A.inv.find(h => h.ip === '10.0.0.15').names.includes('ALICE-LAPTOP'));
});

test('reads pcapng with a nanosecond interface', () => {
  // SHB + IDB (tsresol 9) + one EPB carrying a broadcast ARP request
  const arp = [255, 255, 255, 255, 255, 255, 2, 0, 0, 0, 0, 1, 8, 6, 0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2];
  const pad = a => { while (a.length % 4) a.push(0); return a; };
  const u32 = v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];
  const block = (type, body) => { body = pad(body); const len = body.length + 12; return [...u32(type), ...u32(len), ...body, ...u32(len)]; };
  const shb = block(0x0a0d0d0a, [...u32(0x1a2b3c4d), 1, 0, 0, 0, ...u32(0xffffffff), ...u32(0xffffffff)]);
  const idb = block(1, [1, 0, 0, 0, ...u32(65535), 9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
  const ts = 1762909200n * 1000000000n + 123456789n;
  const epb = block(6, [...u32(0), ...u32(Number(ts >> 32n)), ...u32(Number(ts & 0xffffffffn)), ...u32(arp.length), ...u32(arp.length), ...arp]);
  const buf = new Uint8Array([...shb, ...idb, ...epb]);
  assert.equal(E.captureFormat(buf), 'pcapng');
  return E.loadCapture(buf, 't.pcapng').then(cap => {
    assert.equal(cap.pk.length, 1);
    assert.equal(cap.pk[0].s.proto, 'ARP');
    assert.equal(cap.pk[0].s.info, 'Who has 10.0.0.2? Tell 10.0.0.1');
    assert.ok(Math.abs(cap.pk[0].t - 1762909200.123456789) < 1e-6);
  });
});

test('rejects files that are not captures', async () => {
  await assert.rejects(E.loadCapture(new TextEncoder().encode('hello, this is not a pcap file at all'), 'x.txt'), /Not a pcap/);
});

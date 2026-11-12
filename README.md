# DeepPacket

DeepPacket is a packet-capture analyzer that runs entirely in the browser. Open a `.pcap` or `.pcapng` file and it charts the traffic, maps who talked to whom, reconstructs any intrusion step by step against MITRE ATT&CK, and pulls out the files, credentials and indicators that crossed the wire.

Nothing is uploaded. The whole tool is one HTML file with no server and no external requests.

## Quick start

Open `dist/deeppacket.html` in a browser, then drop a capture on the page or choose **Open the sample attack**.

## What it shows

| View | What you get |
|---|---|
| Overview | Packets, data, duration, throughput, hosts and flows; traffic over time by protocol; protocols, top talkers, services, packet sizes and TCP flags. A capture strip under the header lets you drag to focus on any time window. |
| Threats | Heuristic detections mapped to ATT&CK, a kill-chain view, and an attack-flow sequence diagram of attacker, victims and C2. Each detection links to its evidence packets. |
| Network map | Local network on one side, internet on the other. Single-peer hosts are folded into groups, and attack paths are drawn as arrows. |
| Packets | A virtualized packet list with Wireshark-style filters, a protocol tree linked to a hex view, and TCP stream reassembly. |
| Artifacts | Files recovered from HTTP, FTP, SMTP and raw TCP (with MD5/SHA-256 and an image gallery); cleartext credentials and secrets; indicators (IPs, domains, URLs, user agents, emails, hashes); and a host inventory with OS guesses, services and software banners. |
| DNS, TLS & HTTP | Queried domains, TLS server names and cleartext HTTP requests. |

### Detections

- Port scans (SYN, NULL, FIN, Xmas, UDP), horizontal scans, ping and ARP sweeps
- Brute force against SSH, FTP, RDP, SMB, databases and web logins
- Web attacks: SQL injection, XSS, path traversal, command injection, Log4Shell, Shellshock, attack-tool user agents and forced browsing, including signs of success in the response
- Suspicious downloads, executables disguised as images, reverse shells and sessions on backdoor ports
- C2 beaconing, DNS tunnelling, NXDOMAIN bursts (DGA), ICMP tunnels and large outbound transfers
- ARP spoofing, rogue DHCP, DHCP starvation, SYN and ICMP floods, Heartbleed
- Cleartext credentials (HTTP Basic and forms, FTP, POP3, IMAP, SMTP, Telnet, SNMP communities) and secrets in payloads

Detection is heuristic. A clean result does not prove the traffic is benign.

### Supported captures

pcap (micro- and nanosecond, either byte order) and pcapng (multiple interfaces, any timestamp resolution), gzip-compressed or not. Link types: Ethernet (with VLAN tags), Linux cooked v1/v2, raw IP and BSD loopback.

## Project layout

```
src/            engine and UI sources
  core.js         capture readers and protocol dissectors
  analysis.js     streams, aggregation, threat detection, attack-flow model
  artifacts.js    TCP reassembly, file carving, credentials, indicators, inventory
  ui.js           views, filters, packet inspector, threats
  graph.js        network map
  strip.js        capture strip and landing preview
  art.js          Artifacts view
  style.css       theme
  shell.html      page template
fonts/          Archivo and IBM Plex Mono (SIL Open Font License), embedded at build time
samples/        attack_scenario.pcap, the synthetic demo capture
tools/
  build.py        bundles everything into dist/deeppacket.html
  gen_attack_pcap.py  regenerates the sample capture (needs scapy and Pillow)
tests/
  engine.test.mjs  engine tests for Node's built-in runner
  smoke_browser.py browser smoke test (Playwright)
dist/           the built single-file app (committed, generated)
```

## Development

Requirements: Node 20+ for the tests and Python 3.10+ for the build.

```sh
npm test                # engine tests
npm run build           # rebuild dist/deeppacket.html after editing src/
npm run test:browser    # optional; needs `pip install playwright` and Chromium
npm run sample          # regenerate samples/attack_scenario.pcap (needs scapy, Pillow)
```

Commit the rebuilt `dist/deeppacket.html` together with source changes; CI fails if it is stale.

## The sample capture

`samples/attack_scenario.pcap` is generated, not recorded. It mixes normal office traffic with a scripted intrusion: a port scan and web exploitation from 203.0.113.66, an SSH brute force, a reverse shell and beaconing to a C2 server, lateral movement, DNS tunnelling, bulk exfiltration, ARP spoofing by an insider and a SYN flood. It also carries files (images, PDFs, a ZIP, an FTP export, an email attachment) and cleartext logins.

The "executables" in it are harmless stand-ins: only the MZ/ELF header shape and a note, with no runnable code. All addresses are private or from documentation ranges.

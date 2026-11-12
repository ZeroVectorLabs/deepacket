"""Bundle src/, fonts and the sample capture into one self-contained HTML file: dist/deepacket.html."""
import base64, gzip, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
src = ROOT / 'src'
html = (src/'shell.html').read_text()
js = '\n'.join((src/f).read_text() for f in ['core.js','analysis.js','artifacts.js','ui.js','graph.js','strip.js','art.js'])
assert '</script' not in js
demo = base64.b64encode(gzip.compress((ROOT / 'samples' / 'attack_scenario.pcap').read_bytes(), 9, mtime=0)).decode()
def ff(name, file, w, extra=''):
    d = base64.b64encode((ROOT / 'fonts' / file).read_bytes()).decode()
    return "@font-face{font-family:'%s';src:url(data:font/woff2;base64,%s) format('woff2');font-weight:%s;font-style:normal;font-display:swap;%s}\n" % (name, d, w, extra)
fonts = ff('Archivo','archivo.woff2','100 900','font-stretch:62% 125%;') + ff('IBM Plex Mono','plex400.woff2','400') + ff('IBM Plex Mono','plex500.woff2','500')
logo = lambda n: 'data:image/png;base64,' + base64.b64encode((ROOT / 'assets' / f'logo-{n}.png').read_bytes()).decode()
html = html.replace('/*FONTS*/', fonts).replace('/*LOGO64*/', logo(64)).replace('/*LOGO256*/', logo(256))
html = html.replace('/*CSS*/', (src/'style.css').read_text()).replace('/*JS*/', js).replace('/*DEMO*/', demo)
(ROOT / 'dist').mkdir(exist_ok=True)
(ROOT / 'dist' / 'deepacket.html').write_text(html)
print('built', len(html)//1024, 'KB')

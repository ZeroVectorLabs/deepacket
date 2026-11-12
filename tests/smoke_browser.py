"""Browser smoke test: opens dist/deepacket.html, loads the sample and visits every view.

Needs Python Playwright and a Chromium/Chrome build:  pip install playwright && playwright install chromium
Run:  python3 tests/smoke_browser.py   (exits non-zero on any page error; set CHROME_PATH to use an installed Chrome)
"""
import asyncio, os, pathlib, sys
from playwright.async_api import async_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
VIEWS = ['overview', 'threats', 'conversations', 'packets', 'artifacts', 'insights']

async def main():
    errors = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=os.environ.get('CHROME_PATH') or None)
        page = await browser.new_page(viewport={'width': 1440, 'height': 900})
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: errors.append(m.text) if m.type == 'error' else None)
        await page.goto((ROOT / 'dist' / 'deepacket.html').as_uri())
        await page.click('#demoBtn')
        await page.wait_for_selector('#view-overview.on', timeout=20000)
        for v in VIEWS:
            await page.click(f'.tab[data-view={v}]')
            await page.wait_for_timeout(700)
        await page.fill('#fin', 'ip:10.0.0.20 port:4444')
        await page.wait_for_timeout(500)
        count = await page.inner_text('#fcount')
        await browser.close()
    if '27 of' not in count:
        errors.append('filter returned unexpected count: ' + count)
    for e in errors:
        print('ERROR', e)
    print('smoke test', 'failed' if errors else 'passed')
    sys.exit(1 if errors else 0)

asyncio.run(main())

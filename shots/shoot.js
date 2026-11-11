const { chromium } = require('playwright-core');
(async () => {
  const browser = await chromium.launch({args: ['--no-sandbox']});
  const page = await browser.newPage({viewport: {width: 1280, height: 800}});
  const targets = [
    ['http://127.0.0.1:3000', 'juice.png', 6000],
    ['http://127.0.0.1:8888', 'crapi.png', 5000],
    ['http://127.0.0.1:8080', 'roundcube.png', 4000],
    ['http://127.0.0.1:9000', 'sonarqube.png', 4000],
    ['https://github.com/ChahbaniRayen/app-securite-/actions', 'gh-actions.png', 6000],
    ['file:///home/ubuntu/secscan-platform/results/20261111-150145/dast/zap-full-juice-shop.html', 'zap-report.png', 4000],
  ];
  for (const [url, out, wait] of targets) {
    try {
      await page.goto(url, {waitUntil: 'load', timeout: 30000});
      await page.waitForTimeout(wait);
      await page.screenshot({path: out});
      console.log('OK', out);
    } catch (e) { console.log('ECHEC', out, e.message.split('\n')[0]); }
  }
  await browser.close();
})();

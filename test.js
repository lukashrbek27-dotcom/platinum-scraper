const { chromium } = require('playwright');

async function test() {
    console.log('🚀 Spouštím prohlížeč...');
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    console.log('🌐 Načítám krmivo-platinum.cz...');
    await page.goto('https://www.krmivo-platinum.cz/', {
        waitUntil: 'domcontentloaded',
        timeout: 30000
    });
    
    await page.waitForTimeout(3000);
    await page.screenshot({ path: 'screenshot.png', fullPage: true });
    
    console.log('📸 Screenshot uložen!');
    await browser.close();
    console.log('✅ Hotovo!');
}

test().catch(err => {
    console.error('❌ Chyba:', err.message);
});
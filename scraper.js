const { chromium } = require('playwright');
const fs = require('fs');

const CATEGORIES = [
    { name: 'Granule pro psy', url: 'https://www.krmivo-platinum.cz/granule-c130/' },
    { name: 'Granule pro psy (alt)', url: 'https://www.krmivo-platinum.cz/granule-pro-psy-c77/' },
    { name: 'Pro psy', url: 'https://www.krmivo-platinum.cz/pro-psy-c76/' },
    { name: 'Pro kočky', url: 'https://www.krmivo-platinum.cz/pro-kocky-c75/' },
    { name: 'VETACTIVE', url: 'https://www.krmivo-platinum.cz/vetactive-c100/' },
    { name: 'MeatCrisp Chicken', url: 'https://www.krmivo-platinum.cz/meatcrisp-chicken-c149/' },
    { name: 'MeatCrisp Fish', url: 'https://www.krmivo-platinum.cz/meatcrisp-fish-c150/' },
    { name: 'Reklamní předměty', url: 'https://www.krmivo-platinum.cz/reklamni-predmety-c91/' },
];

async function scrape() {
    console.log('🚀 Spouštím scraper...');
    
    const browser = await chromium.launch({ 
        headless: true,
        args: ['--disable-blink-features=AutomationControlled']
    });
    
    const context = await browser.newContext({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        viewport: { width: 1920, height: 1080 },
        locale: 'cs-CZ'
    });
    
    await context.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });
    
    const page = await context.newPage();
    const allProducts = [];
    
    for (const category of CATEGORIES) {
        console.log(`\n📂 ${category.name}`);
        console.log(`   ${category.url}`);
        
        try {
            await page.goto(category.url, {
                waitUntil: 'networkidle',
                timeout: 60000
            });
            
            console.log('   ⏳ Čekám na produkty...');
            await page.waitForTimeout(3000);
            
            console.log('   📜 Scrolluji pro obrázky...');
            await page.evaluate(async () => {
                await new Promise((resolve) => {
                    let totalHeight = 0;
                    const distance = 300;
                    const timer = setInterval(() => {
                        const scrollHeight = document.body.scrollHeight;
                        window.scrollBy(0, distance);
                        totalHeight += distance;
                        if (totalHeight >= scrollHeight) {
                            clearInterval(timer);
                            resolve();
                        }
                    }, 100);
                });
            });
            
            await page.waitForTimeout(5000);
            
            const products = await page.evaluate((catName) => {
                const items = [];
                const elements = document.querySelectorAll('.ProductView, div[class*="ProductView"]');
                
                elements.forEach(el => {
                    const text = el.innerText || '';
                    const lines = text.split('\n').filter(l => l.trim());
                    const name = lines[0]?.trim();
                    const priceLine = lines.find(l => l.includes('Kč'));
                    const price = priceLine?.trim();
                    const stock = text.includes('Skladem') ? 'Skladem' : 
                                  text.includes('Vyprodáno') ? 'Vyprodáno' : 'Neznámá';
                    const link = el.querySelector('a');
                    const url = link?.href;
                    
                    let image = null;
                    const img = el.querySelector('img');
                    if (img) {
                        image = img.dataset?.src || img.src;
                    }
                    
                    if (image && image.includes('data:image/gif')) {
                        image = null;
                    }
                    
                    // FILTR: Přeskoč vzorky
                    const lowerName = (name || '').toLowerCase();
                    if (lowerName.includes('vzorek') || 
                        lowerName.includes('50g') || 
                        lowerName.includes('50 g') ||
                        lowerName.includes('test')) {
                        return;
                    }
                    
                    if (name && price) {
                        items.push({
                            name,
                            price,
                            stock,
                            url,
                            image,
                            category: catName,
                            scrapedAt: new Date().toISOString()
                        });
                    }
                });
                
                return items;
            }, category.name);
            
            console.log(`   ✅ ${products.length} produktů`);
            allProducts.push(...products);
            
            await page.waitForTimeout(3000);
            
        } catch (err) {
            console.log(`   ❌ Chyba: ${err.message}`);
        }
    }
    
    await browser.close();
    
    const output = {
        scrapedAt: new Date().toISOString(),
        source: 'krmivo-platinum.cz',
        totalProducts: allProducts.length,
        categories: CATEGORIES.length,
        products: allProducts
    };
    
    fs.writeFileSync('products.json', JSON.stringify(output, null, 2));
    console.log(`\n🎉 Hotovo! ${allProducts.length} produktů uloženo do products.json`);
    
    const withImages = allProducts.filter(p => p.image && p.image.startsWith('http')).length;
    console.log(`📸 Produktů s obrázkem: ${withImages}/${allProducts.length}`);
}

scrape().catch(err => {
    console.error('💥 Chyba:', err.message);
});
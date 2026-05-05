const { chromium } = require('playwright');
const fs = require('fs');

// Kategorie k prozkoumání
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
            
            // Počkej na načtení produktů (BSSHOP je načítá dynamicky)
            await page.waitForTimeout(8000);
            
            // Najdi produkty
            const products = await page.evaluate((catName) => {
                const items = [];
                
                // Najdi všechny ProductView elementy
                const elements = document.querySelectorAll('.ProductView, div[class*="ProductView"]');
                
                elements.forEach(el => {
                    const text = el.innerText || '';
                    
                    // Extrahuj název (první řádek)
                    const lines = text.split('\n').filter(l => l.trim());
                    const name = lines[0]?.trim();
                    
                    // Extrahuj cenu (řádek s "Kč")
                    const priceLine = lines.find(l => l.includes('Kč'));
                    const price = priceLine?.trim();
                    
                    // Extrahuj dostupnost
                    const stock = text.includes('Skladem') ? 'Skladem' : 
                                  text.includes('Vyprodáno') ? 'Vyprodáno' : 'Neznámá';
                    
                    // Najdi URL (první odkaz v elementu)
                    const link = el.querySelector('a');
                    const url = link?.href;
                    
                    // Najdi obrázek
                    const img = el.querySelector('img');
                    const image = img?.src;
                    
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
            
            // Počkej mezi kategoriemi (abychom nezatěžovali server)
            await page.waitForTimeout(3000);
            
        } catch (err) {
            console.log(`   ❌ Chyba: ${err.message}`);
        }
    }
    
    await browser.close();
    
    // Ulož výsledky
    const output = {
        scrapedAt: new Date().toISOString(),
        source: 'krmivo-platinum.cz',
        totalProducts: allProducts.length,
        categories: CATEGORIES.length,
        products: allProducts
    };
    
    fs.writeFileSync('products.json', JSON.stringify(output, null, 2));
    console.log(`\n🎉 Hotovo! ${allProducts.length} produktů uloženo do products.json`);
}

scrape().catch(err => {
    console.error('💥 Chyba:', err.message);
});
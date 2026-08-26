const { chromium } = require('playwright');
const fs = require('fs');
const {
    ReviewStageError,
    assertAllowedDocument,
    createNetworkGuardSession,
    sanitizeText,
    validateCategoryExtraction,
    validateDetailExtraction,
} = require('./review-hardening');

const CATEGORIES = [
    { name: 'Granule pro psy', animalType: 'dog', url: 'https://www.krmivo-platinum.cz/granule-pro-psy-c77/' },
    { name: 'Granule pro kočky', animalType: 'cat', url: 'https://www.krmivo-platinum.cz/granule-pro-kocky-c101/' },
];

function extractDetailVariants() {
    const rows = document.querySelectorAll('.item.variant');
    const result = [];
    let invalidRows = 0;
    rows.forEach(row => {
        const rawText = row.innerText || '';
        const lines = rawText.split('\n').map(line => line.trim()).filter(Boolean);

        // The currently selected 1.5 kg offer is rendered as one collapsed line.
        // It remains a real offer: require both an anchored size and the semantic
        // price value element instead of accepting an arbitrary short row.
        if (lines.length < 2) {
            const sizeMatch = rawText.replace(/\s+/gu, ' ').trim()
                .match(/^((?:\d+\s*[x×]\s*)?\d+(?:[,.]\d+)?\s*(?:kg|g))/iu);
            const priceElement = row.querySelector('.price .value, .bs-priceLayout .value, .value');
            const priceText = priceElement?.innerText?.trim();
            const numericPrice = Number.parseInt(String(priceText || '').replace(/[^0-9]/gu, ''), 10);
            if (!sizeMatch || !priceText || !Number.isFinite(numericPrice) || numericPrice <= 0) {
                invalidRows += 1;
                return;
            }
            result.push({ sizeText: sizeMatch[1].trim(), priceText, salePriceText: null, originalPriceText: null });
            return;
        }

        const sizeText = lines[0]; // např. "1,5 kg" nebo "2 x 5 kg"
        const prices = lines.filter(line => line.includes('Kč'));
        if (prices.length === 0) { invalidRows += 1; return; }
        const parseNum = value => parseInt(value.replace(/\s/g, '').replace('Kč', ''), 10);
        if (prices.length === 1) {
            result.push({ sizeText, priceText: prices[0], salePriceText: null, originalPriceText: null });
        } else {
            // Dva řádky ceny = bundle sleva: vyšší je původní, nižší je akční
            const isMultipack = /^\s*\d+\s*[x×]\s*\d/iu.test(sizeText);
            if (isMultipack) {
                const unitPriceText = row.querySelector('.pricePerPiece')?.innerText?.trim() || null;
                const totalPriceText = row.querySelector('.price.primary.user .value')?.innerText?.trim() || null;
                const originalPriceText = row.querySelector('.price.primary.retail .value')?.innerText?.trim() || null;
                if (!unitPriceText || !totalPriceText || !originalPriceText) { invalidRows += 1; return; }
                result.push({
                    sizeText,
                    priceText: totalPriceText,
                    salePriceText: totalPriceText,
                    originalPriceText,
                    multipackUnitPriceText: unitPriceText,
                    multipackTotalPriceText: totalPriceText,
                });
                return;
            }
            const nums = prices.map(parseNum);
            const original = prices[nums.indexOf(Math.max(...nums))];
            const sale = prices[nums.indexOf(Math.min(...nums))];
            result.push({ sizeText, priceText: sale, salePriceText: sale, originalPriceText: original });
        }
    });
    return { variants: result, rowCount: rows.length, invalidRows };
}

async function scrape(options = {}) {
    console.log('🚀 Spouštím scraper...');
    const reviewMode = options.reviewMode === true;
    const generatedAt = options.generatedAt || null;
    const metrics = {
        categoryRequests: 0,
        categorySuccesses: 0,
        categoryErrors: 0,
        detailRequests: 0,
        detailSuccesses: 0,
        detailErrors: 0,
        categoryCards: 0,
        excludedSamples: 0,
        invalidCategoryCards: 0,
        detailVariantRows: 0,
        invalidDetailRows: 0,
        network: null,
    };
    const browser = await (options.chromium || chromium).launch({
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
    const networkGuard = reviewMode ? createNetworkGuardSession() : null;
    if (networkGuard) {
        await networkGuard.install(context);
        metrics.network = networkGuard.metrics;
    }
    const page = await context.newPage();
    let allProducts = [];
    try {
    for (const category of CATEGORIES) {
        console.log(`\n📂 ${category.name}`);
        console.log(`   ${category.url}`);
        
        try {
            metrics.categoryRequests += 1;
            const response = await page.goto(category.url, {
                waitUntil: 'networkidle',
                timeout: 60000
            });
            if (reviewMode) {
                networkGuard.assertNoFatalViolations('category_navigation');
                await assertAllowedDocument(page, response, 'category_navigation');
            }
            
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
            
            const extraction = await page.evaluate(({ catName, animalType }) => {
                const items = [];
                const elements = document.querySelectorAll('.ProductView, div[class*="ProductView"]');
                let excludedSamples = 0;
                let invalidCards = 0;

                elements.forEach(el => {
                    const text = el.innerText || '';
                    const lines = text.split('\n').filter(l => l.trim());
                    const name = lines[0]?.trim();
                    const priceEl = el.querySelector('.price .value, .bs-priceLayout .value, .value');
                    const price = priceEl ? priceEl.innerText.trim() : lines.find(l => l.includes('Kč'))?.trim();
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
                        excludedSamples += 1;
                        return;
                    }

                    if (name && price) {
                        items.push({
                            name,
                            price,
                            salePrice: null,
                            originalPrice: null,
                            stock,
                            url,
                            image,
                            category: catName,
                            animalType,
                            scrapedAt: new Date().toISOString()
                        });
                    } else {
                        invalidCards += 1;
                    }
                });

                return { items, cardCount: elements.length, excludedSamples, invalidCards };
            }, { catName: category.name, animalType: category.animalType });
            const products = reviewMode ? validateCategoryExtraction(extraction, category.name) : extraction.items;
            console.log(`   ✅ ${products.length} produktů`);
            allProducts.push(...products);
            metrics.categorySuccesses += 1;
            metrics.categoryCards += extraction.cardCount;
            metrics.excludedSamples += extraction.excludedSamples;
            metrics.invalidCategoryCards += extraction.invalidCards;
            
            await page.waitForTimeout(3000);
            
        } catch (err) {
            metrics.categoryErrors += 1;
            console.log(`   ❌ Chyba: ${sanitizeText(err.message)}`);
            if (reviewMode) {
                const failure = err instanceof ReviewStageError ? err : new ReviewStageError('category', err.message, { category: category.name });
                failure.metrics = metrics;
                throw failure;
            }
        }
    }
    
    // KROK 2: Scrapuj varianty velikostí z detailní stránky
    const productsWithVariants = [];
    for (const product of allProducts) {
        console.log(`\n🔍 Detail: ${product.name}`);
        try {
            metrics.detailRequests += 1;
            const response = await page.goto(product.url, { waitUntil: 'networkidle', timeout: 30000 });
            if (reviewMode) {
                networkGuard.assertNoFatalViolations('detail_navigation');
                await assertAllowedDocument(page, response, 'detail_navigation');
            }
            await page.waitForTimeout(2000);
            const extraction = await page.evaluate(extractDetailVariants);
            const variants = reviewMode ? validateDetailExtraction(extraction, product) : extraction.variants;

            console.log(`   Varianty (${variants?.length ?? 0}):`, JSON.stringify(variants));

            if (variants && variants.length > 0) {
                for (const v of variants) {
                    productsWithVariants.push({
                        ...product,
                        price: v.priceText,
                        salePrice: v.salePriceText,
                        originalPrice: v.originalPriceText,
                        ...(v.multipackUnitPriceText ? {
                            multipackUnitPrice: v.multipackUnitPriceText,
                            multipackTotalPrice: v.multipackTotalPriceText,
                        } : {}),
                        size: v.sizeText,
                        ...(reviewMode ? { scrapedAt: generatedAt } : {}),
                    });
                }
            } else {
                productsWithVariants.push(product);
            }
            metrics.detailSuccesses += 1;
            metrics.detailVariantRows += extraction.rowCount;
            metrics.invalidDetailRows += extraction.invalidRows;
        } catch (e) {
            metrics.detailErrors += 1;
            console.log(`   ❌ ${sanitizeText(e.message)}`);
            if (reviewMode) {
                const failure = e instanceof ReviewStageError ? e : new ReviewStageError('detail', e.message, { product: product.name, url: product.url });
                failure.metrics = metrics;
                throw failure;
            }
            productsWithVariants.push(product);
        }
        await page.waitForTimeout(1000);
    }
    allProducts = productsWithVariants;

    const output = {
        scrapedAt: generatedAt || new Date().toISOString(),
        source: 'krmivo-platinum.cz',
        totalProducts: allProducts.length,
        categories: CATEGORIES.length,
        ...(reviewMode ? { categoryNames: CATEGORIES.map(category => category.name) } : {}),
        products: allProducts
    };
    if (!reviewMode) {
        fs.writeFileSync('products.json', JSON.stringify(output, null, 2));
        console.log(`\n🎉 Hotovo! ${allProducts.length} produktů uloženo do products.json`);
    }
    
    const withImages = allProducts.filter(p => p.image && p.image.startsWith('http')).length;
    console.log(`📸 Produktů s obrázkem: ${withImages}/${allProducts.length}`);
    return reviewMode ? { output, metrics } : output;
    } finally {
        await browser.close();
    }
}

if (require.main === module) {
    scrape().catch(err => {
        console.error('💥 Chyba:', sanitizeText(err.message));
        process.exitCode = 1;
    });
}

module.exports = { CATEGORIES, extractDetailVariants, scrape };

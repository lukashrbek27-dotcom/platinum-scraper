'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { ReviewStageError, assertAllowedDocument, canonicalJson, classifyNavigationFrame, classifyNetworkRequest, createNetworkGuardSession, safeFailure, sanitizeDiagnostic, sanitizeText, sanitizeUrl, sha256, validateCategoryExtraction, validateDetailExtraction, validateReviewSnapshot, writeFileGroupCreateOnly } = require('../review-hardening');
const { extractDetailVariants } = require('../scraper');
const { REVIEW_OUTPUT_ROOT, assertSupportedOutputRoot, runReview } = require('../platinum-review');

const GENERATED_AT = '2026-08-13T13:00:00.000Z';
const RUN_ID = 'platinum-live-20260813T130000000Z';
function products() { return Array.from({ length: 90 }, (_, index) => ({ name: `Food ${index}`, price: `${100 + index} Kč`, salePrice: null, originalPrice: null, stock: 'Skladem', url: `https://www.krmivo-platinum.cz/food-${index}/`, image: `https://cdn.krmivo-platinum.cz/food-${index}.jpg`, category: index < 60 ? 'Granule pro psy' : 'Granule pro kočky', animalType: index < 60 ? 'dog' : 'cat', size: index < 49 ? `2 x ${index + 1} kg` : `${index + 1} kg`, scrapedAt: GENERATED_AT })); }
function fixture(overrides = {}) { const list = overrides.products || products(); const raw = { schemaVersion: 1, reviewOnly: true, runId: RUN_ID, generatedAt: GENERATED_AT, scrapedAt: GENERATED_AT, source: 'krmivo-platinum.cz', totalProducts: list.length, categories: 2, categoryNames: ['Granule pro psy', 'Granule pro kočky'], products: list, runStats: { categoryRequests: 2, categorySuccesses: 2, categoryErrors: 0, detailRequests: 20, detailSuccesses: 20, detailErrors: 0 }, ...overrides }; const rawBytes = Buffer.from(canonicalJson(raw)); const provenance = { runId: raw.runId, generatedAt: raw.generatedAt, raw: { size: rawBytes.length, sha256: sha256(rawBytes) } }; return { raw, rawBytes, provenance }; }
const fakeScrape = (result = fixture().raw) => async () => ({ output: result, metrics: result.runStats });
const temporaryRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), 'platinum-review-test-'));

test('review output root is absolute and can be configured for CI', () => {
  assert.equal(path.isAbsolute(REVIEW_OUTPUT_ROOT), true);
  const child = path.join(REVIEW_OUTPUT_ROOT, RUN_ID);
  assert.doesNotThrow(() => assertSupportedOutputRoot(child));
  assert.throws(() => assertSupportedOutputRoot(REVIEW_OUTPUT_ROOT), /must be a child/u);
});

test('review CLI writes PASS artifacts only to an explicit external output directory', async () => { const root = temporaryRoot(); try { const outputDir = path.join(root, RUN_ID); const result = await runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape(), clock: () => new Date(GENERATED_AT) }); assert.equal(result.passed, true); assert.deepEqual(fs.readdirSync(outputDir).sort(), ['platinum-provenance.json', 'platinum-raw-validation.json', 'platinum-raw.json']); } finally { fs.rmSync(root, { recursive: true, force: true }); } });
test('review output is create-only and rejects a second run', async () => { const root = temporaryRoot(); try { const outputDir = path.join(root, RUN_ID); await runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape(), clock: () => new Date(GENERATED_AT) }); await assert.rejects(runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape() }), /must be empty/u); } finally { fs.rmSync(root, { recursive: true, force: true }); } });
test('supported CLI output cannot escape the approved Platinum review root', () => assert.throws(() => assertSupportedOutputRoot(path.join(os.tmpdir(), RUN_ID)), /must be a child/u));
test('review run never writes the historical products.json', async () => { const historical = path.join(__dirname, '..', 'products.json'); const before = sha256(fs.readFileSync(historical)); const root = temporaryRoot(); try { await runReview({ outputDir: path.join(root, RUN_ID), generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape(), clock: () => new Date(GENERATED_AT) }); } finally { fs.rmSync(root, { recursive: true, force: true }); } assert.equal(sha256(fs.readFileSync(historical)), before); });

for (const [name, stage] of [['category failure blocks the complete run', 'category'], ['detail failure blocks the complete run', 'detail'], ['top-level failure is propagated for a non-zero CLI exit', 'review_orchestration']]) test(name, async () => { const root = temporaryRoot(); try { const outputDir = path.join(root, RUN_ID); const failing = async () => { throw new ReviewStageError(stage, `${stage} failed`); }; await assert.rejects(runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: failing }), /failed/u); assert.equal(JSON.parse(fs.readFileSync(path.join(outputDir, 'platinum-failure.json'))).status, 'FAIL'); assert.equal(fs.existsSync(path.join(outputDir, 'platinum-raw.json')), false); } finally { fs.rmSync(root, { recursive: true, force: true }); } });

test('partial result creates failure only and no PASS raw artifact', async () => { const root = temporaryRoot(); try { const outputDir = path.join(root, RUN_ID); const partial = fixture({ products: products().slice(0, 89) }).raw; await assert.rejects(runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape(partial) }), /validation failed/u); assert.equal(fs.existsSync(path.join(outputDir, 'platinum-failure.json')), true); assert.equal(fs.existsSync(path.join(outputDir, 'platinum-raw.json')), false); } finally { fs.rmSync(root, { recursive: true, force: true }); } });
test('PASS raw and provenance are bound by exact byte hash', async () => { const root = temporaryRoot(); try { const outputDir = path.join(root, RUN_ID); await runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape(), clock: () => new Date(GENERATED_AT) }); const rawBytes = fs.readFileSync(path.join(outputDir, 'platinum-raw.json')); const provenance = JSON.parse(fs.readFileSync(path.join(outputDir, 'platinum-provenance.json'))); assert.equal(provenance.raw.sha256, sha256(rawBytes)); assert.equal(provenance.raw.size, rawBytes.length); } finally { fs.rmSync(root, { recursive: true, force: true }); } });
test('explicit generatedAt makes metadata deterministic with a fixed clock', async () => { const roots = [temporaryRoot(), temporaryRoot()]; try { const outputs = []; for (const root of roots) { const outputDir = path.join(root, RUN_ID); await runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape(), clock: () => new Date(GENERATED_AT) }); outputs.push(['platinum-raw.json', 'platinum-provenance.json', 'platinum-raw-validation.json'].map(file => fs.readFileSync(path.join(outputDir, file), 'utf8'))); } assert.deepEqual(outputs[0], outputs[1]); } finally { for (const root of roots) fs.rmSync(root, { recursive: true, force: true }); } });

test('network guard permits a Platinum main-frame document host', () => assert.equal(classifyNetworkRequest('https://www.krmivo-platinum.cz/a', { navigation: true, frameKind: 'main' }).allowed, true));
test('network guard keeps an external main-frame navigation fatal', () => assert.equal(classifyNetworkRequest('https://example.com/a', { navigation: true, frameKind: 'main' }).fatal, true));
test('network guard keeps a main-frame YouTube redirect fatal', () => assert.deepEqual(classifyNetworkRequest('https://www.youtube.com/watch?v=secret#fragment', { navigation: true, frameKind: 'main' }), { allowed: false, fatal: true, kind: 'document', host: 'www.youtube.com', reason: 'document_host_not_allowed' }));
test('network guard blocks credentials in a document URL', () => assert.equal(classifyNetworkRequest('https://user:pass@www.krmivo-platinum.cz/a', { navigation: true, frameKind: 'main' }).allowed, false));
test('network guard blocks a nonstandard port', () => assert.equal(classifyNetworkRequest('https://www.krmivo-platinum.cz:8443/a', { navigation: true, frameKind: 'main' }).allowed, false));
test('network guard aborts an unapproved asset host', () => assert.equal(classifyNetworkRequest('https://assets.example.com/a.js').reason, 'asset_host_not_allowed'));
test('network guard permits the approved Platinum CDN for assets', () => assert.equal(classifyNetworkRequest('https://cdn.krmivo-platinum.cz/a.jpg').allowed, true));
test('network guard aborts an external YouTube subframe without making it fatal', () => assert.deepEqual(classifyNetworkRequest('https://www.youtube.com/embed/a?token=SECRET#fragment', { navigation: true, frameKind: 'subframe' }), { allowed: false, fatal: false, kind: 'subframe_document', host: 'www.youtube.com', reason: 'external_subframe_blocked' }));
test('indeterminate document frame identity remains fail-closed', () => assert.deepEqual(classifyNetworkRequest('https://www.krmivo-platinum.cz/a', { navigation: true, frameKind: 'unknown' }), { allowed: false, fatal: true, kind: 'document', reason: 'frame_identity_unavailable' }));

function navigationRequest(url, frame) { return { url: () => url, resourceType: () => 'document', isNavigationRequest: () => true, frame: () => frame }; }
test('Playwright frame identity distinguishes main frame, subframe and popup top-level frame', () => {
  const main = {}; const page = { mainFrame: () => main }; main.page = () => page;
  const subframe = { page: () => page };
  const popupMain = {}; const popup = { mainFrame: () => popupMain }; popupMain.page = () => popup;
  assert.equal(classifyNavigationFrame(navigationRequest('https://www.krmivo-platinum.cz/a', main)), 'main');
  assert.equal(classifyNavigationFrame(navigationRequest('https://www.youtube.com/embed/a', subframe)), 'subframe');
  assert.equal(classifyNavigationFrame(navigationRequest('https://www.youtube.com/a', popupMain)), 'main');
  assert.equal(classifyNavigationFrame({ resourceType: () => 'document', isNavigationRequest: () => true, frame: () => { throw new Error('unavailable'); } }), 'unknown');
});

test('route guard aborts and counts a sanitized external subframe without allowing a document', async () => {
  let handler; const context = { route: async (_pattern, callback) => { handler = callback; } };
  const guard = createNetworkGuardSession(); await guard.install(context);
  const main = {}; const page = { mainFrame: () => main }; main.page = () => page;
  const subframe = { page: () => page };
  let aborted = null; let continued = false;
  await handler({ request: () => navigationRequest('https://www.youtube.com/embed/a?token=SECRET#fragment', subframe), abort: async reason => { aborted = reason; }, continue: async () => { continued = true; } });
  assert.equal(aborted, 'blockedbyclient'); assert.equal(continued, false);
  assert.equal(guard.metrics.blockedSubframes, 1); assert.equal(guard.metrics.blockedSubframeHosts['www.youtube.com'], 1);
  assert.equal(guard.metrics.allowedDocuments, 0); assert.equal(guard.metrics.fatalViolations.length, 0);
  const diagnostic = JSON.stringify(guard.metrics); assert.equal(diagnostic.includes('SECRET'), false); assert.equal(diagnostic.includes('?token='), false); assert.equal(diagnostic.includes('#fragment'), false);
});
test('challenge content is rejected without bypass', async () => { const page = { url: () => 'https://www.krmivo-platinum.cz/a', evaluate: async () => ({ title: 'Verify you are human', body: 'captcha' }) }; await assert.rejects(assertAllowedDocument(page, { status: () => 200 }, 'category_navigation'), /Challenge/u); });
test('category accounting rejects empty and invalid cards', () => { assert.throws(() => validateCategoryExtraction({ items: [], cardCount: 0, excludedSamples: 0, invalidCards: 0 }, 'dog')); assert.throws(() => validateCategoryExtraction({ items: [{}], cardCount: 2, excludedSamples: 0, invalidCards: 1 }, 'dog')); });
test('detail accounting rejects missing and partial variants', () => { assert.throws(() => validateDetailExtraction({ variants: [], rowCount: 0, invalidRows: 0 }, { name: 'Food' })); assert.throws(() => validateDetailExtraction({ variants: [{}], rowCount: 2, invalidRows: 1 }, { name: 'Food' })); });
function extractRows(rows) {
  const previousDocument = global.document;
  global.document = { querySelectorAll: selector => { assert.equal(selector, '.item.variant'); return rows; } };
  try { return extractDetailVariants(); } finally { global.document = previousDocument; }
}
function variantRow(innerText, priceText = null, selectors = {}) { return { innerText, querySelector: selector => {
  if (Object.hasOwn(selectors, selector)) return { innerText: selectors[selector] };
  assert.equal(selector, '.price .value, .bs-priceLayout .value, .value');
  return priceText == null ? null : { innerText: priceText };
} }; }
test('diagnosed collapsed 1.5 kg offer is parsed from anchored size and semantic price value', () => {
  const extraction = extractRows([variantRow('1,5 kgpytel_51-5A273 Kč', '273 Kč')]);
  assert.deepEqual(extraction, { variants: [{ sizeText: '1,5 kg', priceText: '273 Kč', salePriceText: null, originalPriceText: null }], rowCount: 1, invalidRows: 0 });
  assert.equal(validateDetailExtraction(extraction, { name: 'Adult Chicken' }).length, 1);
});
test('multipack extraction retains the explicit final bundle total instead of the rounded per-piece label', () => {
  const extraction = extractRows([variantRow('3 x 5 kg\nkompletsleva\n747 Kč / ks\nVTAL 15\n2 548 Kč\n2 242 Kč', null, {
    '.pricePerPiece': '747 Kč / ks', '.price.primary.user .value': '2 242 Kč', '.price.primary.retail .value': '2 548 Kč',
  })]);
  assert.deepEqual(extraction, { variants: [{ sizeText: '3 x 5 kg', priceText: '2 242 Kč', salePriceText: '2 242 Kč', originalPriceText: '2 548 Kč', multipackUnitPriceText: '747 Kč / ks', multipackTotalPriceText: '2 242 Kč' }], rowCount: 1, invalidRows: 0 });
});
test('unknown collapsed row remains fatal', () => assert.throws(() => validateDetailExtraction(extractRows([variantRow('Choose a package', '273 Kč')]), { name: 'Food' }), /accounting/u));
test('real collapsed row without price remains fatal', () => assert.throws(() => validateDetailExtraction(extractRows([variantRow('1,5 kgpytel_51-5A')]), { name: 'Food' }), /accounting/u));
test('real collapsed row without size remains fatal', () => assert.throws(() => validateDetailExtraction(extractRows([variantRow('pytel_51-5A273 Kč', '273 Kč')]), { name: 'Food' }), /accounting/u));
test('invalid sale/original relationship remains fatal', () => assert.throws(() => validateDetailExtraction({ variants: [{ sizeText: '2 x 5 kg', priceText: '150 Kč', salePriceText: '150 Kč', originalPriceText: '140 Kč' }], rowCount: 1, invalidRows: 0 }, { name: 'Food' }), /sale\/original/u));
test('baseline accepts exactly 90/60/30/49 with complete provenance', () => { const current = fixture(); assert.equal(validateReviewSnapshot(current.raw, current.provenance, current.rawBytes).passed, true); });

for (const [name, mutate, code] of [
  ['wrong total is blocked', raw => { raw.products.pop(); raw.totalProducts = raw.products.length; }, 'unexpected_total'],
  ['wrong dog/cat ratio is blocked', raw => { raw.products[0].animalType = 'cat'; }, 'dog_count_drift'],
  ['wrong multipack count is blocked', raw => { raw.products[0].size = '1 kg'; }, 'multipack_count_drift'],
  ['declared total mismatch is blocked', raw => { raw.totalProducts = 89; }, 'declared_total_mismatch'],
  ['missing category is blocked', raw => { raw.categoryNames = ['Granule pro psy']; }, 'category_contract_mismatch'],
  ['incomplete detail count is blocked', raw => { raw.runStats.detailSuccesses = 19; }, 'incomplete_detail_run'],
  ['duplicate URL plus size is blocked', raw => { raw.products[1].url = raw.products[0].url; raw.products[1].size = raw.products[0].size; }, 'duplicate_source_identity'],
  ['missing size is blocked', raw => { raw.products[0].size = null; }, 'missing_size'],
  ['missing price is blocked', raw => { raw.products[0].price = null; }, 'missing_price'],
  ['missing species is blocked', raw => { raw.products[0].animalType = null; }, 'missing_species'],
]) test(name, () => { const current = fixture(); mutate(current.raw); current.rawBytes = Buffer.from(canonicalJson(current.raw)); current.provenance.raw = { size: current.rawBytes.length, sha256: sha256(current.rawBytes) }; assert.ok(validateReviewSnapshot(current.raw, current.provenance, current.rawBytes).errors.some(error => error.code === code)); });

test('wrong raw/provenance SHA is blocked', () => { const current = fixture(); current.provenance.raw.sha256 = '0'.repeat(64); assert.ok(validateReviewSnapshot(current.raw, current.provenance, current.rawBytes).errors.some(error => error.code === 'raw_provenance_mismatch')); });

for (const [stage, index] of [
  ['before_prepare', -1],
  ['before_temp_write', 0], ['before_temp_write', 1], ['before_temp_write', 2],
  ['before_finalize', 0], ['before_finalize', 1], ['before_finalize', 2],
]) test(`review PASS group rolls back fault at ${stage}:${index}`, async () => {
  const root = temporaryRoot();
  try {
    const outputDir = path.join(root, RUN_ID);
    const groupWriter = files => writeFileGroupCreateOnly(files, { transactionId: 'fault-test', faultInjector: (currentStage, currentIndex) => {
      if (currentStage === stage && currentIndex === index) throw new Error(`injected ${stage}:${index}`);
    } });
    await assert.rejects(runReview({ outputDir, generatedAt: GENERATED_AT, runId: RUN_ID, scrapeRunner: fakeScrape(), clock: () => new Date(GENERATED_AT), groupWriter }), /injected/u);
    assert.deepEqual(fs.readdirSync(outputDir), ['platinum-failure.json']);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('artifact group conflict and rollback preserve unrelated existing files', () => {
  const root = temporaryRoot();
  try {
    const foreign = path.join(root, 'foreign.txt'); fs.writeFileSync(foreign, 'keep');
    const targets = ['a.json', 'b.json'].map(name => ({ path: path.join(root, name), contents: name }));
    fs.writeFileSync(targets[0].path, 'existing');
    assert.throws(() => writeFileGroupCreateOnly(targets), /Refusing to overwrite/u);
    assert.equal(fs.readFileSync(targets[0].path, 'utf8'), 'existing');
    fs.rmSync(targets[0].path);
    assert.throws(() => writeFileGroupCreateOnly(targets, { transactionId: 'cleanup-test', faultInjector: (stage, index) => { if (stage === 'before_finalize' && index === 1) throw new Error('finalize failure'); } }), /finalize failure/u);
    assert.deepEqual(fs.readdirSync(root), ['foreign.txt']);
    assert.equal(fs.readFileSync(foreign, 'utf8'), 'keep');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('failure diagnostics redact URL credentials, query, fragment, tokens, headers and cookies', () => {
  const cyclic = { nested: { url: 'https://user:pass@www.krmivo-platinum.cz/detail?token=secret#frag' }, headers: { authorization: 'Bearer SECRET' }, cookie: 'session=SECRET', text: 'token=SECRET https://www.krmivo-platinum.cz/a?api_key=SECRET#x' };
  cyclic.self = cyclic;
  const error = new ReviewStageError('detail', 'Failed https://user:pass@www.krmivo-platinum.cz/detail?token=SECRET#frag token=SECRET', cyclic);
  error.metrics = { categorySuccesses: 2, responseHeaders: { cookie: 'SECRET' } };
  const report = safeFailure(error, GENERATED_AT, RUN_ID);
  const serialized = JSON.stringify(report);
  for (const secret of ['user', 'pass', 'SECRET', '?token=', '#frag', 'Bearer']) assert.equal(serialized.includes(secret), false);
  assert.equal(report.stage, 'detail');
  assert.equal(report.completed.categorySuccesses, 2);
  assert.match(report.reason, /krmivo-platinum\.cz\/detail/u);
  assert.equal(report.details.self, '[CIRCULAR]');
});

test('sanitizer is bounded and total for malformed, cyclic, deep and long values', () => {
  const cyclic = {}; cyclic.self = cyclic;
  let deep = {}; let cursor = deep; for (let index = 0; index < 20; index += 1) { cursor.next = {}; cursor = cursor.next; }
  assert.doesNotThrow(() => sanitizeDiagnostic({ cyclic, deep, error: new Error('token=SECRET'), odd: Symbol('x') }));
  assert.equal(sanitizeText('x'.repeat(5000)).length, 1000);
  assert.equal(sanitizeUrl('not a url'), '[REDACTED_URL]');
  assert.equal(sanitizeUrl('https://user:pass@example.com/a?q=1#x'), 'https://example.com/a');
  assert.equal(sanitizeDiagnostic({ url: 'not a url' }).url, '[REDACTED_URL]');
});

test('isolated imports cannot launch a browser, use network, write files or change exitCode', () => {
  const root = temporaryRoot();
  try {
    const scraperPath = path.join(__dirname, '..', 'scraper.js');
    const reviewPath = path.join(__dirname, '..', 'platinum-review.js');
    const script = `
      const Module=require('node:module'); const fs=require('node:fs'); const original=Module._load;
      Module._load=function(request,parent,isMain){ if(request==='playwright') return {chromium:{launch(){throw new Error('BROWSER_CONSTRUCTED')}}}; if(['http','https','net','tls'].includes(request)) throw new Error('NETWORK_MODULE_LOADED'); return original.apply(this,arguments); };
      for(const name of ['writeFileSync','openSync','mkdirSync','renameSync','linkSync']) fs[name]=()=>{throw new Error('WRITE_ATTEMPT')};
      const before=process.exitCode; require(${JSON.stringify(scraperPath)}); require(${JSON.stringify(reviewPath)});
      if(process.exitCode!==before) throw new Error('EXIT_CODE_CHANGED'); process.stdout.write('IMPORT_SAFE');`;
    const child = spawnSync(process.execPath, ['-e', script], { cwd: root, encoding: 'utf8', timeout: 10000 });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, 'IMPORT_SAFE');
    assert.deepEqual(fs.readdirSync(root), []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('scheduled workflow is hardened review-only and has no publication path', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'scrape.yml'), 'utf8');
  assert.match(workflow, /cron:\s*'0 6 \* \* \*'/u);
  assert.match(workflow, /workflow_dispatch:/u);
  assert.match(workflow, /permissions:\s*\n\s*contents:\s*read/u);
  assert.match(workflow, /group:\s*platinum-hardened-review/u);
  assert.match(workflow, /cancel-in-progress:\s*false/u);
  assert.match(workflow, /npm run scrape:review/u);
  assert.match(workflow, /Require exact PASS artifact contract/u);
  assert.match(workflow, /actions\/upload-artifact@v4/u);
  assert.match(workflow, /retention-days:\s*14/u);
  assert.doesNotMatch(workflow, /contents:\s*write/u);
  assert.doesNotMatch(workflow, /git\s+(?:add|commit|push)\b/u);
  assert.doesNotMatch(workflow, /products\.json|current\.json|generate-platinum-price-overlay|combined-overlay|gcloud|gsutil/u);
});

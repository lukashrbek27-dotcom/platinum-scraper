'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { canonicalJson, sha256, validateManagedPriceReviewSnapshot } = require('../review-hardening');
const {
  buildManagedPriceArtifacts,
  main,
  parseExplicitMultipackCount,
  parseSizeKg,
  priceStateFromRaw,
} = require('../platinum-managed-price-validation');

const GENERATED_AT = '2026-08-20T06:00:00.000Z';
const CATALOG_COMMIT = '4'.repeat(40);

function rowState(index) {
  if (index < 49) {
    const unit = 100 + index;
    return { size: `2 x ${index + 1} g`, sizeKg: Number((2 * (index + 1) / 1000).toFixed(3)), unitPrice: `${unit} Kč / ks`, totalPrice: unit * 2 };
  }
  const price = 100 + index;
  return { size: `${index + 1} kg`, sizeKg: index + 1, price: `${price} Kč`, totalPrice: price };
}

function fixture() {
  const products = [];
  const catalog = [];
  for (let index = 0; index < 90; index += 1) {
    const state = rowState(index);
    const url = `https://www.krmivo-platinum.cz/product-${index}/`;
    products.push({
      name: `Food ${index}`,
      url,
      size: state.size,
      price: `${state.totalPrice} Kč`,
      salePrice: null,
      originalPrice: null,
      ...(state.unitPrice ? { multipackUnitPrice: state.unitPrice, multipackTotalPrice: `${state.totalPrice} Kč` } : {}),
      stock: 'Skladem',
      animalType: index < 60 ? 'dog' : 'cat',
    });
    catalog.push({
      id: `platinum-food-${index}`,
      name: `Food ${index}`,
      sizeKg: state.sizeKg,
      offers: [{ partner: 'Platinum', affiliateUrl: `${url}?utm_source=test`, price: state.totalPrice, salePrice: null, originalPrice: null }],
    });
  }
  const raw = { schemaVersion: 1, reviewOnly: true, generatedAt: GENERATED_AT, products };
  const rawBytes = Buffer.from(canonicalJson(raw));
  const reviewProvenance = { raw: { sha256: sha256(rawBytes), size: rawBytes.length }, remoteActions: { publish: false } };
  const reviewProvenanceBytes = Buffer.from(canonicalJson(reviewProvenance));
  const reviewValidation = { passed: true, raw: { sha256: sha256(rawBytes), size: rawBytes.length } };
  const reviewValidationBytes = Buffer.from(canonicalJson(reviewValidation));
  const catalogBytes = Buffer.from(canonicalJson(catalog));
  const catalogSha256 = sha256(catalogBytes);
  const currentOverlay = { schemaVersion: 2, snapshotVersion: GENERATED_AT, generatedAt: GENERATED_AT, catalogSha256, entries: [] };
  const currentOverlayBytes = Buffer.from(canonicalJson(currentOverlay));
  return { raw, rawBytes, reviewProvenance, reviewProvenanceBytes, reviewValidation, reviewValidationBytes, catalog, catalogBytes, catalogSha256, currentOverlay, currentOverlayBytes };
}

function build(current = fixture()) {
  return buildManagedPriceArtifacts({
    rawBytes: Buffer.from(canonicalJson(current.raw)),
    reviewProvenanceBytes: (() => {
      const bytes = Buffer.from(canonicalJson(current.raw));
      current.reviewProvenance.raw = { sha256: sha256(bytes), size: bytes.length };
      return Buffer.from(canonicalJson(current.reviewProvenance));
    })(),
    reviewValidationBytes: (() => {
      const bytes = Buffer.from(canonicalJson(current.raw));
      current.reviewValidation.raw = { sha256: sha256(bytes), size: bytes.length };
      return Buffer.from(canonicalJson(current.reviewValidation));
    })(),
    catalogBytes: Buffer.from(canonicalJson(current.catalog)),
    currentOverlayBytes: Buffer.from(canonicalJson(current.currentOverlay)),
    expectedCatalogSha256: sha256(Buffer.from(canonicalJson(current.catalog))),
    expectedCurrentOverlaySha256: sha256(Buffer.from(canonicalJson(current.currentOverlay))),
    catalogCommit: CATALOG_COMMIT,
    generatedAt: GENERATED_AT,
  });
}

test('deterministic catalog URL plus total packing maps exactly 90/90 with 49 multipacks', () => {
  const result = build();
  assert.equal(result.validation.passed, true);
  assert.deepEqual(result.validation.managedContract, { total: 90, exactSafe: 90, unresolved: 0, ambiguous: 0, coverage: '90/90', multipacks: 49 });
  assert.equal(result.candidate.offers.length, 90);
  assert.equal(result.candidate.offers.filter(offer => offer.normalizations.length > 0).length, 49);
  assert.ok(result.candidate.offers.every(offer => offer.matchMethod === 'canonical_url_total_packing_v1'));
});

test('multipack parsing uses only an explicit count and normalized total packing', () => {
  assert.equal(parseExplicitMultipackCount('12 × 100 g'), 12);
  assert.equal(parseSizeKg('12 × 100 g'), 1.2);
  assert.equal(parseExplicitMultipackCount('1.2 kg'), null);
  assert.throws(() => parseExplicitMultipackCount('1 x 100 g'), /multipack_count/u);
});

test('multipacks use the explicit final bundle total and retain unit-price rounding evidence', () => {
  for (const [size, unit, total] of [
    ['3 x 5 kg', '747 Kč / ks', 2242],
    ['3 x 5 kg', '818 Kč / ks', 2453],
    ['6 x 5 kg', '790 Kč / ks', 4739],
    ['3 x 900 g', '250 Kč / ks', 751],
    ['6 x 900 g', '237 Kč / ks', 1421],
    ['2 x 3 kg', '697 Kč / ks', 1393],
  ]) {
    const parsed = priceStateFromRaw({ size, price: `${total} Kč`, salePrice: `${total} Kč`, originalPrice: `${total + 100} Kč`, multipackUnitPrice: unit, multipackTotalPrice: `${total} Kč` });
    assert.equal(parsed.state.price, total);
    assert.equal(parsed.state.salePrice, total);
    assert.equal(parsed.normalizations[0].reason, 'explicit_bundle_total_price');
  }
});

test('multipack without an explicit final bundle total fails closed', () => {
  assert.throws(() => priceStateFromRaw({ size: '3 x 5 kg', price: '747 Kč / ks', salePrice: '747 Kč / ks', originalPrice: '2548 Kč', multipackUnitPrice: '747 Kč / ks' }), /missing_explicit_multipack_total_price/u);
});

test('an extra valid non-managed raw row is reported but does not block or auto-add', () => {
  const current = fixture();
  current.raw.products.push({ name: 'New', url: 'https://www.krmivo-platinum.cz/new-product/', size: '3 kg', price: '300 Kč', stock: 'Skladem', animalType: 'dog' });
  const result = build(current);
  assert.equal(result.validation.passed, true);
  assert.equal(result.validation.mapping.nonManagedObservations, 1);
  assert.equal(result.candidate.offers.length, 90);
  assert.equal(result.candidate.remoteActions.autoAdd, false);
});

test('duplicate source identity and managed collision block', () => {
  const current = fixture();
  current.raw.products.push({ ...current.raw.products[0] });
  const result = build(current);
  assert.equal(result.validation.passed, false);
  assert.ok(result.validation.blockers.some(blocker => blocker.code === 'duplicate_source_identity'));
});

test('ambiguous catalog source identity blocks', () => {
  const current = fixture();
  current.catalog.push({ ...current.catalog[0], id: 'platinum-ambiguous-product' });
  current.currentOverlay.catalogSha256 = sha256(Buffer.from(canonicalJson(current.catalog)));
  const result = build(current);
  assert.equal(result.validation.passed, false);
  assert.ok(result.validation.blockers.some(blocker => blocker.code === 'ambiguous_managed_source_identity'));
});

test('missing managed coverage blocks', () => {
  const current = fixture();
  current.raw.products.shift();
  const result = build(current);
  assert.equal(result.validation.passed, false);
  assert.equal(result.validation.managedContract.coverage, '89/90');
  assert.ok(result.validation.blockers.some(blocker => blocker.code === 'missing_managed_offer'));
});

test('invalid managed price blocks', () => {
  const current = fixture();
  current.raw.products[70].price = '0 Kč';
  const result = build(current);
  assert.equal(result.validation.passed, false);
  assert.ok(result.validation.blockers.some(blocker => blocker.code === 'price_outside_guard_range'));
  const absurd = fixture();
  absurd.raw.products[70].price = '50001 Kč';
  assert.ok(build(absurd).validation.blockers.some(blocker => blocker.code === 'price_outside_guard_range'));
});

test('invalid managed sale relationship blocks', () => {
  const current = fixture();
  Object.assign(current.raw.products[70], { price: '150 Kč', salePrice: '150 Kč', originalPrice: '140 Kč' });
  const result = build(current);
  assert.equal(result.validation.passed, false);
  assert.ok(result.validation.blockers.some(blocker => blocker.code === 'invalid_sale_combination'));
});

test('valid current overlay is applied to the effective comparison and anomalies are evidence-only', () => {
  const current = fixture();
  current.currentOverlay.entries.push({ source: 'production', partner: 'Platinum', productId: 'platinum-food-70', offerIdentity: { kind: 'product-partner', partner: 'Platinum' }, price: 100, salePrice: null, originalPrice: null });
  const result = build(current);
  const change = result.validation.anomalyEvidence.offers.find(item => item.productId === 'platinum-food-70');
  assert.deepEqual(change.before, { price: 100, salePrice: null, originalPrice: null });
  assert.equal(change.after.price, 170);
  assert.equal(change.relativeChange, 0.7);
  assert.equal(change.multiplicativeChange, 1.7);
  assert.equal(result.validation.passed, true);
  assert.equal(result.validation.firstTransition.automaticPublishEligible, false);
  assert.equal(result.validation.anomalyEvidence.thresholdPolicy, 'report_only_more_history_required');
});

test('sale-clear evidence is computed without becoming a new threshold blocker', () => {
  const current = fixture();
  current.currentOverlay.entries.push({ source: 'production', partner: 'Platinum', productId: 'platinum-food-70', offerIdentity: { kind: 'product-partner', partner: 'Platinum' }, price: 150, salePrice: 150, originalPrice: 180 });
  const result = build(current);
  assert.equal(result.validation.anomalyEvidence.saleClearedOffers, 1);
  assert.equal(result.validation.anomalyEvidence.saleClearRatio, 1 / 90);
  assert.equal(result.validation.passed, true);
});

test('current overlay catalog SHA mismatch and invalid overlay fail closed', () => {
  const mismatch = fixture();
  mismatch.currentOverlay.catalogSha256 = '0'.repeat(64);
  assert.throws(() => build(mismatch), /current_overlay_catalog_sha_mismatch/u);
  const invalid = fixture();
  invalid.currentOverlay.entries = [{ secret: 'forbidden' }];
  assert.throws(() => build(invalid), /forbidden field|invalid_current_overlay/u);
});

test('catalog and current overlay byte SHA arguments are independently enforced', () => {
  const current = fixture();
  assert.throws(() => buildManagedPriceArtifacts({
    rawBytes: current.rawBytes,
    reviewProvenanceBytes: current.reviewProvenanceBytes,
    reviewValidationBytes: current.reviewValidationBytes,
    catalogBytes: current.catalogBytes,
    currentOverlayBytes: current.currentOverlayBytes,
    expectedCatalogSha256: '0'.repeat(64),
    expectedCurrentOverlaySha256: sha256(current.currentOverlayBytes),
    catalogCommit: CATALOG_COMMIT,
    generatedAt: GENERATED_AT,
  }), /catalog_sha_mismatch/u);
});

test('managed technical profile preserves health guards but permits a non-managed extra observation', () => {
  const current = fixture();
  const products = [...current.raw.products, { name: 'New', url: 'https://www.krmivo-platinum.cz/new/', size: '1 kg', price: '100 Kč', animalType: 'dog' }];
  const raw = { source: 'krmivo-platinum.cz', reviewOnly: true, runId: 'platinum-live-20260820T060000000Z', generatedAt: GENERATED_AT, scrapedAt: GENERATED_AT, totalProducts: products.length, categories: 2, categoryNames: ['Granule pro psy', 'Granule pro kočky'], products, runStats: { categoryRequests: 2, categorySuccesses: 2, categoryErrors: 0, detailRequests: 20, detailSuccesses: 20, detailErrors: 0 } };
  const rawBytes = Buffer.from(canonicalJson(raw));
  const provenance = { runId: raw.runId, generatedAt: raw.generatedAt, raw: { sha256: sha256(rawBytes), size: rawBytes.length } };
  assert.equal(validateManagedPriceReviewSnapshot(raw, provenance, rawBytes).passed, true);
});

test('managed candidate and validation outputs are create-only', () => {
  const current = fixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'platinum-managed-test-'));
  try {
    const files = new Map([
      ['raw', current.rawBytes], ['review-provenance', current.reviewProvenanceBytes], ['review-validation', current.reviewValidationBytes],
      ['catalog', current.catalogBytes], ['current-overlay', current.currentOverlayBytes],
    ]);
    const args = ['--output-dir', root, '--raw', 'raw', '--review-provenance', 'review-provenance', '--review-validation', 'review-validation', '--catalog', 'catalog', '--catalog-commit', CATALOG_COMMIT, '--catalog-sha256', current.catalogSha256, '--current-overlay', 'current-overlay', '--current-overlay-sha256', sha256(current.currentOverlayBytes), '--generated-at', GENERATED_AT];
    const dependencies = { readFile: name => files.get(name) };
    assert.equal(main(args, dependencies).validation.passed, true);
    assert.throws(() => main(args, dependencies), /overwrite/u);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

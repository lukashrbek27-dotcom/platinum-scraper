#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  assertCanonicalIso,
  canonicalJson,
  sha256,
  writeFileGroupCreateOnly,
} = require('./review-hardening');

const PARTNER = 'Platinum';
const SOURCE = 'platinum-scraper';
const MANAGED_TOTAL = 90;
const EXPECTED_MULTIPACKS = 49;
const MINIMUM_PRICE_CZK = 10;
const MAXIMUM_PRICE_CZK = 50_000;
const OVERLAY_MAX_PRICE_CZK = 10_000_000;
const OVERLAY_MAX_ENTRIES = 5_000;
const OVERLAY_MAX_BYTES = 512 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const SAFE_LABEL_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} ._:/+-]{0,127}$/u;
const SNAPSHOT_KEYS = new Set(['schemaVersion', 'snapshotVersion', 'generatedAt', 'catalogSha256', 'entries']);
const ENTRY_KEYS = new Set(['source', 'partner', 'productId', 'offerIdentity', 'price', 'salePrice', 'originalPrice']);
const IDENTITY_KEYS = new Set(['kind', 'partner']);

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const compareText = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const isRecord = value => typeof value === 'object' && value !== null && !Array.isArray(value);

function assertExactKeys(value, allowed, context) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new Error(`${context} contains forbidden field: ${key}`);
}

function assertSha256(value, field) {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) throw new Error(`${field} must be a lowercase SHA-256`);
  return value;
}

function assertSafeLabel(value, field) {
  if (typeof value !== 'string' || !SAFE_LABEL_PATTERN.test(value)) throw new Error(`${field} is invalid`);
  return value;
}

function canonicalTargetUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) throw new Error('missing_url');
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:' || !/^(www\.)?krmivo-platinum\.cz$/iu.test(parsed.hostname)) throw new Error('invalid_target_url');
  const pathname = parsed.pathname.replace(/\/+$/u, '') || '/';
  return `https://${parsed.hostname.toLowerCase()}${pathname.toLowerCase()}`;
}

function parseSizeKg(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('missing_size');
  const normalized = value.trim().toLowerCase().replace(/\s+/gu, ' ').replace(',', '.');
  const multipackKg = normalized.match(/^(\d+)\s*[x×]\s*(\d+(?:\.\d+)?)\s*kg$/u);
  if (multipackKg) return Number((Number(multipackKg[1]) * Number(multipackKg[2])).toFixed(3));
  const multipackGrams = normalized.match(/^(\d+)\s*[x×]\s*(\d+(?:\.\d+)?)\s*g$/u);
  if (multipackGrams) return Number((Number(multipackGrams[1]) * Number(multipackGrams[2]) / 1000).toFixed(3));
  const kilograms = normalized.match(/^(\d+(?:\.\d+)?)\s*kg$/u);
  if (kilograms) return Number(kilograms[1]);
  const grams = normalized.match(/^(\d+(?:\.\d+)?)\s*g$/u);
  if (grams) return Number((Number(grams[1]) / 1000).toFixed(3));
  throw new Error('invalid_size');
}

function parseExplicitMultipackCount(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('missing_size');
  const normalized = value.trim().toLowerCase().replace(/\s+/gu, ' ').replace(',', '.');
  const match = normalized.match(/^(\d+)\s*[x×]\s*\d+(?:\.\d+)?\s*(?:kg|g)$/u);
  if (!match) return null;
  const count = Number(match[1]);
  if (!Number.isSafeInteger(count) || count <= 1) throw new Error('invalid_multipack_count');
  return count;
}

function parseCzk(value) {
  if (typeof value === 'number') return value;
  if (typeof value !== 'string') throw new Error('invalid_price');
  const normalized = value.replace(/\u00a0/gu, ' ').trim().replace(/[Kk]č/gu, '').replace(/\s+/gu, '');
  if (!/^\d+(?:,\d{1,2})?$/u.test(normalized)) throw new Error('invalid_price');
  return Number(normalized.replace(',', '.'));
}

function parseUnitCzkMinor(value) {
  if (typeof value !== 'string') return null;
  const match = value.match(/^\s*([0-9][0-9\s\u00a0]*)(?:,([0-9]{1,2}))?\s*Kč\s*\/\s*ks\s*$/iu);
  if (!match) return null;
  const crowns = Number(match[1].replace(/[\s\u00a0]/gu, ''));
  const hellers = match[2] ? Number(match[2].padEnd(2, '0')) : 0;
  const minor = crowns * 100 + hellers;
  if (!Number.isSafeInteger(minor) || minor <= 0) throw new Error('invalid_unit_price');
  return minor;
}

function normalizeRawPrice(value, field) {
  const unitMinor = parseUnitCzkMinor(value);
  if (unitMinor === null) {
    if (typeof value === 'string' && /\/\s*\S/u.test(value)) throw new Error('unsupported_price_unit');
    return { value: parseCzk(value), normalization: null };
  }
  throw new Error(`${field}_must_use_explicit_total_price`);
}

function validatePriceState(state, { maximum = MAXIMUM_PRICE_CZK, minimum = MINIMUM_PRICE_CZK } = {}) {
  if (!Number.isFinite(state.price) || state.price < minimum || state.price > maximum) return 'price_outside_guard_range';
  const hasSale = hasOwn(state, 'salePrice');
  const hasOriginal = hasOwn(state, 'originalPrice');
  if (hasSale !== hasOriginal) return 'incomplete_sale_pair';
  if (!hasSale) return null;
  if (state.salePrice === null || state.originalPrice === null) return state.salePrice === null && state.originalPrice === null ? null : 'incomplete_sale_clear';
  if (!Number.isFinite(state.salePrice) || !Number.isFinite(state.originalPrice)
      || state.salePrice <= 0 || state.originalPrice <= state.salePrice || state.salePrice !== state.price) return 'invalid_sale_combination';
  return null;
}

function priceStateFromRaw(raw) {
  const multipackCount = parseExplicitMultipackCount(raw?.size);
  if (multipackCount !== null) {
    const unitMinor = parseUnitCzkMinor(raw?.multipackUnitPrice);
    if (unitMinor === null) throw new Error('missing_explicit_multipack_unit_price');
    if (raw?.multipackTotalPrice == null) throw new Error('missing_explicit_multipack_total_price');
    const total = normalizeRawPrice(raw.multipackTotalPrice, 'multipackTotalPrice');
    const price = normalizeRawPrice(raw?.price, 'price');
    if (price.value !== total.value) throw new Error('multipack_price_total_mismatch');
    const normalization = {
      field: 'price', reason: 'explicit_bundle_total_price', unitPrice: unitMinor / 100,
      multipackCount, totalPrice: total.value, unitPriceTimesCount: unitMinor * multipackCount / 100,
      roundingDelta: total.value - unitMinor * multipackCount / 100,
    };
    if (raw?.salePrice == null && raw?.originalPrice == null) {
      return { state: { price: total.value, salePrice: null, originalPrice: null }, normalizations: [normalization] };
    }
    if (raw?.salePrice == null || raw?.originalPrice == null) throw new Error('incomplete_sale_pair');
    const sale = normalizeRawPrice(raw.salePrice, 'salePrice');
    const original = normalizeRawPrice(raw.originalPrice, 'originalPrice');
    if (sale.value !== total.value) throw new Error('multipack_sale_total_mismatch');
    return { state: { price: total.value, salePrice: total.value, originalPrice: original.value }, normalizations: [normalization] };
  }
  const price = normalizeRawPrice(raw?.price, 'price');
  if (raw?.salePrice == null && raw?.originalPrice == null) {
    return { state: { price: price.value, salePrice: null, originalPrice: null }, normalizations: price.normalization ? [price.normalization] : [] };
  }
  if (raw?.salePrice == null || raw?.originalPrice == null) throw new Error('incomplete_sale_pair');
  const sale = normalizeRawPrice(raw.salePrice, 'salePrice');
  const original = normalizeRawPrice(raw.originalPrice, 'originalPrice');
  return {
    state: { price: price.value, salePrice: sale.value, originalPrice: original.value },
    normalizations: [price.normalization, sale.normalization, original.normalization].filter(Boolean),
  };
}

function catalogPriceState(offer) {
  const state = {
    price: offer?.price,
    salePrice: offer?.salePrice ?? null,
    originalPrice: offer?.originalPrice ?? null,
  };
  const error = validatePriceState(state, { minimum: Number.MIN_VALUE, maximum: OVERLAY_MAX_PRICE_CZK });
  if (error) throw new Error(`invalid_catalog_${error}`);
  return state;
}

function samePriceState(left, right) {
  return left.price === right.price
    && (left.salePrice ?? null) === (right.salePrice ?? null)
    && (left.originalPrice ?? null) === (right.originalPrice ?? null);
}

function parseCurrentOverlay(overlayBytes, catalog, expectedCatalogSha256) {
  if (!Buffer.isBuffer(overlayBytes) || overlayBytes.length <= 0 || overlayBytes.length > OVERLAY_MAX_BYTES) throw new Error('invalid_current_overlay_size');
  let input;
  try { input = JSON.parse(overlayBytes.toString('utf8')); } catch { throw new Error('invalid_current_overlay_json'); }
  if (!isRecord(input)) throw new Error('invalid_current_overlay');
  assertExactKeys(input, SNAPSHOT_KEYS, 'current overlay');
  if (input.schemaVersion !== 2) throw new Error('invalid_current_overlay_schema');
  assertCanonicalIso(input.snapshotVersion, 'current overlay snapshotVersion');
  assertCanonicalIso(input.generatedAt, 'current overlay generatedAt');
  if (Date.parse(input.generatedAt) < Date.parse(input.snapshotVersion)) throw new Error('invalid_current_overlay_timestamps');
  assertSha256(input.catalogSha256, 'current overlay catalogSha256');
  if (input.catalogSha256 !== expectedCatalogSha256) throw new Error('current_overlay_catalog_sha_mismatch');
  if (!Array.isArray(input.entries) || input.entries.length > OVERLAY_MAX_ENTRIES) throw new Error('invalid_current_overlay_entries');

  const productsById = new Map();
  for (const product of catalog) {
    if (!isRecord(product) || typeof product.id !== 'string' || !product.id || !Array.isArray(product.offers)) throw new Error('invalid_catalog_product');
    if (productsById.has(product.id)) throw new Error('duplicate_catalog_product_id');
    productsById.set(product.id, product);
  }
  const entriesByIdentity = new Map();
  for (const [index, entry] of input.entries.entries()) {
    const context = `current overlay entries[${index}]`;
    if (!isRecord(entry)) throw new Error('invalid_current_overlay_entry');
    assertExactKeys(entry, ENTRY_KEYS, context);
    assertSafeLabel(entry.source, `${context}.source`);
    assertSafeLabel(entry.partner, `${context}.partner`);
    assertSafeLabel(entry.productId, `${context}.productId`);
    if (!isRecord(entry.offerIdentity)) throw new Error('invalid_current_overlay_identity');
    assertExactKeys(entry.offerIdentity, IDENTITY_KEYS, `${context}.offerIdentity`);
    if (entry.offerIdentity.kind !== 'product-partner' || entry.offerIdentity.partner !== entry.partner) throw new Error('invalid_current_overlay_identity');
    const priceError = validatePriceState(entry, { minimum: Number.MIN_VALUE, maximum: OVERLAY_MAX_PRICE_CZK });
    if (priceError) throw new Error(`current_overlay_${priceError}`);
    const product = productsById.get(entry.productId);
    if (!product) throw new Error('current_overlay_unknown_product');
    const offers = product.offers.filter(offer => offer?.partner === entry.partner);
    if (offers.length !== 1) throw new Error('current_overlay_offer_identity_mismatch');
    const key = JSON.stringify([entry.productId, entry.partner]);
    if (entriesByIdentity.has(key)) throw new Error('current_overlay_duplicate_identity');
    entriesByIdentity.set(key, entry);
  }
  return { snapshot: input, entriesByIdentity };
}

function effectivePriceState(product, offer, overlay) {
  const embedded = catalogPriceState(offer);
  const entry = overlay.entriesByIdentity.get(JSON.stringify([product.id, offer.partner]));
  if (!entry) return embedded;
  return {
    price: entry.price,
    salePrice: hasOwn(entry, 'salePrice') ? entry.salePrice : embedded.salePrice,
    originalPrice: hasOwn(entry, 'originalPrice') ? entry.originalPrice : embedded.originalPrice,
  };
}

function anomalyFor(before, after) {
  const changed = !samePriceState(before, after);
  const relativeChange = changed ? Math.abs(after.price - before.price) / before.price : 0;
  const multiplicativeChange = changed ? Math.max(after.price / before.price, before.price / after.price) : 1;
  const saleCleared = before.salePrice != null && after.salePrice == null;
  return { changed, relativeChange, multiplicativeChange, saleCleared };
}

function addBlocker(groups, code, example = null) {
  const group = groups.get(code) || { code, count: 0, examples: [] };
  group.count += 1;
  if (example != null && group.examples.length < 20) group.examples.push(String(example));
  groups.set(code, group);
}

function buildManagedPriceArtifacts({
  rawBytes,
  reviewProvenanceBytes,
  reviewValidationBytes,
  catalogBytes,
  currentOverlayBytes,
  expectedCatalogSha256,
  expectedCurrentOverlaySha256,
  catalogCommit,
  generatedAt,
}) {
  assertCanonicalIso(generatedAt, 'generatedAt');
  assertSha256(expectedCatalogSha256, 'expectedCatalogSha256');
  assertSha256(expectedCurrentOverlaySha256, 'expectedCurrentOverlaySha256');
  if (typeof catalogCommit !== 'string' || !GIT_COMMIT_PATTERN.test(catalogCommit)) throw new Error('catalogCommit must be a lowercase 40-character Git commit');
  const actualCatalogSha256 = sha256(catalogBytes);
  const actualCurrentOverlaySha256 = sha256(currentOverlayBytes);
  if (actualCatalogSha256 !== expectedCatalogSha256) throw new Error('catalog_sha_mismatch');
  if (actualCurrentOverlaySha256 !== expectedCurrentOverlaySha256) throw new Error('current_overlay_sha_mismatch');

  let raw;
  let reviewProvenance;
  let reviewValidation;
  let catalog;
  try {
    raw = JSON.parse(rawBytes.toString('utf8'));
    reviewProvenance = JSON.parse(reviewProvenanceBytes.toString('utf8'));
    reviewValidation = JSON.parse(reviewValidationBytes.toString('utf8'));
    catalog = JSON.parse(catalogBytes.toString('utf8'));
  } catch { throw new Error('invalid_input_json'); }
  if (!Array.isArray(catalog)) throw new Error('invalid_catalog');
  if (reviewValidation?.passed !== true) throw new Error('review_validation_not_pass');
  if (reviewProvenance?.raw?.sha256 !== sha256(rawBytes) || reviewProvenance?.raw?.size !== rawBytes.length) throw new Error('review_raw_provenance_mismatch');
  if (reviewValidation?.raw?.sha256 !== sha256(rawBytes) || reviewValidation?.raw?.size !== rawBytes.length) throw new Error('review_validation_raw_mismatch');
  if (Object.values(reviewProvenance?.remoteActions || {}).some(Boolean)) throw new Error('review_provenance_remote_action');

  const overlay = parseCurrentOverlay(currentOverlayBytes, catalog, expectedCatalogSha256);
  const blockers = new Map();
  const catalogBySourceIdentity = new Map();
  const managedByProductId = new Map();
  for (const product of catalog) {
    const offers = Array.isArray(product?.offers) ? product.offers.filter(offer => offer?.partner === PARTNER) : [];
    if (offers.length > 1) addBlocker(blockers, 'ambiguous_managed_offer', product?.id);
    if (offers.length !== 1) continue;
    if (typeof product?.id !== 'string' || !product.id) { addBlocker(blockers, 'invalid_managed_product_id'); continue; }
    let sourceIdentity;
    try {
      const sizeKg = Number(product.sizeKg);
      if (!Number.isFinite(sizeKg) || sizeKg <= 0) throw new Error('invalid_managed_size');
      sourceIdentity = `${canonicalTargetUrl(offers[0].affiliateUrl)}|${sizeKg}`;
      catalogPriceState(offers[0]);
    } catch (error) { addBlocker(blockers, error.message, product.id); continue; }
    if (catalogBySourceIdentity.has(sourceIdentity)) addBlocker(blockers, 'ambiguous_managed_source_identity', sourceIdentity);
    if (managedByProductId.has(product.id)) addBlocker(blockers, 'duplicate_managed_identity', product.id);
    const managed = { product, offer: offers[0], sourceIdentity };
    catalogBySourceIdentity.set(sourceIdentity, managed);
    managedByProductId.set(product.id, managed);
  }
  if (managedByProductId.size !== MANAGED_TOTAL) addBlocker(blockers, 'managed_total_mismatch', `${managedByProductId.size}/${MANAGED_TOTAL}`);

  const seenSourceIdentities = new Set();
  const mappedProductIds = new Set();
  const offers = [];
  const changes = [];
  const nonManaged = [];
  let multipacks = 0;
  for (const [index, row] of (Array.isArray(raw?.products) ? raw.products : []).entries()) {
    let sourceIdentity;
    try { sourceIdentity = `${canonicalTargetUrl(row?.url)}|${parseSizeKg(row?.size)}`; }
    catch (error) { addBlocker(blockers, error.message, `row:${index}`); continue; }
    if (seenSourceIdentities.has(sourceIdentity)) { addBlocker(blockers, 'duplicate_source_identity', sourceIdentity); continue; }
    seenSourceIdentities.add(sourceIdentity);
    const managed = catalogBySourceIdentity.get(sourceIdentity);
    if (!managed) { nonManaged.push({ sourceIdentity }); continue; }
    if (mappedProductIds.has(managed.product.id)) { addBlocker(blockers, 'duplicate_managed_mapping', managed.product.id); continue; }
    if (row?.stock !== 'Skladem') { addBlocker(blockers, 'missing_or_unavailable_managed_offer', managed.product.id); continue; }
    let parsed;
    try { parsed = priceStateFromRaw(row); }
    catch (error) { addBlocker(blockers, error.message, managed.product.id); continue; }
    const priceError = validatePriceState(parsed.state);
    if (priceError) { addBlocker(blockers, priceError, managed.product.id); continue; }
    const multipackCount = parseExplicitMultipackCount(row.size);
    if (multipackCount !== null) multipacks += 1;
    mappedProductIds.add(managed.product.id);
    const effective = effectivePriceState(managed.product, managed.offer, overlay);
    const anomaly = anomalyFor(effective, parsed.state);
    changes.push({ productId: managed.product.id, before: effective, after: parsed.state, ...anomaly });
    offers.push({
      source: SOURCE,
      partner: PARTNER,
      productId: managed.product.id,
      offerIdentity: { kind: 'product-partner', partner: PARTNER },
      sourceIdentity,
      matchMethod: 'canonical_url_total_packing_v1',
      price: parsed.state.price,
      salePrice: parsed.state.salePrice,
      originalPrice: parsed.state.originalPrice,
      normalizations: parsed.normalizations,
    });
  }
  for (const productId of managedByProductId.keys()) if (!mappedProductIds.has(productId)) addBlocker(blockers, 'missing_managed_offer', productId);
  if (multipacks !== EXPECTED_MULTIPACKS) addBlocker(blockers, 'managed_multipack_count_mismatch', `${multipacks}/${EXPECTED_MULTIPACKS}`);

  const exactSafe = mappedProductIds.size;
  const unresolved = Math.max(0, MANAGED_TOTAL - exactSafe);
  const ambiguous = [...blockers.values()].filter(group => group.code.includes('ambiguous')).reduce((total, group) => total + group.count, 0);
  const sortedOffers = offers.sort((left, right) => compareText(left.productId, right.productId));
  const sortedChanges = changes.sort((left, right) => compareText(left.productId, right.productId));
  const changed = sortedChanges.filter(item => item.changed);
  const saleCleared = sortedChanges.filter(item => item.saleCleared);
  const anomalyEvidence = {
    comparisonBasis: 'embedded_catalog_plus_valid_current_schema_v2_overlay',
    thresholdPolicy: 'report_only_more_history_required',
    comparedOffers: sortedChanges.length,
    changedOffers: changed.length,
    changedRatio: sortedChanges.length ? changed.length / sortedChanges.length : null,
    saleClearedOffers: saleCleared.length,
    saleClearRatio: sortedChanges.length ? saleCleared.length / sortedChanges.length : null,
    maxRelativeChange: sortedChanges.length ? Math.max(...sortedChanges.map(item => item.relativeChange)) : null,
    maxMultiplicativeChange: sortedChanges.length ? Math.max(...sortedChanges.map(item => item.multiplicativeChange)) : null,
    offers: sortedChanges,
  };
  const blockerList = [...blockers.values()].sort((left, right) => compareText(left.code, right.code));
  const candidate = {
    schemaVersion: 1,
    contract: 'platinum-managed-price-candidate-v1',
    reviewOnly: true,
    generatedAt,
    source: SOURCE,
    partner: PARTNER,
    catalogCommit,
    catalogSha256: actualCatalogSha256,
    currentOverlaySha256: actualCurrentOverlaySha256,
    managedContract: { total: MANAGED_TOTAL, exactSafe, unresolved, ambiguous, coverage: `${exactSafe}/${MANAGED_TOTAL}`, multipacks },
    offers: sortedOffers,
    nonManagedObservations: { count: nonManaged.length, identities: nonManaged.sort((left, right) => compareText(left.sourceIdentity, right.sourceIdentity)) },
    remoteActions: { publish: false, upload: false, deploy: false, gcs: false, currentJson: false, catalogImport: false, autoAdd: false },
  };
  const candidateBytes = Buffer.from(canonicalJson(candidate), 'utf8');
  const validation = {
    schemaVersion: 1,
    validator: 'platinum-managed-price-validation-v1',
    reviewOnly: true,
    generatedAt,
    passed: blockerList.length === 0 && exactSafe === MANAGED_TOTAL && unresolved === 0,
    managedContract: candidate.managedContract,
    mapping: { method: 'canonical_url_total_packing_v1', nonManagedObservations: nonManaged.length },
    currentEffectiveState: {
      catalogSha256: actualCatalogSha256,
      currentOverlaySha256: actualCurrentOverlaySha256,
      snapshotVersion: overlay.snapshot.snapshotVersion,
      platinumOverlayEntries: [...overlay.entriesByIdentity.keys()].filter(key => key.endsWith(`,\"${PARTNER}\"]`)).length,
    },
    anomalyEvidence,
    firstTransition: { reviewOnly: true, automaticPublishEligible: false, reason: 'more_history_required' },
    inputs: {
      raw: { sha256: sha256(rawBytes), size: rawBytes.length },
      reviewProvenance: { sha256: sha256(reviewProvenanceBytes), size: reviewProvenanceBytes.length },
      reviewValidation: { sha256: sha256(reviewValidationBytes), size: reviewValidationBytes.length },
      catalog: { commit: catalogCommit, sha256: actualCatalogSha256, size: catalogBytes.length },
      currentOverlay: { sha256: actualCurrentOverlaySha256, size: currentOverlayBytes.length },
      candidate: { sha256: sha256(candidateBytes), size: candidateBytes.length },
    },
    blockers: blockerList,
    remoteActions: candidate.remoteActions,
  };
  return { candidate, candidateBytes, validation, validationBytes: Buffer.from(canonicalJson(validation), 'utf8') };
}

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw new Error(`Unexpected argument: ${token}`);
    const separator = token.indexOf('=');
    const name = separator >= 0 ? token.slice(2, separator) : token.slice(2);
    const value = separator >= 0 ? token.slice(separator + 1) : argv[++index];
    if (!value) throw new Error(`Missing value for --${name}`);
    values.set(name, value);
  }
  return values;
}

function required(args, name) {
  const value = args.get(name);
  if (!value) throw new Error(`Missing required --${name}`);
  return value;
}

function main(argv = process.argv.slice(2), dependencies = {}) {
  const args = parseArgs(argv);
  const readFile = dependencies.readFile || (filePath => fs.readFileSync(filePath));
  const outputDir = path.resolve(required(args, 'output-dir'));
  const candidatePath = path.join(outputDir, 'platinum-managed-price-candidate.json');
  const validationPath = path.join(outputDir, 'platinum-managed-price-validation.json');
  const result = buildManagedPriceArtifacts({
    rawBytes: readFile(required(args, 'raw')),
    reviewProvenanceBytes: readFile(required(args, 'review-provenance')),
    reviewValidationBytes: readFile(required(args, 'review-validation')),
    catalogBytes: readFile(required(args, 'catalog')),
    currentOverlayBytes: readFile(required(args, 'current-overlay')),
    expectedCatalogSha256: required(args, 'catalog-sha256'),
    expectedCurrentOverlaySha256: required(args, 'current-overlay-sha256'),
    catalogCommit: required(args, 'catalog-commit'),
    generatedAt: required(args, 'generated-at'),
  });
  const writer = dependencies.groupWriter || writeFileGroupCreateOnly;
  writer([
    { path: candidatePath, contents: result.candidateBytes },
    { path: validationPath, contents: result.validationBytes },
  ]);
  if (!result.validation.passed) {
    const error = new Error(`Platinum managed-price validation failed: ${result.validation.blockers.map(item => item.code).join(', ')}`);
    error.stage = 'managed_price_validation';
    throw error;
  }
  return { ...result, artifacts: { candidate: candidatePath, validation: validationPath } };
}

if (require.main === module) {
  try {
    const result = main();
    process.stdout.write(`${JSON.stringify({ verdict: 'PLATINUM_MANAGED_PRICE_PASS', managedContract: result.validation.managedContract, anomalyEvidence: result.validation.anomalyEvidence }, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`Platinum managed-price validation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  EXPECTED_MULTIPACKS,
  MANAGED_TOTAL,
  PARTNER,
  SOURCE,
  buildManagedPriceArtifacts,
  canonicalTargetUrl,
  main,
  parseCzk,
  parseCurrentOverlay,
  parseExplicitMultipackCount,
  parseSizeKg,
  parseUnitCzkMinor,
  priceStateFromRaw,
  validatePriceState,
};

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SOURCE = 'krmivo-platinum.cz';
const DOCUMENT_HOSTS = new Set(['krmivo-platinum.cz', 'www.krmivo-platinum.cz']);
const ASSET_HOSTS = new Set([...DOCUMENT_HOSTS, 'cdn.krmivo-platinum.cz']);
const EXPECTED_CATEGORIES = Object.freeze([
  Object.freeze({ name: 'Granule pro psy', animalType: 'dog' }),
  Object.freeze({ name: 'Granule pro kočky', animalType: 'cat' }),
]);
const BASELINE = Object.freeze({ totalProducts: 90, dog: 60, cat: 30, uniqueUrlSize: 90, multipacks: 49 });
const CHALLENGE_PATTERN = /captcha|access denied|verify (?:that )?you are human|cloudflare|bot detection|robot check|pristup odepren|overte,? ze nejste robot/iu;
const SENSITIVE_KEY_PATTERN = /authorization|cookie|set-cookie|token|secret|password|passwd|api[-_]?key|session|credential|header/iu;
const URL_PATTERN = /https?:\/\/[^\s"'<>]+/giu;
const MAX_DIAGNOSTIC_DEPTH = 8;
const MAX_DIAGNOSTIC_ITEMS = 100;
const MAX_DIAGNOSTIC_TEXT = 1000;

class ReviewStageError extends Error {
  constructor(stage, message, details = {}) {
    super(message);
    this.name = 'ReviewStageError';
    this.stage = stage;
    this.details = details;
  }
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function assertCanonicalIso(value, field) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`${field} must be a canonical UTC ISO instant`);
  }
  return value;
}

function safeRunId(value) {
  if (typeof value !== 'string' || !/^platinum-live-[0-9]{8}T[0-9]{9}Z$/u.test(value)) throw new Error('Invalid --run-id');
  return value;
}

function ensureReviewOutputDirectory(outputDir, sourceRoot) {
  if (!path.isAbsolute(outputDir)) throw new Error('--output-dir must be absolute');
  const resolved = path.resolve(outputDir);
  const source = path.resolve(sourceRoot);
  const relative = path.relative(source, resolved);
  if (!relative || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    throw new Error('Review output directory must stay outside the Platinum source directory');
  }
  if (fs.existsSync(resolved)) {
    const stat = fs.lstatSync(resolved);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Review output path must be a real directory');
    if (fs.readdirSync(resolved).length !== 0) throw new Error('Review output directory must be empty');
  } else {
    const parent = path.dirname(resolved);
    const parentStat = fs.lstatSync(parent);
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) throw new Error('Review output parent must be a real directory');
    fs.mkdirSync(resolved);
  }
  return resolved;
}

function writeCreateOnly(filePath, contents) {
  const descriptor = fs.openSync(filePath, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, contents, 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function removeOwnedFile(filePath, identity, operation = fs) {
  try {
    const current = operation.lstatSync(filePath);
    if (current.isFile() && !current.isSymbolicLink() && current.dev === identity.dev && current.ino === identity.ino) operation.unlinkSync(filePath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

function writeFileGroupCreateOnly(inputFiles, options = {}) {
  if (!Array.isArray(inputFiles) || inputFiles.length === 0) throw new Error('Artifact group must not be empty');
  const operation = options.fs || fs;
  const transactionId = options.transactionId || crypto.randomUUID();
  const invoke = (stage, index, file) => options.faultInjector?.(stage, index, file);
  const prepared = [];
  const finalized = [];
  const targets = new Set();
  const files = inputFiles.map(file => ({
    path: path.resolve(file.path),
    contents: Buffer.isBuffer(file.contents) ? file.contents : Buffer.from(String(file.contents), 'utf8'),
  }));
  for (const file of files) {
    if (targets.has(file.path)) throw new Error('Artifact group contains a duplicate target');
    targets.add(file.path);
    if (operation.existsSync(file.path)) throw new Error(`Refusing to overwrite existing artifact: ${file.path}`);
  }
  try {
    invoke('before_prepare', -1, null);
    for (const [index, file] of files.entries()) {
      invoke('before_temp_write', index, file);
      const temporaryPath = `${file.path}.pending-${transactionId}-${index}`;
      const descriptor = operation.openSync(temporaryPath, 'wx', 0o600);
      const identity = operation.fstatSync(descriptor);
      prepared.push({ path: temporaryPath, identity });
      try {
        operation.writeFileSync(descriptor, file.contents);
        operation.fsyncSync(descriptor);
      } finally {
        operation.closeSync(descriptor);
      }
    }
    for (const [index, file] of files.entries()) {
      invoke('before_finalize', index, file);
      operation.linkSync(prepared[index].path, file.path);
      finalized.push({ path: file.path, identity: prepared[index].identity });
    }
    for (const item of prepared) removeOwnedFile(item.path, item.identity, operation);
  } catch (error) {
    const cleanupErrors = [];
    for (const item of finalized.reverse()) {
      try { removeOwnedFile(item.path, item.identity, operation); } catch (cleanupError) { cleanupErrors.push(cleanupError.message); }
    }
    for (const item of prepared.reverse()) {
      try { removeOwnedFile(item.path, item.identity, operation); } catch (cleanupError) { cleanupErrors.push(cleanupError.message); }
    }
    if (cleanupErrors.length) error.cleanupErrors = cleanupErrors;
    throw error;
  }
}

function sanitizeUrl(value) {
  try {
    const parsed = new URL(String(value));
    if (!['http:', 'https:'].includes(parsed.protocol)) return '[REDACTED_URL]';
    const pathname = decodeURIComponent(parsed.pathname);
    if (/token|secret|password|passwd|api[-_]?key|session|credential/iu.test(pathname)) return `${parsed.protocol}//${parsed.hostname}/[REDACTED]`;
    return `${parsed.protocol}//${parsed.hostname}${parsed.pathname || '/'}`.slice(0, MAX_DIAGNOSTIC_TEXT);
  } catch {
    return '[REDACTED_URL]';
  }
}

function sanitizeText(value) {
  try {
    return String(value ?? '')
      .replace(URL_PATTERN, match => sanitizeUrl(match))
      .replace(/\b(authorization|cookie|set-cookie|token|secret|password|passwd|api[-_]?key|session|credential)\s*[:=]\s*[^\s,;]+/giu, '$1=[REDACTED]')
      .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/giu, 'Bearer [REDACTED]')
      .slice(0, MAX_DIAGNOSTIC_TEXT);
  } catch {
    return '[REDACTED]';
  }
}

function sanitizeDiagnostic(value, seen = new WeakSet(), depth = 0) {
  try {
    if (typeof value === 'string') return sanitizeText(value);
    if (value === null || ['boolean', 'number'].includes(typeof value)) return Number.isFinite(value) || typeof value !== 'number' ? value : String(value);
    if (typeof value === 'bigint' || typeof value === 'symbol' || typeof value === 'function' || typeof value === 'undefined') return sanitizeText(String(value));
    if (depth >= MAX_DIAGNOSTIC_DEPTH) return '[DEPTH_LIMIT]';
    if (seen.has(value)) return '[CIRCULAR]';
    seen.add(value);
    if (value instanceof Error) {
      return {
        name: sanitizeText(value.name || 'Error'),
        ...(value.code ? { code: sanitizeText(value.code) } : {}),
        message: sanitizeText(value.message || 'Failure'),
        ...(value.details !== undefined ? { details: sanitizeDiagnostic(value.details, seen, depth + 1) } : {}),
      };
    }
    if (Array.isArray(value)) return value.slice(0, MAX_DIAGNOSTIC_ITEMS).map(item => sanitizeDiagnostic(item, seen, depth + 1));
    const result = {};
    for (const key of Object.keys(value).slice(0, MAX_DIAGNOSTIC_ITEMS)) {
      const safeKey = sanitizeText(key);
      if (SENSITIVE_KEY_PATTERN.test(key)) result[safeKey] = '[REDACTED]';
      else if (/(?:^|_)url$/iu.test(key)) result[safeKey] = typeof value[key] === 'string' ? sanitizeUrl(value[key]) : '[REDACTED_URL]';
      else result[safeKey] = sanitizeDiagnostic(value[key], seen, depth + 1);
    }
    return result;
  } catch {
    return '[REDACTED]';
  }
}

function parseSafeUrl(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { throw new Error('invalid_url'); }
  if (parsed.protocol !== 'https:') throw new Error('invalid_protocol');
  if (parsed.username || parsed.password) throw new Error('credentials_in_url');
  if (parsed.port) throw new Error('nonstandard_port');
  return parsed;
}

function classifyNavigationFrame(request) {
  const documentRequest = request?.isNavigationRequest?.() === true || request?.resourceType?.() === 'document';
  if (!documentRequest) return null;
  try {
    const frame = request.frame();
    const ownerPage = frame?.page?.();
    const mainFrame = ownerPage?.mainFrame?.();
    if (!frame || !ownerPage || !mainFrame) return 'unknown';
    return frame === mainFrame ? 'main' : 'subframe';
  } catch {
    return 'unknown';
  }
}

function classifyNetworkRequest(rawUrl, { resourceType = 'other', navigation = false, frameKind = null } = {}) {
  const documentRequest = navigation || resourceType === 'document';
  if (documentRequest && !['main', 'subframe'].includes(frameKind)) {
    return { allowed: false, fatal: true, kind: 'document', reason: 'frame_identity_unavailable' };
  }
  let parsed;
  try { parsed = parseSafeUrl(rawUrl); } catch (error) {
    return { allowed: false, fatal: documentRequest && frameKind !== 'subframe', kind: documentRequest && frameKind === 'subframe' ? 'subframe_document' : documentRequest ? 'document' : 'asset', reason: error.message };
  }
  const host = parsed.hostname.toLowerCase();
  if (documentRequest) {
    if (frameKind === 'subframe') {
      return DOCUMENT_HOSTS.has(host)
        ? { allowed: true, fatal: false, kind: 'document', host }
        : { allowed: false, fatal: false, kind: 'subframe_document', host, reason: 'external_subframe_blocked' };
    }
    return DOCUMENT_HOSTS.has(host)
      ? { allowed: true, fatal: false, kind: 'document', host }
      : { allowed: false, fatal: true, kind: 'document', host, reason: 'document_host_not_allowed' };
  }
  return ASSET_HOSTS.has(host)
    ? { allowed: true, fatal: false, kind: 'asset', host }
    : { allowed: false, fatal: false, kind: 'asset', host, reason: 'asset_host_not_allowed' };
}

function createNetworkGuardSession() {
  const metrics = { requests: 0, allowedDocuments: 0, allowedAssets: 0, blockedAssets: 0, blockedSubframes: 0, blockedSubframeHosts: {}, fatalViolations: [] };
  return {
    metrics,
    async install(context) {
      await context.route('**/*', async route => {
        const request = route.request();
        const decision = classifyNetworkRequest(request.url(), {
          resourceType: request.resourceType(),
          navigation: request.isNavigationRequest(),
          frameKind: classifyNavigationFrame(request),
        });
        metrics.requests += 1;
        if (decision.allowed) {
          if (decision.kind === 'document') metrics.allowedDocuments += 1;
          else metrics.allowedAssets += 1;
          await route.continue();
          return;
        }
        if (decision.fatal) metrics.fatalViolations.push({ reason: decision.reason, host: decision.host || null });
        else if (decision.kind === 'subframe_document') {
          metrics.blockedSubframes += 1;
          if (decision.host) metrics.blockedSubframeHosts[decision.host] = (metrics.blockedSubframeHosts[decision.host] || 0) + 1;
        } else metrics.blockedAssets += 1;
        await route.abort('blockedbyclient');
      });
    },
    assertNoFatalViolations(stage) {
      if (metrics.fatalViolations.length) {
        throw new ReviewStageError(stage, 'Blocked disallowed document navigation', { violations: metrics.fatalViolations });
      }
    },
  };
}

async function assertAllowedDocument(page, response, stage) {
  if (!response) throw new ReviewStageError(stage, 'Document navigation returned no response');
  const status = response.status();
  if (status < 200 || status >= 400) throw new ReviewStageError(stage, `Document returned HTTP ${status}`);
  const decision = classifyNetworkRequest(page.url(), { resourceType: 'document', navigation: true, frameKind: 'main' });
  if (!decision.allowed) throw new ReviewStageError(stage, `Final document URL is not allowed (${decision.reason})`);
  const diagnostic = await page.evaluate(() => ({
    title: String(document.title || '').slice(0, 300),
    body: String(document.body?.innerText || '').slice(0, 4000),
  }));
  if (CHALLENGE_PATTERN.test(`${diagnostic.title}\n${diagnostic.body}`)) {
    throw new ReviewStageError(stage, 'Challenge or anti-bot document detected');
  }
}

function validateCategoryExtraction(result, category) {
  if (!result || !Array.isArray(result.items)) throw new ReviewStageError('category_parse', 'Category parser returned an invalid result', { category });
  if (!Number.isInteger(result.cardCount) || result.cardCount <= 0) throw new ReviewStageError('category_parse', 'Category contains no product cards', { category });
  if (result.invalidCards !== 0) throw new ReviewStageError('category_parse', 'Category contains unparseable product cards', { category, invalidCards: result.invalidCards });
  if (result.items.length <= 0) throw new ReviewStageError('category_parse', 'Category contains no accepted products', { category });
  if (result.cardCount !== result.items.length + result.excludedSamples) {
    throw new ReviewStageError('category_parse', 'Category card accounting is incomplete', { category });
  }
  return result.items;
}

function validateDetailExtraction(result, product) {
  if (!result || !Array.isArray(result.variants)) throw new ReviewStageError('detail_parse', 'Detail parser returned an invalid result', { product: product?.name });
  if (!Number.isInteger(result.rowCount) || result.rowCount <= 0) throw new ReviewStageError('detail_parse', 'Detail contains no variant rows', { product: product?.name });
  if (result.invalidRows !== 0 || result.variants.length !== result.rowCount) {
    throw new ReviewStageError('detail_parse', 'Detail variant accounting is incomplete', { product: product?.name, invalidRows: result.invalidRows });
  }
  const priceNumber = value => Number.parseInt(String(value || '').replace(/[^0-9]/gu, ''), 10);
  for (const variant of result.variants) {
    const price = priceNumber(variant?.priceText);
    const sale = priceNumber(variant?.salePriceText);
    const original = priceNumber(variant?.originalPriceText);
    if (!variant?.sizeText || !Number.isFinite(price) || price <= 0) {
      throw new ReviewStageError('detail_parse', 'Detail variant is missing a valid size or price', { product: product?.name });
    }
    const hasSale = variant?.salePriceText != null;
    const hasOriginal = variant?.originalPriceText != null;
    if (hasSale !== hasOriginal || (hasSale && (!Number.isFinite(sale) || !Number.isFinite(original) || sale <= 0 || original <= sale || price !== sale))) {
      throw new ReviewStageError('detail_parse', 'Detail variant has an invalid sale/original relationship', { product: product?.name });
    }
  }
  return result.variants;
}

function normalizedSourceIdentity(product) {
  const parsed = parseSafeUrl(product.url);
  if (!DOCUMENT_HOSTS.has(parsed.hostname.toLowerCase())) throw new Error('invalid_product_host');
  const canonical = `https://${parsed.hostname.toLowerCase()}${(parsed.pathname.replace(/\/+$/u, '') || '/').toLowerCase()}`;
  return `${canonical}|${String(product.size || '').trim().toLowerCase().replace(/\s+/gu, ' ')}`;
}

function validateReviewSnapshot(raw, provenance, rawBytes) {
  const errors = [];
  const add = (code, details = null) => errors.push({ code, details });
  const products = Array.isArray(raw?.products) ? raw.products : [];
  if (raw?.source !== SOURCE) add('invalid_source');
  if (raw?.reviewOnly !== true) add('not_review_only');
  try { assertCanonicalIso(raw?.generatedAt, 'generatedAt'); } catch { add('invalid_generated_at'); }
  try { assertCanonicalIso(raw?.scrapedAt, 'scrapedAt'); } catch { add('invalid_scraped_at'); }
  if (raw?.totalProducts !== products.length) add('declared_total_mismatch');
  if (products.length !== BASELINE.totalProducts) add('unexpected_total', `${products.length}/${BASELINE.totalProducts}`);
  const names = Array.isArray(raw?.categoryNames) ? raw.categoryNames : [];
  if (names.length !== EXPECTED_CATEGORIES.length || new Set(names).size !== names.length
      || EXPECTED_CATEGORIES.some(expected => !names.includes(expected.name))) add('category_contract_mismatch');
  if (raw?.categories !== EXPECTED_CATEGORIES.length) add('category_count_mismatch');
  const dog = products.filter(product => product?.animalType === 'dog').length;
  const cat = products.filter(product => product?.animalType === 'cat').length;
  const unknownSpecies = products.length - dog - cat;
  if (dog !== BASELINE.dog) add('dog_count_drift', `${dog}/${BASELINE.dog}`);
  if (cat !== BASELINE.cat) add('cat_count_drift', `${cat}/${BASELINE.cat}`);
  if (unknownSpecies) add('unexpected_species', unknownSpecies);
  const identities = new Set();
  let multipacks = 0;
  for (const [index, product] of products.entries()) {
    if (!product?.url) add('missing_url', index);
    if (!product?.size) add('missing_size', index);
    if (!product?.price) add('missing_price', index);
    if (!product?.animalType) add('missing_species', index);
    if (/^\s*\d+\s*[x×]\s*\d/iu.test(String(product?.size || ''))) multipacks += 1;
    try {
      const identity = normalizedSourceIdentity(product);
      if (identities.has(identity)) add('duplicate_source_identity', identity);
      identities.add(identity);
    } catch (error) { add(error.message, index); }
  }
  if (identities.size !== BASELINE.uniqueUrlSize) add('unique_identity_drift', `${identities.size}/${BASELINE.uniqueUrlSize}`);
  if (multipacks !== BASELINE.multipacks) add('multipack_count_drift', `${multipacks}/${BASELINE.multipacks}`);
  const stats = raw?.runStats;
  if (!stats || stats.categoryRequests !== EXPECTED_CATEGORIES.length || stats.categorySuccesses !== EXPECTED_CATEGORIES.length
      || stats.categoryErrors !== 0) add('incomplete_category_run');
  if (!stats || !Number.isInteger(stats.detailRequests) || stats.detailRequests <= 0
      || stats.detailSuccesses !== stats.detailRequests || stats.detailErrors !== 0) add('incomplete_detail_run');
  if (!provenance || provenance.raw?.sha256 !== sha256(rawBytes) || provenance.raw?.size !== rawBytes.length) add('raw_provenance_mismatch');
  if (provenance?.runId !== raw?.runId || provenance?.generatedAt !== raw?.generatedAt) add('run_provenance_mismatch');
  return {
    schemaVersion: 1,
    validator: 'platinum-live-review',
    generatedAt: raw?.generatedAt,
    runId: raw?.runId,
    passed: errors.length === 0,
    baseline: BASELINE,
    counts: { total: products.length, dog, cat, unknownSpecies, uniqueUrlSize: identities.size, multipacks },
    runCompleteness: stats || null,
    raw: { sha256: sha256(rawBytes), size: rawBytes.length },
    errors,
  };
}

function validateManagedPriceReviewSnapshot(raw, provenance, rawBytes) {
  const errors = [];
  const add = (code, details = null) => errors.push({ code, details });
  const products = Array.isArray(raw?.products) ? raw.products : [];
  if (raw?.source !== SOURCE) add('invalid_source');
  if (raw?.reviewOnly !== true) add('not_review_only');
  try { assertCanonicalIso(raw?.generatedAt, 'generatedAt'); } catch { add('invalid_generated_at'); }
  try { assertCanonicalIso(raw?.scrapedAt, 'scrapedAt'); } catch { add('invalid_scraped_at'); }
  if (raw?.totalProducts !== products.length) add('declared_total_mismatch');
  const names = Array.isArray(raw?.categoryNames) ? raw.categoryNames : [];
  if (names.length !== EXPECTED_CATEGORIES.length || new Set(names).size !== names.length
      || EXPECTED_CATEGORIES.some(expected => !names.includes(expected.name))) add('category_contract_mismatch');
  if (raw?.categories !== EXPECTED_CATEGORIES.length) add('category_count_mismatch');
  const dog = products.filter(product => product?.animalType === 'dog').length;
  const cat = products.filter(product => product?.animalType === 'cat').length;
  const unknownSpecies = products.length - dog - cat;
  if (unknownSpecies) add('unexpected_species', unknownSpecies);
  const identities = new Set();
  let multipacks = 0;
  for (const [index, product] of products.entries()) {
    if (!product?.url) add('missing_url', index);
    if (!product?.size) add('missing_size', index);
    if (!product?.animalType) add('missing_species', index);
    if (/^\s*\d+\s*[x×]\s*\d/iu.test(String(product?.size || ''))) multipacks += 1;
    try {
      const identity = normalizedSourceIdentity(product);
      if (identities.has(identity)) add('duplicate_source_identity', identity);
      identities.add(identity);
    } catch (error) { add(error.message, index); }
  }
  const stats = raw?.runStats;
  if (!stats || stats.categoryRequests !== EXPECTED_CATEGORIES.length || stats.categorySuccesses !== EXPECTED_CATEGORIES.length
      || stats.categoryErrors !== 0) add('incomplete_category_run');
  if (!stats || !Number.isInteger(stats.detailRequests) || stats.detailRequests <= 0
      || stats.detailSuccesses !== stats.detailRequests || stats.detailErrors !== 0) add('incomplete_detail_run');
  if (!provenance || provenance.raw?.sha256 !== sha256(rawBytes) || provenance.raw?.size !== rawBytes.length) add('raw_provenance_mismatch');
  if (provenance?.runId !== raw?.runId || provenance?.generatedAt !== raw?.generatedAt) add('run_provenance_mismatch');
  return {
    schemaVersion: 1,
    validator: 'platinum-managed-price-review',
    generatedAt: raw?.generatedAt,
    runId: raw?.runId,
    passed: errors.length === 0,
    boundary: 'scraper_health_only_managed_coverage_validated_separately',
    counts: { total: products.length, dog, cat, unknownSpecies, uniqueUrlSize: identities.size, multipacks },
    runCompleteness: stats || null,
    raw: { sha256: sha256(rawBytes), size: rawBytes.length },
    errors,
  };
}

function safeFailure(error, generatedAt, runId) {
  const diagnostic = sanitizeDiagnostic(error);
  return {
    schemaVersion: 1,
    status: 'FAIL',
    stage: sanitizeText(error?.stage || 'review_orchestration'),
    generatedAt,
    runId,
    error: {
      name: sanitizeText(error?.name || 'Error'),
      ...(error?.code ? { code: sanitizeText(error.code) } : {}),
    },
    reason: sanitizeText(error?.message || error || 'Unknown review failure'),
    details: diagnostic?.details || null,
    completed: sanitizeDiagnostic(error?.metrics || null),
    remoteActions: { publish: false, upload: false, deploy: false, scheduler: false },
  };
}

module.exports = {
  ASSET_HOSTS,
  BASELINE,
  DOCUMENT_HOSTS,
  EXPECTED_CATEGORIES,
  ReviewStageError,
  assertAllowedDocument,
  assertCanonicalIso,
  canonicalJson,
  classifyNetworkRequest,
  classifyNavigationFrame,
  createNetworkGuardSession,
  ensureReviewOutputDirectory,
  safeFailure,
  sanitizeDiagnostic,
  sanitizeText,
  sanitizeUrl,
  safeRunId,
  sha256,
  validateCategoryExtraction,
  validateDetailExtraction,
  validateManagedPriceReviewSnapshot,
  validateReviewSnapshot,
  writeCreateOnly,
  writeFileGroupCreateOnly,
};

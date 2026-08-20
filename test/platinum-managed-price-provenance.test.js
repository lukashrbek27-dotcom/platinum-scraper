'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { canonicalJson, sha256 } = require('../review-hardening');
const { buildManagedPriceArtifacts } = require('../platinum-managed-price-validation');
const { createManagedPriceProvenance, main } = require('../platinum-managed-price-provenance');

const GENERATED_AT = '2026-08-20T06:00:00.000Z';
const PRODUCER_COMMIT = 'a'.repeat(40);
const CATALOG_COMMIT = '467a67fd0afca9644fabd8a761c5c0d1efe3b5b0';

function fixture() {
  const catalog = [];
  const products = [];
  for (let index = 0; index < 90; index += 1) {
    const multipack = index < 49;
    const unit = 100 + index;
    const size = multipack ? `2 x ${index + 1} g` : `${index + 1} kg`;
    const sizeKg = multipack ? Number((2 * (index + 1) / 1000).toFixed(3)) : index + 1;
    const url = `https://www.krmivo-platinum.cz/product-${index}/`;
    const price = multipack ? unit * 2 : unit;
    products.push({ url, size, price: multipack ? `${unit} Kč / ks` : `${unit} Kč`, salePrice: null, originalPrice: null, stock: 'Skladem' });
    catalog.push({ id: `platinum-food-${index}`, sizeKg, offers: [{ partner: 'Platinum', affiliateUrl: url, price, salePrice: null, originalPrice: null }] });
  }
  const rawBytes = Buffer.from(canonicalJson({ products }));
  const reviewProvenanceBytes = Buffer.from(canonicalJson({ raw: { sha256: sha256(rawBytes), size: rawBytes.length }, remoteActions: { publish: false } }));
  const reviewValidationBytes = Buffer.from(canonicalJson({ passed: true, raw: { sha256: sha256(rawBytes), size: rawBytes.length } }));
  const catalogBytes = Buffer.from(canonicalJson(catalog));
  const catalogSha256 = sha256(catalogBytes);
  const currentOverlayBytes = Buffer.from(canonicalJson({ schemaVersion: 2, snapshotVersion: GENERATED_AT, generatedAt: GENERATED_AT, catalogSha256, entries: [] }));
  const managed = buildManagedPriceArtifacts({ rawBytes, reviewProvenanceBytes, reviewValidationBytes, catalogBytes, currentOverlayBytes, expectedCatalogSha256: catalogSha256, expectedCurrentOverlaySha256: sha256(currentOverlayBytes), catalogCommit: CATALOG_COMMIT, generatedAt: GENERATED_AT });
  return { rawBytes, reviewProvenanceBytes, reviewValidationBytes, catalogBytes, currentOverlayBytes, candidateBytes: managed.candidateBytes, validationBytes: managed.validationBytes };
}

function options(current = fixture()) {
  return {
    generatedAt: GENERATED_AT,
    githubRunId: '32350000000',
    githubRunAttempt: '1',
    repository: 'lukashrbek27-dotcom/platinum-scraper',
    workflowPath: '.github/workflows/scrape.yml',
    workflowRef: 'lukashrbek27-dotcom/platinum-scraper/.github/workflows/scrape.yml@refs/heads/main',
    producerCommit: PRODUCER_COMMIT,
    catalogCommit: CATALOG_COMMIT,
    ...current,
  };
}

test('managed provenance binds GitHub run, producer, catalog, overlay and every input artifact', () => {
  const current = fixture();
  const provenance = createManagedPriceProvenance(options(current));
  assert.equal(provenance.verdict, 'PASS');
  assert.equal(provenance.github.runId, '32350000000');
  assert.equal(provenance.github.runAttempt, '1');
  assert.equal(provenance.github.producerCommit, PRODUCER_COMMIT);
  assert.equal(provenance.catalog.commit, CATALOG_COMMIT);
  assert.equal(provenance.currentOverlay.sha256, sha256(current.currentOverlayBytes));
  assert.equal(provenance.artifacts.raw.sha256, sha256(current.rawBytes));
  assert.equal(provenance.artifacts.reviewProvenance.sha256, sha256(current.reviewProvenanceBytes));
  assert.equal(provenance.artifacts.candidate.sha256, sha256(current.candidateBytes));
  assert.equal(provenance.artifacts.validation.sha256, sha256(current.validationBytes));
  assert.equal(provenance.managedContract.coverage, '90/90');
  assert.ok(Object.values(provenance.remoteActions).every(value => value === false));
});

test('tampered candidate, catalog and current overlay bindings fail closed', () => {
  for (const field of ['candidateBytes', 'catalogBytes', 'currentOverlayBytes']) {
    const current = fixture();
    current[field] = Buffer.concat([current[field], Buffer.from(' ')]);
    assert.throws(() => createManagedPriceProvenance(options(current)), /mismatch|invalid/u, field);
  }
});

test('provenance records the exact validation bytes rather than a semantic reserialization', () => {
  const current = fixture();
  current.validationBytes = Buffer.concat([current.validationBytes, Buffer.from(' ')]);
  const provenance = createManagedPriceProvenance(options(current));
  assert.equal(provenance.artifacts.validation.sha256, sha256(current.validationBytes));
  assert.equal(provenance.artifacts.validation.size, current.validationBytes.length);
});

test('unsafe workflow metadata is rejected and no secret-bearing field is accepted', () => {
  assert.throws(() => createManagedPriceProvenance({ ...options(), workflowRef: 'token=SECRET' }), /workflowRef/u);
  assert.throws(() => createManagedPriceProvenance({ ...options(), repository: 'https://user:pass@example.com/repo' }), /repository/u);
  const serialized = JSON.stringify(createManagedPriceProvenance(options()));
  assert.doesNotMatch(serialized, /token|credential|authorization|cookie|password/iu);
});

test('provenance output is create-only', () => {
  const current = fixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'platinum-provenance-test-'));
  try {
    const files = new Map(Object.entries(current));
    const args = ['--output-dir', root, '--generated-at', GENERATED_AT, '--github-run-id', '32350000000', '--github-run-attempt', '1', '--repository', 'lukashrbek27-dotcom/platinum-scraper', '--workflow-path', '.github/workflows/scrape.yml', '--workflow-ref', 'lukashrbek27-dotcom/platinum-scraper/.github/workflows/scrape.yml@refs/heads/main', '--producer-commit', PRODUCER_COMMIT, '--catalog-commit', CATALOG_COMMIT, '--raw', 'rawBytes', '--review-provenance', 'reviewProvenanceBytes', '--review-validation', 'reviewValidationBytes', '--candidate', 'candidateBytes', '--validation', 'validationBytes', '--catalog', 'catalogBytes', '--current-overlay', 'currentOverlayBytes'];
    const dependencies = { readFile: name => files.get(name) };
    assert.equal(main(args, dependencies).provenance.verdict, 'PASS');
    assert.throws(() => main(args, dependencies), /EEXIST/u);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('workflow pins private catalog checkout and remains review-only without publisher or GCS', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'scrape.yml'), 'utf8');
  assert.match(workflow, /repository:\s*lukashrbek27-dotcom\/mazlicek-plus/u);
  assert.match(workflow, /ref:\s*467a67fd0afca9644fabd8a761c5c0d1efe3b5b0/u);
  assert.match(workflow, /token:\s*\$\{\{ secrets\.PLATINUM_CATALOG_READ_TOKEN \}\}/u);
  assert.match(workflow, /persist-credentials:\s*false/u);
  assert.match(workflow, /sparse-checkout:[\s\S]*src\/data\/partner-foods\.json/u);
  assert.match(workflow, /git -C app-catalog rev-parse HEAD/u);
  assert.match(workflow, /platinum-managed-price-validation\.js/u);
  assert.match(workflow, /platinum-managed-price-provenance\.js/u);
  assert.match(workflow, /permissions:\s*\n\s*contents:\s*read/u);
  assert.doesNotMatch(workflow, /contents:\s*write|git\s+(?:add|commit|push)\b|gcloud|gsutil|publish-combined|price-overlay-publisher|deploy/u);
  assert.doesNotMatch(workflow, /echo[^\n]*PLATINUM_CATALOG_READ_TOKEN|secrets\.PLATINUM_CATALOG_READ_TOKEN[^\n]*(?:artifact|summary)/u);
});

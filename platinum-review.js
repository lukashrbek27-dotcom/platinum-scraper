#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { scrape } = require('./scraper');
const {
  ASSET_HOSTS,
  DOCUMENT_HOSTS,
  assertCanonicalIso,
  canonicalJson,
  ensureReviewOutputDirectory,
  safeFailure,
  safeRunId,
  sanitizeText,
  sha256,
  validateReviewSnapshot,
  validateManagedPriceReviewSnapshot,
  writeCreateOnly,
  writeFileGroupCreateOnly,
} = require('./review-hardening');

const REVIEW_OUTPUT_ROOT = path.resolve(
  process.env.PLATINUM_REVIEW_OUTPUT_ROOT
    || (process.platform === 'win32' ? 'C:\\Mazlicek\\scarper-output' : '/tmp/platinum-review'),
);

function assertSupportedOutputRoot(outputDir) {
  const root = path.resolve(REVIEW_OUTPUT_ROOT);
  const resolved = path.resolve(outputDir);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error(`--output-dir must be a child of ${REVIEW_OUTPUT_ROOT}`);
}

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw new Error(`Unexpected argument: ${token}`);
    const equals = token.indexOf('=');
    values.set(equals >= 0 ? token.slice(2, equals) : token.slice(2), equals >= 0 ? token.slice(equals + 1) : argv[++index]);
  }
  return values;
}

function required(args, name) {
  const value = args.get(name);
  if (!value) throw new Error(`Missing required --${name}`);
  return value;
}

function fileMetadata(filePath, role) {
  const bytes = fs.readFileSync(filePath);
  return { role, path: filePath, size: bytes.length, sha256: sha256(bytes) };
}

async function runReview({ outputDir, generatedAt, runId, validationProfile = 'full-review', scrapeRunner = scrape, clock = () => new Date(), sourceRoot = __dirname, groupWriter = writeFileGroupCreateOnly }) {
  assertCanonicalIso(generatedAt, 'generatedAt');
  safeRunId(runId);
  if (path.basename(path.resolve(outputDir)) !== runId) throw new Error('--output-dir basename must equal --run-id');
  const safeOutputDir = ensureReviewOutputDirectory(outputDir, sourceRoot);
  const startedAt = clock();
  let scrapeResult;
  try {
    scrapeResult = await scrapeRunner({ reviewMode: true, generatedAt });
    const endedAt = clock();
    const raw = {
      ...scrapeResult.output,
      schemaVersion: 1,
      reviewOnly: true,
      runId,
      generatedAt,
      scrapedAt: generatedAt,
      products: scrapeResult.output.products.map(product => ({ ...product, scrapedAt: generatedAt })),
      runStats: scrapeResult.metrics,
    };
    const rawBytes = Buffer.from(canonicalJson(raw), 'utf8');
    const provenance = {
      schemaVersion: 1,
      source: 'krmivo-platinum.cz',
      reviewOnly: true,
      runId,
      generatedAt,
      startedAt: startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
      durationMs: endedAt.getTime() - startedAt.getTime(),
      approvedHosts: {
        documents: [...DOCUMENT_HOSTS].sort(),
        assets: [...ASSET_HOSTS].sort(),
      },
      categories: scrapeResult.output.categoryNames,
      requests: scrapeResult.metrics,
      sources: [
        fileMetadata(path.join(sourceRoot, 'scraper.js'), 'legacyParserAndOrchestration'),
        fileMetadata(path.join(sourceRoot, 'review-hardening.js'), 'reviewHardening'),
        fileMetadata(path.join(sourceRoot, 'platinum-review.js'), 'reviewCli'),
      ],
      raw: { file: 'platinum-raw.json', size: rawBytes.length, sha256: sha256(rawBytes) },
      remoteActions: { publish: false, upload: false, deploy: false, scheduler: false },
    };
    const provenanceBytes = Buffer.from(canonicalJson(provenance), 'utf8');
    if (!['full-review', 'managed-price'].includes(validationProfile)) throw new Error('Unsupported validation profile');
    const validation = validationProfile === 'managed-price'
      ? validateManagedPriceReviewSnapshot(raw, provenance, rawBytes)
      : validateReviewSnapshot(raw, provenance, rawBytes);
    validation.provenance = { file: 'platinum-provenance.json', size: provenanceBytes.length, sha256: sha256(provenanceBytes) };
    if (!validation.passed) {
      const error = new Error(`Platinum live review validation failed: ${validation.errors.map(item => item.code).join(', ')}`);
      error.stage = 'live_validation';
      error.details = { errors: validation.errors };
      error.metrics = scrapeResult.metrics;
      throw error;
    }
    const artifacts = {
      raw: path.join(safeOutputDir, 'platinum-raw.json'),
      provenance: path.join(safeOutputDir, 'platinum-provenance.json'),
      validation: path.join(safeOutputDir, 'platinum-raw-validation.json'),
    };
    groupWriter([
      { path: artifacts.raw, contents: rawBytes },
      { path: artifacts.provenance, contents: provenanceBytes },
      { path: artifacts.validation, contents: canonicalJson(validation) },
    ]);
    return { passed: true, artifacts, validation };
  } catch (error) {
    if (scrapeResult?.metrics && !error.metrics) error.metrics = scrapeResult.metrics;
    const failurePath = path.join(safeOutputDir, 'platinum-failure.json');
    writeCreateOnly(failurePath, canonicalJson(safeFailure(error, generatedAt, runId)));
    error.failurePath = failurePath;
    throw error;
  }
}

async function main(argv = process.argv.slice(2), dependencies = {}) {
  const args = parseArgs(argv);
  const outputDir = path.resolve(required(args, 'output-dir'));
  assertSupportedOutputRoot(outputDir);
  const generatedAt = assertCanonicalIso(required(args, 'generated-at'), 'generated-at');
  const runId = args.get('run-id') || path.basename(outputDir);
  const validationProfile = args.get('validation-profile') || 'full-review';
  return runReview({ outputDir, generatedAt, runId, validationProfile, ...dependencies });
}

if (require.main === module) {
  main().then(result => {
    process.stdout.write(`${JSON.stringify({ verdict: 'PLATINUM_LIVE_REVIEW_READY', artifacts: result.artifacts, counts: result.validation.counts }, null, 2)}\n`);
  }).catch(error => {
    process.stderr.write(`Platinum review failed: ${sanitizeText(error.message)}${error.failurePath ? `; failure=${error.failurePath}` : ''}\n`);
    process.exitCode = 1;
  });
}

module.exports = { REVIEW_OUTPUT_ROOT, assertSupportedOutputRoot, fileMetadata, main, parseArgs, runReview };

#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  assertCanonicalIso,
  canonicalJson,
  sha256,
  writeCreateOnly,
} = require('./review-hardening');

const GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const RUN_ID_PATTERN = /^[1-9][0-9]{0,19}$/u;
const RUN_ATTEMPT_PATTERN = /^[1-9][0-9]{0,5}$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const WORKFLOW_PATH = '.github/workflows/scrape.yml';
const WORKFLOW_REF_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml@refs\/(?:heads|tags)\/[A-Za-z0-9._/-]+$/u;

function assertMatch(value, pattern, field) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${field} is invalid`);
  return value;
}

function artifact(bytes, file) {
  return { file, size: bytes.length, sha256: sha256(bytes) };
}

function createManagedPriceProvenance({
  generatedAt,
  githubRunId,
  githubRunAttempt,
  repository,
  workflowPath,
  workflowRef,
  producerCommit,
  catalogCommit,
  rawBytes,
  reviewProvenanceBytes,
  reviewValidationBytes,
  candidateBytes,
  validationBytes,
  catalogBytes,
  currentOverlayBytes,
}) {
  assertCanonicalIso(generatedAt, 'generatedAt');
  assertMatch(githubRunId, RUN_ID_PATTERN, 'githubRunId');
  assertMatch(githubRunAttempt, RUN_ATTEMPT_PATTERN, 'githubRunAttempt');
  assertMatch(repository, REPOSITORY_PATTERN, 'repository');
  if (workflowPath !== WORKFLOW_PATH) throw new Error('workflowPath is invalid');
  assertMatch(workflowRef, WORKFLOW_REF_PATTERN, 'workflowRef');
  assertMatch(producerCommit, GIT_COMMIT_PATTERN, 'producerCommit');
  assertMatch(catalogCommit, GIT_COMMIT_PATTERN, 'catalogCommit');

  let reviewProvenance;
  let candidate;
  let validation;
  try {
    reviewProvenance = JSON.parse(reviewProvenanceBytes.toString('utf8'));
    candidate = JSON.parse(candidateBytes.toString('utf8'));
    validation = JSON.parse(validationBytes.toString('utf8'));
  } catch { throw new Error('invalid_managed_provenance_input_json'); }
  if (candidate?.contract !== 'platinum-managed-price-candidate-v1' || candidate?.reviewOnly !== true) throw new Error('invalid_managed_candidate_contract');
  if (validation?.validator !== 'platinum-managed-price-validation-v1' || validation?.passed !== true) throw new Error('managed_validation_not_pass');
  if (candidate.generatedAt !== generatedAt || validation.generatedAt !== generatedAt) throw new Error('managed_generated_at_mismatch');
  if (candidate.catalogCommit !== catalogCommit || validation.inputs?.catalog?.commit !== catalogCommit) throw new Error('managed_catalog_commit_mismatch');
  if (validation.inputs?.raw?.sha256 !== sha256(rawBytes)) throw new Error('managed_raw_hash_mismatch');
  if (validation.inputs?.reviewProvenance?.sha256 !== sha256(reviewProvenanceBytes)) throw new Error('managed_review_provenance_hash_mismatch');
  if (validation.inputs?.reviewValidation?.sha256 !== sha256(reviewValidationBytes)) throw new Error('managed_review_validation_hash_mismatch');
  if (validation.inputs?.candidate?.sha256 !== sha256(candidateBytes)) throw new Error('managed_candidate_hash_mismatch');
  if (validation.inputs?.catalog?.sha256 !== sha256(catalogBytes)) throw new Error('managed_catalog_hash_mismatch');
  if (validation.inputs?.currentOverlay?.sha256 !== sha256(currentOverlayBytes)) throw new Error('managed_current_overlay_hash_mismatch');
  if (reviewProvenance?.raw?.sha256 !== sha256(rawBytes)) throw new Error('review_provenance_raw_hash_mismatch');
  if (candidate.managedContract?.total !== 90 || candidate.managedContract?.exactSafe !== 90
      || candidate.managedContract?.unresolved !== 0 || candidate.managedContract?.coverage !== '90/90') throw new Error('managed_candidate_coverage_mismatch');
  if (JSON.stringify(candidate.managedContract) !== JSON.stringify(validation.managedContract)) throw new Error('managed_contract_binding_mismatch');
  if (Object.values(candidate.remoteActions || {}).some(Boolean)
      || Object.values(validation.remoteActions || {}).some(Boolean)
      || Object.values(reviewProvenance.remoteActions || {}).some(Boolean)) throw new Error('forbidden_remote_action');

  return {
    schemaVersion: 1,
    contract: 'platinum-managed-price-provenance-v1',
    reviewOnly: true,
    generatedAt,
    github: {
      runId: githubRunId,
      runAttempt: githubRunAttempt,
      repository,
      workflowPath,
      workflowRef,
      producerCommit,
    },
    catalog: { commit: catalogCommit, ...artifact(catalogBytes, 'partner-foods.json') },
    currentOverlay: artifact(currentOverlayBytes, 'current-production-schema-v2-overlay.json'),
    artifacts: {
      raw: artifact(rawBytes, 'platinum-raw.json'),
      reviewProvenance: artifact(reviewProvenanceBytes, 'platinum-provenance.json'),
      reviewValidation: artifact(reviewValidationBytes, 'platinum-raw-validation.json'),
      candidate: artifact(candidateBytes, 'platinum-managed-price-candidate.json'),
      validation: artifact(validationBytes, 'platinum-managed-price-validation.json'),
    },
    managedContract: validation.managedContract,
    verdict: 'PASS',
    remoteActions: { publish: false, upload: false, deploy: false, gcs: false, currentJson: false, catalogImport: false, autoAdd: false },
  };
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
  const outputPath = path.join(outputDir, 'platinum-managed-price-provenance.json');
  const provenance = createManagedPriceProvenance({
    generatedAt: required(args, 'generated-at'),
    githubRunId: required(args, 'github-run-id'),
    githubRunAttempt: required(args, 'github-run-attempt'),
    repository: required(args, 'repository'),
    workflowPath: required(args, 'workflow-path'),
    workflowRef: required(args, 'workflow-ref'),
    producerCommit: required(args, 'producer-commit'),
    catalogCommit: required(args, 'catalog-commit'),
    rawBytes: readFile(required(args, 'raw')),
    reviewProvenanceBytes: readFile(required(args, 'review-provenance')),
    reviewValidationBytes: readFile(required(args, 'review-validation')),
    candidateBytes: readFile(required(args, 'candidate')),
    validationBytes: readFile(required(args, 'validation')),
    catalogBytes: readFile(required(args, 'catalog')),
    currentOverlayBytes: readFile(required(args, 'current-overlay')),
  });
  const bytes = Buffer.from(canonicalJson(provenance), 'utf8');
  (dependencies.writer || writeCreateOnly)(outputPath, bytes);
  return { provenance, bytes, artifact: outputPath };
}

if (require.main === module) {
  try {
    const result = main();
    process.stdout.write(`${JSON.stringify({ verdict: 'PLATINUM_MANAGED_PRICE_PROVENANCE_PASS', artifact: result.artifact, managedContract: result.provenance.managedContract }, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`Platinum managed-price provenance failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { WORKFLOW_PATH, createManagedPriceProvenance, main };

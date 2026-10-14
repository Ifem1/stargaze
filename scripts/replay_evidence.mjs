import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
};

const validTimestamp = (value) => typeof value === 'string'
  && /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,9})?Z$/.test(value);
const matchesPackage = (items, ecosystem, name) => Array.isArray(items) && items.some((item) =>
  item?.package?.ecosystem === ecosystem && item?.package?.name === name);
const sourceMetadata = (source, bytes, assessment, release) => {
  if (source.response_status !== 200 || bytes.length === 0 || bytes.length >= 12000) return { valid: false, metadata: {} };
  let body;
  try { body = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return { valid: false, metadata: {} }; }
  let data;
  try { data = JSON.parse(body); } catch { return { valid: false, metadata: {} }; }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { valid: false, metadata: {} };
  switch (source.kind) {
    case 'github_advisory': {
      const valid = data.ghsa_id === assessment.advisory_id
        && matchesPackage(data.vulnerabilities, assessment.ecosystem, assessment.package_name)
        && validTimestamp(data.published_at) && validTimestamp(data.updated_at);
      return { valid, metadata: valid ? { published_at: data.published_at, updated_at: data.updated_at } : {} };
    }
    case 'osv_advisory': {
      const valid = (data.id === assessment.advisory_id || data.aliases?.includes(assessment.advisory_id))
        && matchesPackage(data.affected, assessment.ecosystem, assessment.package_name)
        && (data.modified === undefined || validTimestamp(data.modified))
        && (data.published === undefined || validTimestamp(data.published));
      return { valid, metadata: valid ? { published: data.published ?? '', modified: data.modified ?? '', withdrawn: data.withdrawn ?? '' } : {} };
    }
    case 'npm_release': return { valid: data.name === release.package_name && data.version === release.version, metadata: {} };
    case 'github_commit': {
      const repository = release.repository_url.replace(/\.git$/, '').replace(/\/$/, '');
      return { valid: data.sha === release.commit_sha && data.html_url === `${repository}/commit/${release.commit_sha}`, metadata: {} };
    }
    default: return { valid: false, metadata: {} };
  }
};

const requireObject = (value, name) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object.`);
};

export async function verifyEvidenceReplay({ archive, assessment, release, attempt, baseDir = process.cwd() }) {
  requireObject(archive, 'Archive');
  requireObject(assessment, 'Assessment');
  requireObject(release, 'Release');
  requireObject(attempt, 'Attempt');
  if (!Array.isArray(attempt.manifest) || !Array.isArray(assessment.sources)) throw new Error('Assessment and attempt sources must be arrays.');
  if (!Number.isSafeInteger(attempt.sequence) || attempt.sequence < 1
      || attempt.assessment_id !== assessment.id || attempt.id !== `${assessment.id}/attempt-${attempt.sequence}`
      || attempt.sequence > assessment.attempt_count) throw new Error('Attempt identity does not match the supplied assessment history.');
  if (assessment.release_id !== release.id || release.id !== assessment.release_id
      || archive.advisory_id !== assessment.advisory_id || archive.ecosystem !== assessment.ecosystem
      || archive.package_name !== assessment.package_name || archive.revision !== assessment.revision) {
    throw new Error('Archive or release does not match the frozen assessment identity.');
  }
  if (attempt.manifest.length !== assessment.sources.length) throw new Error('Attempt source count does not match frozen source list.');
  if (typeof attempt.state !== 'string' || typeof attempt.failure_reason !== 'string'
      || typeof attempt.verdict !== 'string' || typeof attempt.revision_authenticated !== 'boolean'
      || typeof attempt.evidence_complete !== 'boolean' || !attempt.revision_metadata
      || typeof attempt.revision_metadata !== 'object' || Array.isArray(attempt.revision_metadata)) {
    throw new Error('Attempt record is missing immutable packet fields.');
  }
  if (attempt.sequence === assessment.attempt_count) {
    const current = ['state', 'verdict', 'packet_digest', 'evidence_complete', 'revision_authenticated'];
    if (current.some((key) => attempt[key] !== assessment[key])) throw new Error('Latest attempt does not match current assessment state.');
    if (canonical(attempt.revision_metadata) !== canonical(assessment.revision_metadata)
        || canonical(attempt.manifest) !== canonical(assessment.evidence_manifest)) {
      throw new Error('Latest attempt evidence does not match current assessment state.');
    }
  }

  let verifiedBytes = 0;
  let missingBodies = 0;
  for (let index = 0; index < attempt.manifest.length; index += 1) {
    const committed = attempt.manifest[index];
    const frozen = assessment.sources[index];
    if (committed.url !== frozen.url || committed.role !== frozen.role || committed.kind !== frozen.kind) {
      throw new Error(`Attempt source ${index + 1} does not match the frozen source identity.`);
    }
    const archived = archive.sources.find((source) => source.url === committed.url && source.role === committed.role
      && source.response_status === committed.response_status && source.body_sha256 === committed.body_sha256
      && source.body_bytes === committed.body_bytes && (source.kind === undefined || source.kind === committed.kind)
      && (source.metadata_identity_valid === undefined || source.metadata_identity_valid === committed.metadata_identity_valid)
      && (source.revision_metadata === undefined || canonical(source.revision_metadata) === canonical(committed.revision_metadata)));
    if (!archived) {
      throw new Error(`Archived response commitment does not match on-chain source ${committed.url}.`);
    }

    if (committed.body_bytes === 0 && committed.body_sha256 === '') {
      if (committed.response_status === 200 && committed.complete) throw new Error('A complete source cannot have an empty body commitment.');
      if (committed.metadata_identity_valid || committed.complete || committed.revision_authenticated
          || canonical(committed.revision_metadata) !== '{}') throw new Error('Missing body has inconsistent evidence metadata.');
      if (archived.archive_path || archived.body_present === true) throw new Error('Missing-body record unexpectedly references archived bytes.');
      missingBodies += 1;
      continue;
    }
    if (typeof archived.archive_path !== 'string' || archived.body_present === false) {
      throw new Error(`Archived response body is missing for ${committed.url}.`);
    }
    const bytes = await readFile(resolve(baseDir, archived.archive_path));
    if (sha256(bytes) !== committed.body_sha256 || bytes.length !== committed.body_bytes) {
      throw new Error(`Snapshot bytes fail SHA-256 verification for ${committed.url}.`);
    }
    verifiedBytes += bytes.length;
    const sourceResult = sourceMetadata(committed, bytes, assessment, release);
    if (sourceResult.valid !== committed.metadata_identity_valid) throw new Error(`Metadata identity result cannot be replayed for ${committed.url}.`);
    if (canonical(sourceResult.metadata) !== canonical(committed.revision_metadata)) throw new Error(`Provider metadata cannot be replayed for ${committed.url}.`);
    if (committed.role === 'PRIMARY' && attempt.revision_authenticated === true) {
      const provider = committed.kind === 'github_advisory' ? 'ghsa' : committed.kind === 'osv_advisory' ? 'osv' : '';
      if (!provider || assessment.revision !== `${provider}-sha256:${committed.body_sha256}` || committed.revision_authenticated !== true) {
        throw new Error('Authenticated primary revision does not match archived exact bytes.');
      }
    }
    if (committed.role === 'PRIMARY' && committed.revision_authenticated === true
        && attempt.revision_authenticated !== true) throw new Error('Unauthenticated attempt incorrectly marks its primary revision authenticated.');
  }

  const packet = { domain: 'STARGAZE_EVIDENCE_PACKET_V2', attempt_id: attempt.id,
    attempt_sequence: attempt.sequence, release,
    advisory: { id: assessment.advisory_id, revision: assessment.revision, ecosystem: assessment.ecosystem,
      package: assessment.package_name, policy: assessment.policy_version, metadata: attempt.revision_metadata },
    sources: attempt.manifest, complete: attempt.evidence_complete,
    revision_authenticated: attempt.revision_authenticated, state: attempt.state,
    failure_reason: attempt.failure_reason, verdict: attempt.verdict };
  const digest = sha256(Buffer.from(canonical(packet), 'utf8'));
  if (digest !== attempt.packet_digest) throw new Error('Recomputed packet digest does not match the immutable attempt commitment.');
  if (attempt.sequence === assessment.attempt_count && digest !== assessment.packet_digest) {
    throw new Error('Latest attempt digest does not match the current assessment commitment.');
  }
  return { result: 'MATCH', assessment_id: assessment.id, attempt_id: attempt.id,
    revision: assessment.revision, packet_digest: digest, source_count: attempt.manifest.length,
    archived_bytes_verified: verifiedBytes, missing_body_count: missingBodies,
    is_latest_attempt: attempt.sequence === assessment.attempt_count };
}

async function main() {
  const [manifestFile, assessmentFile, releaseFile, attemptFile] = process.argv.slice(2);
  if (!manifestFile || !assessmentFile || !releaseFile || !attemptFile) {
    throw new Error('Usage: node scripts/replay_evidence.mjs <archive-manifest.json> <assessment.json> <release.json> <attempt.json>');
  }
  const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
  const result = await verifyEvidenceReplay({ archive: await load(manifestFile), assessment: await load(assessmentFile),
    release: await load(releaseFile), attempt: await load(attemptFile), baseDir: process.cwd() });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => { process.stderr.write(`REPLAY_FAILED ${error?.stack ?? error}\n`); process.exitCode = 1; });
}

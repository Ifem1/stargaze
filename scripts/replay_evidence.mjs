import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const [manifestFile, assessmentFile, releaseFile, attemptFile] = process.argv.slice(2);
if (!manifestFile || !assessmentFile || !releaseFile || !attemptFile) {
  throw new Error('Usage: node scripts/replay_evidence.mjs <archive-manifest.json> <assessment.json> <release.json> <attempt.json>');
}
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const archive = await load(manifestFile);
const assessment = await load(assessmentFile);
const release = await load(releaseFile);
const attempt = await load(attemptFile);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
};
const validTimestamp = (value) => typeof value === 'string'
  && /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,9})?Z$/.test(value);
const matchesPackage = (items, ecosystem, name) => Array.isArray(items) && items.some((item) =>
  item?.package?.ecosystem === ecosystem && item?.package?.name === name);
const sourceMetadata = (source, body, assessment, release) => {
  let data;
  try { data = JSON.parse(body.toString('utf8')); } catch { return { valid: false, metadata: {} }; }
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

if (attempt.assessment_id !== assessment.id || attempt.sequence < 1
    || attempt.id !== `${assessment.id}/attempt-${attempt.sequence}`) throw new Error('Attempt identity does not match the supplied assessment.');
if (archive.advisory_id !== assessment.advisory_id || archive.ecosystem !== assessment.ecosystem
    || archive.package_name !== assessment.package_name || archive.revision !== assessment.revision) {
  throw new Error('Archive manifest does not match the frozen assessment identity.');
}
if (attempt.manifest.length !== assessment.sources.length) throw new Error('Attempt source count does not match frozen source list.');
for (const committed of attempt.manifest) {
  const archived = archive.sources.find((source) => source.url === committed.url && source.role === committed.role);
  if (!archived || archived.role !== committed.role || archived.body_sha256 !== committed.body_sha256
      || archived.response_status !== committed.response_status || archived.body_bytes !== committed.body_bytes) {
    throw new Error(`Archived response commitment does not match on-chain source ${committed.url}.`);
  }
  const bytes = await readFile(resolve(archived.archive_path));
  if (sha256(bytes) !== committed.body_sha256 || bytes.length !== committed.body_bytes) throw new Error(`Snapshot bytes fail SHA-256 verification for ${committed.url}.`);
  const sourceResult = sourceMetadata(committed, bytes, assessment, release);
  const valid = committed.response_status === 200 && sourceResult.valid;
  if (valid !== committed.metadata_identity_valid) throw new Error(`Metadata identity result cannot be replayed for ${committed.url}.`);
  if (canonical(sourceResult.metadata) !== canonical(committed.revision_metadata)) throw new Error(`Provider metadata cannot be replayed for ${committed.url}.`);
  const primary = committed.role === 'PRIMARY';
  const expectedRevision = `${committed.kind === 'github_advisory' ? 'ghsa' : 'osv'}-sha256:${committed.body_sha256}`;
  if (primary && attempt.revision_authenticated === true
      && (assessment.revision !== expectedRevision || committed.revision_authenticated !== true)) throw new Error('Authenticated primary revision does not match archived exact bytes.');
  if (primary && attempt.revision_authenticated !== true && committed.revision_authenticated === true) throw new Error('Unauthenticated attempt incorrectly marks its primary revision authenticated.');
}
const packet = { domain: 'STARGAZE_EVIDENCE_PACKET_V2', attempt_id: attempt.id,
  attempt_sequence: attempt.sequence, release,
  advisory: { id: assessment.advisory_id, revision: assessment.revision, ecosystem: assessment.ecosystem,
    package: assessment.package_name, policy: assessment.policy_version, metadata: assessment.revision_metadata },
  sources: attempt.manifest, complete: attempt.evidence_complete,
  revision_authenticated: attempt.revision_authenticated, state: attempt.state,
  failure_reason: attempt.failure_reason, verdict: attempt.verdict };
const replayedDigest = sha256(Buffer.from(canonical(packet), 'utf8'));
if (replayedDigest !== attempt.packet_digest || replayedDigest !== assessment.packet_digest) throw new Error('Recomputed packet digest does not match finalized assessment commitments.');
process.stdout.write(`${JSON.stringify({ result: 'MATCH', assessment_id: assessment.id, attempt_id: attempt.id,
  revision: assessment.revision, packet_digest: replayedDigest, source_count: attempt.manifest.length,
  archived_bytes_verified: attempt.manifest.reduce((total, source) => total + source.body_bytes, 0) }, null, 2)}\n`);

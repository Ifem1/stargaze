import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { canonical, sha256, verifyEvidenceReplay } from '../scripts/replay_evidence.mjs';

const tempDirs = [];
const primaryUrl = 'https://api.github.com/advisories/GHSA-r5fr-rjxr-66jc';
const preflight = JSON.parse(await readFile('evidence/manifests/ghsa-lodash-preflight-20261014.json', 'utf8'));
const body = await readFile(preflight.sources[0].archive_path);
const bodyHash = sha256(body);
const release = { id: 'rel-fixture', project: 'stargaze-replay-tests', repository_url: 'https://github.com/lodash/lodash',
  owner: '0x0000000000000000000000000000000000000001', registered_by: '0x0000000000000000000000000000000000000001',
  version: '4.18.0', commit_sha: '0'.repeat(40), artifact_digest: '1'.repeat(64), ecosystem: 'npm', package_name: 'lodash',
  manifest_digest: '2'.repeat(64), predecessor_id: '', sequence: 1, status: 'SEALED' };
const assessmentBase = { id: 'asm-replay', release_id: release.id, advisory_id: preflight.advisory_id,
  revision: preflight.revision, title: 'Archived authoritative test advisory', ecosystem: 'npm', package_name: 'lodash',
  policy_version: 'replay-test-v1', registered_by: release.owner,
  sources: [{ url: primaryUrl, role: 'PRIMARY', host: 'api.github.com', kind: 'github_advisory', source_epoch: 1 }],
  state: 'DECIDED', verdict: 'NOT_AFFECTED', authorization: 'AUTHORIZED_FOR_THIS_ADVISORY', packet_digest: '',
  eligible: true, revision_authenticated: true, revision_metadata: { published_at: '2026-04-01T23:51:12Z', updated_at: '2026-04-01T23:51:13Z' },
  evidence_complete: true, evidence_manifest: [], attempt_count: 3, trust_epoch_valid: true, sequence: 1 };

function manifestEntry({ status, bytes, missing = false }) {
  return { url: primaryUrl, role: 'PRIMARY', kind: 'github_advisory', response_status: status,
    body_sha256: bytes.length ? sha256(bytes) : '', body_bytes: bytes.length,
    metadata_identity_valid: status === 200 && bytes.equals(body), complete: status === 200 && bytes.equals(body),
    revision_authenticated: status === 200 && bytes.equals(body),
    revision_metadata: status === 200 && bytes.equals(body) ? assessmentBase.revision_metadata : {},
    ...(missing ? {} : { archive_path: `evidence-replay-tests/${sha256(bytes)}.bin` }) };
}

function attemptFor(sequence, source, state, failureReason, verdict, revisionMetadata) {
  const attempt = { id: `${assessmentBase.id}/attempt-${sequence}`, assessment_id: assessmentBase.id, sequence,
    state, failure_reason: failureReason, manifest: [source], revision_authenticated: source.revision_authenticated,
    revision_metadata: revisionMetadata, verdict, evidence_complete: source.complete };
  const packet = { domain: 'STARGAZE_EVIDENCE_PACKET_V2', attempt_id: attempt.id, attempt_sequence: sequence,
    release, advisory: { id: assessmentBase.advisory_id, revision: assessmentBase.revision, ecosystem: 'npm',
      package: 'lodash', policy: 'replay-test-v1', metadata: revisionMetadata }, sources: attempt.manifest,
    complete: attempt.evidence_complete, revision_authenticated: attempt.revision_authenticated,
    state, failure_reason: failureReason, verdict };
  attempt.packet_digest = createHash('sha256').update(canonical(packet)).digest('hex');
  return attempt;
}

const setup = async () => {
  const directory = await mkdtemp(join(tmpdir(), 'stargaze-replay-'));
  tempDirs.push(directory);
  const unavailableBody = Buffer.from('upstream temporarily unavailable');
  const attempt1Source = manifestEntry({ status: 503, bytes: unavailableBody });
  const attempt2Source = manifestEntry({ status: 0, bytes: Buffer.alloc(0), missing: true });
  const attempt3Source = manifestEntry({ status: 200, bytes: body });
  const attempt1 = attemptFor(1, attempt1Source, 'RETRYABLE_FAILURE', 'HTTP_UNAVAILABLE_OR_INCOMPLETE_SOURCE', '', {});
  const attempt2 = attemptFor(2, attempt2Source, 'RETRYABLE_FAILURE', 'TEMPORARY_SOURCE_RETRIEVAL_FAILURE', '', {});
  const attempt3 = attemptFor(3, attempt3Source, 'DECIDED', '', 'NOT_AFFECTED', assessmentBase.revision_metadata);
  const archive = { domain: 'STARGAZE_ADVISORY_ARCHIVE_V1', provider: 'github', advisory_id: assessmentBase.advisory_id,
    ecosystem: 'npm', package_name: 'lodash', revision: assessmentBase.revision, primary_url: primaryUrl,
    sources: [attempt1Source, attempt2Source, attempt3Source] };
  await mkdir(resolve(directory, 'evidence-replay-tests'), { recursive: true });
  await writeFile(resolve(directory, attempt1Source.archive_path), unavailableBody);
  await writeFile(resolve(directory, attempt3Source.archive_path), body);
  const assessment = { ...assessmentBase, packet_digest: attempt3.packet_digest, evidence_manifest: attempt3.manifest };
  return { directory, archive, assessment, release, attempt1, attempt2, attempt3,
    unavailableBody, attempt1Source, attempt2Source, attempt3Source };
};

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('immutable historical evidence replay', () => {
  it('replays an earlier failed attempt without comparing it to the latest digest', async () => {
    const fixture = await setup();
    const result = await verifyEvidenceReplay({ ...fixture, attempt: fixture.attempt1, baseDir: fixture.directory });
    expect(result).toMatchObject({ result: 'MATCH', attempt_id: 'asm-replay/attempt-1', is_latest_attempt: false,
      missing_body_count: 0, archived_bytes_verified: fixture.unavailableBody.length });
    expect(result.packet_digest).toBe(fixture.attempt1.packet_digest);
    expect(result.packet_digest).not.toBe(fixture.assessment.packet_digest);
  });

  it('replays an empty unavailable-source record without inventing response bytes', async () => {
    const fixture = await setup();
    const result = await verifyEvidenceReplay({ ...fixture, attempt: fixture.attempt2, baseDir: fixture.directory });
    expect(result).toMatchObject({ result: 'MATCH', attempt_id: 'asm-replay/attempt-2', is_latest_attempt: false,
      missing_body_count: 1, archived_bytes_verified: 0 });
  });

  it('matches the latest recovered successful attempt to the assessment digest', async () => {
    const fixture = await setup();
    const result = await verifyEvidenceReplay({ ...fixture, attempt: fixture.attempt3, baseDir: fixture.directory });
    expect(result).toMatchObject({ result: 'MATCH', attempt_id: 'asm-replay/attempt-3', is_latest_attempt: true,
      packet_digest: fixture.assessment.packet_digest, missing_body_count: 0, archived_bytes_verified: body.length });
  });

  it('rejects changed archive commitments and modified source bytes', async () => {
    const fixture = await setup();
    const changedArchive = structuredClone(fixture.archive);
    changedArchive.sources[2].metadata_identity_valid = false;
    await expect(verifyEvidenceReplay({ ...fixture, archive: changedArchive, attempt: fixture.attempt3, baseDir: fixture.directory }))
      .rejects.toThrow('Archived response commitment');
    await writeFile(resolve(fixture.directory, fixture.attempt3Source.archive_path), Buffer.from('tampered'));
    await expect(verifyEvidenceReplay({ ...fixture, attempt: fixture.attempt3, baseDir: fixture.directory }))
      .rejects.toThrow('SHA-256 verification');
  });

  it('rejects missing snapshots for bodyful HTTP failures', async () => {
    const fixture = await setup();
    const withoutPath = structuredClone(fixture.archive);
    delete withoutPath.sources[0].archive_path;
    await expect(verifyEvidenceReplay({ ...fixture, archive: withoutPath, attempt: fixture.attempt1, baseDir: fixture.directory }))
      .rejects.toThrow('Archived response body is missing');
  });

  it('rejects mismatched assessment, attempt, source, or packet identity', async () => {
    const fixture = await setup();
    await expect(verifyEvidenceReplay({ ...fixture, assessment: { ...fixture.assessment, id: 'asm-other' },
      attempt: fixture.attempt1, baseDir: fixture.directory })).rejects.toThrow('Attempt identity');
    await expect(verifyEvidenceReplay({ ...fixture, attempt: { ...fixture.attempt1, id: 'asm-wrong/attempt-1' },
      baseDir: fixture.directory })).rejects.toThrow('Attempt identity');
    await expect(verifyEvidenceReplay({ ...fixture, attempt: { ...fixture.attempt1, failure_reason: 'tampered' },
      baseDir: fixture.directory })).rejects.toThrow('immutable attempt commitment');
  });

  it('verifies every attempt after later retries were appended', async () => {
    const fixture = await setup();
    for (const attempt of [fixture.attempt1, fixture.attempt2, fixture.attempt3]) {
      expect((await verifyEvidenceReplay({ ...fixture, attempt, baseDir: fixture.directory })).result).toBe('MATCH');
    }
  });
});

import { describe, expect, it } from 'vitest';
import { confirmAssessmentAttempt, confirmAssessmentRecord, confirmReleaseRecord } from './record-confirmation';

const releaseExpected = { project: 'acme/widget', repository: 'https://github.com/acme/widget', owner: '0xAbC', version: '2.0.0', commit: 'a'.repeat(40), artifact: 'b'.repeat(64), ecosystem: 'npm', package: '@acme/widget', manifest: 'c'.repeat(64), predecessor: 'rel-1' };
const sources = [{ url: 'https://api.github.com/advisories/GHSA-2222-3333-4444', role: 'PRIMARY' as const }];

describe('exact finalized record confirmation', () => {
  it('confirms the submitted release identity and returns its exact on-chain ID', () => {
    const id = confirmReleaseRecord({ id: 'rel-42', ...releaseExpected, repository_url: releaseExpected.repository, owner: '0xabc', commit_sha: releaseExpected.commit, artifact_digest: releaseExpected.artifact, package_name: releaseExpected.package, manifest_digest: releaseExpected.manifest, predecessor_id: releaseExpected.predecessor }, releaseExpected);
    expect(id).toBe('rel-42');
  });

  it('rejects any release identity mismatch instead of inferring success from a counter', () => {
    expect(() => confirmReleaseRecord({ id: 'rel-42', ...releaseExpected, repository_url: releaseExpected.repository, owner: '0xabc', commit_sha: releaseExpected.commit, artifact_digest: 'd'.repeat(64), package_name: releaseExpected.package, manifest_digest: releaseExpected.manifest, predecessor_id: releaseExpected.predecessor }, releaseExpected)).toThrow('exactly match');
  });

  it('confirms the exact assessment key, requester and ordered evidence commitment', () => {
    const id = confirmAssessmentRecord({ id: 'asm-11', release_id: 'rel-42', advisory_id: 'GHSA-2222-3333-4444', revision: 'rev-1', title: 'Advisory', ecosystem: 'npm', package_name: '@acme/widget', policy_version: 'policy-1', registered_by: '0xabc', sources }, { releaseId: 'rel-42', advisoryId: 'GHSA-2222-3333-4444', revision: 'rev-1', title: 'Advisory', ecosystem: 'npm', package: '@acme/widget', policy: 'policy-1', requester: '0xAbC', sources });
    expect(id).toBe('asm-11');
  });

  it('rejects assessment confirmation when requester or frozen evidence differs', () => {
    const record = { id: 'asm-11', release_id: 'rel-42', advisory_id: 'GHSA-2222-3333-4444', revision: 'rev-1', title: 'Advisory', ecosystem: 'npm', package_name: '@acme/widget', policy_version: 'policy-1', registered_by: '0xdef', sources };
    const expected = { releaseId: 'rel-42', advisoryId: 'GHSA-2222-3333-4444', revision: 'rev-1', title: 'Advisory', ecosystem: 'npm', package: '@acme/widget', policy: 'policy-1', requester: '0xAbC', sources };
    expect(() => confirmAssessmentRecord(record, expected)).toThrow('exactly match');
    expect(() => confirmAssessmentRecord({ ...record, registered_by: '0xabc', sources: [] }, expected)).toThrow('exactly match');
  });
});

describe('assessment attempt confirmation', () => {
  it('confirms exact assessment identity and append-only sequence', () => {
    expect(confirmAssessmentAttempt({ id: 'asm-7', attempt_count: 2, state: 'DECIDED', packet_digest: 'd'.repeat(64) },
      { id: 'asm-7/attempt-2', assessment_id: 'asm-7', sequence: 2, state: 'DECIDED', packet_digest: 'd'.repeat(64) },
      { assessmentId: 'asm-7', sequence: 2 })).toBe('asm-7/attempt-2');
  });
  it('rejects unrelated global records, sequences, or packet commitments', () => {
    expect(() => confirmAssessmentAttempt({ id: 'asm-7', attempt_count: 2, state: 'DECIDED', packet_digest: 'd'.repeat(64) },
      { id: 'asm-8/attempt-2', assessment_id: 'asm-8', sequence: 2, state: 'DECIDED', packet_digest: 'd'.repeat(64) },
      { assessmentId: 'asm-7', sequence: 2 })).toThrow('exact assessment');
  });
});

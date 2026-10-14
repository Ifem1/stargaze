import { describe, expect, it, vi } from 'vitest';
import { authorizeThenExecute, evaluateFinalPolicy, validatePolicy } from '../scripts/gate';

const hash = 'a'.repeat(64);
const packet = 'b'.repeat(64);
const policy = { chain_id: 61999, contract_address: `0x${'1'.repeat(40)}`, release_id: 'rel-1', artifact_digest: hash,
  required: [{ advisory_id: 'GHSA-1', revision: 'ghsa-sha256:' + 'c'.repeat(64) }] };
const release = { id: 'rel-1', artifact_digest: hash, status: 'SEALED' };
const assessment = { id: 'asm-1', release_id: 'rel-1', advisory_id: policy.required[0].advisory_id,
  revision: policy.required[0].revision, state: 'DECIDED', verdict: 'NOT_AFFECTED', eligible: true,
  packet_digest: packet, revision_authenticated: true, evidence_complete: true };
const check = { advisory_id: assessment.advisory_id, revision: assessment.revision, assessment_id: assessment.id,
  verdict: 'NOT_AFFECTED', packet_digest: packet, revision_authenticated: true, evidence_complete: true, trust_epoch_valid: true };
const reader = (a: unknown = assessment, r: unknown = release, g: unknown = { status: 'AUTHORIZED_FOR_POLICY_SET',
  release_id: 'rel-1', artifact_digest: hash, checks: [check] }) => ({ getRelease: vi.fn().mockResolvedValue(r),
  getAssessmentByIdentity: vi.fn().mockResolvedValue(a), authorizationForRelease: vi.fn().mockResolvedValue(g) });

describe('fail-closed indexed release gate', () => {
  it('authorizes an exact indexed and on-chain cleared policy set', async () => {
    const source = reader();
    const result = await evaluateFinalPolicy(policy, source);
    expect(result.decision).toBe('AUTHORIZED_FOR_POLICY_SET');
    expect(result.policy_digest).toMatch(/^[a-f0-9]{64}$/);
    expect(source.authorizationForRelease).toHaveBeenCalledOnce();
    expect(source.getAssessmentByIdentity).toHaveBeenCalledOnce();
  });
  it.each(['AFFECTED', 'CONDITIONAL', 'INSUFFICIENT_EVIDENCE'])('denies assessment verdict %s', async (verdict) => {
    await expect(evaluateFinalPolicy(policy, reader({ ...assessment, verdict, eligible: false }, release,
      { status: 'HOLD', release_id: 'rel-1', artifact_digest: hash, reason: 'REQUIRED_REVISION_NOT_CLEARED', checks: [] }))).rejects.toThrow('DENY');
  });
  it('denies empty, duplicate, malformed, or wrong-chain policies', () => {
    expect(() => validatePolicy({ ...policy, required: [] })).toThrow('DENY');
    expect(() => validatePolicy({ ...policy, chain_id: 61997 })).toThrow('61999');
    expect(() => validatePolicy({ ...policy, required: [policy.required[0], policy.required[0]] })).toThrow('duplicate');
    expect(() => validatePolicy({ ...policy, required: [{}] })).toThrow('malformed');
  });
  it('denies wrong artifact, pending or malformed release reads', async () => {
    await expect(evaluateFinalPolicy(policy, reader(assessment, { ...release, artifact_digest: 'd'.repeat(64) }))).rejects.toThrow('mismatch');
    await expect(evaluateFinalPolicy(policy, reader(assessment, null))).rejects.toThrow('release read failed');
  });
  it.each([
    ['wrong indexed identity', { ...assessment, revision: 'other' }],
    ['wrong attempt', { ...assessment, state: 'RETRYABLE_FAILURE' }],
    ['unauthenticated revision', { ...assessment, revision_authenticated: false }],
    ['incomplete evidence', { ...assessment, evidence_complete: false }],
    ['changed packet', { ...assessment, packet_digest: 'e'.repeat(64) }],
  ])('denies %s after authoritative gate response', async (_label, row) => {
    await expect(evaluateFinalPolicy(policy, reader(row))).rejects.toThrow('DENY');
  });
  it('denies malformed indexed gate data and duplicate or reordered checks', async () => {
    await expect(evaluateFinalPolicy(policy, reader(assessment, release, null))).rejects.toThrow('malformed');
    await expect(evaluateFinalPolicy(policy, reader(assessment, release, { status: 'HOLD', release_id: 'rel-1', artifact_digest: hash, checks: [] }))).rejects.toThrow('did not authorize');
    await expect(evaluateFinalPolicy(policy, reader(assessment, release, { status: 'AUTHORIZED_FOR_POLICY_SET', release_id: 'rel-1', artifact_digest: hash, checks: [{ ...check, trust_epoch_valid: false }] }))).rejects.toThrow('malformed indexed');
  });
  it('reads multiple exact advisory identities and denies if any requirement is missing', async () => {
    const second = { advisory_id: 'GHSA-2', revision: 'osv-sha256:' + 'f'.repeat(64) };
    const multiPolicy = { ...policy, required: [...policy.required, second] };
    const secondAssessment = { ...assessment, id: 'asm-2', advisory_id: second.advisory_id, revision: second.revision, packet_digest: '3'.repeat(64) };
    const secondCheck = { ...check, advisory_id: second.advisory_id, revision: second.revision, assessment_id: 'asm-2', packet_digest: '3'.repeat(64) };
    const source = reader([assessment, secondAssessment], release, { status: 'AUTHORIZED_FOR_POLICY_SET', release_id: 'rel-1', artifact_digest: hash, checks: [check, secondCheck] });
    source.getAssessmentByIdentity.mockImplementation(async (_release, advisoryId) => advisoryId === 'GHSA-1' ? assessment : secondAssessment);
    expect((await evaluateFinalPolicy(multiPolicy, source)).verified).toHaveLength(2);
    expect(source.getAssessmentByIdentity).toHaveBeenCalledTimes(2);
    source.getAssessmentByIdentity.mockImplementation(async () => ({}));
    await expect(evaluateFinalPolicy(multiPolicy, source)).rejects.toThrow('not finally cleared');
  });
  it('does not allow RPC/indexed read failures to authorize', async () => {
    const broken = reader();
    broken.authorizationForRelease.mockRejectedValue(new Error('RPC offline'));
    await expect(evaluateFinalPolicy(policy, broken)).rejects.toThrow('RPC offline');
  });
  it('never starts the protected command when any authoritative or record check fails', async () => {
    const execute = vi.fn().mockResolvedValue(0);
    await expect(authorizeThenExecute(policy, reader(assessment, release, { status: 'HOLD' }), execute)).rejects.toThrow('DENY');
    await expect(authorizeThenExecute(policy, reader(null), execute)).rejects.toThrow('DENY');
    expect(execute).not.toHaveBeenCalled();
  });
});

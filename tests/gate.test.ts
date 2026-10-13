import { describe, expect, it, vi } from 'vitest';
import { authorizeThenExecute, evaluateFinalPolicy, validatePolicy } from '../scripts/gate';

const hash = 'a'.repeat(64);
const policy = { chain_id: 61999, contract_address: `0x${'1'.repeat(40)}`, release_id: 'rel-1', artifact_digest: hash,
  required: [{ advisory_id: 'GHSA-1', revision: 'r1' }] };
const release = { id: 'rel-1', artifact_digest: hash, status: 'SEALED' };
const assessment = { id: 'asm-1', release_id: 'rel-1', advisory_id: 'GHSA-1', revision: 'r1', state: 'DECIDED',
  verdict: 'NOT_AFFECTED', eligible: true, packet_digest: 'b'.repeat(64) };
const reader = (a: unknown = assessment, r: unknown = release) => ({ getRelease: vi.fn().mockResolvedValue(r),
  getAssessment: vi.fn().mockResolvedValue(a), listAssessments: vi.fn().mockResolvedValue([a]) });

describe('fail-closed release gate', () => {
  it('authorizes only an explicit complete revision set and binds policy digest', async () => {
    const result = await evaluateFinalPolicy(policy, reader());
    expect(result.decision).toBe('AUTHORIZED_FOR_POLICY_SET');
    expect(result.policy_digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it.each(['AFFECTED', 'CONDITIONAL', 'INSUFFICIENT_EVIDENCE'])('denies %s', async (verdict) => {
    await expect(evaluateFinalPolicy(policy, reader({ ...assessment, verdict }))).rejects.toThrow('DENY');
  });
  it('denies an empty policy', () => expect(() => validatePolicy({ ...policy, required: [] })).toThrow('DENY'));
  it('denies wrong chain, artifact, pending and malformed reads', async () => {
    await expect(evaluateFinalPolicy({ ...policy, chain_id: 61997 }, reader())).rejects.toThrow('61999');
    await expect(evaluateFinalPolicy(policy, reader(assessment, { ...release, artifact_digest: 'c'.repeat(64) }))).rejects.toThrow('mismatch');
    await expect(evaluateFinalPolicy(policy, reader({ ...assessment, state: 'OPEN' }))).rejects.toThrow('not finally cleared');
    await expect(evaluateFinalPolicy(policy, reader(null))).rejects.toThrow('not finally cleared');
  });
  it('does not allow registry read failures to authorize', async () => {
    const broken = { getRelease: vi.fn().mockResolvedValue(release), getAssessment: vi.fn(), listAssessments: vi.fn().mockRejectedValue(new Error('RPC offline')) };
    await expect(evaluateFinalPolicy(policy, broken)).rejects.toThrow('RPC offline');
  });
  it.each([
    ['affected', { ...assessment, verdict: 'AFFECTED' }, release],
    ['malformed release', assessment, null],
  ])('never starts the protected command on %s', async (_label, a, r) => {
    const execute = vi.fn().mockResolvedValue(0);
    await expect(authorizeThenExecute(policy, reader(a, r), execute)).rejects.toThrow('DENY');
    expect(execute).not.toHaveBeenCalled();
  });
});

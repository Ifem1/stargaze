import { describe, expect, it, vi } from 'vitest';
import { authorizeThenExecute, evaluateFinalPolicy, validatePolicy } from '../scripts/gate';

const hash = 'a'.repeat(64);
const packet = 'b'.repeat(64);
const policy = { chain_id: 61999, contract_address: `0x${'1'.repeat(40)}`, release_id: 'rel-1', artifact_digest: hash,
  required: [{ advisory_id: 'GHSA-1', revision: 'ghsa-sha256:' + 'c'.repeat(64) }] };
const release = { id: 'rel-1', artifact_digest: hash, status: 'SEALED' };
const check = { advisory_id: policy.required[0].advisory_id, revision: policy.required[0].revision,
  assessment_id: 'asm-1', verdict: 'NOT_AFFECTED', packet_digest: packet, revision_authenticated: true,
  evidence_complete: true, trust_epoch_valid: true };
const approved = { status: 'AUTHORIZED_FOR_POLICY_SET', release_id: 'rel-1', artifact_digest: hash, checks: [check] };
const reader = (r: unknown = release, g: unknown = approved) => ({ getRelease: vi.fn().mockResolvedValue(r),
  authorizationForRelease: vi.fn().mockResolvedValue(g) });

describe('fail-closed compact atomic release gate', () => {
  it('authorizes the exact contract policy response and sends a 32-byte identity commitment', async () => {
    const source = reader();
    const result = await evaluateFinalPolicy(policy, source);
    expect(result.decision).toBe('AUTHORIZED_FOR_POLICY_SET');
    expect(result.policy_digest).toMatch(/^[a-f0-9]{64}$/);
    expect(source.authorizationForRelease).toHaveBeenCalledOnce();
    const commitments = source.authorizationForRelease.mock.calls[0][1] as Uint8Array;
    expect(commitments).toBeInstanceOf(Uint8Array);
    expect(commitments).toHaveLength(32);
  });
  it.each([
    ['wrong advisory identity', { ...check, advisory_id: 'GHSA-other' }],
    ['wrong revision', { ...check, revision: 'other' }],
    ['missing assessment identity', { ...check, assessment_id: '' }],
    ['affected verdict', { ...check, verdict: 'AFFECTED' }],
    ['unauthenticated revision', { ...check, revision_authenticated: false }],
    ['incomplete evidence', { ...check, evidence_complete: false }],
    ['invalid trust epoch', { ...check, trust_epoch_valid: false }],
    ['malformed packet commitment', { ...check, packet_digest: 'bad' }],
  ])('denies a contract check with %s', async (_label, malformedCheck) => {
    await expect(evaluateFinalPolicy(policy, reader(release, { ...approved, checks: [malformedCheck] }))).rejects.toThrow('DENY');
  });
  it('denies empty, duplicate, malformed, wrong-chain, and over-bound policies', () => {
    expect(() => validatePolicy({ ...policy, required: [] })).toThrow('DENY');
    expect(() => validatePolicy({ ...policy, chain_id: 61997 })).toThrow('61999');
    expect(() => validatePolicy({ ...policy, required: [policy.required[0], policy.required[0]] })).toThrow('duplicate');
    expect(() => validatePolicy({ ...policy, required: [{}] })).toThrow('malformed');
    expect(() => validatePolicy({ ...policy, required: Array.from({ length: 6 }, (_, i) => ({ advisory_id: `GHSA-${i}`, revision: `r${i}` })) })).toThrow('one and five');
  });
  it('denies wrong artifact and malformed release reads', async () => {
    await expect(evaluateFinalPolicy(policy, reader({ ...release, artifact_digest: 'd'.repeat(64) }))).rejects.toThrow('mismatch');
    await expect(evaluateFinalPolicy(policy, reader(null))).rejects.toThrow('release read failed');
  });
  it('denies HOLD, missing, reordered, or duplicate contract checks', async () => {
    await expect(evaluateFinalPolicy(policy, reader(release, null))).rejects.toThrow('malformed');
    await expect(evaluateFinalPolicy(policy, reader(release, { status: 'HOLD', checks: [] }))).rejects.toThrow('did not authorize');
    await expect(evaluateFinalPolicy(policy, reader(release, { ...approved, checks: [] }))).rejects.toThrow('did not authorize');
    await expect(evaluateFinalPolicy(policy, reader(release, { ...approved, checks: [check, check] }))).rejects.toThrow('did not authorize');
  });
  it('authorizes two exact advisory identities from one atomic response and holds when either is missing', async () => {
    const second = { advisory_id: 'GHSA-2', revision: 'osv-sha256:' + 'f'.repeat(64) };
    const multiPolicy = { ...policy, required: [...policy.required, second] };
    const secondCheck = { ...check, advisory_id: second.advisory_id, revision: second.revision,
      assessment_id: 'asm-2', packet_digest: '3'.repeat(64) };
    const source = reader(release, { ...approved, checks: [check, secondCheck] });
    expect((await evaluateFinalPolicy(multiPolicy, source)).verified).toHaveLength(2);
    expect(source.authorizationForRelease.mock.calls[0][1]).toHaveLength(64);
    source.authorizationForRelease.mockResolvedValue({ status: 'HOLD', checks: [] });
    await expect(evaluateFinalPolicy(multiPolicy, source)).rejects.toThrow('did not authorize');
  });
  it('sends exactly five packed commitments when the supported maximum is used', async () => {
    const required = Array.from({ length: 5 }, (_, index) => ({ advisory_id: `GHSA-${index}`,
      revision: `ghsa-sha256:${String(index + 1).repeat(64)}` }));
    const fivePolicy = { ...policy, required };
    const checks = required.map((item, index) => ({ ...check, ...item, assessment_id: `asm-${index + 1}` }));
    const source = reader(release, { ...approved, checks });
    expect((await evaluateFinalPolicy(fivePolicy, source)).verified).toHaveLength(5);
    expect(source.authorizationForRelease.mock.calls[0][1]).toHaveLength(160);
  });
  it('fails closed when the RPC read fails', async () => {
    const broken = reader();
    broken.authorizationForRelease.mockRejectedValue(new Error('RPC offline'));
    await expect(evaluateFinalPolicy(policy, broken)).rejects.toThrow('RPC offline');
  });
  it('never starts the protected command when authorization is missing', async () => {
    const execute = vi.fn().mockResolvedValue(0);
    await expect(authorizeThenExecute(policy, reader(release, { status: 'HOLD' }), execute)).rejects.toThrow('DENY');
    await expect(authorizeThenExecute(policy, reader(null), execute)).rejects.toThrow('DENY');
    expect(execute).not.toHaveBeenCalled();
  });
});

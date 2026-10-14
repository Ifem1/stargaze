import { describe, expect, it, vi } from 'vitest';
import { prepareAdvisoryRevision } from './advisory-revision';

const advisory = (overrides: Record<string, unknown> = {}) => JSON.stringify({
  ghsa_id: 'GHSA-r5fr-rjxr-66jc', summary: 'Lodash advisory', published_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-04-01T23:51:13Z', vulnerabilities: [{ package: { ecosystem: 'npm', name: 'lodash' } }], ...overrides,
});
const response = (body: string, status = 200) => new Response(body, { status });

describe('authoritative advisory revision preparation', () => {
  it('derives the revision from exact primary response bytes and exposes source metadata', async () => {
    const body = advisory();
    const result = await prepareAdvisoryRevision('GHSA-r5fr-rjxr-66jc', 'github', 'npm', 'lodash', vi.fn().mockResolvedValue(response(body)));
    expect(result.url).toBe('https://api.github.com/advisories/GHSA-r5fr-rjxr-66jc');
    expect(result.revision).toMatch(/^ghsa-sha256:[a-f0-9]{64}$/);
    expect(result.bodyBytes).toBe(new TextEncoder().encode(body).length);
    expect(result.published).toBe('2026-01-01T00:00:00Z');
    expect(result.updated).toBe('2026-04-01T23:51:13Z');
  });
  it('rejects mismatched IDs and package identity', async () => {
    await expect(prepareAdvisoryRevision('GHSA-r5fr-rjxr-66jc', 'github', 'npm', 'lodash', vi.fn().mockResolvedValue(response(advisory({ ghsa_id: 'GHSA-2222-3333-4444' }))))).rejects.toThrow('ID or affected package');
    await expect(prepareAdvisoryRevision('GHSA-r5fr-rjxr-66jc', 'github', 'npm', 'other', vi.fn().mockResolvedValue(response(advisory())))).rejects.toThrow('ID or affected package');
  });
  it('rejects missing source metadata and non-success HTTP responses', async () => {
    await expect(prepareAdvisoryRevision('GHSA-r5fr-rjxr-66jc', 'github', 'npm', 'lodash', vi.fn().mockResolvedValue(response(advisory({ updated_at: '' }))))).rejects.toThrow('published_at or updated_at');
    await expect(prepareAdvisoryRevision('GHSA-r5fr-rjxr-66jc', 'github', 'npm', 'lodash', vi.fn().mockResolvedValue(response('offline', 503)))).rejects.toThrow('HTTP 503');
  });
  it('supports OSV source metadata and provider-specific revision identity', async () => {
    const body = JSON.stringify({ id: 'OSV-2026-1', aliases: ['GHSA-r5fr-rjxr-66jc'], published: '2026-01-01T00:00:00Z', modified: '2026-04-01T23:51:13Z', affected: [{ package: { ecosystem: 'npm', name: 'lodash' } }] });
    const result = await prepareAdvisoryRevision('GHSA-r5fr-rjxr-66jc', 'osv', 'npm', 'lodash', vi.fn().mockResolvedValue(response(body)));
    expect(result.url).toBe('https://api.osv.dev/v1/vulns/GHSA-r5fr-rjxr-66jc');
    expect(result.revision).toMatch(/^osv-sha256:[a-f0-9]{64}$/);
  });
});

import { describe, expect, it } from 'vitest';
import { normalizeEvidenceSources } from './evidence-sources';

describe('frozen evidence sources', () => {
  const primary = { url: 'https://api.github.com/advisories/GHSA-2222-3333-4444', role: 'PRIMARY' as const };

  it('accepts a single primary source', () => {
    expect(normalizeEvidenceSources([primary])).toEqual([primary]);
  });

  it('supports four sources with one primary and lexicographic URL ordering', () => {
    const sources = [primary,
      { url: 'https://registry.npmjs.org/sample-package/1.0.0', role: 'SUPPLEMENTAL' as const },
      { url: 'https://api.osv.dev/v1/vulns/GHSA-2222-3333-4444', role: 'SUPPLEMENTAL' as const },
      { url: 'https://api.github.com/repos/sample/project/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', role: 'SUPPLEMENTAL' as const },
    ];
    expect(normalizeEvidenceSources(sources).map((source) => source.url)).toEqual(sources.map((source) => source.url).sort());
  });

  it('rejects missing or multiple primary roles and duplicate URLs', () => {
    expect(() => normalizeEvidenceSources([{ ...primary, role: 'SUPPLEMENTAL' }])).toThrow('exactly one primary');
    expect(() => normalizeEvidenceSources([primary, { ...primary, url: 'https://example.test/secondary' }])).toThrow('exactly one primary');
    expect(() => normalizeEvidenceSources([primary, { ...primary, role: 'SUPPLEMENTAL' }])).toThrow('unique');
  });

  it('rejects empty source URLs and source counts outside one through four', () => {
    expect(() => normalizeEvidenceSources([{ ...primary, url: '  ' }])).toThrow('needs a URL');
    expect(() => normalizeEvidenceSources([])).toThrow('between one and four');
    expect(() => normalizeEvidenceSources([primary, ...Array.from({ length: 4 }, (_, i) => ({ url: `https://example.test/${i}`, role: 'SUPPLEMENTAL' as const }))])).toThrow('between one and four');
  });
});

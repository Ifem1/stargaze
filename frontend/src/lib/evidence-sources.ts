export type EvidenceRole = 'PRIMARY' | 'SUPPLEMENTAL';
export type EvidenceSource = { url: string; role: EvidenceRole };

export function normalizeEvidenceSources(sources: EvidenceSource[]): EvidenceSource[] {
  if (sources.length < 1 || sources.length > 4) throw new Error('Provide between one and four evidence sources.');
  if (sources.some((source) => !source.url.trim())) throw new Error('Every evidence source needs a URL.');
  if (sources.some((source) => source.role !== 'PRIMARY' && source.role !== 'SUPPLEMENTAL')) throw new Error('Choose a valid evidence role for each source.');
  if (sources.filter((source) => source.role === 'PRIMARY').length !== 1) throw new Error('Choose exactly one primary source.');
  const normalized = sources.map((source) => ({ url: source.url.trim(), role: source.role }));
  if (new Set(normalized.map((source) => source.url)).size !== normalized.length) throw new Error('Evidence source URLs must be unique.');
  return normalized.sort((a, b) => a.url < b.url ? -1 : a.url > b.url ? 1 : 0);
}

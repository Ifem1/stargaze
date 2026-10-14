export type AdvisoryProvider = 'github' | 'osv';
export type PreparedAdvisoryRevision = {
  provider: AdvisoryProvider;
  advisoryId: string;
  revision: string;
  url: string;
  title: string;
  digest: string;
  bodyBytes: number;
  published: string;
  updated: string;
};

const timestamp = /^\d{4}-\d{2}-\d{2}T[^\s]{1,32}Z$/;

export async function prepareAdvisoryRevision(
  advisoryId: string,
  provider: AdvisoryProvider,
  ecosystem: string,
  packageName: string,
  fetcher: typeof fetch = fetch,
): Promise<PreparedAdvisoryRevision> {
  const id = advisoryId.trim();
  if (!id || id.length > 100 || id.includes('/') || id.includes('..')) throw new Error('Enter one advisory identifier.');
  if (provider === 'github' && !/^GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}$/i.test(id)) {
    throw new Error('Enter a valid GHSA identifier.');
  }
  const url = provider === 'github'
    ? `https://api.github.com/advisories/${id}`
    : `https://api.osv.dev/v1/vulns/${id}`;
  const response = await fetcher(url, { headers: { accept: 'application/json' } });
  if (!response.ok) throw new Error(`Authoritative advisory endpoint returned HTTP ${response.status}.`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!bytes.length || bytes.length >= 12_000) throw new Error('Advisory response is empty or exceeds the contract evidence bound.');
  const body = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  let metadata: Record<string, unknown>;
  try {
    metadata = JSON.parse(body) as Record<string, unknown>;
  } catch {
    throw new Error('Authoritative advisory response is not valid JSON.');
  }
  const packageMatches = (items: unknown) => Array.isArray(items) && items.some((item) => {
    if (!item || typeof item !== 'object') return false;
    const packageInfo = (item as { package?: unknown }).package;
    return !!packageInfo && typeof packageInfo === 'object'
      && (packageInfo as { ecosystem?: unknown }).ecosystem === ecosystem
      && (packageInfo as { name?: unknown }).name === packageName;
  });
  let published = '';
  let updated = '';
  let title = '';
  if (provider === 'github') {
    if (metadata.ghsa_id !== id || !packageMatches(metadata.vulnerabilities)) throw new Error('GitHub advisory ID or affected package does not match the selected release.');
    if (typeof metadata.published_at !== 'string' || !timestamp.test(metadata.published_at)
        || typeof metadata.updated_at !== 'string' || !timestamp.test(metadata.updated_at)) {
      throw new Error('GitHub advisory is missing valid published_at or updated_at metadata.');
    }
    published = metadata.published_at;
    updated = metadata.updated_at;
    title = typeof metadata.summary === 'string' ? metadata.summary : id;
  } else {
    const aliases = Array.isArray(metadata.aliases) ? metadata.aliases : [];
    if (metadata.id !== id && !aliases.includes(id)) throw new Error('OSV advisory ID or aliases do not match the selected identifier.');
    if (!packageMatches(metadata.affected)) throw new Error('OSV affected package does not match the selected release.');
    if (metadata.published !== undefined && (typeof metadata.published !== 'string' || !timestamp.test(metadata.published))) throw new Error('OSV published metadata is malformed.');
    if (metadata.modified !== undefined && (typeof metadata.modified !== 'string' || !timestamp.test(metadata.modified))) throw new Error('OSV modified metadata is malformed.');
    published = typeof metadata.published === 'string' ? metadata.published : '';
    updated = typeof metadata.modified === 'string' ? metadata.modified : '';
    title = typeof metadata.summary === 'string' ? metadata.summary : id;
  }
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
    .map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return { provider, advisoryId: id, revision: `${provider === 'github' ? 'ghsa' : 'osv'}-sha256:${digest}`,
    url, title, digest, bodyBytes: bytes.byteLength, published, updated };
}

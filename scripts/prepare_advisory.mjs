import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const [provider, advisoryId, ecosystem, packageName, supplementalJson = '[]', archiveLabel = 'advisory'] = process.argv.slice(2);
if (!['github', 'osv'].includes(provider ?? '') || !advisoryId || !ecosystem || !packageName) {
  throw new Error('Usage: node scripts/prepare_advisory.mjs <github|osv> <advisory-id> <ecosystem> <package> [supplemental-sources-json] [archive-label]');
}
if (!/^[a-zA-Z0-9._-]{1,80}$/.test(archiveLabel)) throw new Error('Archive label must use 1-80 simple filename characters.');
const endpoint = provider === 'github'
  ? `https://api.github.com/advisories/${advisoryId}`
  : `https://api.osv.dev/v1/vulns/${advisoryId}`;
const supplementals = JSON.parse(supplementalJson);
if (!Array.isArray(supplementals) || supplementals.length > 3
    || supplementals.some((source) => !source || typeof source.url !== 'string' || source.role !== 'SUPPLEMENTAL')) {
  throw new Error('Supplemental sources must be up to three {url, role:"SUPPLEMENTAL"} entries.');
}
const sources = [{ url: endpoint, role: 'PRIMARY' }, ...supplementals].sort((a, b) => a.url.localeCompare(b.url));
const entries = [];
for (const source of sources) {
  const response = await fetch(source.url, { headers: { accept: 'application/json', 'user-agent': 'stargaze-advisory-preflight' } });
  const bytes = Buffer.from(await response.arrayBuffer());
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (!response.ok || !bytes.length || bytes.length >= 12_000) throw new Error(`${source.url} returned HTTP ${response.status} or an out-of-bound body.`);
  const parsed = JSON.parse(bytes.toString('utf8'));
  const bodyPath = `evidence/snapshots/sha256/${digest}.bin`;
  await mkdir(resolve(bodyPath, '..'), { recursive: true });
  await writeFile(bodyPath, bytes, { flag: 'wx' }).catch(async (error) => {
    if (error.code !== 'EEXIST') throw error;
    const { readFile } = await import('node:fs/promises');
    const existing = await readFile(bodyPath);
    if (!existing.equals(bytes)) throw new Error(`Content-address collision at ${bodyPath}.`);
  });
  let identityValid = false;
  let revisionMetadata = {};
  if (source.role === 'PRIMARY' && provider === 'github') {
    identityValid = parsed.ghsa_id === advisoryId
      && Array.isArray(parsed.vulnerabilities)
      && parsed.vulnerabilities.some((item) => item.package?.ecosystem === ecosystem && item.package?.name === packageName)
      && typeof parsed.published_at === 'string' && typeof parsed.updated_at === 'string';
    revisionMetadata = { published_at: parsed.published_at ?? '', updated_at: parsed.updated_at ?? '' };
  } else if (source.role === 'PRIMARY') {
    identityValid = (parsed.id === advisoryId || (Array.isArray(parsed.aliases) && parsed.aliases.includes(advisoryId)))
      && Array.isArray(parsed.affected)
      && parsed.affected.some((item) => item.package?.ecosystem === ecosystem && item.package?.name === packageName);
    revisionMetadata = { published: parsed.published ?? '', modified: parsed.modified ?? '', withdrawn: parsed.withdrawn ?? '' };
  } else {
    identityValid = true;
  }
  entries.push({ url: source.url, role: source.role, response_status: response.status, body_sha256: digest,
    body_bytes: bytes.length, archive_path: bodyPath, metadata_identity_valid: identityValid,
    revision_metadata: revisionMetadata });
}
const primary = entries.find((entry) => entry.role === 'PRIMARY');
if (!primary?.metadata_identity_valid) throw new Error('Primary advisory ID/package metadata failed validation.');
const manifest = { domain: 'STARGAZE_ADVISORY_ARCHIVE_V1', provider, advisory_id: advisoryId, ecosystem,
  package_name: packageName, revision: `${provider === 'github' ? 'ghsa' : 'osv'}-sha256:${primary.body_sha256}`,
  primary_url: endpoint, sources: entries };
const outputPath = `evidence/manifests/${archiveLabel}.json`;
await mkdir(resolve(outputPath, '..'), { recursive: true });
await writeFile(outputPath, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
process.stdout.write(`${JSON.stringify({ manifest: outputPath, revision: manifest.revision, sources: entries }, null, 2)}\n`);

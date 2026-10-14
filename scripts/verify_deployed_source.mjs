import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

const address = process.env.STARGAZE_CONTRACT_ADDRESS;
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '')) throw new Error('Set STARGAZE_CONTRACT_ADDRESS.');
if (studionet.id !== 61999 || studionet.rpcUrls.default.http[0] !== 'https://studio.genlayer.com/api') throw new Error('Wrong chain definition.');
const client = createClient({ chain: studionet, endpoint: 'https://studio.genlayer.com/api' });
const [chainId, code, schema, local] = await Promise.all([
  client.getChainId(), client.getContractCode(address), client.getContractSchema(address), readFile('contracts/stargaze.py'),
]);
const remote = Buffer.from(code, 'utf8');
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const report = { checkedAt: new Date().toISOString(), chainId, rpc: 'https://studio.genlayer.com/api', address,
  localBytes: local.length, remoteBytes: remote.length, localSha256: hash(local), remoteSha256: hash(remote),
  byteForByteMatch: local.equals(remote), schemaMethodCount: Object.keys(schema.methods ?? {}).length,
  compactAuthorizationPresent: Boolean(schema.methods?.authorization_for_release_compact), explorerVerifiedBadge: false };
await mkdir('evidence/live', { recursive: true });
await writeFile('evidence/live/deployed-source-parity.json', JSON.stringify(report, null, 2) + String.fromCharCode(10));
console.log(JSON.stringify(report, null, 2));
if (chainId !== 61999 || !report.byteForByteMatch || !report.compactAuthorizationPresent) process.exitCode = 1;

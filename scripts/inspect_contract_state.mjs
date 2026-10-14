import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';

const address = process.env.STARGAZE_CONTRACT_ADDRESS;
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '')) throw new Error('Set STARGAZE_CONTRACT_ADDRESS.');
const client = createClient({ chain: studionet, endpoint: 'https://studio.genlayer.com/api' });
const chainId = await client.getChainId();
if (chainId !== 61999) throw new Error(`Wrong chain ${chainId}.`);
const read = (functionName, args = []) => client.readContract({ address, functionName, args,
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL });
const [releaseCount, assessmentCount, releases, assessments, ghsaAuthorized, npmAuthorized] = await Promise.all([
  read('get_release_counter'), read('get_assessment_counter'), read('list_releases', [0, 20]),
  read('list_assessments', [0, 50]), read('is_source_authorized', ['api.github.com', 'PRIMARY']),
  read('is_source_authorized', ['registry.npmjs.org', 'SUPPLEMENTAL']),
]);
const gates = [];
for (const assessment of assessments) {
  const commitment = createHash('sha256').update(`${assessment.release_id}|${assessment.advisory_id}|${assessment.revision}`).digest();
  gates.push({ assessment_id: assessment.id, result: await read('authorization_for_release_compact', [assessment.release_id, commitment]) });
}
const result = { checkedAt: new Date().toISOString(), chainId, rpc: 'https://studio.genlayer.com/api', contract: address,
  releaseCount: Number(releaseCount), assessmentCount: Number(assessmentCount), sourceRoles: {
    githubPrimary: ghsaAuthorized, npmSupplemental: npmAuthorized }, releases, assessments, gates };
const output = process.env.STARGAZE_STATE_OUTPUT ?? 'evidence/live/state-readback.json';
await mkdir(output.slice(0, output.lastIndexOf('/')), { recursive: true }).catch(() => {});
await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

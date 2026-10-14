import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';
import { createHash } from 'node:crypto';

const address = process.env.STARGAZE_CONTRACT_ADDRESS;
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '')) throw new Error('Set STARGAZE_CONTRACT_ADDRESS.');
const client = createClient({ chain: studionet, endpoint: 'https://studio.genlayer.com/api' });
const read = (functionName, args = []) => client.readContract({ address, functionName, args,
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL });
const [chainId, releaseCount, assessmentCount, releases, assessments] = await Promise.all([
  client.getChainId(), read('get_release_counter'), read('get_assessment_counter'),
  read('list_releases', [0, 10]), read('list_assessments', [0, 20]),
]);
const rel = releases.find(({ id }) => id === 'rel-2');
const good = assessments.find(({ id }) => id === 'asm-2');
const unresolved = assessments.find(({ id }) => id === 'asm-3');
const pack = (items) => Buffer.concat(items.map(({ releaseId, advisory_id, revision }) => createHash('sha256')
  .update(`${releaseId}|${advisory_id}|${revision}`).digest()));
const singleGate = await read('authorization_for_release_compact', [rel.id, pack([
  { releaseId: rel.id, advisory_id: good.advisory_id, revision: good.revision },
])]);
const multiGate = await read('authorization_for_release_compact', [rel.id, pack([
  { releaseId: rel.id, advisory_id: good.advisory_id, revision: good.revision },
  { releaseId: rel.id, advisory_id: unresolved.advisory_id, revision: unresolved.revision },
])]);
console.log(JSON.stringify({ chainId, releaseCount: Number(releaseCount), assessmentCount: Number(assessmentCount),
  singleGate, multiGate, releases, assessments }, null, 2));

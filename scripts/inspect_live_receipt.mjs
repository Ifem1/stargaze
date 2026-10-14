import { mkdir, writeFile } from 'node:fs/promises';
import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionStatus } from 'genlayer-js/types';

const hash = process.env.STARGAZE_TX_HASH;
if (!/^0x[0-9a-fA-F]{64}$/.test(hash ?? '')) throw new Error('Set STARGAZE_TX_HASH.');
const client = createClient({ chain: studionet, endpoint: 'https://studio.genlayer.com/api' });
if (await client.getChainId() !== 61999) throw new Error('RPC chain mismatch.');
const receipt = await client.waitForTransactionReceipt({ hash, status: TransactionStatus.FINALIZED, interval: 3000, retries: 120 });
const leaders = receipt.consensus_data?.leader_receipt ?? [];
const result = { checkedAt: new Date().toISOString(), chainId: 61999, rpc: 'https://studio.genlayer.com/api',
  requestedHash: hash, receiptHash: receipt.tx_id ?? receipt.hash, status: receipt.status_name,
  consensus: receipt.result_name, rounds: receipt.num_of_rounds, round: receipt.last_round?.round,
  committed: receipt.last_round?.votes_committed, revealed: receipt.last_round?.votes_revealed,
  validatorVotes: receipt.consensus_data?.votes ?? {},
  leader: leaders.filter(({ mode }) => mode === 'leader').map(({ execution_result, genvm_result }) => ({
    execution_result, error_code: genvm_result?.error_code, error_description: genvm_result?.error_description,
    stderr: genvm_result?.stderr, stdout: genvm_result?.stdout,
  })) };
await mkdir('evidence/live', { recursive: true });
const output = process.env.STARGAZE_RECEIPT_OUTPUT ?? `evidence/live/receipt-${hash.slice(2, 14)}.json`;
await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

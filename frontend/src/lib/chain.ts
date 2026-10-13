import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { ExecutionResult, TransactionHashVariant, TransactionStatus, type CalldataEncodable } from 'genlayer-js/types';

export const CHAIN_ID = 61999;
export const CHAIN_HEX = '0xF22F';
export const RPC_URL = 'https://studio.genlayer.com/api';
export const EXPLORER_URL = 'https://explorer-studio.genlayer.com';
export const contractAddress = process.env.NEXT_PUBLIC_STARGAZE_CONTRACT_ADDRESS ?? '';

export type Eip1193 = { request(args: { method: string; params?: unknown[] }): Promise<unknown>; on?(event: string, listener: (...args: unknown[]) => void): void; removeListener?(event: string, listener: (...args: unknown[]) => void): void };
declare global { interface Window { ethereum?: Eip1193 } }

export function assertNetworkDefinition() {
  if (studionet.id !== CHAIN_ID) throw new Error('Installed GenLayerJS does not define stable Studionet 61999.');
}
export function makeClient(account?: string, provider?: Eip1193) {
  assertNetworkDefinition();
  if (provider && account) return createClient({ chain: studionet, account: account as `0x${string}`, provider: provider as never });
  return createClient({ chain: studionet });
}
export async function readContract<T>(functionName: string, args: CalldataEncodable[] = []): Promise<T> {
  if (!/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) throw new Error('Set NEXT_PUBLIC_STARGAZE_CONTRACT_ADDRESS to the verified Studionet contract.');
  const client = makeClient();
  return await client.readContract({ address: contractAddress as `0x${string}`, functionName, args, transactionHashVariant: TransactionHashVariant.LATEST_FINAL }) as T;
}
export async function writeContract(functionName: string, args: CalldataEncodable[], account: string, provider: Eip1193, onStatus: (message: string) => void) {
  if (!/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) throw new Error('Contract address is not configured.');
  const chainHex = String(await provider.request({ method: 'eth_chainId' })).toLowerCase();
  if (chainHex !== CHAIN_HEX.toLowerCase()) throw new Error('Writes are blocked until the wallet is on Studionet 61999.');
  const client = makeClient(account, provider);
  const write = { address: contractAddress as `0x${string}`, functionName, args };
  onStatus('Estimating network fees');
  onStatus('Waiting for wallet signature');
  const hash = await client.writeContract({ ...write, value: 0n });
  onStatus(`Broadcast ${hash}`);
  onStatus('Waiting for validator decision and finality');
  await client.waitForTransactionReceipt({ hash, status: TransactionStatus.FINALIZED });
  const result = await client.getTransaction({ hash });
  if (result.statusName !== TransactionStatus.FINALIZED || result.txExecutionResultName !== ExecutionResult.FINISHED_WITH_RETURN) {
    throw new Error(`Finalized execution failed: ${String(result.statusName ?? 'unknown status')} / ${String(result.txExecutionResultName ?? 'missing execution result')}`);
  }
  onStatus('Finalized; confirming contract state');
  return { hash, result };
}

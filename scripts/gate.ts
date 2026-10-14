import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';

export const CHAIN_ID = 61999;
export const RPC_URL = 'https://studio.genlayer.com/api';
export const EXPLORER_URL = 'https://explorer-studio.genlayer.com';

type Release = { id: string; artifact_digest: string; status: string };
type GateCheck = { advisory_id: string; revision: string; assessment_id: string; verdict: string;
  packet_digest: string; revision_authenticated: boolean; evidence_complete: boolean; trust_epoch_valid: boolean };
type ContractGate = { status: string; release_id: string; artifact_digest: string; checks: GateCheck[] };
export type Policy = {
  chain_id: number; contract_address: string; release_id: string;
  artifact_digest: string; required: Array<{ advisory_id: string; revision: string }>;
};
export type FinalReader = {
  getRelease(id: string): Promise<unknown>;
  authorizationForRelease(releaseId: string, requirementCommitments: Uint8Array): Promise<unknown>;
};

function fail(message: string): never { throw new Error(message); }
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const isDigest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

export function validatePolicy(value: unknown): Policy {
  if (!isRecord(value) || value.chain_id !== CHAIN_ID) fail('DENY: policy must target Studionet chain 61999.');
  if (typeof value.contract_address !== 'string' || !/^0x[a-fA-F0-9]{40}$/.test(value.contract_address)) fail('DENY: invalid contract address.');
  if (typeof value.release_id !== 'string' || value.release_id.length < 5) fail('DENY: invalid release ID.');
  if (!isDigest(value.artifact_digest)) fail('DENY: invalid artifact SHA-256.');
  if (!Array.isArray(value.required) || value.required.length < 1 || value.required.length > 5) fail('DENY: between one and five advisory revision requirements are supported.');
  const seen = new Set<string>();
  for (const pair of value.required) {
    if (!isRecord(pair) || typeof pair.advisory_id !== 'string' || !pair.advisory_id || typeof pair.revision !== 'string' || !pair.revision) fail('DENY: malformed advisory revision requirement.');
    const key = `${pair.advisory_id}\0${pair.revision}`;
    if (seen.has(key)) fail('DENY: duplicate advisory revision requirement.');
    seen.add(key);
  }
  return value as unknown as Policy;
}

export async function evaluateFinalPolicy(policyInput: unknown, reader: FinalReader) {
  const policy = validatePolicy(policyInput);
  const releaseRaw = await reader.getRelease(policy.release_id);
  if (!isRecord(releaseRaw)) fail('DENY: release read failed or malformed.');
  const release = releaseRaw as unknown as Release;
  if (release.id !== policy.release_id || release.status !== 'SEALED' || release.artifact_digest !== policy.artifact_digest) fail('DENY: release identity or artifact digest mismatch.');

  const commitments = Buffer.concat(policy.required.map((item) => createHash('sha256')
    .update(`${policy.release_id}|${item.advisory_id}|${item.revision}`).digest()));
  const gateRaw = await reader.authorizationForRelease(policy.release_id, commitments);
  if (!isRecord(gateRaw)) fail('DENY: authoritative contract gate read failed or malformed.');
  const gate = gateRaw as unknown as ContractGate;
  if (gate.status !== 'AUTHORIZED_FOR_POLICY_SET' || gate.release_id !== policy.release_id
      || gate.artifact_digest !== policy.artifact_digest || !Array.isArray(gate.checks)
      || gate.checks.length !== policy.required.length) {
    fail('DENY: authoritative contract gate did not authorize the exact policy set.');
  }
  const verified = [];
  for (let index = 0; index < policy.required.length; index += 1) {
    const required = policy.required[index];
    const checkRaw: unknown = gate.checks[index];
    if (!isRecord(checkRaw) || checkRaw.advisory_id !== required.advisory_id || checkRaw.revision !== required.revision
        || typeof checkRaw.assessment_id !== 'string' || !checkRaw.assessment_id || checkRaw.verdict !== 'NOT_AFFECTED'
        || !isDigest(checkRaw.packet_digest) || checkRaw.revision_authenticated !== true
        || checkRaw.evidence_complete !== true || checkRaw.trust_epoch_valid !== true) {
      fail(`DENY: malformed indexed authorization check for ${required.advisory_id}@${required.revision}.`);
    }
    verified.push({ advisory_id: required.advisory_id, revision: required.revision,
      assessment_id: checkRaw.assessment_id, packet_digest: checkRaw.packet_digest });
  }
  const policyDigest = createHash('sha256').update(JSON.stringify({ domain: 'STARGAZE_GATE_POLICY_V1', chain_id: CHAIN_ID,
    contract_address: policy.contract_address.toLowerCase(), release_id: policy.release_id,
    artifact_digest: policy.artifact_digest, required: [...policy.required].sort((a, b) => `${a.advisory_id}@${a.revision}`.localeCompare(`${b.advisory_id}@${b.revision}`)) })).digest('hex');
  return { decision: 'AUTHORIZED_FOR_POLICY_SET', chain_id: CHAIN_ID, contract_address: policy.contract_address,
    release_id: policy.release_id, artifact_digest: policy.artifact_digest, policy_digest: policyDigest, verified };
}

export async function authorizeThenExecute(
  policyInput: unknown,
  reader: FinalReader,
  execute: () => Promise<number>,
) {
  const authorization = await evaluateFinalPolicy(policyInput, reader);
  const exitCode = await execute();
  return { authorization, exitCode };
}

async function checkRpcChainId() {
  const response = await fetch(RPC_URL, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }), signal: AbortSignal.timeout(12000) });
  if (!response.ok) fail(`DENY: Studionet RPC returned HTTP ${response.status}.`);
  const body: unknown = await response.json();
  if (!isRecord(body) || body.result !== '0xf22f') fail('DENY: RPC did not confirm chain 61999.');
}

async function main() {
  const separator = process.argv.indexOf('--');
  if (separator < 3 || process.argv.length <= separator + 1) fail('Usage: tsx scripts/gate.ts <policy.json> -- <protected-command> [args...]');
  const [, , policyPath] = process.argv;
  const contractAddress = process.env.STARGAZE_CONTRACT_ADDRESS;
  if (!contractAddress || !/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) fail('DENY: STARGAZE_CONTRACT_ADDRESS is missing or invalid.');
  const policy = validatePolicy(JSON.parse(await readFile(policyPath, 'utf8')));
  if (policy.contract_address.toLowerCase() !== contractAddress.toLowerCase()) fail('DENY: policy contract does not match configured canonical contract.');
  if (studionet.id !== CHAIN_ID) fail('DENY: installed GenLayerJS Studionet definition is not chain 61999.');
  await checkRpcChainId();
  const client = createClient({ chain: studionet });
  const reader: FinalReader = {
    getRelease: (id) => client.readContract({ address: policy.contract_address as `0x${string}`, functionName: 'get_release', args: [id], transactionHashVariant: TransactionHashVariant.LATEST_FINAL }),
    authorizationForRelease: (releaseId, requirementCommitments) => client.readContract({ address: policy.contract_address as `0x${string}`, functionName: 'authorization_for_release_compact', args: [releaseId, requirementCommitments], transactionHashVariant: TransactionHashVariant.LATEST_FINAL }),
  };
  const command = process.argv[separator + 1];
  const args = process.argv.slice(separator + 2);
  const { authorization, exitCode } = await authorizeThenExecute(policy, reader, () => new Promise<number>((resolve, reject) => {
    const child = spawn(command, args, { shell: false, stdio: 'inherit', env: process.env });
    child.on('error', reject);
    child.on('exit', (code, signal) => resolve(code ?? (signal ? 128 : 1)));
  }));
  process.stdout.write(`${JSON.stringify(authorization, null, 2)}\n`);
  process.exitCode = exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.message : 'DENY: unknown gate failure'}\n`); process.exitCode = 1; });
}

import { createHash } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { Wallet } from 'ethers';
import { satisfies } from 'semver';
import { createAccount, createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant, TransactionStatus } from 'genlayer-js/types';

const rpc = 'https://studio.genlayer.com/api';
const chainId = 61999;
const address = process.env.STARGAZE_CONTRACT_ADDRESS;
const keyPath = process.env.STARGAZE_KEYSTORE_PATH;
const releaseId = process.env.STARGAZE_RELEASE_ID ?? 'rel-2';
const advisoryFiles = [
  'multi-ghsa-29mw-wpgm-hmr9.json',
  'multi-ghsa-x5rq-j2xg-h7qm.json',
];
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '') || !keyPath) throw new Error('Set contract and encrypted keystore paths.');
if (studionet.id !== chainId || studionet.rpcUrls.default.http[0] !== rpc) throw new Error('Wrong chain definition.');

async function hiddenPassword() {
  if (process.env.STARGAZE_KEYSTORE_PASSWORD) return process.env.STARGAZE_KEYSTORE_PASSWORD;
  if (!process.stdin.isTTY || !process.stdin.setRawMode) throw new Error('A local TTY is required for hidden unlock.');
  process.stdout.write('Local keystore password (input hidden): ');
  process.stdin.setRawMode(true); process.stdin.resume();
  return new Promise((resolvePassword, reject) => {
    let value = '';
    const onData = (chunk) => { for (const byte of chunk) {
      if (byte === 3) { process.stdin.off('data', onData); process.stdin.setRawMode(false); reject(new Error('Cancelled')); return; }
      if (byte === 13 || byte === 10) { process.stdin.off('data', onData); process.stdin.setRawMode(false); process.stdin.pause(); process.stdout.write('\n'); resolvePassword(value); return; }
      if (byte === 8 || byte === 127) value = value.slice(0, -1); else value += String.fromCharCode(byte);
    } };
    process.stdin.on('data', onData);
  });
}

const password = await hiddenPassword();
const wallet = await Wallet.fromEncryptedJson(await readFile(keyPath, 'utf8'), password);
const account = createAccount(wallet.privateKey);
const client = createClient({ chain: studionet, endpoint: rpc, account });
if (await client.getChainId() !== chainId) throw new Error('RPC chain mismatch.');
const read = (functionName, args = []) => client.readContract({ address, functionName, args,
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL });
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const txs = [];
async function send(label, functionName, args) {
  const hash = await client.writeContract({ account, address, functionName, args, value: 0n });
  process.stdout.write(`SUBMITTED ${label} ${hash}\n`);
  const receipt = await client.waitForTransactionReceipt({ hash, status: TransactionStatus.FINALIZED, interval: 5000, retries: 120 });
  const leader = receipt.consensus_data?.leader_receipt?.find((item) => item.mode === 'leader');
  const result = { label, hash, status: receipt.status_name, consensus: receipt.result_name,
    execution: leader?.execution_result, validatorVotes: receipt.consensus_data?.votes ?? {},
    round: receipt.last_round?.round, committed: receipt.last_round?.votes_committed,
    revealed: receipt.last_round?.votes_revealed };
  txs.push(result);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return result;
}
function assertSuccessfulWrite(receipt) {
  if (receipt.status !== 'FINALIZED' || receipt.consensus !== 'MAJORITY_AGREE' || receipt.execution !== 'SUCCESS') {
    throw new Error(`Live write did not reach finalized majority agreement and successful execution: ${JSON.stringify(receipt)}`);
  }
}
const release = await read('get_release', [releaseId]);
if (!release?.id || release.owner.toLowerCase() !== account.address.toLowerCase()) throw new Error('Signer must own the selected sealed release.');
if (release.ecosystem !== 'npm' || release.package_name !== 'lodash' || release.version !== '4.18.0' || release.status !== 'SEALED') {
  throw new Error('Selected fixture must remain the sealed npm/lodash 4.18.0 release.');
}
for (const [host, role] of [['api.github.com', 'PRIMARY'], ['registry.npmjs.org', 'SUPPLEMENTAL']]) {
  if (!(await read('is_source_authorized', [host, role]))) throw new Error(`Required source role ${host}/${role} is not authorized.`);
}

const requirements = [];
const advisoryChecks = [];
for (const filename of advisoryFiles) {
  const manifestPath = join('evidence', 'manifests', filename);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const primary = manifest.sources.find((source) => source.role === 'PRIMARY');
  const supplemental = manifest.sources.find((source) => source.role === 'SUPPLEMENTAL');
  if (!primary || !supplemental || manifest.domain !== 'STARGAZE_ADVISORY_ARCHIVE_V1'
      || manifest.provider !== 'github' || manifest.ecosystem !== release.ecosystem
      || manifest.package_name !== release.package_name || primary.url !== manifest.primary_url
      || primary.url !== `https://api.github.com/advisories/${manifest.advisory_id}`) {
    throw new Error(`Invalid frozen advisory manifest: ${filename}`);
  }
  const primaryBytes = await readFile(primary.archive_path);
  const packageBytes = await readFile(supplemental.archive_path);
  if (sha256(primaryBytes) !== primary.body_sha256 || sha256(primaryBytes) !== manifest.revision.slice('ghsa-sha256:'.length)
      || sha256(packageBytes) !== supplemental.body_sha256) throw new Error(`Archive/revision digest mismatch: ${filename}`);
  const data = JSON.parse(primaryBytes.toString('utf8'));
  const range = data.vulnerabilities?.find((item) => item.package?.ecosystem === 'npm'
    && item.package?.name === 'lodash')?.vulnerable_version_range;
  if (data.ghsa_id !== manifest.advisory_id || !range || satisfies(release.version, range)) {
    throw new Error(`Advisory ${manifest.advisory_id} does not authenticate or its range includes ${release.version}.`);
  }
  const currentPrimary = await fetch(primary.url, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'stargaze-live-multi-advisory' } });
  const currentPackage = await fetch(supplemental.url, { headers: { accept: 'application/json', 'user-agent': 'stargaze-live-multi-advisory' } });
  if (!currentPrimary.ok || !currentPackage.ok) throw new Error(`Authoritative source fetch failed for ${manifest.advisory_id}.`);
  const [livePrimary, livePackage] = await Promise.all([currentPrimary.arrayBuffer(), currentPackage.arrayBuffer()]);
  if (sha256(Buffer.from(livePrimary)) !== primary.body_sha256 || sha256(Buffer.from(livePackage)) !== supplemental.body_sha256) {
    throw new Error(`Current provider bytes differ from frozen content-addressed manifest ${manifest.advisory_id}; no writes submitted.`);
  }
  const sourceSet = [
    { url: primary.url, role: 'PRIMARY' },
    { url: supplemental.url, role: 'SUPPLEMENTAL' },
  ].sort((a, b) => a.url.localeCompare(b.url));
  const key = [release.id, manifest.advisory_id, manifest.revision];
  let assessment = await read('get_assessment_by_identity', key);
  if (!assessment?.id) {
    const registration = await send(`register-${manifest.advisory_id}`, 'register_assessment', [
      release.id, manifest.advisory_id, manifest.revision, data.summary ?? manifest.advisory_id,
      release.ecosystem, release.package_name, 'stargaze-live-multi-v1', JSON.stringify(sourceSet),
    ]);
    assertSuccessfulWrite(registration);
    assessment = await read('get_assessment_by_identity', key);
    if (!assessment?.id || assessment.release_id !== release.id || assessment.advisory_id !== manifest.advisory_id
        || assessment.revision !== manifest.revision) throw new Error(`Registration readback mismatch for ${manifest.advisory_id}.`);
  }
  if (assessment.state === 'OPEN') {
    const evaluation = await send(`evaluate-${assessment.id}`, 'evaluate_assessment', [assessment.id]);
    // A disagreement is preserved as a terminal live attempt; do not retry for a desired verdict.
    if (evaluation.status !== 'FINALIZED') throw new Error(`Evaluation did not finalize for ${assessment.id}.`);
    assessment = await read('get_assessment', [assessment.id]);
  }
  advisoryChecks.push({ manifest: filename, manifestPath, revision: manifest.revision,
    primaryUrl: primary.url, primaryBodySha256: primary.body_sha256, primaryBodyBytes: primary.body_bytes,
    packageMetadataUrl: supplemental.url, packageMetadataSha256: supplemental.body_sha256,
    packageMetadataBytes: supplemental.body_bytes, publishedAt: data.published_at, updatedAt: data.updated_at,
    affectedRange: range, targetVersion: release.version, targetOutsideAffectedRange: true,
    currentProviderBytesEqualArchive: true });
  requirements.push({ advisory_id: manifest.advisory_id, revision: manifest.revision, assessment });
}

const commitments = (items) => Buffer.concat(items.map((item) => createHash('sha256')
  .update(`${release.id}|${item.advisory_id}|${item.revision}`).digest()));
const combinedGate = await read('authorization_for_release_compact', [release.id, commitments(requirements)]);
const allDecidedClear = requirements.length === 2 && requirements.every(({ assessment }) => assessment?.state === 'DECIDED'
  && assessment?.verdict === 'NOT_AFFECTED' && assessment?.revision_authenticated === true
  && assessment?.evidence_complete === true && assessment?.packet_digest);
const outputDir = resolve('evidence/live/multi-advisory');
await mkdir(outputDir, { recursive: true });
const positivePolicy = { chain_id: chainId, contract_address: address, release_id: release.id,
  artifact_digest: release.artifact_digest, required: requirements.map(({ advisory_id, revision }) => ({ advisory_id, revision })) };
const positivePath = join(outputDir, 'positive-policy.json');
await writeFile(positivePath, `${JSON.stringify(positivePolicy, null, 2)}\n`);
const positiveMarker = join(outputDir, 'positive-command.marker');
const negativeMarker = join(outputDir, 'negative-command.marker');
const unresolved = await read('get_assessment_by_identity', [release.id, 'GHSA-r5fr-rjxr-66jc', 'osv-sha256:6d94cb4483ee2659025e95633e85e3b5acde11b9013b2a126672eba03a36c457']);
const negativePolicy = { ...positivePolicy, required: [
  { advisory_id: requirements[0].advisory_id, revision: requirements[0].revision },
  { advisory_id: unresolved.advisory_id, revision: unresolved.revision },
] };
const negativePath = join(outputDir, 'negative-policy.json');
await writeFile(negativePath, `${JSON.stringify(negativePolicy, null, 2)}\n`);
async function runGate(name, policyPath, marker) {
  await rm(marker, { force: true });
  const expression = `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed')`;
  const child = spawnSync(process.execPath, [resolve('node_modules/tsx/dist/cli.mjs'), 'scripts/gate.ts', policyPath,
    '--', process.execPath, '-e', expression], { encoding: 'utf8', env: { ...process.env, STARGAZE_CONTRACT_ADDRESS: address } });
  let executed = false;
  try { executed = (await readFile(marker, 'utf8')) === 'executed'; } catch { /* absent means command did not run */ }
  return { name, exitCode: child.status, stdout: child.stdout, stderr: child.stderr, protectedCommandExecuted: executed,
    passed: name === 'positive' ? child.status === 0 && executed : child.status !== 0 && !executed };
}
let gateRuns = [];
if (allDecidedClear && combinedGate.status === 'AUTHORIZED_FOR_POLICY_SET') {
  gateRuns.push(await runGate('positive', positivePath, positiveMarker));
  gateRuns.push(await runGate('negative-unresolved-requirement', negativePath, negativeMarker));
}
const result = { checkedAt: new Date().toISOString(), chainId, rpc, contract: address,
  signer: account.address, release, advisoryChecks, transactions: txs, requirements,
  allDecidedClear, combinedGate, unresolvedRequirement: unresolved, negativeGateExpected: 'HOLD', gateRuns,
  testCounts: { positiveCommand: gateRuns[0]?.protectedCommandExecuted ?? false,
    negativeCommandBlocked: gateRuns[1]?.passed ?? false } };
await writeFile(join(outputDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
process.stdout.write(`MULTI_ADVISORY_PROOF ${JSON.stringify(result)}\n`);
if (!allDecidedClear || combinedGate.status !== 'AUTHORIZED_FOR_POLICY_SET'
    || gateRuns.length !== 2 || gateRuns.some((item) => !item.passed)) process.exitCode = 1;

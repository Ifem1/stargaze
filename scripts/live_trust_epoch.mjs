import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Wallet } from 'ethers';
import { createAccount, createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant, TransactionStatus } from 'genlayer-js/types';

const rpc = 'https://studio.genlayer.com/api';
const chainId = 61999;
const sourceHashExpected = '44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12';
const contractAddress = process.env.STARGAZE_TRUST_TEST_ADDRESS;
const keyPath = process.env.STARGAZE_KEYSTORE_PATH;
if (!/^0x[0-9a-fA-F]{40}$/.test(contractAddress ?? '') || !keyPath) throw new Error('Set isolated contract and encrypted keystore paths.');
if (studionet.id !== chainId || studionet.rpcUrls.default.http[0] !== rpc) throw new Error('Wrong GenLayer chain definition.');
const password = process.env.STARGAZE_KEYSTORE_PASSWORD;
if (!password) throw new Error('Set ephemeral encrypted-keystore password in process environment.');
const wallet = await Wallet.fromEncryptedJson(await readFile(keyPath, 'utf8'), password);
const account = createAccount(wallet.privateKey);
const client = createClient({ chain: studionet, endpoint: rpc, account });
if (await client.getChainId() !== chainId) throw new Error('RPC chain mismatch.');
const read = (functionName, args = []) => client.readContract({ address: contractAddress, functionName, args,
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL });
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const stable = (value) => Array.isArray(value) ? `[${value.map(stable).join(',')}]`
  : value && typeof value === 'object' ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const txs = [];
async function send(label, functionName, args, { expectSuccess = true } = {}) {
  const txHash = await client.writeContract({ account, address: contractAddress, functionName, args, value: 0n });
  process.stdout.write(`SUBMITTED ${label} ${txHash}\n`);
  const receipt = await client.waitForTransactionReceipt({ hash: txHash, status: TransactionStatus.FINALIZED, interval: 5000, retries: 120 });
  const leader = receipt.consensus_data?.leader_receipt?.find((item) => item.mode === 'leader');
  const record = { label, hash: txHash, status: receipt.status_name, consensus: receipt.result_name,
    execution: leader?.execution_result, errorCode: leader?.genvm_result?.error_code,
    errorDescription: leader?.genvm_result?.error_description,
    validatorVotes: receipt.consensus_data?.votes ?? {}, round: receipt.last_round?.round,
    committed: receipt.last_round?.votes_committed, revealed: receipt.last_round?.votes_revealed };
  txs.push(record);
  process.stdout.write(`${JSON.stringify(record)}\n`);
  const successful = record.status === 'FINALIZED' && record.consensus === 'MAJORITY_AGREE' && record.execution === 'SUCCESS';
  if (expectSuccess && !successful) throw new Error(`Write did not reach finalized majority agreement and successful execution: ${JSON.stringify(record)}`);
  return record;
}
const contractCode = Buffer.from(await client.getContractCode(contractAddress), 'utf8');
const sourceSha256 = hash(contractCode);
if (sourceSha256 !== sourceHashExpected) throw new Error(`Isolated contract source mismatch: ${sourceSha256}`);
const initialReleases = Number(await read('get_release_counter'));
const initialAssessments = Number(await read('get_assessment_counter'));
if (initialReleases !== 0 || initialAssessments !== 0) throw new Error('Refusing to use a non-empty isolated test deployment.');
const bootstrap = [];
for (const [host, role] of [['api.github.com', 'PRIMARY'], ['registry.npmjs.org', 'SUPPLEMENTAL']]) {
  const tx = await send(`authorize-${host}-${role}`, 'authorize_source_host', [host, role]);
  bootstrap.push(tx);
  if (!(await read('is_source_authorized', [host, role]))) throw new Error(`Source authorization readback failed for ${host}/${role}.`);
}

async function packageArtifact(version) {
  const metadataUrl = `https://registry.npmjs.org/lodash/${version}`;
  const response = await fetch(metadataUrl, { headers: { accept: 'application/json', 'user-agent': 'stargaze-live-trust-epoch' } });
  if (!response.ok) throw new Error(`npm metadata fetch failed: ${response.status} ${metadataUrl}`);
  const metadataBytes = Buffer.from(await response.arrayBuffer());
  const metadata = JSON.parse(metadataBytes.toString('utf8'));
  if (metadata.name !== 'lodash' || metadata.version !== version || !metadata.gitHead || !metadata.dist?.tarball || !metadata.dist?.integrity) {
    throw new Error(`npm metadata identity incomplete for lodash ${version}.`);
  }
  const tarballResponse = await fetch(metadata.dist.tarball, { headers: { 'user-agent': 'stargaze-live-trust-epoch' } });
  if (!tarballResponse.ok) throw new Error(`npm tarball fetch failed: ${tarballResponse.status} ${metadata.dist.tarball}`);
  const tarball = Buffer.from(await tarballResponse.arrayBuffer());
  const integrity = `sha512-${createHash('sha512').update(tarball).digest('base64')}`;
  if (integrity !== metadata.dist.integrity) throw new Error(`Published package SRI mismatch for lodash ${version}.`);
  const artifactDigest = hash(tarball);
  const archivePath = `evidence/snapshots/sha256/${artifactDigest}.bin`;
  const fsPath = resolve(archivePath);
  await mkdir(resolve('evidence/snapshots/sha256'), { recursive: true });
  try { await writeFile(fsPath, tarball, { flag: 'wx' }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    if (!Buffer.from(await readFile(fsPath)).equals(tarball)) throw new Error(`Tarball archive conflict for ${version}.`);
  }
  const releaseManifest = { ecosystem: 'npm', package_name: 'lodash', version,
    metadata_url: metadataUrl, metadata_sha256: hash(metadataBytes), tarball_url: metadata.dist.tarball,
    npm_integrity: metadata.dist.integrity, artifact_sha256: artifactDigest, artifact_bytes: tarball.length,
    archive_path: archivePath, git_head: metadata.gitHead };
  return { metadata, artifactDigest, manifestDigest: hash(Buffer.from(JSON.stringify(releaseManifest))), releaseManifest };
}

const advisoryManifests = {
  'GHSA-29mw-wpgm-hmr9': JSON.parse(await readFile('evidence/manifests/multi-ghsa-29mw-wpgm-hmr9.json', 'utf8')),
  'GHSA-r5fr-rjxr-66jc': JSON.parse(await readFile('evidence/manifests/ghsa-lodash-preflight-20261014.json', 'utf8')),
};
async function validateAdvisory(id, version) {
  const manifest = advisoryManifests[id];
  const primary = manifest.sources.find((item) => item.role === 'PRIMARY');
  if (!primary || manifest.primary_url !== `https://api.github.com/advisories/${id}`) throw new Error(`Missing canonical manifest for ${id}.`);
  const bytes = Buffer.from(await readFile(primary.archive_path));
  if (hash(bytes) !== manifest.revision.slice('ghsa-sha256:'.length)) throw new Error(`Frozen advisory hash mismatch for ${id}.`);
  const body = JSON.parse(bytes.toString('utf8'));
  const range = body.vulnerabilities?.find((item) => item.package?.ecosystem === 'npm'
    && item.package?.name === 'lodash')?.vulnerable_version_range;
  const live = await fetch(primary.url, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'stargaze-live-trust-epoch' } });
  if (!live.ok || hash(Buffer.from(await live.arrayBuffer())) !== hash(bytes)) throw new Error(`Live GHSA bytes differ from frozen revision ${id}.`);
  return { advisory_id: id, revision: manifest.revision, title: body.summary,
    package: 'npm/lodash', published_at: body.published_at, updated_at: body.updated_at,
    vulnerable_version_range: range, target_version: version, source_bytes_sha256: hash(bytes), source_bytes: bytes.length };
}
function sourceList(id, version) {
  return [
    { url: `https://api.github.com/advisories/${id}`, role: 'PRIMARY' },
    { url: `https://registry.npmjs.org/lodash/${version}`, role: 'SUPPLEMENTAL' },
  ].sort((a, b) => a.url.localeCompare(b.url));
}
async function registerRelease(version, predecessor, artifact) {
  const tx = await send(`register-release-lodash-${version}`, 'register_release', [
    'stargaze-live-trust-epoch-20261014', 'https://github.com/lodash/lodash', account.address.toLowerCase(), version,
    artifact.metadata.gitHead.toLowerCase(), artifact.artifactDigest, 'npm', 'lodash', artifact.manifestDigest, predecessor,
  ]);
  const releases = await read('list_releases', [0, 5]);
  const item = releases.find((release) => release.version === version);
  if (!item || item.owner.toLowerCase() !== account.address.toLowerCase() || item.artifact_digest !== artifact.artifactDigest) {
    throw new Error(`Exact release state readback mismatch for lodash ${version}.`);
  }
  return { tx, release: item, artifactManifest: artifact.releaseManifest };
}
async function registerAssessment(release, advisory) {
  const sources = sourceList(advisory.advisory_id, release.version);
  const tx = await send(`register-assessment-${release.id}-${advisory.advisory_id}`, 'register_assessment', [
    release.id, advisory.advisory_id, advisory.revision, advisory.title, 'npm', 'lodash',
    'stargaze-live-trust-epoch-v1', JSON.stringify(sources),
  ]);
  const assessment = await read('get_assessment_by_identity', [release.id, advisory.advisory_id, advisory.revision]);
  if (!assessment?.id || assessment.release_id !== release.id || assessment.sources.length !== 2) throw new Error('Assessment registration state mismatch.');
  return { tx, assessment, sources };
}
async function evaluateAssessment(assessment) {
  const tx = await send(`evaluate-${assessment.id}`, 'evaluate_assessment', [assessment.id]);
  const finalState = await read('get_assessment', [assessment.id]);
  return { tx, assessment: finalState };
}
async function compactGate(release, advisory) {
  const commitment = createHash('sha256').update(`${release.id}|${advisory.advisory_id}|${advisory.revision}`).digest();
  return read('authorization_for_release_compact', [release.id, commitment]);
}

const aMeta = await packageArtifact('4.18.0');
const bMeta = await packageArtifact('4.17.23');
const advisoryA = await validateAdvisory('GHSA-29mw-wpgm-hmr9', '4.18.0');
const advisoryB = await validateAdvisory('GHSA-r5fr-rjxr-66jc', '4.17.23');
const releaseA = await registerRelease('4.18.0', '', aMeta);
const assessmentA = await registerAssessment(releaseA.release, advisoryA);
const initialA = await evaluateAssessment(assessmentA.assessment);
const gateBefore = await compactGate(releaseA.release, advisoryA);
const releaseB = await registerRelease('4.17.23', releaseA.release.id, bMeta);
const assessmentB = await registerAssessment(releaseB.release, advisoryB);
const adverse = await evaluateAssessment(assessmentB.assessment);

const originalA = await read('get_assessment', [initialA.assessment.id]);
const originalB = await read('get_assessment', [adverse.assessment.id]);
const revokeTx = await send('revoke-api.github.com-PRIMARY', 'revoke_source_host', ['api.github.com', 'PRIMARY']);
const revokedAllowed = await read('is_source_authorized', ['api.github.com', 'PRIMARY']);
const oldAAfterRevoke = await read('get_assessment', [originalA.id]);
const oldBAfterRevoke = await read('get_assessment', [originalB.id]);
const oldGateAfterRevoke = await compactGate(releaseA.release, advisoryA);
const oldAImmutable = stable(oldAAfterRevoke) === stable(originalA);
const oldBImmutable = stable(oldBAfterRevoke) === stable(originalB);
const reauthorizeTx = await send('reauthorize-api.github.com-PRIMARY', 'authorize_source_host', ['api.github.com', 'PRIMARY']);
const reauthorized = await read('is_source_authorized', ['api.github.com', 'PRIMARY']);
const oldGateAfterReauthorize = await compactGate(releaseA.release, advisoryA);

const reattestationReg = await registerAssessment(releaseA.release, advisoryA);
const reattestation = await evaluateAssessment(reattestationReg.assessment);
const history = await read('get_assessment_history_by_identity', [releaseA.release.id, advisoryA.advisory_id, advisoryA.revision, 0, 5]);
const newGate = await compactGate(releaseA.release, advisoryA);

let adverseReattestation;
try {
  const args = [releaseB.release.id, advisoryB.advisory_id, advisoryB.revision, advisoryB.title,
    'npm', 'lodash', 'stargaze-live-trust-epoch-v1', JSON.stringify(sourceList(advisoryB.advisory_id, releaseB.release.version))];
  const hashValue = await client.writeContract({ account, address: contractAddress, functionName: 'register_assessment', args, value: 0n });
  const receipt = await client.waitForTransactionReceipt({ hash: hashValue, status: TransactionStatus.FINALIZED, interval: 5000, retries: 120 });
  const leader = receipt.consensus_data?.leader_receipt?.find((item) => item.mode === 'leader');
  adverseReattestation = { hash: hashValue, status: receipt.status_name, consensus: receipt.result_name,
    execution: leader?.execution_result, errorCode: leader?.genvm_result?.error_code,
    errorDescription: leader?.genvm_result?.error_description, validatorVotes: receipt.consensus_data?.votes ?? {} };
  txs.push({ label: 'adverse-reattestation-rejected', ...adverseReattestation });
} catch (error) {
  adverseReattestation = { rejected: true, error: String(error?.shortMessage ?? error?.message ?? error) };
}
const historyB = await read('get_assessment_history_by_identity', [releaseB.release.id, advisoryB.advisory_id, advisoryB.revision, 0, 5]);
const currentB = await read('get_assessment_by_identity', [releaseB.release.id, advisoryB.advisory_id, advisoryB.revision]);

const finalSource = Buffer.from(await client.getContractCode(contractAddress), 'utf8');
const deployment = JSON.parse(await readFile('evidence/live/trust-epoch-deployment.json', 'utf8'));
const result = { checkedAt: new Date().toISOString(), chainId, rpc, contract: contractAddress,
  deployedSourceSha256: hash(finalSource), sourceSha256Expected, deployment, signer: account.address,
  bootstrapTransactions: bootstrap, releases: [releaseA, releaseB],
  advisories: { clearCandidate: advisoryA, adverseCandidate: advisoryB },
  assessments: { originalClear: initialA, adverse: adverse, reattestation: { registration: reattestationReg, evaluation: reattestation } },
  trustEpochLifecycle: { authorizedInitially: true, originalSourceEpoch: originalA.sources.find((item) => item.host === 'api.github.com')?.source_epoch,
    revokeTransaction: revokeTx, authorizedAfterRevocation: revokedAllowed,
    originalAssessmentImmutableAfterRevocation: oldAImmutable, adverseAssessmentImmutableAfterRevocation: oldBImmutable,
    originalClearGateAfterRevocation: oldGateAfterRevoke, reauthorizationTransaction: reauthorizeTx,
    authorizedAfterReauthorization: reauthorized, oldApprovalAfterReauthorization: oldGateAfterReauthorize,
    newIdentityHistory: history, newAssessmentSourceEpoch: reattestation.assessment.sources.find((item) => item.host === 'api.github.com')?.source_epoch,
    newGate, adverseReattestation, adverseHistory: historyB, adverseCurrentRecord: currentB,
    adverseBypassPrevented: historyB.length === 1 && currentB.id === originalB.id },
  transactions: txs };
await mkdir('evidence/live/trust-epoch', { recursive: true });
await writeFile('evidence/live/trust-epoch/result.json', `${JSON.stringify(result, null, 2)}\n`);
process.stdout.write(`TRUST_EPOCH_PROOF ${JSON.stringify(result)}\n`);
const successful = hash(finalSource) === sourceHashExpected && revokedAllowed === false && reauthorized === true
  && oldAImmutable && oldBImmutable && oldGateAfterRevoke.status === 'HOLD'
  && oldGateAfterReauthorize.status === 'HOLD' && history.length === 2 && newGate.status === 'AUTHORIZED_FOR_POLICY_SET'
  && historyB.length === 1 && currentB.id === originalB.id;
if (!successful) process.exitCode = 1;

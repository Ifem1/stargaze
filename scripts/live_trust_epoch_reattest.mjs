import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { Wallet } from 'ethers';
import { createAccount, createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant, TransactionStatus } from 'genlayer-js/types';

const address = process.env.STARGAZE_TRUST_TEST_ADDRESS;
const keyPath = process.env.STARGAZE_KEYSTORE_PATH;
const password = process.env.STARGAZE_KEYSTORE_PASSWORD;
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '') || !keyPath || !password) throw new Error('Set isolated contract and temporary wallet environment.');
if (studionet.id !== 61999 || studionet.rpcUrls.default.http[0] !== 'https://studio.genlayer.com/api') throw new Error('Wrong network.');
const account = createAccount((await Wallet.fromEncryptedJson(await readFile(keyPath, 'utf8'), password)).privateKey);
const client = createClient({ chain: studionet, endpoint: 'https://studio.genlayer.com/api', account });
if (await client.getChainId() !== 61999) throw new Error('RPC chain mismatch.');
const read = (name, args = []) => client.readContract({ address, functionName: name, args,
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL });
const txs = [];
async function send(label, name, args) {
  const hash = await client.writeContract({ account, address, functionName: name, args, value: 0n });
  process.stdout.write(`SUBMITTED ${label} ${hash}\n`);
  const r = await client.waitForTransactionReceipt({ hash, status: TransactionStatus.FINALIZED, interval: 5000, retries: 120 });
  const leader = r.consensus_data?.leader_receipt?.find((item) => item.mode === 'leader');
  const record = { label, hash, status: r.status_name, consensus: r.result_name, execution: leader?.execution_result,
    validatorVotes: r.consensus_data?.votes ?? {}, round: r.last_round?.round,
    committed: r.last_round?.votes_committed, revealed: r.last_round?.votes_revealed };
  txs.push(record); process.stdout.write(`${JSON.stringify(record)}\n`);
  if (record.status !== 'FINALIZED' || record.consensus !== 'MAJORITY_AGREE' || record.execution !== 'SUCCESS') {
    throw new Error(`Write did not successfully finalize: ${JSON.stringify(record)}`);
  }
  return record;
}
const release = await read('get_release', ['rel-1']);
if (release.owner.toLowerCase() !== account.address.toLowerCase() || release.version !== '4.18.0') throw new Error('Unexpected isolated target release.');
const failedAdverse = await read('get_assessment', ['asm-1']);
if (failedAdverse.state !== 'DECIDED' || failedAdverse.verdict !== 'AFFECTED') throw new Error('Adverse control record changed; refusing further writes.');
const manifest = JSON.parse(await readFile('evidence/manifests/multi-ghsa-x5rq-j2xg-h7qm.json', 'utf8'));
const primary = manifest.sources.find((source) => source.role === 'PRIMARY');
const primaryBytes = Buffer.from(await readFile(primary.archive_path));
const primaryHash = createHash('sha256').update(primaryBytes).digest('hex');
if (manifest.advisory_id !== 'GHSA-x5rq-j2xg-h7qm' || manifest.revision !== `ghsa-sha256:${primaryHash}`) throw new Error('Advisory manifest is not content-addressed.');
const live = await fetch(primary.url, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'stargaze-trust-epoch-reattest' } });
if (!live.ok || createHash('sha256').update(Buffer.from(await live.arrayBuffer())).digest('hex') !== primaryHash) throw new Error('Current canonical advisory bytes differ from the frozen content address.');
const advisoryBody = JSON.parse(primaryBytes.toString('utf8'));
const currentGate = async () => {
  const commitment = createHash('sha256').update(`${release.id}|${manifest.advisory_id}|${manifest.revision}`).digest();
  return read('authorization_for_release_compact', [release.id, commitment]);
};
const sourceSet = [
  { url: primary.url, role: 'PRIMARY' },
  { url: 'https://registry.npmjs.org/lodash/4.18.0', role: 'SUPPLEMENTAL' },
].sort((a, b) => a.url.localeCompare(b.url));
const existing = await read('get_assessment_by_identity', [release.id, manifest.advisory_id, manifest.revision]);
if (existing?.id) throw new Error('Selected favorable candidate unexpectedly exists; refusing re-evaluation.');
if (!(await read('is_source_authorized', ['api.github.com', 'PRIMARY']))) throw new Error('GitHub source not authorized after first reauthorization.');
const register = async (label) => {
  const tx = await send(label, 'register_assessment', [release.id, manifest.advisory_id, manifest.revision,
    advisoryBody.summary, 'npm', 'lodash', 'stargaze-trust-epoch-v1', JSON.stringify(sourceSet)]);
  const assessment = await read('get_assessment_by_identity', [release.id, manifest.advisory_id, manifest.revision]);
  return { tx, assessment };
};
const first = await register('register-ghsa-x5rq-under-trust-epoch-3');
const eval1Tx = await send('evaluate-epoch-3', 'evaluate_assessment', [first.assessment.id]);
const firstAssessment = await read('get_assessment', [first.assessment.id]);
const initialGate = await currentGate();
const baseResult = { checkedAt: new Date().toISOString(), chainId: 61999, rpc: 'https://studio.genlayer.com/api', contract: address,
  signer: account.address, release, adverseControl: { assessment: failedAdverse,
    failedReattestationTx: '0x80ee12747ef5812763914d1e29840845143259ae14bdfcdd4c1ed780d0d1d762',
    failedReattestationReceipt: 'evidence/live/trust-epoch-reattestation-error-receipt.json' },
  advisory: { id: manifest.advisory_id, revision: manifest.revision, primaryUrl: primary.url,
    primaryBodySha256: primaryHash, primaryBodyBytes: primaryBytes.length,
    packageMetadataUrl: 'https://registry.npmjs.org/lodash/4.18.0',
    packageMetadataSha256: manifest.sources.find((source) => source.role === 'SUPPLEMENTAL').body_sha256,
    vulnerableVersionRange: advisoryBody.vulnerabilities?.find((item) => item.package?.name === 'lodash'
      && item.package?.ecosystem === 'npm')?.vulnerable_version_range },
  firstApproval: { registration: first.tx, evaluation: { tx: eval1Tx, assessment: firstAssessment }, initialGate },
  trustEpochLifecycle: null, transactions: txs };
if (firstAssessment.state !== 'DECIDED' || firstAssessment.verdict !== 'NOT_AFFECTED'
    || firstAssessment.revision_authenticated !== true || firstAssessment.evidence_complete !== true
    || initialGate.status !== 'AUTHORIZED_FOR_POLICY_SET') {
  const out = 'evidence/live/trust-epoch/favorable-first-attempt.json';
  await mkdir('evidence/live/trust-epoch', { recursive: true }); await writeFile(out, `${JSON.stringify(baseResult, null, 2)}\n`);
  process.stdout.write(`TRUST_EPOCH_FIRST_ASSESSMENT_NOT_CLEAR ${JSON.stringify(baseResult)}\n`);
  process.exitCode = 1;
} else {
  const before = await read('get_assessment', [firstAssessment.id]);
  const revokeTx = await send('revoke-api.github.com-PRIMARY-epoch-3', 'revoke_source_host', ['api.github.com', 'PRIMARY']);
  const authorizedAfterRevoke = await read('is_source_authorized', ['api.github.com', 'PRIMARY']);
  const oldAfterRevoke = await read('get_assessment', [before.id]);
  const gateAfterRevoke = await currentGate();
  const reauthorizeTx = await send('reauthorize-api.github.com-PRIMARY-epoch-5', 'authorize_source_host', ['api.github.com', 'PRIMARY']);
  const authorizedAfterReauthorize = await read('is_source_authorized', ['api.github.com', 'PRIMARY']);
  const gateAfterReauthorize = await currentGate();
  const second = await register('register-ghsa-x5rq-trust-epoch-5-reattestation');
  const sourceEpoch = second.assessment.sources.find((source) => source.host === 'api.github.com')?.source_epoch;
  const eval2Tx = await send('evaluate-epoch-5-reattestation', 'evaluate_assessment', [second.assessment.id]);
  const secondAssessment = await read('get_assessment', [second.assessment.id]);
  const history = await read('get_assessment_history_by_identity', [release.id, manifest.advisory_id, manifest.revision, 0, 5]);
  const gateAfterReattestation = await currentGate();
  baseResult.trustEpochLifecycle = { firstSourceEpoch: before.sources.find((source) => source.host === 'api.github.com')?.source_epoch,
    revocation: { transaction: revokeTx, sourceAuthorizedAfter: authorizedAfterRevoke,
      historicalAssessmentUnchanged: JSON.stringify(oldAfterRevoke) === JSON.stringify(before),
      assessmentAfter: oldAfterRevoke, gate: gateAfterRevoke },
    reauthorization: { transaction: reauthorizeTx, sourceAuthorizedAfter: authorizedAfterReauthorize,
      oldApprovalRemainsBlocked: gateAfterReauthorize.status === 'HOLD', gate: gateAfterReauthorize },
    reattestation: { registration: second.tx, evaluation: { tx: eval2Tx, assessment: secondAssessment },
      sourceEpoch, history, gate: gateAfterReattestation },
    adverseVerdictReattestationStillRejected: failedAdverse.verdict === 'AFFECTED'
      && failedAdverse.id === 'asm-1' };
  const success = authorizedAfterRevoke === false && authorizedAfterReauthorize === true
    && JSON.stringify(oldAfterRevoke) === JSON.stringify(before) && gateAfterRevoke.status === 'HOLD'
    && gateAfterReauthorize.status === 'HOLD' && history.length === 2 && sourceEpoch === 5
    && secondAssessment.identity_version === 2 && secondAssessment.verdict === 'NOT_AFFECTED'
    && gateAfterReattestation.status === 'AUTHORIZED_FOR_POLICY_SET';
  baseResult.trustEpochLifecycle.passed = success;
  const out = 'evidence/live/trust-epoch/result.json';
  await mkdir('evidence/live/trust-epoch', { recursive: true }); await writeFile(out, `${JSON.stringify(baseResult, null, 2)}\n`);
  process.stdout.write(`TRUST_EPOCH_PROOF ${JSON.stringify(baseResult)}\n`);
  if (!success) process.exitCode = 1;
}

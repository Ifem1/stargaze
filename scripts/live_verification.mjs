import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Wallet } from "ethers";
import { createAccount, createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { TransactionHashVariant, TransactionStatus } from "genlayer-js/types";

const RPC = "https://studio.genlayer.com/api";
const CHAIN_ID = 61999;
const ADVISORY_ID = "GHSA-r5fr-rjxr-66jc";
const POLICY_VERSION = "stargaze-live-v1";
const SOURCES = [
  { url: `https://api.github.com/advisories/${ADVISORY_ID}`, role: "PRIMARY" },
  { url: "https://registry.npmjs.org/lodash/4.17.23", role: "SUPPLEMENTAL" },
];
const OSV_URL = `https://api.osv.dev/v1/vulns/${ADVISORY_ID}`;
const PROJECT = "stargaze-live-verification-fixture";
const REPOSITORY = "https://github.com/lodash/lodash";

const read = (client, address, functionName, args = []) => client.readContract({
  address,
  functionName,
  args,
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
});

function compactRequirements(releaseId, requirements) {
  return Buffer.concat(requirements.map(({ advisory_id, revision }) => createHash("sha256")
    .update(`${releaseId}|${advisory_id}|${revision}`).digest()));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function archiveSource(url, role, responseStatus, bytes, metadataIdentityValid, revisionMetadata = {}) {
  const digest = sha256(bytes);
  const archivePath = `evidence/snapshots/sha256/${digest}.bin`;
  await mkdir("evidence/snapshots/sha256", { recursive: true });
  try { await writeFile(archivePath, bytes, { flag: "wx" }); }
  catch (error) {
    if (error.code !== "EEXIST") throw error;
    const existing = await readFile(archivePath);
    if (!existing.equals(bytes)) throw new Error(`Content-address collision at ${archivePath}.`);
  }
  return { url, role, response_status: responseStatus, body_sha256: digest, body_bytes: bytes.length,
    archive_path: archivePath, metadata_identity_valid: metadataIdentityValid, revision_metadata: revisionMetadata };
}

function readHidden(prompt) {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) {
    throw new Error("Run this script in a local TTY so the keystore password is not echoed.");
  }
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = "";
    const onData = (chunk) => {
      for (const byte of chunk) {
        if (byte === 3) {
          process.stdin.off("data", onData);
          process.stdin.setRawMode(false);
          process.stdin.pause();
          reject(new Error("Password entry cancelled."));
          return;
        }
        if (byte === 13 || byte === 10) {
          process.stdin.off("data", onData);
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdout.write("\n");
          resolve(value);
          return;
        }
        if (byte === 8 || byte === 127) value = value.slice(0, -1);
        else value += String.fromCharCode(byte);
      }
    };
    process.stdin.on("data", onData);
  });
}

function receiptSummary(label, hash, receipt) {
  const votes = receipt.consensus_data?.votes ?? {};
  const leaders = receipt.consensus_data?.leader_receipt ?? [];
  return {
    label,
    txId: hash,
    status: receipt.status_name,
    consensus: receipt.result_name,
    execution: leaders.map(({ mode, execution_result, vote }) => ({ mode, execution_result, vote })),
    validatorVotes: votes,
    round: receipt.last_round?.round,
    committed: receipt.last_round?.votes_committed,
    revealed: receipt.last_round?.votes_revealed,
  };
}

async function main() {
  const address = process.env.STARGAZE_CONTRACT_ADDRESS;
  const keystorePath = process.env.STARGAZE_KEYSTORE_PATH;
  if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? "")) throw new Error("Set STARGAZE_CONTRACT_ADDRESS.");
  if (!keystorePath) throw new Error("Set STARGAZE_KEYSTORE_PATH to the local encrypted throwaway keystore.");
  if (studionet.id !== CHAIN_ID || studionet.rpcUrls.default.http[0] !== RPC) {
    throw new Error("The installed GenLayer chain definition is not the required stable Studionet target.");
  }

  const password = await readHidden("Local keystore password (input hidden): ");
  const keystore = await readFile(keystorePath, "utf8");
  const wallet = await Wallet.fromEncryptedJson(keystore, password);
  const account = createAccount(wallet.privateKey);
  const client = createClient({ chain: studionet, endpoint: RPC, account });
  const observedChainId = await client.getChainId();
  if (observedChainId !== CHAIN_ID) throw new Error(`Wrong RPC chain ${observedChainId}; expected ${CHAIN_ID}.`);

  const releaseCount = await read(client, address, "get_release_counter");
  const assessmentCount = await read(client, address, "get_assessment_counter");
  if (Number(releaseCount) > 2 || Number(assessmentCount) > 2
      || (Number(releaseCount) === 0 && Number(assessmentCount) !== 0)
      || (Number(releaseCount) === 1 && Number(assessmentCount) > 1)) {
    throw new Error("Unexpected live verification registry state; refusing to replay or overwrite records.");
  }

  const advisoryResponse = await fetch(SOURCES[0].url, {
    headers: { accept: "application/vnd.github+json", "user-agent": "stargaze-live-verification" },
  });
  if (!advisoryResponse.ok) throw new Error(`GitHub advisory fetch failed with HTTP ${advisoryResponse.status}.`);
  const advisoryBytes = Buffer.from(await advisoryResponse.arrayBuffer());
  if (advisoryBytes.length >= 12_000) throw new Error("Advisory API body exceeds the contract evidence limit.");
  const advisoryText = advisoryBytes.toString("utf8");
  const advisory = JSON.parse(advisoryText);
  const affectedRange = advisory.vulnerabilities?.find(
    (item) => item.package?.ecosystem === "npm" && item.package?.name === "lodash",
  )?.vulnerable_version_range;
  if (advisory.ghsa_id !== ADVISORY_ID || !affectedRange?.includes("<= 4.17.23") || !advisory.description?.includes("4.18.0")) {
    throw new Error("Live GHSA content does not confirm the expected affected/fixed lodash range.");
  }
  const advisoryRevision = `ghsa-sha256:${sha256(advisoryBytes)}`;
  const archivedSources = [];
  archivedSources.push(await archiveSource(SOURCES[0].url, "PRIMARY", advisoryResponse.status, advisoryBytes, true,
    { published_at: advisory.published_at, updated_at: advisory.updated_at }));
  const osvResponse = await fetch(OSV_URL, { headers: { accept: "application/json" } });
  if (!osvResponse.ok) throw new Error(`OSV advisory fetch failed with HTTP ${osvResponse.status}.`);
  const osvBytes = Buffer.from(await osvResponse.arrayBuffer());
  if (osvBytes.length >= 12_000) throw new Error("OSV advisory API body exceeds the contract evidence limit.");
  const osv = JSON.parse(osvBytes.toString("utf8"));
  const osvPackage = osv.affected?.some((item) => item.package?.ecosystem === "npm" && item.package?.name === "lodash");
  if (osv.id !== ADVISORY_ID && !osv.aliases?.includes(ADVISORY_ID) || !osvPackage) {
    throw new Error("Live OSV advisory does not bind the GHSA identifier and lodash package.");
  }
  const osvRevision = `osv-sha256:${sha256(osvBytes)}`;
  const osvTimestamp = (value) => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
    ? `${value.slice(0, 19)}${value.includes(".") ? value.slice(19).replace(/0+Z$/, "Z") : ""}Z`.replace(/ZZ$/, "Z")
    : value;
  archivedSources.push(await archiveSource(OSV_URL, "PRIMARY", osvResponse.status, osvBytes, true,
    { published: osvTimestamp(osv.published) ?? "", modified: osvTimestamp(osv.modified) ?? "", withdrawn: osv.withdrawn ?? "" }));
  archivedSources.push(await archiveSource(OSV_URL, "SUPPLEMENTAL", osvResponse.status, osvBytes, true,
    { published: osvTimestamp(osv.published) ?? "", modified: osvTimestamp(osv.modified) ?? "", withdrawn: osv.withdrawn ?? "" }));

  const releases = [];
  for (const version of ["4.17.23", "4.18.0"]) {
    const metadataResponse = await fetch(`https://registry.npmjs.org/lodash/${version}`);
    if (!metadataResponse.ok) throw new Error(`npm metadata fetch failed for lodash ${version}.`);
    const metadataBytes = Buffer.from(await metadataResponse.arrayBuffer());
    const metadataText = metadataBytes.toString("utf8");
    const metadata = JSON.parse(metadataText);
    if (metadata.name !== "lodash" || metadata.version !== version || metadata.repository?.url !== "git+https://github.com/lodash/lodash.git") {
      throw new Error(`npm registry identity mismatch for lodash ${version}.`);
    }
    const tarballResponse = await fetch(metadata.dist.tarball);
    if (!tarballResponse.ok) throw new Error(`npm artifact fetch failed for lodash ${version}.`);
    const tarball = Buffer.from(await tarballResponse.arrayBuffer());
    const manifest = {
      gitHead: metadata.gitHead,
      integrity: metadata.dist.integrity,
      name: metadata.name,
      repository: metadata.repository.url,
      tarball: metadata.dist.tarball,
      version: metadata.version,
    };
    archivedSources.push(await archiveSource(`https://registry.npmjs.org/lodash/${version}`, "SUPPLEMENTAL",
      metadataResponse.status, metadataBytes, true));
    releases.push({
      version,
      commit: metadata.gitHead,
      artifactDigest: sha256(tarball),
      manifestDigest: sha256(JSON.stringify(manifest)),
      manifest,
      metadataBodyBytes: Buffer.byteLength(metadataText),
    });
  }

  const title = advisory.summary;
  const owner = account.address.toLowerCase();
  const txs = [];
  const send = async (label, functionName, args) => {
    const hash = await client.writeContract({ account, address, functionName, args, value: 0n });
    process.stdout.write(`\nSUBMITTED ${label} ${hash}\n`);
    const receipt = await client.waitForTransactionReceipt({
      hash,
      status: TransactionStatus.FINALIZED,
      interval: 5_000,
      retries: 120,
    });
    const summary = receiptSummary(label, hash, receipt);
    txs.push(summary);
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    if (receipt.status_name !== "FINALIZED" || receipt.result_name !== "MAJORITY_AGREE") {
      throw new Error(`${label} did not finalize with majority agreement.`);
    }
    const leader = receipt.consensus_data?.leader_receipt?.find((item) => item.mode === "leader");
    if (leader?.execution_result !== "SUCCESS") throw new Error(`${label} leader execution failed.`);
    const votes = Object.values(receipt.consensus_data?.votes ?? {});
    const agreementCount = votes.filter((vote) => vote === "agree").length;
    const hasConsensusDisagreement = votes.some((vote) => vote === "disagree" || vote === "invalid");
    if (votes.length < 3 || agreementCount < Math.floor(votes.length / 2) + 1
        || (hasConsensusDisagreement && !label.startsWith("evaluate-"))) {
      throw new Error(`${label} did not receive a strict validator majority.`);
    }
    if (hasConsensusDisagreement) process.stdout.write(`WARNING ${label} finalized majority consensus despite individual disagree/invalid validator votes.\n`);
    return summary;
  };

  if (Number(releaseCount) === 0) {
    await send("authorize-api-github", "authorize_source_host", ["api.github.com", "PRIMARY"]);
    await send("authorize-npm-registry", "authorize_source_host", ["registry.npmjs.org", "SUPPLEMENTAL"]);
    await send("authorize-api-osv-primary", "authorize_source_host", ["api.osv.dev", "PRIMARY"]);
    await send("authorize-api-osv-supplemental", "authorize_source_host", ["api.osv.dev", "SUPPLEMENTAL"]);
  }

  const first = releases[0];
  if (Number(releaseCount) === 0) {
    await send("register-vulnerable-release", "register_release", [
      PROJECT, REPOSITORY, owner, first.version, first.commit, first.artifactDigest,
      "npm", "lodash", first.manifestDigest, "",
    ]);
  }
  const vulnerable = await read(client, address, "get_release", ["rel-1"]);
  if (vulnerable.owner?.toLowerCase() !== owner || vulnerable.package_name !== "lodash"
      || vulnerable.version !== first.version || vulnerable.commit_sha !== first.commit
      || vulnerable.artifact_digest !== first.artifactDigest || vulnerable.manifest_digest !== first.manifestDigest) {
    throw new Error("Existing vulnerable release does not match freshly verified npm artifact data.");
  }

  const second = releases[1];
  if (Number(releaseCount) < 2) {
    await send("register-patched-successor", "register_release", [
      PROJECT, REPOSITORY, owner, second.version, second.commit, second.artifactDigest,
      "npm", "lodash", second.manifestDigest, vulnerable.id,
    ]);
  }
  const patched = await read(client, address, "get_release", ["rel-2"]);
  if (patched.owner?.toLowerCase() !== owner || patched.package_name !== "lodash"
      || patched.version !== second.version || patched.commit_sha !== second.commit
      || patched.artifact_digest !== second.artifactDigest || patched.manifest_digest !== second.manifestDigest
      || patched.predecessor_id !== vulnerable.id) {
    throw new Error("Existing patched release does not match its verified artifact or predecessor.");
  }

  const frozenSourcesA = [
    { url: SOURCES[0].url, role: "PRIMARY" },
    { url: "https://registry.npmjs.org/lodash/4.17.23", role: "SUPPLEMENTAL" },
  ];
  if (Number(assessmentCount) === 0) {
    await send("register-vulnerable-assessment", "register_assessment", [
      vulnerable.id, ADVISORY_ID, advisoryRevision, title, "npm", "lodash", POLICY_VERSION,
      JSON.stringify(frozenSourcesA),
    ]);
  }
  const assessmentA = await read(client, address, "get_assessment", ["asm-1"]);
  if (assessmentA.state === "OPEN") await send("evaluate-vulnerable-assessment", "evaluate_assessment", [assessmentA.id]);

  const frozenSourcesB = [
    { url: SOURCES[0].url, role: "PRIMARY" },
    { url: "https://registry.npmjs.org/lodash/4.18.0", role: "SUPPLEMENTAL" },
  ];
  if (Number(assessmentCount) < 2) {
    await send("register-patched-assessment", "register_assessment", [
      patched.id, ADVISORY_ID, advisoryRevision, title, "npm", "lodash", POLICY_VERSION,
      JSON.stringify(frozenSourcesB),
    ]);
  }
  const assessmentB = await read(client, address, "get_assessment", ["asm-2"]);
  if (assessmentB.state === "OPEN") await send("evaluate-patched-assessment", "evaluate_assessment", [assessmentB.id]);

  const frozenSourcesF = [
    { url: OSV_URL, role: "PRIMARY" },
    { url: "https://registry.npmjs.org/lodash/4.18.0", role: "SUPPLEMENTAL" },
  ];
  await send("register-osv-indexed-assessment", "register_assessment", [
    patched.id, ADVISORY_ID, osvRevision, osv.summary ?? title, "npm", "lodash", POLICY_VERSION,
    JSON.stringify(frozenSourcesF),
  ]);
  const assessmentF = await read(client, address, "get_assessment_by_identity", [patched.id, ADVISORY_ID, osvRevision]);
  if (assessmentF.state === "OPEN") await send("evaluate-osv-indexed-assessment", "evaluate_assessment", [assessmentF.id]);

  const incorrectRevision = `ghsa-sha256:${"0".repeat(64)}`;
  await send("register-false-revision-control", "register_assessment", [
    vulnerable.id, ADVISORY_ID, incorrectRevision, title, "npm", "lodash", POLICY_VERSION,
    JSON.stringify([{ url: SOURCES[0].url, role: "PRIMARY" }, { url: "https://registry.npmjs.org/lodash/4.17.23", role: "SUPPLEMENTAL" }]),
  ]);
  const assessmentD = await read(client, address, "get_assessment_by_identity", [vulnerable.id, ADVISORY_ID, incorrectRevision]);
  if (assessmentD.state === "OPEN") await send("evaluate-false-revision-control", "evaluate_assessment", [assessmentD.id]);

  const revocationProject = "stargaze-revocation-fixture";
  await send("register-revocation-fixture-release", "register_release", [
    revocationProject, REPOSITORY, owner, second.version, second.commit, second.artifactDigest,
    "npm", "lodash", second.manifestDigest, "",
  ]);
  const releaseE = await read(client, address, "get_release_by_identity", [revocationProject, "npm", "lodash", second.version, second.commit]);
  const sourcesE = [
    { url: SOURCES[0].url, role: "PRIMARY" },
    { url: OSV_URL, role: "SUPPLEMENTAL" },
  ];
  await send("register-revocation-assessment", "register_assessment", [
    releaseE.id, ADVISORY_ID, advisoryRevision, title, "npm", "lodash", POLICY_VERSION, JSON.stringify(sourcesE),
  ]);
  const assessmentE = await read(client, address, "get_assessment_by_identity", [releaseE.id, ADVISORY_ID, advisoryRevision]);
  if (assessmentE.state === "OPEN") await send("evaluate-revocation-assessment", "evaluate_assessment", [assessmentE.id]);

  const policyARequirements = [{ advisory_id: ADVISORY_ID, revision: advisoryRevision }];
  const policyBRequirements = [...policyARequirements, { advisory_id: ADVISORY_ID, revision: osvRevision }];
  const policyA = JSON.stringify(policyARequirements);
  const policyB = JSON.stringify(policyBRequirements);
  const vulnerableGate = await read(client, address, "authorization_for_release_compact", [vulnerable.id, compactRequirements(vulnerable.id, policyARequirements)]);
  const patchedGate = await read(client, address, "authorization_for_release_compact", [patched.id, compactRequirements(patched.id, policyBRequirements)]);
  const preRevocationGateE = await read(client, address, "authorization_for_release_compact", [releaseE.id, compactRequirements(releaseE.id, policyARequirements)]);
  await send("revoke-osv-supplemental-source", "revoke_source_host", ["api.osv.dev", "SUPPLEMENTAL"]);
  const revokedGateE = await read(client, address, "authorization_for_release_compact", [releaseE.id, compactRequirements(releaseE.id, policyARequirements)]);
  const finalAssessmentD = await read(client, address, "get_assessment", [assessmentD.id]);
  const finalAssessmentE = await read(client, address, "get_assessment", [assessmentE.id]);
  const finalAssessmentF = await read(client, address, "get_assessment", [assessmentF.id]);
  const finalVulnerable = await read(client, address, "get_assessment", [assessmentA.id]);
  const finalPatched = await read(client, address, "get_assessment", [assessmentB.id]);
  const attemptA = await read(client, address, "get_assessment_attempt", [assessmentA.id, 1]);
  const attemptB = await read(client, address, "get_assessment_attempt", [assessmentB.id, 1]);
  const attemptD = await read(client, address, "get_assessment_attempt", [assessmentD.id, 1]);
  const attemptE = await read(client, address, "get_assessment_attempt", [assessmentE.id, 1]);
  const attemptF = await read(client, address, "get_assessment_attempt", [assessmentF.id, 1]);
  const lineage = await read(client, address, "get_release_lineage", [patched.id]);
  const archiveManifest = { domain: "STARGAZE_ADVISORY_ARCHIVE_V1", provider: "github", advisory_id: ADVISORY_ID,
    ecosystem: "npm", package_name: "lodash", revision: advisoryRevision, primary_url: SOURCES[0].url,
    sources: archivedSources };
  for (const [label, assessment, attempt] of [["scenario A", finalVulnerable, attemptA], ["scenario B", finalPatched, attemptB]]) {
    if (assessment.revision !== advisoryRevision || assessment.revision_authenticated !== true || assessment.evidence_complete !== true
        || assessment.attempt_count !== 1 || attempt.packet_digest !== assessment.packet_digest) {
      throw new Error(`${label} final state does not contain the expected authenticated, complete attempt.`);
    }
    for (const committed of attempt.manifest) {
      const archived = archivedSources.find((item) => item.url === committed.url && item.role === committed.role);
      if (!archived || archived.body_sha256 !== committed.body_sha256 || archived.body_bytes !== committed.body_bytes
          || archived.response_status !== committed.response_status || committed.metadata_identity_valid !== true) {
        throw new Error(`${label} finalized source commitment does not match the exact archived response bytes.`);
      }
    }
  }
  if (finalAssessmentD.state !== "INVALID_REVISION" || finalAssessmentD.revision_authenticated === true
      || finalAssessmentD.eligible === true || attemptD.failure_reason !== "AUTHORITATIVE_ID_PACKAGE_OR_REVISION_MISMATCH") {
    throw new Error("False-revision control did not fail closed with an immutable invalid-revision attempt.");
  }
  if (finalAssessmentE.state !== "DECIDED" || finalAssessmentE.verdict !== "NOT_AFFECTED"
      || preRevocationGateE.status !== "AUTHORIZED_FOR_POLICY_SET" || revokedGateE.status !== "HOLD") {
    throw new Error("Emergency source-role revocation did not block current promotion while retaining historical decision state.");
  }
  if (finalAssessmentF.state !== "DECIDED" || finalAssessmentF.verdict !== "NOT_AFFECTED"
      || finalAssessmentF.revision !== osvRevision || patchedGate.status !== "AUTHORIZED_FOR_POLICY_SET") {
    if (finalAssessmentF.state !== "INVALID_REVISION" || finalAssessmentF.revision_authenticated !== true) {
      throw new Error("OSV indexed multi-revision policy did not either authenticate and authorize, or fail closed as INVALID_REVISION.");
    }
    process.stdout.write("WARNING OSV consensus finalized INVALID_REVISION; indexed multi-revision authorization correctly remains HOLD.\n");
  }
  const replayRoot = `evidence/replays/studionet-${address.toLowerCase()}`;
  for (const id of [assessmentA.id, assessmentB.id, assessmentD.id, assessmentE.id, assessmentF.id]) await mkdir(`${replayRoot}/${id}`, { recursive: true });
  await writeFile(`${replayRoot}/archive.json`, JSON.stringify(archiveManifest, null, 2) + "\n");
  for (const [directory, assessment, release, attempt, specificArchive] of [
    [assessmentA.id, finalVulnerable, vulnerable, attemptA, archiveManifest],
    [assessmentB.id, finalPatched, patched, attemptB, archiveManifest],
    [assessmentD.id, finalAssessmentD, vulnerable, attemptD, { ...archiveManifest, revision: incorrectRevision }],
    [assessmentE.id, finalAssessmentE, releaseE, attemptE, archiveManifest],
    [assessmentF.id, finalAssessmentF, patched, attemptF, { ...archiveManifest, provider: "osv", revision: osvRevision, primary_url: OSV_URL }],
  ]) {
    await writeFile(`${replayRoot}/${directory}/assessment.json`, JSON.stringify(assessment, null, 2) + "\n");
    await writeFile(`${replayRoot}/${directory}/release.json`, JSON.stringify(release, null, 2) + "\n");
    await writeFile(`${replayRoot}/${directory}/attempt.json`, JSON.stringify(attempt, null, 2) + "\n");
    await writeFile(`${replayRoot}/${directory}/archive.json`, JSON.stringify(specificArchive, null, 2) + "\n");
  }
  const gateRun = (label, releaseId, artifactDigest, required, shouldAuthorize) => {
    const marker = `${replayRoot}/protected-${label}-${Date.now()}.txt`;
    const policyPath = `${replayRoot}/policy-${label}.json`;
    writeFileSync(policyPath, JSON.stringify({ chain_id: CHAIN_ID, contract_address: address, release_id: releaseId,
      artifact_digest: artifactDigest, required }, null, 2));
    const command = spawnSync(process.execPath, [resolve("node_modules/tsx/dist/cli.mjs"), "scripts/gate.ts", policyPath,
      "--", process.execPath, "-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'protected command executed')`],
      { shell: false, encoding: "utf8", env: { ...process.env, STARGAZE_CONTRACT_ADDRESS: address } });
    const markerExists = existsSync(marker);
    if (shouldAuthorize ? command.status !== 0 || !markerExists : command.status === 0 || markerExists) {
      throw new Error(`The live ${label} gate did not ${shouldAuthorize ? "execute" : "block"} its protected command.`);
    }
    return { exitCode: command.status, protectedCommandExecuted: markerExists,
      stdout: command.stdout, stderr: command.stderr };
  };
  const gateExecutionA = gateRun("scenario-a", vulnerable.id, vulnerable.artifact_digest, policyARequirements, false);
  const gateExecutionB = gateRun("scenario-b", patched.id, patched.artifact_digest, policyBRequirements, true);
  const gateExecutionEBefore = gateRun("scenario-e-before-revocation", releaseE.id, releaseE.artifact_digest, policyARequirements, true);
  const gateExecutionEAfter = gateRun("scenario-e-after-revocation", releaseE.id, releaseE.artifact_digest, policyARequirements, false);
  const proof = {
    chainId: observedChainId,
    rpc: RPC,
    contractAddress: address,
    owner: account.address,
    sourceCommitment: { advisory: ADVISORY_ID, revision: advisoryRevision, title, bodyBytes: advisoryBytes.length, sources: [
      SOURCES[0], { url: "https://registry.npmjs.org/lodash/4.17.23", role: "SUPPLEMENTAL" },
      { url: "https://registry.npmjs.org/lodash/4.18.0", role: "SUPPLEMENTAL" },
    ] },
    releases,
    transactions: txs,
    scenarioA: { release: vulnerable, assessment: finalVulnerable, attempt: attemptA, gate: vulnerableGate, gateExecution: gateExecutionA },
    scenarioB: { release: patched, assessment: finalPatched, attempt: attemptB, gate: patchedGate, gateExecution: gateExecutionB, lineage },
    scenarioD: { assessment: finalAssessmentD, attempt: attemptD, expectedCommitment: incorrectRevision },
    scenarioE: { release: releaseE, assessment: finalAssessmentE, attempt: attemptE,
      gateBeforeRevocation: preRevocationGateE, gateAfterRevocation: revokedGateE,
      gateExecutionBefore: gateExecutionEBefore, gateExecutionAfter: gateExecutionEAfter,
      revokedSource: { host: "api.osv.dev", role: "SUPPLEMENTAL" } },
    scenarioF: { assessment: finalAssessmentF, attempt: attemptF, required: policyBRequirements,
      gate: patchedGate, protectedExecution: gateExecutionB },
    evidenceArchive: { root: replayRoot, manifest: archiveManifest, exactBytes: archivedSources },
  };
  process.stdout.write(`\nLIVE_PROOF ${JSON.stringify(proof)}\n`);
  if (finalVulnerable.verdict !== "AFFECTED" || vulnerableGate.status !== "HOLD"
      || finalPatched.verdict !== "NOT_AFFECTED" || patchedGate.status !== "AUTHORIZED_FOR_POLICY_SET"
      || finalAssessmentD.state !== "INVALID_REVISION" || revokedGateE.status !== "HOLD"
      || finalAssessmentF.verdict !== "NOT_AFFECTED" || gateExecutionB.protectedCommandExecuted !== true
      || finalVulnerable.state !== "DECIDED" || finalPatched.state !== "DECIDED"
      || lineage.length !== 2 || lineage[0].id !== vulnerable.id || lineage[1].id !== patched.id) {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(`LIVE_VERIFICATION_FAILED ${error?.stack ?? error}`);
  process.exitCode = 1;
});

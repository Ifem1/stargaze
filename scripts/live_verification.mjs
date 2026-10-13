import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
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
const PROJECT = "stargaze-live-verification-fixture";
const REPOSITORY = "https://github.com/lodash/lodash";

const read = (client, address, functionName, args = []) => client.readContract({
  address,
  functionName,
  args,
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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
  const advisoryText = await advisoryResponse.text();
  if (Buffer.byteLength(advisoryText) >= 12_000) throw new Error("Advisory API body exceeds the contract evidence limit.");
  const advisory = JSON.parse(advisoryText);
  const affectedRange = advisory.vulnerabilities?.find(
    (item) => item.package?.ecosystem === "npm" && item.package?.name === "lodash",
  )?.vulnerable_version_range;
  if (advisory.ghsa_id !== ADVISORY_ID || !affectedRange?.includes("<= 4.17.23") || !advisory.description?.includes("4.18.0")) {
    throw new Error("Live GHSA content does not confirm the expected affected/fixed lodash range.");
  }

  const releases = [];
  for (const version of ["4.17.23", "4.18.0"]) {
    const metadataResponse = await fetch(`https://registry.npmjs.org/lodash/${version}`);
    if (!metadataResponse.ok) throw new Error(`npm metadata fetch failed for lodash ${version}.`);
    const metadataText = await metadataResponse.text();
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
    releases.push({
      version,
      commit: metadata.gitHead,
      artifactDigest: sha256(tarball),
      manifestDigest: sha256(JSON.stringify(manifest)),
      manifest,
      metadataBodyBytes: Buffer.byteLength(metadataText),
    });
  }

  const advisoryRevision = advisory.updated_at;
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
    if (votes.length < 3 || agreementCount < Math.floor(votes.length / 2) + 1
        || votes.some((vote) => vote === "disagree" || vote === "invalid")) {
      throw new Error(`${label} did not receive a strict validator majority.`);
    }
    return summary;
  };

  if (Number(releaseCount) === 0) {
    await send("authorize-api-github", "authorize_source_host", ["api.github.com", "PRIMARY"]);
    await send("authorize-npm-registry", "authorize_source_host", ["registry.npmjs.org", "SUPPLEMENTAL"]);
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

  const policy = JSON.stringify([{ advisory_id: ADVISORY_ID, revision: advisoryRevision }]);
  const vulnerableGate = await read(client, address, "authorization_for_release", [vulnerable.id, policy]);
  const patchedGate = await read(client, address, "authorization_for_release", [patched.id, policy]);
  const finalVulnerable = await read(client, address, "get_assessment", [assessmentA.id]);
  const finalPatched = await read(client, address, "get_assessment", [assessmentB.id]);
  const lineage = await read(client, address, "get_release_lineage", [patched.id]);
  const proof = {
    chainId: observedChainId,
    rpc: RPC,
    contractAddress: address,
    owner: account.address,
    sourceCommitment: { advisory: ADVISORY_ID, revision: advisoryRevision, title, bodyBytes: Buffer.byteLength(advisoryText), sources: [
      SOURCES[0], { url: "https://registry.npmjs.org/lodash/4.17.23", role: "SUPPLEMENTAL" },
      { url: "https://registry.npmjs.org/lodash/4.18.0", role: "SUPPLEMENTAL" },
    ] },
    releases,
    transactions: txs,
    scenarioA: { release: vulnerable, assessment: finalVulnerable, gate: vulnerableGate },
    scenarioB: { release: patched, assessment: finalPatched, gate: patchedGate, lineage },
  };
  process.stdout.write(`\nLIVE_PROOF ${JSON.stringify(proof)}\n`);
  if (finalVulnerable.verdict !== "AFFECTED" || vulnerableGate.status !== "HOLD"
      || finalPatched.verdict !== "NOT_AFFECTED" || patchedGate.status !== "AUTHORIZED_FOR_POLICY_SET"
      || finalVulnerable.state !== "DECIDED" || finalPatched.state !== "DECIDED"
      || lineage.length !== 2 || lineage[0].id !== vulnerable.id || lineage[1].id !== patched.id) {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(`LIVE_VERIFICATION_FAILED ${error?.stack ?? error}`);
  process.exitCode = 1;
});

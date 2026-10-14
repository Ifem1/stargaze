import { mkdir, writeFile } from "node:fs/promises";
import { createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { TransactionHashVariant } from "genlayer-js/types";

const url = process.env.STARGAZE_PRODUCTION_URL ?? "https://stargaze-taupe.vercel.app";
const address = process.env.STARGAZE_CONTRACT_ADDRESS;
const expectedChainId = 61999;
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? "")) throw new Error("Set STARGAZE_CONTRACT_ADDRESS.");
if (studionet.id !== expectedChainId) throw new Error("Pinned GenLayerJS Studionet chain ID mismatch.");

const pageResponse = await fetch(url, { redirect: "follow" });
if (!pageResponse.ok) throw new Error(`Production page returned HTTP ${pageResponse.status}.`);
const html = await pageResponse.text();
const scripts = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map((match) => new URL(match[1], url).href);
if (scripts.length === 0) throw new Error("No served JavaScript bundles found in production HTML.");
const bundles = await Promise.all(scripts.map(async (scriptUrl) => {
  const response = await fetch(scriptUrl, { redirect: "follow" });
  if (!response.ok) throw new Error(`Bundle returned HTTP ${response.status}: ${scriptUrl}`);
  return { url: scriptUrl, body: await response.text() };
}));
const configuredAddress = address.toLowerCase();
const addressBundle = bundles.find((bundle) => bundle.body.toLowerCase().includes(configuredAddress));
if (!addressBundle) throw new Error("Served production bundles do not contain the canonical contract address.");

const client = createClient({ chain: studionet, endpoint: "https://studio.genlayer.com/api" });
const chainId = await client.getChainId();
if (chainId !== expectedChainId) throw new Error(`RPC returned chain ${chainId}, expected ${expectedChainId}.`);
const read = (functionName) => client.readContract({
  address,
  functionName,
  args: [],
  transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
});
const [releaseCount, assessmentCount] = await Promise.all([
  read("get_release_counter"),
  read("get_assessment_counter"),
]);
const result = {
  checkedAt: new Date().toISOString(),
  productionUrl: url,
  httpStatus: pageResponse.status,
  servedContractAddress: address,
  servedBundleUrl: addressBundle.url,
  chainId,
  rpc: "https://studio.genlayer.com/api",
  releaseCount: Number(releaseCount),
  assessmentCount: Number(assessmentCount),
  writeSubmitted: false,
};
await mkdir("evidence/live", { recursive: true });
const outputPath = process.env.STARGAZE_READBACK_OUTPUT ?? "evidence/live/production-readback.json";
await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

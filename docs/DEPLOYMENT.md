# Deployment

## Pinned network

- Stable GenLayer Studionet only: chain 61999 (0xF22F)
- RPC: https://studio.genlayer.com/api
- Explorer: https://explorer-studio.genlayer.com
- Repository-local GenLayer CLI: 0.39.1

Never use Studio Dev 61997 or a globally installed RC. Before writes verify CLI version, chain ID and RPC. Contract owner is the deploying address and only that owner administers source roles.

## Current canonical deployment

- Address: 0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a
- Transaction: 0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d
- Source SHA-256: 44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12
- Finalized: MAJORITY_AGREE, leader SUCCESS, five of five agrees
- RPC source check: exact 44,006-byte parity and 22-method schema, including compact authorization; see evidence/live/deployed-source-parity.json.
- Explorer verification badge: not shown / not claimed.

Older deployment addresses are superseded and must not be configured as canonical. See docs/LIVE_VERIFICATION.md for A/B, multi-advisory policy readbacks and remaining live-proof limitations.

## Deployment and application configuration

Run npm ci, install Python 3.12 test dependencies, then run GenVM preflight, lint and schema commands before deployment. Use scripts/deploy_studionet.ps1 on Windows and the repository-local CLI. Record finalized receipts and hash the exact contracts/stargaze.py input.

Set NEXT_PUBLIC_STARGAZE_CONTRACT_ADDRESS in frontend/.env.local for local use. Set the same value in Vercel Production and Preview. Rebuild/redeploy after environment changes and verify that a served JavaScript bundle contains the canonical address and SDK reads target chain 61999.

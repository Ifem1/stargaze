# Deployment

## Pinned network

- Stable GenLayer Studionet only: chain `61999` (`0xF22F`)
- RPC: `https://studio.genlayer.com/api`
- Explorer: `https://explorer-studio.genlayer.com`
- CLI: repository-local `genlayer@0.39.1`

Never set the application or CLI to Studio Dev 61997. Do not deploy without a funded authorized wallet. Contract owner is the deploying address and is the only address that may change source-host eligibility for future assessments.

## Local checks

Run `npm ci` at the repository root, Python 3.12 with `pip install -e '.[test]'`, then `pytest`, `npx genvm-lint check contracts/stargaze.py`, and frontend lint/typecheck/test/build through the frontend npm workspace. Confirm the CLI reports version `0.39.1` and `network info` reports chain 61999 before any deployment.

## Stable deployment

Use the local `tooling/node_modules/.bin/genlayer` binary (or its Windows `.cmd` shim), never a global executable. The deploy command must use `https://studio.genlayer.com/api` explicitly. Record the source SHA-256, deploy transaction hash, contract address and finalized receipt in `docs/LIVE_VERIFICATION.md`. Configure the same address in `frontend/.env.production.local` and Vercel only after source verification.

No deployment has been performed as part of this initial local build. A funded local wallet and explicit external deployment authorization are required for public writes.

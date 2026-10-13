# Deployment

## Pinned network

- Stable GenLayer Studionet only: chain `61999` (`0xF22F`)
- RPC: `https://studio.genlayer.com/api`
- Explorer: `https://explorer-studio.genlayer.com`
- CLI: repository-local `genlayer@0.39.1`

Never set the application or CLI to Studio Dev 61997. Do not deploy without a funded authorized wallet. Contract owner is the deploying address and is the only address that may change source-host eligibility for future assessments.

## Local checks

Run `npm ci` at the repository root, Python 3.12 with `pip install -e '.[test]'`, then `pytest`, `npm run preflight:contract`, `npm run lint:contract`, and `npm run schema:contract`. These scripts call `scripts/run_genvm_lint.py`, which pins GenVM `v0.2.16` and keeps SDK artifacts inside the repository cache. Do not invoke a globally installed `genvm-lint` directly. Run frontend lint/typecheck/test/build through the frontend npm workspace. Confirm the repository-local CLI reports version `0.39.1` and `network info` reports chain 61999 before any deployment.

## Stable deployment

Use the repository-local `node_modules/.bin/genlayer` binary (or `node_modules/.bin/genlayer.cmd` on Windows), never a global executable. The deploy command must use `https://studio.genlayer.com/api` explicitly. Record the source SHA-256, deploy transaction hash, contract address and finalized receipt in `docs/LIVE_VERIFICATION.md`. The active deployment and live A/B evidence are recorded there. Configure that verified address in `frontend/.env.local` for localhost and in the STARGAZE Vercel project's `NEXT_PUBLIC_STARGAZE_CONTRACT_ADDRESS` for production and preview.

Deployment used a funded throwaway Studionet wallet after the user explicitly authorized that deployment and live cycle. Never reuse that wallet for production. Its contract ownership and registered release claims do not assert upstream project ownership or source provenance.

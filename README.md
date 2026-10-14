# Stargaze

**Know what is exposed before you ship.** Stargaze records the relationship between an exact declared software release and an exact authoritative vulnerability advisory revision, then provides a conservative policy-scoped release gate.

This is an advisory applicability protocol, not a general scanner or universal security badge. A release digest is a registrant's immutable claim; it is not proof that a particular binary was built or deployed from that digest.

## Components

- `contracts/stargaze.py` — one GenLayer Intelligent Contract for source authority, sealed release identity, advisory assessments, semantic consensus and historical lineage.
- `scripts/gate.ts` — fresh final-state authorization consumer that executes protected argv only when every required revision is cleared.
- `frontend/` — Next.js App Router, TypeScript, Tailwind, Framer Motion and injected-wallet UI. It has no mock production records.
- `docs/` — architecture, security, deployment and live evidence status.

## Network

Stable Studionet is fixed at chain **61999 (`0xF22F`)**, RPC `https://studio.genlayer.com/api`, explorer `https://explorer-studio.genlayer.com`. Studio Dev chain 61997 is not supported. The compatible GenLayer CLI is pinned locally to 0.39.1.

## Local development

Requires Python 3.12, Node.js 22+, npm, Docker only if running Studio Mode, and the repository-local GenLayer toolchain.

```powershell
python -m pip install -e ".[test]"
pytest -q
npm ci
npm --workspace frontend run lint
npm --workspace frontend run typecheck
npm --workspace frontend test -- --run
npm --workspace frontend run build
```

See [deployment](docs/DEPLOYMENT.md) before any public write. Public deployment requires an authorized, funded local wallet; never paste a private key into chat. The downstream gate accepts a JSON policy with an explicit non-empty `required` list and a protected command after `--`.

## Deployment status

The current canonical deployment is stable Studionet contract [0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a](https://explorer-studio.genlayer.com/address/0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a), transaction [0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d](https://explorer-studio.genlayer.com/tx/0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d). Its source SHA-256 is 44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12; stable RPC source bytes were rechecked byte-for-byte. The live evidence includes two distinct advisory clearances and a compact gate proof. The user reports having manually tested the production frontend and considers it finished; no frontend transaction hash was supplied. A genuine live retry remains unverified. See [live verification](docs/LIVE_VERIFICATION.md) and [final closeout](docs/FINAL_STEWARD_MORE_INFO_CLOSEOUT.md). Source repository: [github.com/Ifem1/stargaze](https://github.com/Ifem1/stargaze).

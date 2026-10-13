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

## Live evidence

**Hardened contract and both advisory scenarios verified.** The canonical Studionet contract is [`0xa3AfabB8af00ac53bDcf5C56ff8D445B39C6a620`](https://explorer-studio.genlayer.com/address/0xa3AfabB8af00ac53bDcf5C56ff8D445B39C6a620). The production frontend is [stargaze-taupe.vercel.app](https://stargaze-taupe.vercel.app), configured to read this address. Deployment, transaction receipts, validator outcomes, packet commitments, both gates and the production read check are recorded in [live verification](docs/LIVE_VERIFICATION.md). The source repository is [github.com/Ifem1/stargaze](https://github.com/Ifem1/stargaze).

The contract source is not shown as explorer-verified. Release registration proves a submitter's declared identity and artifact digest; it does not establish publisher ownership or binary provenance. Semantic consensus is evidence of validator agreement under this protocol, not proof that model classification is universally correct. See [security limits](docs/SECURITY.md) and the [live evidence record](docs/LIVE_VERIFICATION.md).

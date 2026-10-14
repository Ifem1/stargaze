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

The hardened source is deployed to stable Studionet at [`0xb47A5B73D31007e38264A89998a7eBfD7Be46144`](https://explorer-studio.genlayer.com/address/0xb47A5B73D31007e38264A89998a7eBfD7Be46144), from transaction [`0xd43414bc64d4be0d3676f0781d3589bf33a8159c5c8ed1e8e131d0c68da0bc23`](https://explorer-studio.genlayer.com/tx/0xd43414bc64d4be0d3676f0781d3589bf33a8159c5c8ed1e8e131d0c68da0bc23). Deployment finalized with `MAJORITY_AGREE`, leader execution `SUCCESS`, and five agreeing validators. The source SHA-256 is `d809a55066574ea367b8dd4c630261fd479ae53244694798602deb9d0dfb0fe6`.

The production frontend has been redeployed to [stargaze-taupe.vercel.app](https://stargaze-taupe.vercel.app); its served bundle and live Studionet reads match this address. Live A/B GHSA scenarios are finalized: the vulnerable release is blocked and its patched successor is authorized by the downstream gate. A third OSV assessment failed closed on a primary revision mismatch. See the [steward closeout](docs/FINAL_STEWARD_MORE_INFO_CLOSEOUT.md) and [live verification record](docs/LIVE_VERIFICATION.md) for transaction evidence, trust limits and outstanding publication status. The source repository is [github.com/Ifem1/stargaze](https://github.com/Ifem1/stargaze).

The contract source is not shown as explorer-verified. Release registration proves a submitter's declared identity and artifact digest; it does not establish publisher ownership or binary provenance. Semantic consensus is evidence of validator agreement under this protocol, not proof that model classification is universally correct. See [security limits](docs/SECURITY.md) and the [live evidence record](docs/LIVE_VERIFICATION.md).

# STARGAZE steward closeout

**State:** hardened implementation, stable Studionet deployment, live A/B assessment and gate proof, and Production readback are complete. Final CI status and repository push remain outstanding.

## Hardened audit changes

- Advisory identity is bound to canonical primary URLs and frozen GHSA/OSV identifiers. Returned metadata is checked against the requested advisory, package and ecosystem; exact primary bytes must match the frozen revision. Arbitrary paths on an allow-listed hostname fail closed.
- Assessment registration is restricted to the release owner, preventing unauthorized callers from preempting another release's assessment identity. Duplicate identities and cross-release attempts are rejected.
- The frontend supports one through four frozen evidence sources with required roles and stable sorting. Record confirmation checks the exact record identity and sequence. Injected-wallet popover actions and Studionet network switching remain.
- Contract history is append-only; successor lineage and per-source evidence commitments remain visible. Authorization is scoped to the exact release, artifact and required advisory revision set.

## Verification

- Direct Mode adversarial contract suite: **28 passed**.
- Downstream gate suite: **15 passed**.
- Frontend suite: **19 passed**.
- Contract lint, GenVM validation/preflight, schema check (20 methods: 15 views, 5 writes), gate typecheck, frontend lint/typecheck/build passed. `npm audit --omit=dev` previously reported zero vulnerabilities.
- Stable Studionet chain `61999` (`0xF22F`), repository-local CLI `0.39.1`.

## Canonical deployment and live proof

- Contract: [`0xb47A5B73D31007e38264A89998a7eBfD7Be46144`](https://explorer-studio.genlayer.com/address/0xb47A5B73D31007e38264A89998a7eBfD7Be46144)
- Deployment transaction: [`0xd43414bc64d4be0d3676f0781d3589bf33a8159c5c8ed1e8e131d0c68da0bc23`](https://explorer-studio.genlayer.com/tx/0xd43414bc64d4be0d3676f0781d3589bf33a8159c5c8ed1e8e131d0c68da0bc23)
- Deployed contract source SHA-256: `d809a55066574ea367b8dd4c630261fd479ae53244694798602deb9d0dfb0fe6`.
- Deployment receipt: `ACCEPTED`, `MAJORITY_AGREE`, leader execution `SUCCESS`, 5/5 agree.
- Scenario A: `rel-1` / `asm-1` finalized `AFFECTED`, evidence complete and revision authenticated, authorization `BLOCKED`; exact downstream policy exited 1 and did not execute the protected command. Evidence packet `ee6fdb427b27972be433b196debeec109100c2a1ef1330841ebcd675d393829a` replays from captured source bytes (`MATCH`, 13,001 bytes verified).
- Scenario B: successor `rel-2` / `asm-2` finalized `NOT_AFFECTED`, evidence complete and revision authenticated, authorization `AUTHORIZED_FOR_THIS_ADVISORY`; exact successor policy exited 0 and executed the protected command. Packet `bd7f21a5fc4492d93acb1024107d697b28a0df05bcc6e8b39c0dc62fa6a6f602`. The predecessor remains in lineage and historically affected.
- Additional OSV attempt `asm-3` finalized `INVALID_REVISION` with `PRIMARY_REVISION_UNAUTHENTICATED`, no verdict and no authorization. The fetched body hash differed from the frozen OSV revision. Its transaction reached `MAJORITY_AGREE` with 3 agree, 1 disagree and 1 idle; this is a majority result, not unanimous validator agreement.
- The combined GHSA+OSV gate read was denied after the RPC returned `RLP string ends with 308 superfluous bytes`. This is recorded as an RPC error, not represented as an authoritative policy HOLD. Live retry/recovery and revocation scenarios were not run.
- Current readback confirms chain `61999`, release counter `2`, assessment counter `3`; see `evidence/live/production-readback.json`. Gate output and execution markers are in `evidence/live/gates/`; source captures and replay inputs are under `evidence/`.

## Publication

- README now identifies the actual repository: [github.com/Ifem1/stargaze](https://github.com/Ifem1/stargaze).
- Vercel Production is `READY` at [stargaze-taupe.vercel.app](https://stargaze-taupe.vercel.app). The served bundle includes the canonical contract address and a real SDK read returned chain `61999` and the current `2` releases / `3` assessments. Preview is also `READY` and its address variable is configured; deployment protection prevented an anonymous bundle-parity check, so Preview bundle parity is not claimed.
- Final commit and GitHub Actions result are pending the local commit/push attempt. No green CI result is claimed for this closeout revision yet.

## Trust limits

Advisory responses are fetched over HTTPS and may change or be compromised; source allow-list administration is a trust input. Semantic consensus can still agree on an incorrect interpretation. A registered artifact digest is a registrant's claim and does not prove publisher control, build provenance or deployed binary identity. No explorer source-verification badge is claimed. A funded throwaway wallet was used for test deployment and live scenarios; it is not a production signer.

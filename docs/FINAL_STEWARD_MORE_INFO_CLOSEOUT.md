# STARGAZE final live evidence closeout

Canonical Studionet contract: [0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a](https://explorer-studio.genlayer.com/address/0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a). Deployment transaction: [0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d](https://explorer-studio.genlayer.com/tx/0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d). Network 61999; source SHA-256 `44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12`.

## Canonical records and source

On 2026-10-14, stable RPC returned exactly 44,006 bytes equal to the checked-in contract source, same SHA-256, and a 22-method schema with compact authorization. The finalized state readback contains two sealed releases and six assessments. Explorer source verification is not claimed. Existing Lodash records remain: `rel-1` 4.17.23 `AFFECTED` packet `ee6fdb427b27972be433b196debeec109100c2a1ef1330841ebcd675d393829a`; successor `rel-2` 4.18.0 `NOT_AFFECTED` packet `bd7f21a5fc4492d93acb1024107d697b28a0df05bcc6e8b39c0dc62fa6a6f602`.

Scenario A's TypeScript gate returned HOLD and did not run the protected command. Scenario B authorized the successor and executed its harmless protected command. A combined two-advisory gate also executed with both genuine clearances. Adding an unresolved OSV requirement returned HOLD and did not execute. Current full receipts/readbacks and exact outcomes are preserved in `evidence/live/canonical-final-state.json`, `evidence/live/gate-regression/result.json`, and `evidence/live/multi-advisory/result.json`.

## Two-advisory live policy

For declared Lodash 4.18.0, GitHub advisories GHSA-29mw-wpgm-hmr9 and GHSA-x5rq-j2xg-h7qm were independently checked against exact current provider bytes, frozen body hashes and published affected ranges. Both actual ranges exclude 4.18.0. On the canonical contract:

- Registration `asm-4`: `0xeb7be6f7133aaa74db489e8f384985650ad283b0469c6aa579b72c91407c2232`; evaluation `0x792ef5843d5be18df08183eafc7ae35cc9ba67c22d4397fc3d65985d018c13e4`; finalized `MAJORITY_AGREE`, execution `SUCCESS`, `NOT_AFFECTED`, packet `4a6344d1e2cd1d6e77a8e66cbd23e76aa6a07e1c70ca41366fe462e737d35a67`.
- Registration `asm-6`: `0xdb5d8b595899262455e3503ee6eac1108670aaee0a5a509c7f4bc7712b1de65c`; evaluation `0xdcd69add48767950e06704ae8e82b77e7546f7d83135dbb30f24a70b076e7885`; finalized `MAJORITY_AGREE`, execution `SUCCESS`, `NOT_AFFECTED`, packet `1e9936149fa58a00041b0175bf4610cd950f9b17249a26d3fce97eb3dc5778a4`.
- Compact result for both exact requirements: `AUTHORIZED_FOR_POLICY_SET`; TypeScript gate executed marker. The unresolved third requirement returned HOLD / `REQUIRED_REVISION_NOT_CLEARED`, with no command execution.

An earlier candidate GHSA-xxjr-mmjv-4gpg finalized `AFFECTED` for 4.18.0 although the published range ends at 4.17.22. This result is preserved and not treated as a clearance. No repeat attempt was made to seek a different verdict. This semantic inconsistency limits confidence in model judgments even where validators agree.

## Recovery and trust epoch

No live retryable outage was induced. Consequently there is no live retry tx or claim of `RETRYABLE_FAILURE` recovery. Direct Mode tests cover retry with frozen identity and immutable attempts; deployment services were not deliberately disrupted.

For trust testing, the identical source was deployed separately to `0x7b51b5546e352959Fa4B3479c3D6Ed30E9E79149` (deployment tx `0x57e598e35096cbba119384deea8327d911ba28f84c2c1d891f184a2f5aa0821c`, finalized `MAJORITY_AGREE` / `SUCCESS`). Source revoke finalized at `0x8bdd00643d39909264bf0a2ca3e3504bd1b73fa8103a158deb9d5e3c1b84c09c`, then reauthorization finalized at `0xfafbdc39d9e397e7dcb9cea640c6a65996d5cb64f80636b5baf4165ec42633f0`. Affected historical assessments remained blocked. Attempting to reattest the old AFFECTED record finalized at `0x80ee12747ef5812763914d1e29840845143259ae14bdfcdd4c1ed780d0d1d762`, consensus `MAJORITY_AGREE`, but leader execution `ERROR`; the old assessment remained unchanged. A separate epoch-3 evaluation `0xb749f3c54fc44c12c1d639fb5ed297f135250657b9947061619bb6fdc5c02c26` finalized `AFFECTED`, so the gate remained HOLD. Positive live reattestation and new identity-version authorization are not established; Direct Mode covers those restrictions. All trust test records are under `evidence/live/trust-epoch*`.

The OSV evaluation `0xedb8a5d5ec217e5dd1a03ebfcb1d02153a674a8cf353049620b2482ac34b309c` finalized `MAJORITY_DISAGREE`; RPC diagnostics expose no dissent rationale. It did not create a retryable assessment result and was not retried.

## Frontend and production

On 2026-10-14, the user reported manually testing the production frontend and confirmed it is finished. The injected-wallet browser session also directly observed connect, popover, Copy Address, Explorer link, disconnect and reconnect on Studionet 61999. The user's report did not include a transaction hash or detailed case log, so no specific manually tested cases or signed transaction receipt are inferred from it. A frontend-originated transaction remains without independent receipt evidence; no CLI write is represented as a frontend write. Wrong-network rejection and network-switch rejection remain supported by automated frontend tests, without an independent browser rejection observation.

Production URL is [stargaze-taupe.vercel.app](https://stargaze-taupe.vercel.app). Recheck returned HTTP 200, canonical address in the served bundle, chain 61999, and live counts of 2 releases / 6 assessments. Evidence is in `evidence/live/production-readback.json`.

## Test and trust limits

The closeout rerun passed 33 Direct Mode, 16 gate, 7 replay and 19 frontend tests (75 total), plus GenVM validation/lint/schema, TypeScript checks, frontend lint/build, and production dependency audit (0 vulnerabilities). The closeout commit's GitHub Actions run 38615862069 passed both jobs. Historical archived packet replay matched. RPC source parity is verified, but no explorer source badge is claimed. Consensus records validator agreement on captured inputs, not semantic truth. Publisher identity, artifact provenance, binary reproducibility and universal safety are outside this protocol.

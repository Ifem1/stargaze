# Live verification

## Canonical Studionet deployment

- Stable Studionet 61999 (`0xF22F`), RPC `https://studio.genlayer.com/api`.
- Canonical contract [0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a](https://explorer-studio.genlayer.com/address/0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a); deployment transaction [0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d](https://explorer-studio.genlayer.com/tx/0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d).
- Deployed source SHA-256 `44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12`. Recheck on 2026-10-14 fetched 44,006 RPC bytes identical to the 44,006 local bytes; RPC schema has 22 methods including compact authorization. See `evidence/live/deployed-source-parity.json`. Explorer source verification is not claimed.
- Latest authoritative readback: 2 sealed releases and 6 assessments; source roles GitHub PRIMARY and npm SUPPLEMENTAL are enabled. See `evidence/live/canonical-final-state.json`.

## A/B release and downstream gate

- `rel-1`, Lodash 4.17.23, GHSA-r5fr-rjxr-66jc revision `ghsa-sha256:3db586ba1c68306eb90349477e0491f239b1bba1c09e35c781529c5ff7bb10c4`: `DECIDED / AFFECTED`, packet `ee6fdb427b27972be433b196debeec109100c2a1ef1330841ebcd675d393829a`.
- `rel-2`, Lodash 4.18.0, predecessor `rel-1`, same revision: `DECIDED / NOT_AFFECTED`, packet `bd7f21a5fc4492d93acb1024107d697b28a0df05bcc6e8b39c0dc62fa6a6f602`.
- Canonical gate regression runs scenario A against `rel-1` and confirms HOLD/no protected command; scenario B against `rel-2` and confirms authorization/protected command; adding an unresolved OSV requirement confirms HOLD/no execution. Evidence: `evidence/live/gate-regression/result.json`. The two-clearance TypeScript gate execution and separate unresolved-requirement deny are in `evidence/live/multi-advisory/result.json`.

## Two-advisory positive and negative policy proof

Both genuine GHSA bodies were fetched from their canonical GitHub API endpoints, checked against their exact frozen SHA-256 revisions, matched to the lodash npm release identity and archived. Their published vulnerable ranges exclude 4.18.0. Each registration and evaluation finalized on the canonical address with `MAJORITY_AGREE` and leader `SUCCESS`:

| Advisory / assessment | Evaluation transaction | Final outcome | Packet digest |
| --- | --- | --- | --- |
| GHSA-29mw-wpgm-hmr9 / `asm-4`, revision `ghsa-sha256:72b126165303330bdfce6f5ea852162b2efa565796049a9166d53cc2ee381a16` | `0x792ef5843d5be18df08183eafc7ae35cc9ba67c22d4397fc3d65985d018c13e4` | `DECIDED / NOT_AFFECTED` | `4a6344d1e2cd1d6e77a8e66cbd23e76aa6a07e1c70ca41366fe462e737d35a67` |
| GHSA-x5rq-j2xg-h7qm / `asm-6`, revision `ghsa-sha256:e7ff9dc77fff9e03ae976b9b6b51a1b48cb97d7de150270c3b61ab05d7298c94` | `0xdcd69add48767950e06704ae8e82b77e7546f7d83135dbb30f24a70b076e7885` | `DECIDED / NOT_AFFECTED` | `1e9936149fa58a00041b0175bf4610cd950f9b17249a26d3fce97eb3dc5778a4` |

Each gate check reports exact identity, authenticated revision, complete evidence and valid trust epoch. The combined compact gate returned `AUTHORIZED_FOR_POLICY_SET`; the real TypeScript gate executed its harmless protected command (marker present). Adding unresolved `asm-3` OSV requirement `osv-sha256:6d94cb4483ee2659025e95633e85e3b5acde11b9013b2a126672eba03a36c457` returned HOLD / `REQUIRED_REVISION_NOT_CLEARED`; the command did not execute (marker absent). Full manifests, registration receipts, validator votes and gate outputs are in `evidence/live/multi-advisory/result.json`.

An earlier legitimate candidate, GHSA-xxjr-mmjv-4gpg (`asm-5`), finalized `AFFECTED` despite its published range ending at 4.17.22. Its exact result and packet are preserved in `evidence/live/multi-advisory/initial-candidate-result.json`; it is not used as a clearance. This observed semantic inconsistency is a residual risk and no favorable retry was attempted.

## Trust epoch and retry evidence

An isolated deployment of the same source was used to avoid changing canonical A/B records: `0x7b51b5546e352959Fa4B3479c3D6Ed30E9E79149`, deployment tx `0x57e598e35096cbba119384deea8327d911ba28f84c2c1d891f184a2f5aa0821c`, source hash equal to canonical. On this test contract, source revocation finalized at `0x8bdd00643d39909264bf0a2ca3e3504bd1b73fa8103a158deb9d5e3c1b84c09c`; reauthorization finalized at `0xfafbdc39d9e397e7dcb9cea640c6a65996d5cb64f80636b5baf4165ec42633f0`. The previous assessment remained immutable. A same-identity reattestation attempt after reauthorization finalized at `0x80ee12747ef5812763914d1e29840845143259ae14bdfcdd4c1ed780d0d1d762` with `MAJORITY_AGREE`, but leader execution was `ERROR`; no assessment history entry was added, and the old AFFECTED result remained blocked.

A separate epoch-3 advisory assessment (`asm-3`, GHSA-x5rq) finalized at `0xb749f3c54fc44c12c1d639fb5ed297f135250657b9947061619bb6fdc5c02c26`, consensus `MAJORITY_AGREE`, execution `SUCCESS`, but result was `AFFECTED`; gate remained HOLD. Because independent evaluations gave unexpected AFFECTED results against the stated version ranges, no further verdict-seeking attempts were made. Thus live revoke/reauthorize and adverse-result blocking are observed, but successful favorable reattestation/version-2 history is not demonstrated live. Direct Mode tests cover the restricted positive reattestation and adverse-bypass rules.

No genuine retryable operational outage was induced on Studionet. No live `RETRYABLE_FAILURE` followed by successful retry under the same identity is claimed. Direct Mode recovery tests and historical attempt replay are the evidence for this path; production dependencies were not deliberately disrupted.

The earlier OSV assessment transaction `0xedb8a5d5ec217e5dd1a03ebfcb1d02153a674a8cf353049620b2482ac34b309c` finalized `MAJORITY_DISAGREE`; RPC exposes no dissent rationale. It is not treated as a retryable failure or a semantic verdict. Receipt diagnostics: `evidence/live/osv-disagreement-receipt.json`.

## Replay and frontend

- Historical archived advisory evidence replayed `MATCH` with 13,001 verified source bytes. Seven replay tests cover immutable prior attempts, successful recovery, tampering, missing snapshots and mismatched identities. Archived packet files are under `evidence/snapshots/sha256/`.
- On 2026-10-14, the user reported manually testing the production frontend and confirmed it is finished. Separately observed in the injected-wallet browser session: connect, wallet popover, Copy Address (UI confirmed “Copied”), View in Explorer, disconnect and reconnect; chain indicator showed Studionet 61999. The user did not provide a transaction hash or detailed test log, so this report records the user's manual test attestation without inferring specific test cases or a signed transaction receipt. No frontend-originated transaction is independently recorded; no CLI transaction is substituted for that proof. Wrong-network rejection and network-switch rejection are covered by frontend tests, not independently observed in that browser session.
- Vercel Production is [https://stargaze-taupe.vercel.app](https://stargaze-taupe.vercel.app), deployment `dpl_BHxkbJbSBD6fuQxB6mgCA6qSxd8h`. Recheck on 2026-10-14 returned HTTP 200, confirmed the canonical address in the served bundle and chain 61999, and read 2 releases / 6 assessments from Studionet. Evidence: `evidence/live/production-readback.json`.

## Limits

Consensus and packet commitments establish what validators observed and agreed on, not that semantic judgments are correct. The release owner supplies identity and artifact digests; Stargaze does not prove publisher identity, source-code provenance, binary reproducibility, or deployment of the claimed artifact. Approved sources and TLS/API infrastructure remain trust inputs. Explorer source verification is unavailable/not claimed. The live retry, favorable trust-epoch reattestation, and frontend-originated signed write remain unverified as stated above.

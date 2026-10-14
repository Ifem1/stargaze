# STARGAZE final engineering closeout

Canonical deployment (2026-10-14): Stable Studionet 61999, address [0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a](https://explorer-studio.genlayer.com/address/0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a), transaction [0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d](https://explorer-studio.genlayer.com/tx/0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d). Source SHA-256: 44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12.

## Completed evidence

- Deployment finalized MAJORITY_AGREE; leader execution SUCCESS; five validators agreed. The repository-local GenLayer CLI was 0.39.1; chain/RPC were checked as 61999 and https://studio.genlayer.com/api.
- RPC getContractCode returned 44,006 bytes byte-for-byte equal to contracts/stargaze.py. Both hashes are 44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12. RPC schema exposes 22 methods, including authorization_for_release_compact. See evidence/live/deployed-source-parity.json. This is RPC byte parity, not an explorer source-verification badge.
- Finalized reads show rel-1 (Lodash 4.17.23) remains AFFECTED, and successor rel-2 (Lodash 4.18.0) remains NOT_AFFECTED. Packets: ee6fdb427b27972be433b196debeec109100c2a1ef1330841ebcd675d393829a and bd7f21a5fc4492d93acb1024107d697b28a0df05bcc6e8b39c0dc62fa6a6f602.
- Compact authorization returned AUTHORIZED_FOR_POLICY_SET for the single cleared GHSA requirement. Adding an unresolved OSV revision returned HOLD / REQUIRED_REVISION_NOT_CLEARED without the prior RLP decoding error. This does not establish two separately cleared advisories.
- OSV evaluation tx 0xedb8a5d5ec217e5dd1a03ebfcb1d02153a674a8cf353049620b2482ac34b309c finalized MAJORITY_DISAGREE in round 3, with three disagree votes and leader execution SUCCESS. It did not create a semantic decision.
- The prior archived GHSA packet replayed MATCH with 13,001 source bytes verified. Replay tests cover earlier failed attempts, successful recovery, tampering, missing snapshots, mismatched identities and later appended attempts.
- Local tests: 33 Direct Mode, 16 gate, 7 replay and 19 frontend (75 total). GenVM lint/preflight/schema, TypeScript checks, ESLint and optimized build passed.

## Outstanding

- No two-distinct-advisory live clearance has been established.
- Live retry/recovery and revoke/reauthorize reattestation were not demonstrated. Direct Mode tests cover the bounded recovery and trust-epoch protections; no outage was simulated.
- No injected EIP-1193 provider was available in the browser profile. Real connect/disconnect/reconnect, network switch/rejection, and a frontend-originated transaction remain unverified and require an authorized wallet session.
- Vercel Production and Preview environment variables were aligned to the canonical address. Production deployment `dpl_BHxkbJbSBD6fuQxB6mgCA6qSxd8h` is READY and aliased to https://stargaze-taupe.vercel.app. Production readback returned HTTP 200, bundle contains the canonical contract, Studionet chain 61999, two releases and three assessments (evidence/live/production-readback.json).
- GitHub Actions will run the seven historical replay tests on the closeout commit; the prior run predates this workflow addition.
- Explorer source verification is not claimed. Older deployment addresses in repository history are superseded; the address above is canonical for this source revision.

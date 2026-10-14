# Live verification

## Canonical deployment

- Stable Studionet 61999 (0xF22F), RPC https://studio.genlayer.com/api.
- Contract [0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a](https://explorer-studio.genlayer.com/address/0xDf2961e690E1eEE004C443eAB10c389113C7Bd6a).
- Deployment [0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d](https://explorer-studio.genlayer.com/tx/0xc73c96a3628af052cc93536c10e450a8d1097f18cc37c12c3aa9242969350c3d).
- Source SHA-256 44ef3c31b58084da690263cc9d7c05debba319d920d509462b0046077753da12.
- Deployment finalized MAJORITY_AGREE, leader SUCCESS, five validator commits/reveals and five agrees.
- RPC source parity: 44,006 remote bytes equal local bytes, SHA-256 matches, schema has 22 methods including compact authorization. See evidence/live/deployed-source-parity.json. Explorer source badge is not present and is not claimed.

## Finalized reads

- rel-1, Lodash 4.17.23, GHSA-r5fr-rjxr-66jc: DECIDED / AFFECTED, packet ee6fdb427b27972be433b196debeec109100c2a1ef1330841ebcd675d393829a.
- rel-2, Lodash 4.18.0, predecessor rel-1, same GHSA revision: DECIDED / NOT_AFFECTED, packet bd7f21a5fc4492d93acb1024107d697b28a0df05bcc6e8b39c0dc62fa6a6f602.
- One requirement compact policy for rel-2 returned AUTHORIZED_FOR_POLICY_SET. Combining that cleared requirement with unresolved OSV identity returned HOLD / REQUIRED_REVISION_NOT_CLEARED. Compact multi-item read did not reproduce the earlier RLP error. This is not evidence of two cleared distinct advisories.
- Current finalized counters were two releases and three assessments. asm-3 remained OPEN with no attempt or verdict.
- OSV evaluation transaction 0xedb8a5d5ec217e5dd1a03ebfcb1d02153a674a8cf353049620b2482ac34b309c finalized MAJORITY_DISAGREE in round 3 (three disagreements); leader execution succeeded. No verdict is inferred.
- The earlier GHSA archive replays MATCH and verifies 13,001 bytes. Seven replay tests cover independent attempt replay and tamper cases.

## Remaining verification

- Two distinct advisories both cleared on-chain; live retry after a genuine operational failure; and live source revocation/recovery remain outstanding.
- No real injected EIP-1193 provider was available. Wallet lifecycle and frontend-originated signed transaction require an authorized manual browser wallet session.
- Vercel Production and Preview now use the canonical contract variable. Production deployment `dpl_BHxkbJbSBD6fuQxB6mgCA6qSxd8h` is READY; HTTP 200 and bundle/chain/record readback are recorded in evidence/live/production-readback.json.
- Local tests passed: 33 Direct Mode, 16 gate, 7 replay and 19 frontend. GenVM validation/lint/schema, type checks, frontend lint and build passed. The earlier CI run predates replay-suite inclusion.
- RPC parity is not an explorer verification badge, publisher identity proof, artifact provenance or semantic correctness certification.

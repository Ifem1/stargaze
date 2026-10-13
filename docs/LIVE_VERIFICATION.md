# Live verification record

Status: **LIVE VERIFICATION COMPLETE** for contract and scenarios A/B on stable GenLayer Studionet, chain `61999` (`0xF22F`). Reads and receipts were independently repeated against `https://studio.genlayer.com/api` on 2026-10-13.

## Deployment

- Active contract: [`0xD58aC601B897e69B789dA689A5704980470A8349`](https://explorer-studio.genlayer.com/address/0xD58aC601B897e69b789dA689A5704980470A8349)
- Deployment transaction: [`0x5eb4711a82c0b88d8906926cf0a062ab299dff27702939abd5b7ef30db8ef739`](https://explorer-studio.genlayer.com/tx/0x5eb4711a82c0b88d8906926cf0a062ab299dff27702939abd5b7ef30db8ef739)
- Receipt: `FINALIZED`, `MAJORITY_AGREE`; leader execution `SUCCESS`; round 0, five commits and five reveals, five validator `agree` votes.
- Deployed contract source SHA-256: `b943ca6629b402425f16fab78f3dd252dbb22490e58761cbdcd4a0306f0f2d4c`.
- Live reads returned release counter `2` and assessment counter `2`.

The first deployment, [`0xaa0f5cbc57502d3e12fa725621a748c4af69f5ae54fcf75273bfeb2d0a0fe80b`](https://explorer-studio.genlayer.com/tx/0xaa0f5cbc57502d3e12fa725621a748c4af69f5ae54fcf75273bfeb2d0a0fe80b), finalized, but its initial state fields were not declared as persistent GenLayer class attributes. On-chain counter reads exposed that storage defect before any live records were written. It is an unusable superseded deployment. The storage declarations were corrected, direct/preflight checks rerun, and the active deployment above was verified with readable counters before continuing.

The superseded address is `0xB858D204c858ECC60945062faf66643Af4C61112`; its deployment source SHA-256 was `8f2640e6ddaff2243892808c49c0a9595b7ca6a11f0ec136c1fcba54441e4544`. No registration or assessment was made against it.

## Real advisory evidence

- Advisory: [`GHSA-r5fr-rjxr-66jc`](https://github.com/advisories/GHSA-r5fr-rjxr-66jc), “lodash vulnerable to Code Injection via `_.template` imports key names”; fetched revision `2026-04-01T23:51:13Z`.
- Primary evidence URL: `https://api.github.com/advisories/GHSA-r5fr-rjxr-66jc`.
- Supplemental evidence URLs: `https://registry.npmjs.org/lodash/4.17.23` and `https://registry.npmjs.org/lodash/4.18.0`.
- Registry metadata identified the official lodash repository and upstream Git commits; each npm tarball was fetched and its SHA-256 checked before registration.
- **Registrant limitation:** these live release claims are owned by a funded throwaway test wallet under project label `stargaze-live-verification-fixture`. The signer is not represented as an upstream Lodash maintainer or publisher. Stargaze records immutable registrant claims and evidence; it does not prove ownership of the declared repository or that a digest produced a particular deployed binary.

| Release | Version | Upstream commit | npm tarball SHA-256 | Manifest SHA-256 | Predecessor |
|---|---|---|---|---|---|
| `rel-1` | 4.17.23 | `835a537f36ee2fd5fb7f524e213ff9ba2d8698f8` | `9aba685f4b44d7a8e778cdf7085e9512143dabd78812df40e258375e1e8dceb4` | `15071876d9804da13c29c06b00a40b9f15e6325a1619935c28969a062bac2da2` | — |
| `rel-2` | 4.18.0 | `0c9b60c1ae2656ef0d605e6726d72307eb5c31ff` | `aef19210308907f32d1b1d54f40e3cf461dbddae5605efe4027d6646c6967fb0` | `b80de74c0006598e9e55f8458ad18da0f7b3a6d3b77131528714b875bb4d509d` | `rel-1` |

## Full on-chain cycle

All eight protocol writes below finalized with `MAJORITY_AGREE`, leader execution `SUCCESS`, round 0, and five commits/reveals. None recorded a `disagree` or `invalid` vote. Some deterministic metadata writes had three or four active `agree` votes and the remaining validators `idle`; both semantic evaluations had three `agree` and two `idle` votes. The corrected deployment and both host authorizations received five `agree` votes.

| Operation | Transaction | Final result / votes |
|---|---|---|
| Allow `api.github.com` as primary evidence | [`0x39319f537359478737f9e40023d2641048feff4352a5734e743264f6a11852a2`](https://explorer-studio.genlayer.com/tx/0x39319f537359478737f9e40023d2641048feff4352a5734e743264f6a11852a2) | `MAJORITY_AGREE`, 5/5 agree |
| Allow `registry.npmjs.org` as supplemental evidence | [`0xa748e2229e447e01785b63d9926d7a0959159679c0c3aa41d9371eae19caa9ea`](https://explorer-studio.genlayer.com/tx/0xa748e2229e447e01785b63d9926d7a0959159679c0c3aa41d9371eae19caa9ea) | `MAJORITY_AGREE`, 5/5 agree |
| Register vulnerable release `rel-1` | [`0x50adaa47ea332747e5037fa7e5788b2cf006fef98e19c1feff9b2da9873ead4f`](https://explorer-studio.genlayer.com/tx/0x50adaa47ea332747e5037fa7e5788b2cf006fef98e19c1feff9b2da9873ead4f) | `MAJORITY_AGREE`, 3 agree / 2 idle |
| Register patched successor `rel-2` | [`0xcecd131ae5318c14e4873ca3df340ee30cf33844faea16571e8b810e0f0e52ba`](https://explorer-studio.genlayer.com/tx/0xcecd131ae5318c14e4873ca3df340ee30cf33844faea16571e8b810e0f0e52ba) | `MAJORITY_AGREE`, 3 agree / 2 idle |
| Register assessment `asm-1` | [`0xcdff010a4fd47d5cd18ebe783059e9620b102a4116694ff5a03ed50e49ea214c`](https://explorer-studio.genlayer.com/tx/0xcdff010a4fd47d5cd18ebe783059e9620b102a4116694ff5a03ed50e49ea214c) | `MAJORITY_AGREE`, 4 agree / 1 idle |
| Evaluate `asm-1` | [`0x3b588d01d0d372eeab7c3af9d7f56e3ea41a0cacbe26c67ef05e0b6ba945eaa6`](https://explorer-studio.genlayer.com/tx/0x3b588d01d0d372eeab7c3af9d7f56e3ea41a0cacbe26c67ef05e0b6ba945eaa6) | `MAJORITY_AGREE`, 3 agree / 2 idle |
| Register assessment `asm-2` | [`0x0e489a2cc3e2c57cec0770c5f3209ef7e34abbbd3ba54ff70f0dadeda0f634b1`](https://explorer-studio.genlayer.com/tx/0x0e489a2cc3e2c57cec0770c5f3209ef7e34abbbd3ba54ff70f0dadeda0f634b1) | `MAJORITY_AGREE`, 3 agree / 2 idle |
| Evaluate `asm-2` | [`0xc04ccbe5cb73dedc30d9629adcc3be6f96a139d48ec929d08930e9581779d035`](https://explorer-studio.genlayer.com/tx/0xc04ccbe5cb73dedc30d9629adcc3be6f96a139d48ec929d08930e9581779d035) | `MAJORITY_AGREE`, 3 agree / 2 idle |

Both records are `DECIDED` and `eligible=true` for the frozen advisory revision. Independently repeated final-state reads returned:

| Scenario | Release / assessment | Verdict | Packet SHA-256 | Assessment authorization | Downstream gate |
|---|---|---|---|---|---|
| A, vulnerable original | `rel-1` / `asm-1` | `AFFECTED` | `96942446b9bc638879313f60e5d6527eaebb87813577addecc9dde7e879e5646` | `BLOCKED` | `HOLD` (`REQUIRED_REVISION_NOT_CLEARED`) |
| B, patched successor | `rel-2` / `asm-2` | `NOT_AFFECTED` | `dab1081ceabe1e4c9636c37ec2c54e9b83a2848e5632a8faba3142e1296eb6c5` | `AUTHORIZED_FOR_THIS_ADVISORY` | `AUTHORIZED_FOR_POLICY_SET` |

The downstream policy was the exact non-empty JSON pair `[{"advisory_id":"GHSA-r5fr-rjxr-66jc","revision":"2026-04-01T23:51:13Z"}]`. Scenario B gate returned the matching `asm-2` check and exact artifact digest. The same policy returned `HOLD` for `rel-1`. `get_release_lineage("rel-2")` returned `[rel-1, rel-2]`; `rel-1` remains `SEALED`, and its historical `AFFECTED` assessment remains unchanged.

The actual TypeScript downstream consumer was then run against fresh final Studionet reads for both exact policy files. Scenario A exited `1` with `DENY: required revision ... is not finally cleared`; its harmless protected command did not execute. Scenario B returned `AUTHORIZED_FOR_POLICY_SET`, policy digest `2090283d49c3bf02e61a122cb7057fb08caa277139ba75d27e88866b61a65cba`, and ran the harmless local command (which printed `PROTECTED_COMMAND_EXECUTED_B`). This caught and fixed a Windows entry-point URL bug in the CLI before final verification.

## Verification run

- Python Direct Mode/adversarial suite: **13 passed**. It covers immutable release identity and duplicate rejection; source spoofing; affected blocking and historical persistence; missing evidence; exact packet/policy authorization; successor lineage; independent validator recomputation; conflicting evidence and malicious leader rejection; prompt injection treatment; revoked sources; cross-project lineage and duplicate assessment rejection; and conditional/noncanonical verdicts.
- Downstream gate unit suite: **9 passed**; live A/B side-effect checks are above.
- Frontend wallet tests: **5 passed**, covering the account popover actions, Studionet switch request, account/chain changes, rejected connection, and rejected network switch.
- GenVM `validate`, `check`/lint, and schema all passed against pinned SDK `v0.2.16`; schema reports 13 methods (8 views, 5 writes).
- Gate and frontend TypeScript checks, ESLint, and optimized Next.js production build passed. `npm audit --omit=dev` reported 0 vulnerabilities. Repository-local GenLayer CLI reported `0.39.1`.
- The localhost Next.js app returned HTTP 200, displayed both on-chain releases and verdicts, and the browser gate page independently displayed successor authorization and predecessor HOLD.
- No browser E2E suite is configured in this repository; component tests and the two live browser gate reads were exercised instead.

The deployed contract file checksum is recorded above, but the explorer does not currently show a separately published/verified source artifact in this project. The independent checks here are finalized transaction receipts, on-chain state reads, validator votes and reproducible local source hashing; no explorer source-verification badge is claimed.

## Local application and hosting

The local frontend is configured to read this verified contract from `frontend/.env.local` (ignored by Git). Start it with `npm --workspace frontend run dev` and visit `http://localhost:3000`. No Vercel deployment was performed; no Vercel credentials or project were configured in this workspace. No GitHub remote is configured; pushing remains the final step after a target repository URL is supplied.

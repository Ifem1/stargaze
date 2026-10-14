# Architecture

Stargaze uses one principal Intelligent Contract, `contracts/stargaze.py`, plus a TypeScript enforcement CLI and a Next.js App Router application.

## Contract records

- A release is a sealed registrant claim binding project/repository, registering wallet, package identity, version, source commit, artifact SHA-256, manifest SHA-256, and an optional same-project/package predecessor.
- An assessment is keyed by `(release_id, advisory_id, authenticated_revision)`. Only the sealed release owner can reserve that key. The revision is `ghsa-sha256:<64 lowercase hex>` or `osv-sha256:<64 lowercase hex>` and commits to the exact primary advisory response bytes.
- Each assessment has at most three append-only attempts. `OPEN` and `RETRYABLE_FAILURE` may be evaluated; `DECIDED`, `INVALID_REVISION`, and `SUSPENDED` cannot be reevaluated. Attempts retain a source manifest, packet commitment, revision metadata, failure category and verdict.
- Release-to-assessment ordering and assessment identity use separate `TreeMap` indexes. The authorization view resolves only the requested identity pairs, proportional to policy length.

## Evaluation and revision authentication

Registration freezes source URLs/roles, policy, package, revision commitment, and each source role's trust epoch. It does not assert that the revision is authenticated. The leader and every validator independently fetch all bounded evidence. GitHub metadata must return the exact GHSA ID, package/ecosystem, and valid `published_at`/`updated_at` values. OSV metadata must bind the exact ID or alias and affected package, and any `published`/`modified` metadata must be well-formed. The primary body SHA-256 must equal the frozen provider-prefixed revision.

The model receives evidence only after deterministic identity checks pass. It returns one exact semantic verdict. Malformed output and objectively incomplete retrieval are retryable; a valid `CONDITIONAL`/`INSUFFICIENT_EVIDENCE` result is a final substantive hold; mismatched or contradictory identity becomes `INVALID_REVISION`. The validators independently reproduce the complete canonical result JSON, including attempt identity, source manifest, revision authentication, metadata, packet digest and verdict. Contract state changes only after consensus finalizes.

## Evidence commitments and replay

Each manifest row stores frozen URL, role/kind, HTTP status, exact body SHA-256 and byte length, metadata identity result, source revision metadata and completeness. The packet digest covers the release, assessment/policy identity, attempt sequence, authenticated advisory metadata, ordered source manifest, completeness, outcome/failure and verdict. Exact response bytes are retained off-chain under `evidence/snapshots/sha256/<digest>.bin`; `scripts/replay_evidence.mjs` checks each byte file against the finalized manifest and recomputes the canonical packet digest from exported contract reads.

## Trust epochs and authorization

Source authorization and emergency revocation are owner-only and scoped to an exact `(hostname, role)`. Revocation increments that role's epoch. Pending work using the old epoch is suspended; previous results remain immutable, while the authorization view blocks current promotion. Reauthorization increments the epoch again and does not restore an old result. A fresh assessment under a new authenticated content revision is required.

`authorization_for_release()` validates a bounded, nonempty, duplicate-free policy and performs one identity-index read for each exact pair. It requires a `DECIDED`, complete, authenticated `NOT_AFFECTED` record with the current source epochs. Missing, affected, revoked, incomplete, invalid, or unfinalized state returns `HOLD`.

## TypeScript gate and frontend

`scripts/gate.ts` reads fresh `LATEST_FINAL` release state, the contract's authoritative policy result, and one indexed assessment per policy pair. It independently checks the exact release, artifact digest, assessment identities, verdicts, packet hashes, revision authentication and completeness. Only then does it use `spawn(argv, {shell:false})` for the requested command.

The frontend reads the same contract over stable Studionet and signs writes only through injected EIP-1193 wallets. Its advisory preparation workflow fetches canonical GitHub/OSV bytes and derives the content revision; the contract rechecks them independently. Registry and per-release histories are paginated. The attempt view exposes exact per-source commitments, archived-byte links, retry state and bounded attempt history.

No database or backend service participates in authorization. The app does not prove publisher ownership, source-code provenance, binary reproducibility, or universal software safety.

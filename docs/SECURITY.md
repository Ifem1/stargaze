# Security model and review boundaries

## Authorization scope

Authorization applies only to one immutable declared release and one explicit, nonempty set of authenticated advisory revisions. `NOT_AFFECTED` is a semantic applicability result for those bytes and that release. It is not a universal safety claim, publisher identity proof, or binary provenance attestation.

## Advisory revision identity

Caller-provided timestamps or labels are not accepted as revisions. A registration intent must carry `ghsa-sha256:<digest>` or `osv-sha256:<digest>`. Independent validators retrieve the exact canonical endpoint, validate identifier/package/provider metadata, hash the exact bounded response bytes, and compare the provider-prefixed digest. GitHub `published_at` and `updated_at` or OSV `published`/`modified` values are retained from the validated source body. A body change with an unchanged identifier or timestamp fails the earlier commitment. The old assessment remains historical and is not an assertion about the latest advisory revision.

## Attempts and finality

An assessment allows at most three attempts. Only an `OPEN` request or an objectively `RETRYABLE_FAILURE` can proceed. HTTP/network unavailability, incomplete bytes and malformed model output are retryable; a mismatched source identity/revision is terminal `INVALID_REVISION`; source revocation is terminal `SUSPENDED`; a valid semantic verdict, including `AFFECTED`, `CONDITIONAL`, or `INSUFFICIENT_EVIDENCE`, is immutable `DECIDED`. No attempt record is committed unless the contract write finalizes. Authorization accepts only a complete, revision-authenticated `DECIDED/NOT_AFFECTED` record.

## Source authority, revocation and residual trust

The contract owner controls exact lower-case host/role permissions. URL paths are separately constrained to canonical provider endpoints. Revocation is role-scoped, increments that source trust epoch, suspends pending requests using it, and blocks current authorization for prior decisions using the epoch. Reauthorization cannot revive them; the owner must register a fresh request with a new content-addressed revision. Attempts and decisions are never edited or erased.

TLS/API infrastructure, provider data, and configured host policy remain trust inputs. A compromised source can publish false information. Independent validators may agree on an incorrect semantic interpretation. The protocol commits to observed bounded response bytes and consensus, not truth. Archived source bytes support later replay but do not establish publisher control or build provenance. Release digests remain registrant declarations.

## Downstream gate

The TypeScript gate binds policy to chain `61999`, the configured exact contract, sealed release ID and artifact digest. It checks the authoritative on-chain policy result and independently reads each indexed assessment using `LATEST_FINAL`. Any malformed response, revocation, missing pair, non-final state, mismatch, RPC failure or incomplete evidence denies. The protected command is invoked with an argument vector and `shell:false` only after every check passes.

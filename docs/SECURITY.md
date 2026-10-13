# Security model and review boundaries

## Scope

An authorization is limited to an exact immutable declared release and a caller-supplied set of exact `(advisory_id, revision)` pairs. `NOT_AFFECTED` is not a universal software safety claim and does not attest that a declared artifact digest corresponds to a particular binary deployed by a third party.

## Controls

- Sealed release fields cannot be edited; fixes are new linked successors.
- Duplicate release/assessment identity is rejected. Historical assessments remain addressable.
- Only exact configured lower-case HTTPS hostnames and frozen URLs are admissible; credentials, fragments, substring matching, HTTP and ambiguous authority are rejected.
- Every leader and validator independently fetches every frozen source. Non-200, missing, empty, oversized, invalid UTF-8 or partial evidence yields `INSUFFICIENT_EVIDENCE`.
- The LLM is told to treat evidence as untrusted data and may return only four exact verdict strings. Deterministic code binds the label to a domain-separated packet digest and completeness bit. Validators compare all three.
- Promotion requires a non-empty explicit advisory revision set and final accepted state. Missing evidence, disagreement, non-final state, stale artifact, mismatch or RPC failure denies.
- Protected processes are invoked with an argv vector and no shell. The command is not run until checks pass.

## Residual trust assumptions

Host allow-list administration and the declared source policy are trust inputs. HTTPS content may be wrong, compromised or revised; snapshots commit what validators observed and do not prove software provenance. Model judgments may be incorrect. Consensus attests agreement under the protocol, not truth. Live deployment and actual advisory applicability must be independently verified and documented.

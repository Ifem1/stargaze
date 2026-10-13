# STARGAZE — MASTER BUILD SPEC

## 1. Project identity
**Name:** Stargaze

**Tagline:** Know what is exposed before you ship.

**One-line concept:**
Stargaze is a GenLayer-powered release intelligence and authorization protocol that determines whether a specific software release is affected by a specific authoritative vulnerability advisory and then exposes a fail-closed authorization verdict that downstream release workflows can enforce.

## 2. Problem
Security teams constantly face this question:
> Does this specific release actually fall within the scope of this specific advisory, and should deployment be blocked or allowed?

Simple version matching is often not enough. Advisory text may contain conditions, fixed-version ranges, ecosystem differences, special cases, disputed scopes, or ambiguity that ordinary deterministic contracts cannot interpret. GenLayer is appropriate because validators can independently inspect frozen external evidence and reach a semantic verdict.

## 3. Product scope — V1 only
Stargaze V1 must do one thing very well:
- register a software release,
- register an advisory assessment request against that release,
- freeze authoritative evidence sources and criteria,
- let GenLayer validators determine whether the release is AFFECTED / NOT_AFFECTED / CONDITIONAL / INSUFFICIENT_EVIDENCE,
- expose a deterministic authorization status,
- allow a successor release to be registered and assessed separately.

## 4. Distinction from Recall
Recall checks whether an exact product batch is covered by a real recall. Stargaze checks whether an exact software release is affected by a real vulnerability advisory and whether that release should be allowed or blocked.

Shared strengths to emulate:
- exact identity
- frozen admissible evidence
- independent validator evaluation
- fail-closed downstream enforcement
- strong tests and live proof

Distinct strengths Stargaze must add:
- release identity and lineage
- advisory-specific applicability rather than product recall eligibility
- successor release reassessment rather than a permanent sticky activation model
- release authorization as the downstream consequence

## 5. Core contract responsibilities
Build one primary Intelligent Contract in `contracts/stargaze.py`.

### 5.1 Release registration
A release record must freeze:
- repository URL or project slug
- owner wallet
- release label / version string
- full source commit SHA
- artifact digest / build digest string
- ecosystem (npm, pip, cargo, etc.)
- manifest reference (package-lock hash, requirements hash, SBOM hash, or equivalent commitment)
- created_at
- status flags
- optional predecessor release ID for lineage

### 5.2 Advisory assessment registration
An advisory assessment request must freeze:
- release_id
- advisory_id (e.g. CVE / GHSA / vendor ID)
- advisory title / short label
- ecosystem
- target package name(s)
- frozen authoritative evidence sources (HTTPS URLs only)
- authority role per source (PRIMARY / SUPPLEMENTAL)
- assessment policy version
- requester
- created_at
- assessment state

### 5.3 Assessment classifications
Use these exact verdict classes:
- `AFFECTED`
- `NOT_AFFECTED`
- `CONDITIONAL`
- `INSUFFICIENT_EVIDENCE`

Mapped authorization semantics:
- `AFFECTED` => BLOCKED
- `NOT_AFFECTED` => AUTHORIZED_FOR_THIS_ADVISORY
- `CONDITIONAL` => ON_HOLD
- `INSUFFICIENT_EVIDENCE` => ON_HOLD

Important:
`NOT_AFFECTED` means not affected by the assessed advisory, not universally safe.

### 5.4 Evaluation principle
GenLayer must do essential semantic work.
Validators must independently inspect the frozen sources and decide whether the advisory applies to the exact frozen release identity.

To avoid the kind of fragility discovered in Redeem, the consensus-critical output must be a simple, normalized label rather than a rich JSON object.

The LLM should be instructed to return only one exact token from the allowed set:
- AFFECTED
- NOT_AFFECTED
- CONDITIONAL
- INSUFFICIENT_EVIDENCE

Validators must compare the exact normalized label only.
All economic or authorization consequences must be deterministic and derived from this label.

### 5.5 Source policy
Only frozen HTTPS evidence sources may influence the verdict.
The contract should reject unsealed sources.
Evidence sources must be bound to known hostnames or exact URLs frozen at registration time.

### 5.6 Successor lineage
A successor release must reference a predecessor release.
Stargaze must retain both records independently.
A successor assessment does not mutate the predecessor’s historical status.

## 6. Contract methods (expected)
At minimum implement:
- `register_release(...)`
- `seal_release(...)` (optional if registration already seals everything; choose one consistent lifecycle)
- `register_assessment(...)`
- `evaluate_assessment(assessment_id)`
- `get_release(release_id)`
- `get_assessment(assessment_id)`
- `get_release_counter()`
- `get_assessment_counter()`
- `list_releases()`
- `list_assessments()`
- `get_release_lineage(release_id)` or enough fields for the frontend to derive lineage
- `authorization_for_release(release_id)` returning an aggregate authorization view

You may add helper methods as needed, but keep the interface reviewer-friendly.

## 7. State model
### Release states
Suggested:
- DRAFT / REGISTERED
- SEALED

### Assessment states
Suggested:
- OPEN
- EVALUATING
- DECIDED

Assessment decision fields:
- verdict_class
- authorization_result
- evaluated_at
- evidence_manifest_digest or summary fields
- last_review_status

## 8. Downstream enforcement requirement
Stargaze must have a real fail-closed enforcement consumer in the repo.
This can be a simple gate component / script that reads the contract and determines whether a release can be promoted.

Reviewer-friendly behavior:
- If release has any final `AFFECTED` advisory assessment in the relevant policy scope => block.
- If only `NOT_AFFECTED` for the relevant advisory set => eligible.
- If `CONDITIONAL` or `INSUFFICIENT_EVIDENCE` exists => hold.
- Missing or unreadable state => fail closed.

This enforcement layer may be off-chain in V1, but it must be real, documented, and demonstrated.

## 9. Frontend requirements
Build a premium production-grade web app using:
- Next.js App Router
- TypeScript
- Tailwind CSS
- Framer Motion
- Lucide icons used sparingly
- injected wallet only
- Studionet 61999 only

The frontend must include:
- Overview
- Release Registry
- Register Release
- Advisory Intelligence / Assessments
- Release Lineage
- Authorization Gate
- Documentation / About
- a global wallet control
- a transaction drawer
- network gating and switch flow

## 10. No mock data rule
Do not ship fake project data, invented alerts, fake statistics, or simulated rows.
Empty states must be designed elegantly and explain that real contract records will appear there.

## 11. Wallet requirements
- injected EIP-1193 wallet only
- no local generated private keys
- global connect button
- connected wallet popover with: Copy address, View in Explorer, Disconnect
- wrong network badge/button must offer switch to chain 61999
- all writes must be blocked on the wrong network
- react to account/chain changes

## 12. Frontend style requirements
See `02_STARGAZE_FRONTEND_VISUAL_SPEC.md`.

## 13. Testing requirements
Need strong tests across:
- contract unit behavior
- Direct Mode / nondeterministic paths
- adversarial cases
- enforcement consumer behavior
- frontend lint/typecheck/test/build

Target a meaningful suite, not superficial checks.

Must include:
- exact label agreement tests
- disagreement tests
- source-unavailable handling
- conditional and insufficient-evidence handling
- aggregate authorization logic
- successor lineage behavior
- fail-closed gate behavior

## 14. Deployment requirements
- stable Studionet only, chain 61999
- compatible local repo tooling pinned for stable Studionet
- source-verified deployment
- green CI
- live Vercel frontend
- docs aligned to the deployed contract

## 15. Live proof requirements
At minimum, demonstrate these two scenarios:

### Scenario A — affected release blocked
- register vulnerable release
- register advisory assessment with authoritative evidence
- evaluate to `AFFECTED`
- show authorization gate => BLOCKED

### Scenario B — patched successor allowed
- register successor release with predecessor reference
- register equivalent assessment against successor
- evaluate to `NOT_AFFECTED`
- show authorization gate => AUTHORIZED_FOR_THIS_ADVISORY
- original vulnerable release remains historically affected

## 16. Reviewer framing
Stargaze should be framed as:
- exact release identity + exact advisory applicability
- GenLayer does the semantic classification that ordinary contracts cannot
- deterministic code enforces release authorization
- historical findings remain visible
- patched successors are reassessed instead of mutating old records

## 17. Out-of-scope for V1
Do NOT build these unless they are trivial and already covered by the core flow:
- multi-chain support
- multiple wallet vendors beyond injected wallets
- automatic advisory crawling from the entire internet
- backend authority that overrides on-chain verdicts
- rich free-form validator reasoning as consensus-critical output
- large custom visualization frameworks
- unnecessary microservices

# STARGAZE — CONTROLLING IMPLEMENTATION DECISIONS

This document resolves ambiguity in the general concept. If a prior spec conflicts with this document, follow **this** document.

## A. Narrow, concrete release/advisory trust model
The primary unit is **(release_id, advisory_id, advisory_revision)**, not a generic security badge. `NOT_AFFECTED` only authorizes a declared release against a declared advisory revision; never display “universally safe.”

Release data: project/repository identity, owner, full commit SHA, immutable claimed artifact digest, immutable dependency manifest or SBOM commitment, package ecosystem, version, parent release ID, and stable index. Reject malformed identity, duplicates and circular parent references. Avoid claiming a developer-declared digest proves that exact binary was deployed. A GitHub commit hash may prove only what trusted GitHub responses describe; provenance claims must be labelled by trust tier.

Advisory data: advisory ID, **immutable revision or edition commitment**, target ecosystem/package, authoritative HTTPS URLs, authority classification, declared interpretation policy, primary/supplemental roles. The advisory source policy must be explicit, bounded, and snapshotted for each assessment.

No generic admin power to flip or pardon judgments. Source-authority configuration before assessment can be administered by a clearly disclosed trust role, but a revocation affects future eligibility without retroactively rewriting immutable history. Reject hostnames using substring/suffix matching, `@` authority confusion, URL redirect ambiguity, malformed schemes, or untrusted pages masquerading as official hosts.

## B. Immutable records, conservative lifecycle
A release is immutable once sealed. A corrected build becomes a **new successor release**, explicitly linked. A previously recorded AFFECTED assessment cannot be silently overwritten. For a new revision of an advisory, register a new immutable assessment key. Maintain historical assessments with stable IDs. Duplicate assessment proposals against identical release/advisory/revision should be rejected or represented as explicitly versioned review attempts—never accidentally erase earlier evidence.

Avoid dependence on an on-chain elapsed-time clock or timers unless the pinned runtime actually supports the required semantics. Transaction ordering / sequence counters are safer than invented timestamps.

## C. Validator model: agreement on the right *substance*
The LLM returns only a normalized exact **classification token**:
`AFFECTED`, `NOT_AFFECTED`, `CONDITIONAL`, `INSUFFICIENT_EVIDENCE`.

But it is **not sufficient** for validators merely to agree on the label while fetching conflicting source bodies. Independent leader and validator evaluations must agree on BOTH the label and the deterministic identity/evidence commitment and eligibility fields. Use an unambiguous bounded scalar return envelope, for example:
`LABEL|64_lowercase_sha256_packet_digest|EVIDENCE_COMPLETE_FLAG`
with strict deterministic parsing and validation, or another proven equivalent allowed by the pinned GenVM runtime. The LLM is only permitted to generate the LABEL; the digest and completeness are computed in code from every frozen fetched source and authority check. Model reasoning never selects allowed evidence, authority, gate rule, digest, release identity, or payout.

Use `gl.vm.run_nondet_unsafe` only according to the runtime's actual official signature. Validate the exact `gl.vm.Return` / `leader_result.calldata` representation in tests **before deployment**. Avoid reproducing Redeem's label-vs-dict validator mismatch.

### Independence requirements
- Leader and validator independently fetch every frozen source URL.
- Return `INSUFFICIENT_EVIDENCE` for unavailable, 4xx/5xx, empty, truncation, non-UTF8, unauthorized, invalid or nonmatching source packets; do not let a partial packet decisively authorize.
- Exactly defined fixed parser; do not strip arbitrary chat output until it becomes valid.
- Packet commitment binds full release identity, advisory revision, frozen URLs in canonical order, source status, bounded body contents and body digest, authorization flags and errors; the digest must be domain-separated to prevent cross-purpose replay.
- No evaluator may follow instructions embedded in untrusted advisory or dependency content.
- Do not include subjective prose in consensus-critical equality fields.
- Data from multiple different packets must not yield a successful agreement solely because both models say `NOT_AFFECTED`.

## D. Authorization must be scoped and fail closed
Avoid a catch-all `authorized: true` based on **one** favorable advisory verdict.

Provide an advisory-specific view. For a downstream CI gate, require a nonempty **explicit approved advisory-revision set** supplied by the caller or policy file. For each required `(advisory_id, revision)` in that set, verify a final accepted `NOT_AFFECTED` assessment for the exact artifact digest/release ID. If any is missing, pending, affected, conditional, insufficient, malformed, stale relative to policy, or the RPC read fails => DENY / HOLD. No cached positive authorization. Bind gate output to contract address, network ID, exact artifact digest, and policy-set digest. Distinguish **authorized for the assessed policy set** from **globally secure**.

A concrete downstream consumer must run a protected command **only after** fresh successful reads; if read fails or any mismatch occurs, do not run it. Never concatenate shell command text; execute an argv list. Do not cache or auto-retry protected commands. Gate must have tests proving side-effect did not execute on denial, malformed data and RPC failures.

## E. Stable and honest external sources
Select one *real* publicly readable, stable advisory example and a genuine source/patch comparison. Favor official GHSA/CVE/vendor pages with verifiable content and no authentication barriers. No fake production proof, fabricated advisories or privately controlled mock evidence masquerading as official authority. Test fixtures may simulate edge cases but must be visibly labelled fixtures.

If stable live sources do not work in GenVM, document why and either choose another genuine source or record a blocked verification. Do not weaken evidence equality to make transactions settle.

## F. Contract and frontend construction
- One principal Python Intelligent Contract; a standalone fail-closed consumer may live outside the chain.
- Bounded state growth, bounded text and URLs, pagination for large registries (avoid unbounded list views), stable IDs and indexed getters.
- Immutable lineage: predecessor exists, same project ecosystem and owner policy unless explicitly authorized, no self-reference, no skipping identity checks.
- React/Next.js App Router, TypeScript, Tailwind, Framer Motion; copy/use compatible dependencies only.
- Real public reads; injected EIP-1193 only; global connect/disconnect; wallet popover with Copy, Explorer and Disconnect; account/chain change reactions; `wallet_switchEthereumChain` to hex `0xF22F` with add-chain fallback only when appropriate; hard block wrong-network writes.
- TX lifecycle must distinguish broadcast/pending/accepted/finalized/actual execution success, with contract-state read confirmation. Never equate a hash with a successful outcome.

## G. Exact aesthetic decisions
User's reference is a **simple dark-pink luminous gradient**: dark cherry/wine at edges, vivid magenta bloom in a limited area, varying local darkness. **Do not** recreate the large planet, giant nebula, storm of particles or loud artwork from prior rejected mockups.

Design mark: a **minimal 5-point star containing an elegant `S`**; provide original SVG logo and favicon, tasteful at 16 px, transparent background. Use **few icons** (nav icons only where helpful, no emoji). Background should be layered CSS radial/linear gradients, not an image wall. Tiny muted gold/silver sparkles should be rare and low-opacity; screen should remain legible without them. Cards should have soft rose-gold outline/glow and lift on hover, with reduced motion support. Use polished typographic hierarchy and breathable layout rather than icon-heavy cards.

## H. Deployment and truthfulness
- Keep source SHA/commit, deployment tx, contract address, chain, frontend Vercel, and CI linked and consistent.
- Do not replace true evidence with inferred success. Failed checks / undetermined consensus are genuine blockers until fixed.
- If no GitHub destination is provided, build in the extracted directory. Request the exact target repository before configuring a new origin or pushing; never guess it.
- Do not ask for a private key in chat. Use available local secure environment for authorized account operations, and report missing credentials without inventing actions.
- Don't modify unrelated repositories or networks.

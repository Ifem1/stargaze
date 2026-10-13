# STARGAZE — GO/NO-GO REVIEWER GATES

## Technical
- [ ] Contract source pinned to compatible GenVM and stable Studionet 61999.
- [ ] A single principal contract uses real semantic evidence interpretation; no decorative AI.
- [ ] Release identity has exact commit and digest boundaries and immutable lineage.
- [ ] Advisory authority is exact-source/host bound, frozen and revalidated at assessment.
- [ ] Nondet leader and validators agree on verdict + packet digest + eligibility, not label only.
- [ ] Unknown/malformed/partial/conflicting evidence fails closed.
- [ ] Authorization never means universally secure; assessment scope/revision displayed everywhere.
- [ ] Gate requires a nonempty explicit advisory policy set, fresh reads and exact release/digest/chain match.
- [ ] `AFFECTED` on original release persists after successor is cleared.
- [ ] Tests include malicious leader, source mutation, source spoofing, failed web, wrong network, wallet changes, malformed result, stale policies, lineage cycles, duplicate/replay, and gate side effects.
- [ ] Python/GenVM lint, Direct Mode, frontend lint/typecheck/unit/e2e/build, preflight, and CI green with exact counts disclosed.

## UX
- [ ] Dashboard has no fake KPI figures, advisory results, or sample rows presented as live.
- [ ] Original S-within-star SVG + favicon included.
- [ ] Calm dark magenta-gradient with selective vibrant bloom, rare gold/silver flecks, modest hover-glow cards; no cartoon cosmos art or emoji clutter.
- [ ] Wallet popover Copy Address / View Explorer / Disconnect works; wrong-network badge triggers wallet switch.
- [ ] Public read-only pages work disconnected; writes fail closed on wrong network.
- [ ] Real finality-aware transaction drawer; accessible and responsive desktop/mobile.

## Live independent evidence
- [ ] Final deployed contract uses exact tested source, and docs match chain/explorer/tx/commit.
- [ ] Scenario A: real authoritative advisory + exact affected release -> actual settled `AFFECTED` -> gate denies protected action (consumer exit code / no side effect).
- [ ] Scenario B: real successor release + verified lineage and applicable patch evidence -> actual settled `NOT_AFFECTED` (advisory-specific) -> gate permits protected action; predecessor remains blocked.
- [ ] Capture all deployment, registration, assessment hashes, FINALIZED and execution results, chain state, evidence identifiers and exact gate transcript, including failures.
- [ ] Vercel frontend reads/writes canonical contract and is independently smoke-tested.
- [ ] README, architecture, trust-model, security, tests and live-proof documents are complete and honest.

## Submission verdict
Only report `READY TO SUBMIT` when all critical boxes are verified on the same immutable deployed source. Otherwise report exact missing gates and the smallest next action to close them. No guarantees about actual steward scores.

# STARGAZE — LIVE VERIFICATION PLAN

## Goal
Provide concrete live proof that Stargaze can:
1. classify a release as affected and block it,
2. classify a successor release as not affected and allow it.

## Candidate live demonstration shape
Use a narrow, carefully prepared advisory scenario with stable public evidence sources.
The evidence and releases used should be documented clearly in the repo.

## Scenario A — vulnerable release
1. Register release A.
2. Register assessment against advisory X with frozen evidence sources.
3. Evaluate assessment.
4. Expect verdict `AFFECTED`.
5. Confirm authorization gate returns BLOCKED.
6. Record tx hashes and final state.

## Scenario B — patched successor
1. Register release B with predecessor = release A.
2. Register assessment against the same advisory X.
3. Evaluate assessment.
4. Expect verdict `NOT_AFFECTED`.
5. Confirm authorization gate returns AUTHORIZED_FOR_THIS_ADVISORY.
6. Confirm release A remains historically affected.
7. Record tx hashes and final state.

## Evidence to record
For each scenario, record:
- release id
- assessment id
- create/register tx hashes
- evaluate tx hash
- final verdict class
- final authorization result
- source list used
- contract address
- chain id
- frontend URL
- screenshots or explorer links where useful

## Success condition
Stargaze is ready to submit when:
- the final contract is deployed and source-aligned,
- the frontend points at the final contract,
- both live scenarios are documented,
- the authorization gate clearly blocks the affected release and allows the patched successor.

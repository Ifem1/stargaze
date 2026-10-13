# STARGAZE — SECURITY AND REVIEWER GATES

## 1. Core review thesis
Stargaze must prove that GenLayer is essential, not decorative.

The project should score strongly if it demonstrates:
- exact release identity
- exact advisory-bound assessment
- frozen authoritative sources
- independent semantic evaluation by validators
- deterministic downstream authorization
- strong fail-closed behavior
- a real successor-release lifecycle

## 2. Security boundaries to preserve
### 2.1 Frozen scope
The assessed release and assessed advisory must be frozen before evaluation.
No one should be able to swap identity fields after seeing evidence.

### 2.2 Authority policy
Only frozen evidence URLs / domains are admissible.
Do not let arbitrary external links influence the verdict.

### 2.3 Deterministic consequences
The LLM must only classify.
It must never choose:
- money amounts
- final authorization rules
- altered release identity
- altered advisory identity
- altered source list

### 2.4 Fail-closed authorization
Unclear, unavailable, malformed, or disputed assessments must never silently produce `AUTHORIZED`.

### 2.5 Historical integrity
A successor release being cleared must not rewrite the original vulnerable release’s record.

## 3. Reviewer must-see properties
The README and docs should make clear:
- what exact release identity was assessed
- what exact advisory was assessed
- which sources were allowed
- what verdict classes mean
- what downstream authorization means
- what GenLayer contributed
- where the trust boundaries remain

## 4. Minimum documentation set
Required docs:
- README.md
- docs/ARCHITECTURE.md
- docs/DEPLOYMENT.md
- docs/LIVE_VERIFICATION.md

## 5. CI gates
At minimum green CI must prove:
- contract lint / checks
- tests
- frontend lint
- frontend typecheck
- frontend build

## 6. Things that should cause rejection or lower score
Avoid:
- fake frontend data pretending to be live
- wallet custody in browser
- vague AI outputs controlling important state without deterministic mapping
- unbounded permissive parsing of model output
- lack of live proof
- stale README/deployment references
- inability to explain exact release/advisory/evidence lifecycle

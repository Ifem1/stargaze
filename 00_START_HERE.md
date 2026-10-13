# STARGAZE — CODEX MASTER KIT

**This ZIP is a Codex implementation handoff, not a prebuilt application.** Codex is expected to produce the actual Intelligent Contract, complete frontend, tests, CI, deployment scripts and independently verified live evidence.

1. Extract this ZIP into an empty working directory. Do not copy it over an unrelated repository.
2. Open `05_CODEX_MASTER_PROMPT.txt` and give its **entire contents** to Codex.
3. Keep the specs in the extracted directory. `06_IMPLEMENTATION_DECISIONS.md` is the controlling security architecture and supersedes any conflicting earlier examples in `01`–`04`. `07_SUBMISSION_GATES.md` is the acceptance checklist.
4. Codex should execute and fix locally without coming back for permission on routine design or implementation details. **Only ask for genuinely external blockers:** a target GitHub repository URL, credentials or account grants, wallet funding, or consent to deploy to a public network.
5. **Never claim external success without receipts.** If Codex cannot execute wallet-funded deployment and transactions, it must finish the local repo, flag `LIVE NOT VERIFIED`, and provide the exact steps and commands to perform live proof.

## Primary goal
A highly original GenLayer release-advisory adjudication and fail-closed release promotion system with a beautiful restrained dark-magenta interface, using an S-in-star logo, transparent wallet connection, and real on-chain state.

## Stable deployment environment
- Chain: GenLayer Studionet **61999** (`0xF22F`); **never use dev chain 61997**.
- Studionet RPC: `https://studio.genlayer.com/api`
- Explorer: `https://explorer-studio.genlayer.com`
- CLI: install compatible `genlayer` CLI **0.39.1 repo-locally** for 61999; do not use an incompatible globally installed RC.
- Pin SDK, runtime and GenVM versions based on tests in the actual environment. Fail clearly if a pinned tool is unavailable. Do not silently switch networks.

## Important operational difference from Redeem
No fund flow is required. This is a release authorization protocol, not a pooled-token or claims escrow product. Do not introduce payment logic simply to increase perceived complexity.

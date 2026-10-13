# Architecture

Stargaze has one principal Intelligent Contract, `contracts/stargaze.py`. It stores sealed release identities, frozen advisory revision requests, and immutable decisions. Releases bind repository, registrant, version, full commit, artifact SHA-256, manifest SHA-256, package identity, and an optional same-owner/package predecessor. Assessment identity is `(release, advisory ID, advisory revision)`.

Source authority is configured by the disclosed contract deployer. Each assessment snapshots exact HTTPS URLs and source roles after host allow-list validation. Evaluation fetches each source independently on the leader and validator, rejects partial packets, computes a domain-separated canonical packet SHA-256, and asks the model for one exact classification token. The consensus validator requires identical verdict, packet digest, and completeness flag. All contract mutations occur after consensus.

The downstream consumer is a standalone TypeScript CLI. It takes a non-empty explicit advisory revision set, makes fresh final-state reads, verifies chain/contract/release/artifact/policy bindings, and only then starts the protected command with `spawn(argv, { shell: false })`. Errors and incomplete state deny by default.

The frontend is a Next.js App Router application using GenLayerJS on Studionet only. It reads contract state, uses injected EIP-1193 signing for writes, and verifies transaction lifecycle and state after finalization. No off-chain database or pre-seeded production records are used.

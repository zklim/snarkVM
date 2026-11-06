# Aerie adapter checks

The pinned Falcon-512 adapter remains separate from ownership verification and
native consensus recovery. Native recovery policy permits no aggregate IDs.
These checks demonstrate adapter compatibility and fail-closed batch validation;
they do not establish quantum-adversarial aggregation soundness.

| Check | Result | Evidence |
| --- | --- | --- |
| Producer, parallel verifier and direct Falcon differential | 1 passed, 1.57 s | `differential.log` |
| Strict adapter and parameter lint, all targets and features | Passed; warm confirmation 1.72 s | `adapter-clippy.log`, `adapter-clippy-final.log` |
| Derived snarkOS strict lint, full workspace/targets/features | Passed, 1 min 31 s | `os-clippy.log` |
| Shared genuine ML-DSA-65/Falcon authorization conformance | 13 passed, 1 ignored timing experiment, 0.19 s | `shared-conformance.log` |
| Common core source and dependency parity | See current file counts and hashes | `source-parity.json` |
| Recovery core dependency isolation | No Aerie/Akita dependencies | `core-dependencies.txt` |

The differential test rejects omissions, duplicates, reordered members, changed
effects, malformed headers, salt modes and invalid proofs. Direct and aggregate
evidence produce the same reference-ledger state. Invalid aggregate evidence
does not fall back to direct acceptance. These are adapter/reference-ledger
checks, separate from the production four-validator evidence in the core.

One local two-authorization sample used 1,332 direct-signature bytes and a 60,280
byte aggregate. Direct verification took 54 microseconds, aggregate production
1,406 milliseconds and aggregate verification 27 milliseconds. This includes
setup and is an optimized-debug sample, without a portable performance claim.

Run from the derived VM worktree, using `build-environment.json`:

```sh
cargo test --locked -p snarkvm-recovery-aerie \
  --features producer,parallel --test differential -- --nocapture
cargo clippy --locked -p snarkvm-recovery-aerie -p snarkvm-parameters \
  --all-targets --all-features -- -D warnings
cargo test --locked -p snarkvm-recovery-signatures \
  --test conformance -- --nocapture
```

Run the full lint from the derived OS worktree:

```sh
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Adapter-only strict lint without parameter feature unification failed in existing
`snarkvm-parameters` macros with 357 unused/dead-code errors. The failure is
retained in `adapter-clippy-minimal-parameters-failure.log`. Selecting parameters
with all features passed without warning suppression or source changes. The
minimal-parameter warning combination remains unresolved.

`results.json` records commands and hashes. Its starting commits identify base
revisions; they do not identify uncommitted source. Use the final source manifests
and archives for a complete reproducible source identity. No wallet secrets or
runtime key files are included here.

Fresh checks after confirmed-body historical source-membership hardening are in
`post-membership-results.json`. Full derived VM workspace/targets/features strict
lint passed in 4 min 28 s, and the derived OS check passed in 1 min 53 s. Both
pinned nightly format checks passed. These source checks include the pinned
Aerie producer and verifier; they do not add a runtime or quantum-soundness claim.
Exact changed-source hashes, environment and current common-source parity are
retained with those checks. The earlier adapter measurements remain separate.

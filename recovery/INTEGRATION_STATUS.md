# Disclosed recovery integration status

**Local functional acceptance passed; public deployment remains unscheduled.**
The disclosed credits construction validates genuine historical V0/V1 preparation, enrolled V2
commitments, V2→V3 migration and PQ spending. Four validators passed both activations, negative
cases, persistence, interrupted finalization, measured partition/reconnection and checked snapshot
replay. Two clients relayed a transaction accepted by all six nodes. Ordinary unchanged CI and
four-worktree strict checks pass. The composed run and HTTP429 continuation are explicit in the
[results and evidence matrix](../RECOVERY_RESULTS.md).

No private ownership-proof backend is required for directly verified disclosed relations.
Reusable signing secrets remain protected; an opening alone never authorizes replacement effects.
Classical consensus/checkpoint assumptions, unsupported programs, policy upgrades, scaling and
independent audit obligations remain explicit. No live network was deployed.

## Source identity and reproduction

| Component | Exact starting revision |
| --- | --- |
| VM core | `f0f726c7fcaed39e1f5aeb29add1875f14fecdbe` |
| VM Aerie child | `3f56837109459653b6d90f80e473c18a5e8d463c` |
| OS core | `aa6234fb9c69626e11c763c8e052904684c44032` |
| OS Aerie child | `f877f8e6f964726e1f53aa063f92a2ec39cab09c` |
| Genuine pre-versioning VM fixture | `9741f1159a8cd18e2d676d5a095eeffad71ab52c` (3.7.1) |

The named branches retain the core/adapter split. Starting archives and SHA256s
are retained in
`/workspace/security-evaluation/disclosed-recovery-20261022/sources-before.json`.
Current changes are not represented by the starting commits: reproduce the
matching final source snapshot/overlay and lockfiles. Do not use a shared target
cache for timestamp-normalized restored archives. The historical generator has
an isolated pinned lockfile and does not relabel current records as V0.

Tools: Rust 1.96.1, pinned rustfmt nightly-2026-04-02, Python 3, Java 21 for the
historical TLA+ model. In this workspace first source
`/workspace/.setup/snarkos-env.sh`. Core reproduction commands:

```sh
cargo test --locked -p snarkvm-recovery --lib transaction_wire
cargo test --locked -p snarkvm-recovery-signatures --test conformance -- --nocapture
cargo test --locked -p snarkvm-recovery-records
cargo test --locked -p snarkvm-ledger-block transaction::recovery::tests
cargo test --locked -p snarkvm-ledger-store --features rocks --lib test_recovery_ -- --test-threads=1
python3 recovery/model/disclosed.py --output /tmp/disclosed-model
```

The exact scheduled VM command (including `--include-ignored`, profile and
verified historical parameter setup) is retained in
[evidence/disclosed-20261022/production-vm-commands.md](evidence/disclosed-20261022/production-vm-commands.md). In this cloud workspace the shared
RocksDB build uses `CARGO_TARGET_DIR=/workspace/snarkOS/target` and
`RUSTFLAGS='-C target-cpu=skylake'`. Use identical flags when reusing that cache.
Aerie-only reproduction remains on the separate worktree:

```sh
cargo test --locked -p snarkvm-recovery-aerie --features producer,parallel --test differential -- --nocapture
```

## Changed trust and proof boundary

Validators directly check disclosed commitment openings, authenticated creation,
spentness, exact schema, arithmetic and replacement effects. A classical
Chaum–Pedersen certificate links the true legacy serial to the owner's verified
signature key during preparation; it is not accepted as post-compromise
ownership. Enrolled PQ signatures independently authorize exact native effects.
No digest opening or Aerie aggregate supplies missing record ownership checks.

The quantum-recovery claim is conditional on enrollment before legacy compromise,
an authenticated pre-compromise checkpoint and continuing authentic ledger state.
Validator consensus, classical header/index commitments and historical Aleo
proofs remain separate assumptions. No fully PQ validator network, confidentiality
or concrete end-to-end quantum security level is claimed. Native V2/V3 are the
new disclosed credits class, not legacy private circuit ciphertexts.

## Demonstrated behavior and remaining obligations

See the [claim-to-evidence matrix](../RECOVERY_RESULTS.md) for actual accepted transactions,
state/accounting, fault topology, ordinary CI, independent model/vectors and component-test scopes.
A startup refusal or empty blocks are not counted as migration acceptance.
Independent cryptographic/implementation review remains required; ordinary consensus and
checkpoint authentication are not post-quantum. Public-scale capacity and genuine rejected-private-fee
source preparation remain unqualified. Both local activations were fixed before enrollment;
scheduling H2 later requires an unimplemented consensus-gated policy/checkpoint upgrade.

Final normalized source archives and inventories are retained at
`/workspace/security-evaluation/disclosed-recovery-20261022/sources-final-20261030/manifest.json`.
The compiled-input snapshot is `sources-cost-boundary-build/manifest.json`; final script/documentation
updates do not change its verified Rust inputs. These are dirty source snapshots, not new Git commits.

> Post-rebase validation: see [UPSTREAM_REBASE.md](UPSTREAM_REBASE.md). The results below retain pre-rebase evidence, including suites not rerun for this sync.

# Two-stage Aleo recovery: implementation and results

**Local disclosed-credits acceptance passed. Public activations remain unscheduled; no live network was deployed.**
The evaluated optimized node SHA256 is `026fa716dd87b6fa9822d36eb280ccb389599dd4688af26fd94616a420800eb4`.
The exact dirty source overlays and dependency identities are recorded in
[RECOVERY_SOURCE_MANIFEST.json](RECOVERY_SOURCE_MANIFEST.json), not represented by the base Git commits alone.

## Construction and reasoning

The supported source is a genuine historical private `credits.aleo/credits` V0/V1 record.
Preparation verifies its disclosed opening, exact creating transition in an actual
confirmed transaction and block, deterministic legacy serial, unspentness and conservation.
A pre-compromise Aleo owner signature and classical equal-discrete-log certificate bind
that serial and the complete replacement effects. Reusable account seeds are not serialized.

During `[H1,H2)`, the owner creates a native disclosed V2 record committing with SHA3-512
to its exact algorithm/profile/public key, value and context. The new PQ key co-authorizes
enrollment. From H2, that enrolled key authorizes V2-to-V3 migration and V3 spending.
An opening supplies data; it never replaces the enrolled key's authorization.
Every statement binds the full network/genesis identity, policy, effects, fees, window and replay identity.
Rotation requires current authority and new-key possession and rejects security-category downgrades.

V2/V3 are a distinct native disclosed credits class, not existing private console/circuit ciphertexts.
H1 retires legacy record-bearing operations/private fees; H2 retires all legacy transaction authorization.
Unprepared dormant records freeze; validators never manufacture witnesses or rewrite private records.
Historical verification requires the corresponding historical state. Unsupported programs/classes reject.

Ownership/state checks, signatures and optional aggregation remain separate. Native policy uses genuine
ML-DSA-65/Falcon-512 direct verification. The Aerie adapter is isolated on the derived branch;
its aggregate is unnecessary for recovery and proves neither ownership nor conservation.

## Claim-to-evidence matrix

| Claim | Evidence | Limit |
| --- | --- | --- |
| Genuine historical inputs | Old snarkVM 3.7.1 `9741f1159a8cd18e2d676d5a095eeffad71ab52c` development genesis; V0-to-V1 upgrade accepted at 24 on four nodes | Local historical implementation fixture, not mainnet inclusion |
| Both activations, migration and spending | 12 accepted native transactions below; exact accepted bodies/heights on validators, final relay on all six nodes | H1=60/H2=120 fixed before enrollment |
| Authorization/exclusion | 21 negative cases × four validators return structured 422; competing preparations finalize once; genuine key rotation and both backends work | Backend cryptographic assumptions remain |
| Conservation | 3,000,000,000 prepared = 2,998,800,000 unspent + 1,200,000 fees; independent checkpoint parser matches six nodes | Fees burn; experimental resource schedule |
| Persistence/crash | Persisted all-validator restart; validator exits 86 after native finalization before shared commit, restarts and converges | Process interruption, not power-loss qualification |
| Partition/reconnection | Observed pairs 0↔1 and 2↔3; all heads remain 139 for measured 12 s; reconnect and accepted spend at 143 | Single-host controlled topology |
| Supported rollback | Full ledger+BFT snapshot at 23 restored; replay and all accepted bodies/boundary hashes revalidated | Same finalized chain; no arbitrary finalized reorganization |
| Client networking | Client 5 → client 4 → validator 0 observed topology; accepted spend at 168; all six state roots equal | Local transport test |
| Proposer boundary fix | Actual failed transaction regression: old guard fails, fixed resource estimation passes 1/1 in 0.18 s | Activation still enforced separately at candidate height |
| Static and ordinary CI | Four worktrees strict all-target/all-feature Clippy + pinned fmt; unchanged `.ci/test_devnet.sh` PASS in 208.19 s; eight nodes, original log caps respected | No CI thresholds weakened |
| Other retained component checks | BFT 131/131; durable store 19/19; wire 4/4; schema 5/5; signature conformance 13; model 1,504 states/1,138 edges/11 negative obligations; 80 differential cases; codec fuzz 771,520 runs | Component scopes recorded; no whole-crypto fuzz claim |
| Separate Aerie adapter | Pinned Aerie `49b6c212c209286c536196f53618823ffdf0e899`; differential aggregate/direct Falcon test passes | Native aggregates disabled; independent QROM/parameter review needed |

Public evidence: [native summary and accepted bodies](recovery/evidence/disclosed-20261022/checks/native-final-summary.json),
[final state](recovery/evidence/disclosed-20261022/checks/native-final-state.json),
[independent decode](recovery/evidence/disclosed-20261022/checks/native-final-decoded-checkpoint.json),
[CI result](recovery/evidence/disclosed-20261022/checks/ci-final-optimized-results.json),
[all retained checks](recovery/evidence/disclosed-20261022/checks/results.json).

| Accepted native operation | Height |
| --- | --- |
| prepare-competing | 60 |
| prepare-falcon | 62 |
| prepare-rotation | 64 |
| rotate-falcon-to-ml | 68 |
| migrate-ml | 121 |
| migrate-falcon | 123 |
| migrate-rotated | 125 |
| spend-ml | 128 |
| spend-falcon | 129 |
| interrupted-spend | 138 |
| reconnected-spend | 143 |
| client-relayed-spend | 168 |

The first optimized attempt exposed a real proposer bug: cost estimation used the V22 parent
version while admission authorized the V23 candidate at H1. Cost estimation now remains
independent of activation; VM policy still enforces authorization. The failed run and red/green
regression remain retained. The corrected network run completed both activations and fault cases,
then hit HTTP429 at its last post-rollback read. A bounded read-only retry and checked continuation
revalidated every accepted body, state accounting and boundary hash before completing the relay.
This is a composed run, not a claim that the original interrupted invocation passed.
The earlier ordinary debug CI log-cap failure also remains recorded; optimized CI passed unchanged.

## Costs

| Operation | Canonical envelope bytes | JSON bytes | REST admission ms |
| --- | ---: | ---: | ---: |
| prepare-competing | 6,209 | 22,102 | 206.1 |
| prepare-falcon | 2,511 | 8,812 | 358.2 |
| migrate-ml | 9,093 | 32,499 | 135.0 |
| migrate-falcon | 2,752 | 9,781 | 103.8 |
| spend-ml | 9,093 | 32,510 | 101.9 |
| spend-falcon | 2,752 | 9,762 | 124.8 |
| client-relayed-spend | 9,093 | 32,439 | 55.0 |

These are contended single-host observations, not throughput benchmarks. Each accepted native fee
was 100,000 microcredits; the minimum is 1,000 plus canonical envelope bytes. State retains full
snapshots with 10,000-record/100,000-replay/64-MiB bounds and is not qualified for public scale.
Earlier direct backend samples average 750.457 µs ML-DSA-65 and 40.149 µs Falcon-512
(different NIST categories 3/1). Aerie's two-member sample is 60,280 bytes/1,406 ms production/
27 ms verification, versus 1,332 bytes direct signatures. These are separate component samples.

## Reproduce

Use matching sibling source snapshots/lockfiles, Rust 1.96.1 and nightly-2026-04-02 rustfmt.
Cloud setup is `/workspace/.setup/snarkos-env.sh`; the recorded build uses Skylake CPU flags,
LTO disabled, debug information stripped, and the verified exact RocksDB archive/runtime wrapper.

```sh
source /workspace/.setup/snarkos-env.sh
export CARGO_TARGET_DIR=/workspace/snarkOS/target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3
export RUSTFLAGS='-C target-cpu=skylake'
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=debuginfo
# Reuse the exact verified cloud native archive; a fresh environment may rebuild it from pinned sources.
export ROCKSDB_LIB_DIR=/workspace/snarkOS/target/debug/build/librocksdb-sys-630aa221dd10c9ff/out
export ROCKSDB_STATIC=1 RUSTC_WRAPPER=/workspace/.setup/rustc-cxx-runtime.py
cd /workspace/snarkVM
cargo test --locked -p snarkvm-synthesizer-process --features test,snarkvm-console/test_targets --test recovery_cost
# In snarkOS, with the matching sibling snarkVM:
cd /workspace/snarkOS
cargo build --locked --release --features test_network
python3 scripts/test_disclosed_recovery.py --binary target/release/snarkos \
  --network 1 --h1 60 --h2 120 --client-relay \
  --genesis-file ../snarkVM/recovery/history-tools/fixtures/v0-testnet-dev-genesis/genesis.bin \
  --genesis-hash ab1njne0yg0ygw9kwyldxw942syzvhvx7gjdp87nadermkt45w4x5ps88sgkx
PATH="$PWD/target/release:$PATH" .ci/test_devnet.sh
```

Fresh runs generate genuine legacy proofs; optional `--legacy-cache` verifies retained proofs and
node-specific offline snapshots before reuse. `--resume-relay` requires matching retained post-rollback
state and revalidates all accepted bodies and boundary hashes. Signing-key files remain external.

## Assumptions and unresolved obligations

Enrollment must finalize before legacy compromise and survive in an authentic checkpoint,
followed by continuing authentic ledger state. Classical BFT, headers/indexes and historical proofs
are not made quantum safe. No PQ-authenticated checkpoint transport or quantum-safe bootstrap is implemented.
Direct disclosed checks avoid a general ownership proof backend; retained classical DLEQ is pre-compromise
only. ML-DSA/Falcon implementation assumptions and Aerie aggregation soundness need independent review;
no zero-knowledge or concrete end-to-end quantum security level is claimed.

Unprepared records cannot be recovered from compromised legacy authority alone. PQ signing-key theft
is not solved. Arbitrary programs, bonding and public-balance conversions are unsupported.
Scheduling previously-unscheduled H2 after enrollment requires a separate, unimplemented consensus-gated
policy/checkpoint upgrade. Genuine proof-backed rejected-private-fee output preparation remains untested;
its structural eligibility is preserved. Public-scale resource economics, power-loss durability and
independent cryptographic/implementation audits remain outstanding.

Final normalized source archives and inventories are retained at
`/workspace/security-evaluation/disclosed-recovery-20261022/sources-final-20261030/manifest.json`.
The compiled-input snapshot is `sources-cost-boundary-build/manifest.json`; final script/documentation
updates do not change its verified Rust inputs. These are dirty source snapshots, not new Git commits.

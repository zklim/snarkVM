# Private recovery integration evaluation — 2026-10-22

**Acceptance status: incomplete; cryptographic construction blocked.** No private
Aleo recovery transaction, production migration store or transaction-bearing
four-validator activation has been delivered. No live network was contacted for
deployment. The existing experiment and startup guard are preserved. All public
activation heights remain `u32::MAX`.

The concrete blocker is documented in [PROOF_BACKENDS.md](PROOF_BACKENDS.md): no
inspected backend/profile has a justified private, quantum-sound implementation
of the complete Aleo ownership relation. A pinned Winterfell experiment actually
recovers private witnesses from valid proofs. RISC Zero's pinned source claims PQ
STARK security but explicitly leaves its ZK argument unfinished; the inspected
paper supplies IOP/Fiat–Shamir-heuristic analysis, not a relation-specific concrete
QROM profile. Neither this finding nor incomplete SP1 qualification proves that a
suitable construction is impossible. Under the requested failure condition,
dependent production changes were not made and completion is not claimed.

## Delivered in this evaluation

- Inspected and archived existing uncommitted work before extending it. Base
  commits, branch names, file hashes, patches and deterministic source overlays
  are retained in `evidence/ownership-20261022/before-snapshots.json` and external
  source archives. Existing core/adapters and node behavior remain intact. The
  restored VM snapshot's privacy probe also passes a fresh-target release build.
- Specified the threat, surviving authority, historical record classes, exact
  proof/ledger division, preparation/recovery windows, fees, nullifiers and atomic
  transition contract in [OWNERSHIP_PROOF.md](OWNERSHIP_PROOF.md). It is a target
  specification and does not silently reinterpret the existing digest helper.
- Added a real, SHA-pinned proof-backend privacy probe with a standalone lockfile.
  The two proofs verify and expose different private witnesses for the same public
  statement. It is not a production dependency or an ownership verifier.
- Added an independent bounded TLA+ transition model and checksum-pinned runner.
  Baseline: **127,185 distinct states**, six invariants pass. All five deliberately
  broken variants produce required invariant counterexamples; separate reachability
  checks cover V2 creation, V3 creation and V3 consumption. This validates a
  finite target specification, not the Rust implementation or network/storage.
- Re-ran the existing genuine ML-DSA/Falcon 12-test conformance suite successfully.
  Existing Aerie-specific integration remains separate; no ownership or QROM
  claim is attributed to its aggregate relation. Its genuine direct/aggregate
  differential test also passes again.

## Branch and dependency relationships

| Worktree / branch | Exact base | Relationship |
| --- | --- | --- |
| snarkVM / `quantum-recoverability-pqs` | `c493bc514f0850d4e07a0135b0e4f845e38d0c73` | Public-value core, ML-DSA/Falcon adapters, new qualification/model artifacts |
| snarkVM-aerie / `quantum-recoverability-aerie` | Same VM base | Same core/artifacts plus pinned Aerie adapter |
| snarkOS / `quantum-recoverability-pqs` | `5d497bf3253eec606404bee8d65c305d8cd86f76` | Existing capability guard; production dependency remains committed VM above |
| snarkOS-aerie / `quantum-recoverability-aerie` | Same OS base | Same guard/status; no separate production Aerie transaction path |

The evaluated sources are published on the named branches. Each Aerie branch
descends from its core branch; the containing Git commit identifies the published
revision. Original worktree snapshots remain retained as historical evidence. Cargo.lock files pin
ML-DSA `0.1.1`, fn-dsa `0.3.0`, Aerie `49b6c212c209286c536196f53618823ffdf0e899`,
Akita `e023b6a46143f7b23199ccecb2684192baf7b640`, jolt
`c7c2d08d5bb0c7c80501f29f723e595af7fcff3c` and Spongefish
`ef9741346a150039427d9e0c02d6b2d73e93ec81`. Candidate proof dependencies are
isolated from recovery core; exact sources and raw excerpts are in
`evidence/ownership-20261022/sources.json`.

## Production path inspected; integration still absent

| Layer | Source | Missing acceptance evidence |
| --- | --- | --- |
| Private record opening/preparation | `console/program/src/data/record/recovery.rs`, circuit counterpart | Helpers do not prove membership/spentness; current digest does not enroll a PQ key |
| Wire format/identity | `ledger/block/src/transaction/{mod,bytes,merkle,serialize}.rs` | Only Deploy/Execute/Fee; no private recovery envelope or tree leaves |
| Network/admission | OS `node/router/messages/src/unconfirmed_transaction.rs`, `node/rest/src/routes.rs`, `node/bft/src/worker.rs` | Carries existing Transaction; no recovery proof limits/capability routing |
| Verification | `synthesizer/src/vm/verify.rs` | Existing transaction/serial/fee checks and retirement gates; no ownership backend |
| Candidate execution | `synthesizer/src/vm/finalize.rs`, `ledger/src/{advance,check_next_block}.rs` | Existing candidate-height checking; no recovery speculation/finalization/fee outcomes |
| Persistence | `ledger/store/src/{transaction,transition,consensus}`, RocksDB helpers | No authenticated V2 enrollment/consumption indexes in durable block batch |
| Archive | `ledger/store/src/consensus/recovery.rs` | Integrity against caller-supplied root; not consensus enrollment or current-state proof |
| Startup | OS `cli/src/helpers/recovery.rs` | Finite V23/V24 still refuse; removing this would misrepresent capabilities |

Existing atomic/checkpoint APIs must not be confused with recovery crash safety.
Actual durable batch sharing, error paths, roots, checkpoints and restart/undo
behavior still need implementation and fault-injection evidence. Existing
`BlockStore::remove_last_n` is not a guarantee that BFT finalized history can be
reorganized safely.

## Claim-to-evidence and remaining acceptance criteria

| Claim / criterion | Result and retained evidence | Limit |
| --- | --- | --- |
| Existing work preserved | Verified original manifests; before source overlays and SHA256 inventories retained | Reproducibility, not cryptographic correctness |
| Default Winterfell trace unsuitable for this private witness | Two actual valid proofs; `winterfell-privacy.log` | Concrete configuration only; not an Aleo proof |
| Target activation/replay/conservation/competition safety | `model/results.json`, baseline and five counterexample logs | Finite abstraction; proof predicates assumed; no implementation refinement |
| Signature adapter compatibility | 12 tests pass, `conformance.log` | Existing trusted-public-source model; seed privacy not proved |
| Existing Aerie aggregate semantics preserved | Direct/aggregate differential test passes, `aerie-differential.log` | Signature relation only; not ownership or QROM soundness |
| Private V0/V1 preparation, V2 enrollment, V2→V3 and V3 spend | **Not implemented** | Genuine historical record end-to-end fixtures/proofs absent |
| PQ proof privacy and quantum knowledge soundness | **Unjustified for a selected production profile** | Backend/parameters/guest predicate and independent cryptographic analysis required |
| Wire, fee, program, persistent storage and shared old/new consumption | **Not integrated** | No production transaction accepted; no crash-atomicity result |
| Four-validator transaction activation, partitions/reconnection/restarts/reorg | **Not run** | Startup refusal or previous empty-block tests do not satisfy this criterion |
| Proof negatives, ownership differential tests and proof/ledger fuzzing | **Not run for missing ownership backend** | Earlier codec fuzzing/native helpers and new model are separate evidence |
| Public activations unscheduled / adapter separation | Preserved source tables/guard; separate worktrees and dependency graphs | No live deployment or public activation |

## Commands and measured costs

Use Rust 1.96.1, nightly-2026-04-02 rustfmt, Python 3 and Java 21. In this cloud
environment first source `/workspace/.setup/snarkos-env.sh`. From snarkVM:

```sh
cargo test --locked -p snarkvm-recovery-signatures --test conformance -- --nocapture
cargo run --release --locked --manifest-path recovery/proof-evaluation/winterfell-privacy/Cargo.toml
python3 recovery/model/check.py --jar /tmp/recovery-tlc/tla2tools.jar --output /tmp/recovery-model-results
# Probe check, strict Clippy and formatting commands are in its README.
# On snarkVM-aerie, the existing pinned adapter's differential test is:
cargo test --locked -p snarkvm-recovery-aerie --features producer,parallel --test differential -- --nocapture
```

Latest shared-host samples (four CPU quota, not capacity estimates): direct
ML-DSA-65 verification mean **3,146 us** over 100 calls, Falcon-512 **42 us**; the
model baseline took **76.095 s**. Previous uncontended signature samples were
822/31 us, demonstrating timing variance. The standalone privacy probe produced
12,989/12,267-byte proofs for its tiny non-private relation. There is **no Aleo
ownership-proof, production migration throughput or storage overhead measurement**.
The repeated two-Falcon Aerie test measured 60,280 proof bytes, 496 ms production,
13 ms verification versus 1,332 direct signature bytes and 92 us direct verification.
Prior Aerie samples and their assumptions remain in `../RECOVERY_RESULTS.md`.

The external evidence root is
`/workspace/security-evaluation/ownership-integration-20261022`.
`snapshots/index.json` records full pinned source archives plus before/after
worktree overlays. Restore the matching base archive then its worktree overlay;
verify SHA256 before use. These source snapshots do not vendor remote proving
parameters, registry crates or the installed compiler. Lockfiles/checksums and
tool versions remain necessary. `RECOVERY_SOURCE_MANIFEST.json` records current
publication file identities separately from the immutable before snapshots.
Use a fresh Cargo target directory when building a restored snapshot: normalized
archive timestamps can otherwise cause a shared target to reuse stale artifacts.

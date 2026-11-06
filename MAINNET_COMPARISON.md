> Publication: see [RECOVERY_PUBLICATION.md](RECOVERY_PUBLICATION.md). The report below records the validated pre-publication snapshot.

# snarkVM: recovery changes versus mainnet

Compared on 2026-11-06 against **`upstream/mainnet` = `c2909c55efb0c2202e7471e3e2efd73de1c4a468`**
([pinned baseline](https://github.com/aleo-labs-protocol/snarkVM/tree/c2909c55efb0c2202e7471e3e2efd73de1c4a468)).
The baseline is an ancestor of the recovery work. This covers all earlier committed work,
current tracked edits and non-ignored new files, not just the latest diff against HEAD.

| Variant | HEAD (does not include dirty edits) | Commits above mainnet | Changed paths¹ |
| --- | --- | ---: | ---: |
| `quantum-recoverability-pqs` | `31fff32e3393ab0596d31cd060376e5a15c78b73` | 4 | 294 |
| `quantum-recoverability-aerie` | `63713683da4686092cbd2324d9265ee78fc207b9` | 5 | 317 |

¹ Includes source, tests, documentation, binary fixtures, retained logs and original references.
Core paths: **238 added / 56 modified / 0 deleted**. Generated comparison/provenance
metadata is excluded from these counts. Large evidence files are not additional runtime features.
The [complete path inventory](MAINNET_COMPARISON.json) records status, category, blob/SHA256 and
committed/uncommitted layers for every path, including the Aerie variant.

## Changes and reasons

| Area | Change from mainnet | Reason | Main paths |
| --- | --- | --- | --- |
| Activation policy | V23 preparation and V24 retirement; sentinel heights stay unscheduled, ordinary `latest()` stays V22, old test schedules remain readable. | Add explicit future gates without accidentally activating a public fork. | `console/network/` |
| Legacy V2 helpers | Seed-to-key/address derivation, decryption, owner checks, framed SHA3-512 credentials/openings, explicit V2 byte encoding; matched console/circuit implementations and negative tests. | Prepare recovery-compatible witness primitives while keeping ordinary V0/V1 serialization separate. These helpers alone prove neither current ownership nor spendability. | `console/program/src/data/record/`; `circuit/account/`; `circuit/program/` |
| Archival snapshots | Network/version-separated block, mapping and serial-set export/verification with bounded decoding and integrity roots. | Preserve reproducible historical state; a hash still requires independently authenticated provenance. | `ledger/store/src/consensus/recovery*` |
| Recovery core | Typed backend capabilities/limits, canonical effect/signature statements, versioned records, enrollment/rotation, deterministic consumption, replay exclusion and conservation. | Keep the ledger in control of authorization meaning; prevent key/algorithm substitution and backend-selected effects. | `recovery/core/` |
| Historical ownership | Disclosed credits opening/schema verification, pre-compromise owner signature and serial-link DLEQ certificate, exact confirmed source-transition/block membership. | Tie real historical inputs to their owner and replacement effects without serializing reusable signing secrets. | `recovery/records/`; `synthesizer/src/vm/recovery.rs` |
| PQ authorization | Pinned genuine ML-DSA-65 and Falcon-512 direct verifiers, independent vectors, shared substitution/rotation/replay conformance. | Demonstrate backend substitutability with distinct schemes; an opening is data, not authority. | `recovery/signatures/` |
| Production formats | First-class Recovery transaction and accepted outcome; bounded canonical binary/JSON/ID handling; before/after-root finalize operation. | Carry the feature through ordinary transaction/block storage and networking, rather than an unauthenticated sidecar. | `ledger/block/`; `synthesizer/program/.../finalize_operation/` |
| Atomic state and spending | Memory/RocksDB recovery maps, schema upgrade/refusal, archived transactions, per-height snapshots, shared legacy/recovery serial exclusion and one atomic finalization batch. | Prevent cross-path double spending and partial enrollment/output/fee commits; support crash recovery and checked snapshot replay. | `ledger/store/`; `ledger/src/contains.rs` |
| Authorization and candidate height | Gates at VM/process deployment, execution, fee and explicit authorization entry points; historical versus current verification; ordered candidate speculation and native fees. | Retire prohibited legacy paths consistently while permitting historical verification against its historical state. | `synthesizer/src/vm/`; `synthesizer/process/` |
| Boundary resource fix | Native canonical byte-cost estimation is independent of activation; VM checks the candidate height. | The proposer has a V22 parent at H1 while authorizing a V23 candidate; the old cost gate discarded valid preparations. | `synthesizer/process/src/cost.rs`; `synthesizer/process/tests/recovery_cost.rs` |
| Test compatibility | Generators/benchmarks select the latest scheduled height rather than trailing reserved sentinels. | Avoid attempting to advance tests to u32::MAX after adding reserved versions. | `ledger/src/test_helpers/`; `ledger/testchain-generator/`; `synthesizer/benches/` |
| Validation and research | Genuine old-version fixtures and parameter verification; finite/TLA+ models, differential/property tests, codec fuzz corpora; bounded Winterfell/SP1/RISC0 assessment artifacts and licensed references. | Make results reproducible, detect invariant failures, and preserve why evaluated proof systems were not claimed as a PQ ownership solution. | `recovery/history-tools/`; `recovery/model/`; `recovery/fuzz/`; `recovery/proof-evaluation/`; `recovery/evidence/` |
| Dependencies and documentation | Workspace crates and exact crypto pins/lockfiles; source inventories, reports, retained public logs and cache hygiene. | Bind tested code and assumptions to exact versions without treating generated evidence as protocol logic. | `Cargo.*`; nested crate manifests; `QUANTUM_RECOVERY*.md`; `RECOVERY_*.md` |

## Additional Aerie branch changes

`recovery/aerie/` adds a pinned adapter for the precise Falcon-512 profile, separate aggregate production/verification and direct Falcon differential tests. Exact membership/order, duplicates, messages, public keys, salts and parameters are bound; invalid aggregates do not fall back. Aerie/Akita/Jolt types stay outside the core. Native policy disables aggregation. Pins: Aerie `49b6c212c209286c536196f53618823ffdf0e899`, Akita `e023b6a46143f7b23199ccecb2684192baf7b640`, Jolt `c7c2d08d5bb0c7c80501f29f723e595af7fcff3c`, Spongefish `ef9741346a150039427d9e0c02d6b2d73e93ec81`.

## Behavior and compatibility

Before H1, public behavior stays on the scheduled legacy protocol. H1 requires owner-authorized
V0/V1→native V2 preparation and freezes legacy record paths/private fees. From H2, enrolled PQ
keys authorize V2→V3 migration and V3 spending; legacy transaction authorization is retired.
Dormant unprepared records freeze. Both public heights remain **unscheduled**.

The earlier console/circuit V2 hashing helpers and the new native disclosed V2/V3 credits
records are distinct. Neither a SHA3 opening nor an Aerie aggregate independently authenticates
historical ownership. Native preparation uses a classical owner/serial certificate before compromise;
subsequent effects require the previously enrolled PQ key. Validators never manufacture witnesses.
Schema additions preserve old data through the tested forward upgrade; database downgrade and
arbitrary finalized-chain reorganization are unsupported. Classical consensus/header/index and
checkpoint-authentication assumptions remain; this is not a quantum-safe validator network.

## Build and validation

The recovery branches now descend from the exact upstream revisions above. The uncommitted
implementation was restored after the rebase; backups and source archives are retained.
The rebase preserved the upstream proposal-spend multiplier wiring, updated lockfile versions,
VM history mapping spelling and CUDA target. See [the rebase report](UPSTREAM_REBASE.md) for
conflict resolutions, source preservation checks and the current fresh-validation status.

**Fresh post-rebase validation passed:** all four strict checks, recovery/signature/historical-record
tests, the independent model, the BFT suite, a rebuilt node, ordinary eight-node CI and a new
transaction-bearing four-validator recovery run with two-client relay. Exact commands, source/binary
identities and limits are in [UPSTREAM_REBASE.md](UPSTREAM_REBASE.md).
Older [results](RECOVERY_RESULTS.md) retain **pre-rebase evidence**, including suites not rerun here;
their previous binary hashes, timings and pass counts are not fresh results for these revisions.

Reproduce this comparison without checking out or modifying the current branches:

```sh
git fetch --no-tags upstream refs/heads/mainnet:refs/remotes/upstream/mainnet
git diff c2909c55efb0c2202e7471e3e2efd73de1c4a468 HEAD --stat       # committed layer
git diff c2909c55efb0c2202e7471e3e2efd73de1c4a468 --name-status    # tracked working tree
git ls-files --others --exclude-standard            # also include new files
```

The JSON pins the fetched SHA so later mainnet movement cannot silently change this report.
Current source identities are in [RECOVERY_SOURCE_MANIFEST.json](RECOVERY_SOURCE_MANIFEST.json);
pre-rebase and rebased-candidate source snapshots, preservation records and validation logs are retained under
`/workspace/security-evaluation/upstream-rebase-20261106/`.

Remaining work: independent cryptographic/implementation audit, PQ-authenticated checkpoint transport,
quantum-safe consensus, public-scale state/fee qualification, arbitrary-program support and a
consensus-gated policy upgrade to schedule H2 after enrollment. Genuine rejected-private-fee source
preparation is structurally supported but untested. The restored overlay remains uncommitted. No live deployment or remote push is included.

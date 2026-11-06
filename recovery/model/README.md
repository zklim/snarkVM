# Bounded recovery transition model

`Recovery.tla` is an independent target specification, not extracted Rust code or
a refinement proof of the experimental ledger. TLC checks type correctness,
conservation, consumption uniqueness, candidate-height legacy retirement, proof
effect-binding and replay isolation. It also explores persisted snapshots and
rollback to the last persisted state.

The finite instance has five record slots, two initial records (V0 and V1) of
three units each, three remaining output slots, three abstract key classes, two
activation thresholds and height contexts 0..4. Each transaction has one input,
one fresh output and fee one. All transactions deliberately reuse nonce zero.
Actions include legacy spend, legacy private fee, prepare, migrate, spend and
rotate. Transactions share the same consumption index. Proof predicates are
assumed, with seven abstract valid/invalid claim classes. Passing this model does
not validate those cryptographic predicates.

`height` is a head-height context; spending checks its candidate height `height+1`.
Spends can occur within a context before `Advance`. This abstracts candidate
assembly rather than modelling complete blocks, transaction ordering or BFT.
Persist/crash models a visible consistent snapshot; the deliberately torn-write
mutant tests its conservation obligation. It is not a RocksDB/WAL fault-injection
test. No network, ciphertext, proof arithmetic, real key entropy, rejected
execution details, multi-input transactions or finalized-chain reorganization is
modelled. The target allows supported V2 credits spends during preparation; the
current public-value Rust experiment does not implement that path.

Reproduce with Java 21 and Python 3:

```sh
python3 recovery/model/check.py --jar /tmp/recovery-tlc/tla2tools.jar --output /tmp/recovery-model-results
```

The runner downloads TLC v1.8.0 if absent, checks SHA256
`5bd7b64db99ae4c6c35f290de5e809c0ee41af43f8699cf696099ffb6452b1e2`,
and retains logs and `results.json`. It requires a complete passing baseline and
an invariant counterexample (not a parser error or timeout) for each mutant:

| Removed rule | Required counterexample |
| --- | --- |
| Candidate-height gating | Legacy operation at the retirement boundary |
| Shared spentness check | Repeated consumption / supply inflation |
| Atomic visible persistence | Replacement without durable consumption |
| Effect binding | Accepted altered ownership-proof claim |
| Effects-scoped replay identity | One owner's copied nonce blocks an unrelated owner |

Three additional reachability checks require counterexamples to deliberately
false assertions that V2 creation, V3 creation and V3 consumption never occur.
They check progress is reachable in the abstract model, so the safety checks
cannot pass merely because migration is disabled. They are not real transaction
acceptance tests.

Recorded baseline: 394,125 generated states, 127,185 distinct, depth 9; all six
invariants pass. All five mutants yield the required counterexamples. These are
finite-state safety results, not unbounded theorems, liveness, transaction-bearing
devnet validation or evidence of quantum soundness. TLC uses fingerprints; its
reported collision estimate and exact logs are retained.

## Disclosed-recovery model

`disclosed.py` is a separate updated transition specification for the disclosure
scope. It gates using candidate height: at H1 every legacy record-consuming or
producing operation and private fee stops; V0/V1 preparation and V2 rotation are
available until H2; from H2 V2 migration and V3 spending/rotation are available.
Unprepared sources remain dormant, migration has no end deadline, migration
preserves the enrolled key, outputs require recipient possession, and rotation
and spending cannot lower the input key's claimed security category. Public
record-free legacy operations are outside this record-state model.

```sh
python3 recovery/model/disclosed.py --output /tmp/disclosed-model
```

The bounded instance explores six slots, two historical records of three units,
two enrolled key classes, candidate heights 1..5 and one-input/one-output
transactions with unit fees. All replay nonces are zero: exclusion is scoped to
the consumed input/effects, not to the nonce globally. It reached 1,504 states
and 1,138 accepted transition edges, with V0 and V1 preparation, migration,
spending and both rotation phases reachable. Eleven additional checks exercise
candidate-height errors, missing consumption exclusion, torn visibility,
missing effect binding, absent recipient possession, security downgrade, key
substitution, simulated legacy compromise after the window, copied nonces on
distinct inputs, rejection immutability and crash to the last committed snapshot.
The output includes independently specified phase and production historical-cap
boundary vectors for implementation comparison.

The model assumes authentic membership and cryptographic verification predicates;
its negative cases toggle those assumed predicates. It does not model native
curve arithmetic, signatures, hashes, full transaction bytes, proof soundness,
network consensus, real storage/WAL behavior, arbitrary multi-input transactions
or a refinement proof against Rust. Its crash check specifies the atomic-store
obligation and is not evidence of a killed-process experiment. The older TLC
results above remain historical bounded target-model evidence and should not be
represented as validating this updated implementation policy.

`vectors/disclosed-phase.tsv` is generated by this independent specification.
The Rust integration test `recovery/signatures/tests/model_vectors.rs` compares
all 80 native-operation phase cases against the recovery core's `Ledger::plan`,
using a genuine ML-DSA-65 public key and registered production verifiers. The 40
legacy/private-fee cases belong to the host VM and are excluded from that core
comparison. This compares the phase predicate only: it does not establish full
transition refinement, proof soundness, host-VM enforcement or BFT behavior.

```sh
python3 recovery/model/disclosed.py --output /tmp/disclosed-model
cmp /tmp/disclosed-model/disclosed-phase.tsv recovery/model/vectors/disclosed-phase.tsv
cargo test --locked -p snarkvm-recovery-signatures --test model_vectors
```

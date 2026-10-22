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

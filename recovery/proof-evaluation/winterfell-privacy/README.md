# Default-trace privacy qualification probe

This standalone, non-production crate generates and verifies actual Winterfell
proofs for a small ambiguous public statement, serializes/reconstructs them from
public bytes, then extracts each private witness from their public trace openings.
It also checks a changed public square fails verification. A successful run means **reject this unmasked
configuration for private-record recovery**, not accept a recovery transaction.

```sh
# Rust 1.96.1; run from snarkVM, with an isolated target directory if desired.
cargo check --locked --manifest-path recovery/proof-evaluation/winterfell-privacy/Cargo.toml
cargo clippy --locked --manifest-path recovery/proof-evaluation/winterfell-privacy/Cargo.toml --all-targets -- -D warnings
cargo +nightly-2026-04-02 fmt --manifest-path recovery/proof-evaluation/winterfell-privacy/Cargo.toml -- --check
cargo run --release --locked --manifest-path recovery/proof-evaluation/winterfell-privacy/Cargo.toml
```

Public statement: square 9 and public counter bounds 0..63; private witnesses 3
and -3 in the f128 field. Width two, 64-row unmasked default trace, Blake3-256,
32 queries, blowup eight, grinding zero, no extension, FRI fold eight, remainder
31, linear batching. Verification pins the exact option set. This is not an Aleo
relation, a soundness attack or a claim about a separately masked construction.
The upstream MIT license for adapted prover boilerplate is retained alongside
the source. No wallet seeds or production keys are used.

For a restored source archive, use a fresh `CARGO_TARGET_DIR`. Normalized archive
timestamps must not be used to validate a build against an existing target cache.

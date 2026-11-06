# Native recovery wire and storage evidence

The focused storage suite passed 19 tests in 7.27 seconds. The schema suite passed five tests in 0.15 seconds. The native transaction wire suite passed four tests in 0.14 seconds. Five finalization-encoding tests passed, including little- and big-endian bit encodings. The full Cargo elapsed times include queued builds and are not performance benchmarks. `manifest.json` records log hashes.

```sh
source /workspace/.setup/snarkos-env.sh
CARGO_TARGET_DIR=/workspace/snarkOS/target RUSTFLAGS='-C target-cpu=skylake' cargo test --locked -p snarkvm-ledger-store --features rocks --lib test_recovery_ -- --test-threads=1
CARGO_TARGET_DIR=/workspace/snarkOS/target RUSTFLAGS='-C target-cpu=skylake' cargo test --locked -p snarkvm-ledger-store --features rocks --lib helpers::rocksdb::internal::schema::tests -- --test-threads=1 --nocapture
CARGO_TARGET_DIR=/workspace/snarkOS/target RUSTFLAGS='-C target-cpu=skylake' cargo test --locked -p snarkvm-ledger-block transaction::recovery::tests -- --nocapture
CARGO_TARGET_DIR=/workspace/snarkOS/target RUSTFLAGS='-C target-cpu=skylake' cargo test --locked -p snarkvm-synthesizer-program finalize_operation -- --nocapture
```

The tests cover memory and RocksDB candidate aborts, checkpoints, rewind, committed rollback, typed transaction archival and shared transaction/state/serial batches. Subprocess tests terminate at known committed, queued and partially finalized checkpoints with SIGKILL, reopen the database and require the complete prior state. These storage fixtures use structurally valid envelopes and intentionally do not establish signature validity or block consensus.

Wire tests cover binary, JSON and bincode roundtrips; full envelope identity changes with effects or evidence; canonical legacy serial exposure; malformed, truncated and oversized frames; incorrect transaction IDs; and accepted-recovery finalization shape. The source fixture is a V1 credits record; historical provenance and authorization are separate VM checks.

Schema V1 adds recovery namespaces without rewriting existing values. Newer schemas are refused. Older V0-only binaries refuse a V1 database; changing the version stamp is not a supported downgrade.

The crash tests establish process-interruption consistency with RocksDB WAL recovery. They do not establish power-loss durability or permission to reorganize BFT-finalized history. Transaction-bearing node interruption and finality evidence belong to the devnet results.

# Genuine historical V0 sources

The isolated `historical-v0` generator pins snarkVM 3.7.1 revision
`9741f1159a8cd18e2d676d5a095eeffad71ab52c`, before record versioning was
introduced. That source has no record version field or constructor argument.
No current record is relabeled V0.

`fixtures/v0-mainnet-native` contains an original constructor, ciphertext,
commitment and serial-number vector. Its public test account is derived from
`42field`; its encryption scalar is `7scalar`; its amount is 1,000,000,000
microcredits. This vector alone makes **no ledger-inclusion claim**. The manifest
records every artifact's SHA256 and the exact creating revision.

Use Rust 1.96.1 and the checked-in isolated lockfile:

```sh
CARGO_TARGET_DIR=/tmp/historical-v0-target cargo run --release --locked \
  --manifest-path recovery/history-tools/historical-v0/Cargo.toml -- \
  record mainnet /tmp/historical-v0-record
CARGO_TARGET_DIR=/tmp/historical-v0-target cargo run --release --locked \
  --features genesis --manifest-path recovery/history-tools/historical-v0/Cargo.toml -- \
  genesis testnet /tmp/historical-v0-genesis
```

The `genesis` mode calls that pinned historical implementation's real
`VM::genesis_quorum`. It constructs the ordinary four
`credits.aleo/transfer_public_to_private` executions, rather than adding
unauthenticated records to recovery state. The test committee uses public dev
seed 1234567890 and four validators. Key zero starts with 8,000,000,000 public
microcredits, so each original private output is 1,000,000,000 microcredits.
These amounts respect the historical inclusion-upgrade limits of 10^12 per
source and 4*10^12 cumulative shared `credits.aleo/pool` use. Other public
balances preserve the exact genesis supply.

The exported genesis is an isolated, deliberately chosen test-chain trust
anchor. Loading it into current nodes additionally requires canonical block
parsing, matching the expected block hash, matching all four committee/dev-key
addresses, and normal current ledger initialization. Generation does not by
itself establish those current-node checks or migration acceptance. These
public fixture keys must never hold live funds.

`fixtures/v0-testnet-genesis` retains the generated block and all four original
record openings. Its expected block hash is
`ab1nnulyh65kyndy2e0n4p79hg9sc0llzv4yy4d2apnpfzktc8wjgxs0s63gr`;
the exact bytes have SHA256
`78ea18989b5148bcca838814ecbaf2f898de35e09765fa043732ab5948434c5d`.
The current VM test
`pinned_historical_v0_genesis_is_authenticated_by_current_vm` checks current
parsing, canonical encoding, genesis rules, normal VM insertion and retained
source membership. The fixture's manifest describes source generation, not a
substitute for that acceptance test or the transaction-bearing devnet run.

The helper's `test_targets` feature forwards the original revision's
`console/test_targets` feature. It selects that revision's development targets
(coinbase 31, proof 8) for a current node compiled with `test_network`. It does
not change the historical record constructor or patch serialized block bytes.
Generate this separate development genesis with:

```sh
CARGO_TARGET_DIR=/tmp/historical-v0-target cargo run --offline --release --locked \
  --features genesis,test_targets \
  --manifest-path recovery/history-tools/historical-v0/Cargo.toml -- \
  genesis testnet /tmp/historical-v0-dev-genesis
```

The normal-target fixture above remains a separate chain identity. Its genesis
must not be passed to a node expecting development targets, and the node's
metadata checks must remain enabled. The provenance file retains the original
normal-target generator hashes alongside the helper's current hashes.

`fixtures/v0-testnet-dev-genesis` retains this separate old-implementation
development genesis. Its block hash is
`ab1njne0yg0ygw9kwyldxw942syzvhvx7gjdp87nadermkt45w4x5ps88sgkx`,
and its bytes have SHA256
`05f9da76ecb1531021634e3227367fe842867966dfceb2f5476303bc42e7dc36`.
`build-provenance.json` records the source/lock hashes, exact feature forwarding,
toolchain, binary identity and targets. `generator-source.tar.gz` retains the
exact helper sources and lockfile. All four original records, ciphertexts,
record-view keys, commitments and serials match the normal-target fixture.

Reproduce the independent target and artifact comparison with:

```sh
python3 recovery/history-tools/fixtures/v0-testnet-dev-genesis/check.py \
  recovery/history-tools/fixtures/v0-testnet-dev-genesis \
  recovery/history-tools/fixtures/v0-testnet-genesis \
  --output /tmp/historical-dev-genesis-check.json
```

This byte inspection verifies target/profile compatibility and fixture identity.
Current node parsing, ledger initialization and accepted migration transactions
remain separate acceptance checks; `inspection.json` does not establish them.

# Quantum recoverability preparation

## Status and scope

The experimental [V2 design and implementation boundary](QUANTUM_RECOVERY_V2.md)
adds separate full-width opening commitments and migration-witness helpers.
It does not add an on-chain migration or a recovery spend. Ordinary transaction
encoding continues to reject V2 records.

This branch is based on `zklim/snarkVM` mainnet commit
`75b476338d30b6576e62db57daea86d8e5b8b365`.

The implemented scope is **preparation with existing authorization retained**.
It provides archival integrity, native recovery-witness reconstruction, a
constrained seed-to-account derivation, and an unscheduled retirement gate.
It does not provide a post-quantum recovery transaction, a post-quantum proof
backend, or a proof that every existing asset is recoverable. Do not activate
the retirement version with this implementation alone: it rejects transactions
without providing a replacement spending path.

No private seed is included in an archive. Wallet seeds used by the witness
helpers must stay local and become private inputs to a future recovery proof.

## Primary sources and essential findings

Research source revisions:

| Source | Pinned revision |
| --- | --- |
| [Zakura](https://github.com/zakura-core/zakura/tree/134a3e7f1d1ec0056e43258a3d2ab6e391c8acec) | `134a3e7f1d1ec0056e43258a3d2ab6e391c8acec` |
| [ZIP repository](https://github.com/zcash/zips/tree/a34cfc091434275120ff017c92c3b50d3cef623a) | `a34cfc091434275120ff017c92c3b50d3cef623a` |
| Zakura's `zakura-orchard` dependency | version `3.0.0`; crate SHA256 `fa61cbcae46478ca44db70f805d9a328c0a2d9deeb733e6f24128b5c929910c2` |
| Dependency source provenance | `zakura-core/common`, commit `0b13ab9e66ea8855a7b4305b17e44fdccbeb3d58`, path `crates/orchard` |

The Orchard crate archive was checked against the checksum in Zakura's pinned
Cargo.lock before inspection. The ZIP website returned HTTP 403 in this
environment; the normative Markdown was read from the ZIP Git repository.

[ZIP 229](https://github.com/zcash/zips/blob/a34cfc091434275120ff017c92c3b50d3cef623a/zips/zip-0229.md)
is the version 6 transaction-format proposal, marked Draft at this revision.
It introduces Ironwood as a separate pool, with separate note commitments,
nullifiers, balances, and hash domains. It delegates quantum recoverability
to ZIP 2005. It retains spend-authorizing and binding signatures. It expressly
says that old Sprout, Sapling, and Orchard funds require migration and cannot
all be recovered after their protocols are disabled.

[ZIP 2005](https://github.com/zcash/zips/blob/a34cfc091434275120ff017c92c3b50d3cef623a/zips/zip-2005.md)
is marked Proposed. Its critical observation is that replacing signatures and
the proof system does not repair an elliptic-curve note commitment whose
binding fails when discrete logarithms become easy. It binds commitment
randomness to every note field through a conventional hash derivation:

```
pre_rcm = 0x0B || encode(g_d) || encode(pk_d) || LE64(value) || rho || encode(psi)
rcm = ToScalar(PRF_expand(rseed, pre_rcm))
```

The future recovery proof must enforce this derivation, authentic membership,
key derivation, deterministic nullifiers, and authorization of transaction
effects. Merely knowing a viewing key or a curve discrete logarithm is not
the intended authorization. The proposal includes a seed branch and separate
quantum-key machinery for FROST and hardware-wallet use cases. Its FROST
outline retains RedDSA alongside the quantum credential to preserve classical
threshold authorization while discrete logarithms remain hard. The actual
Recovery Protocol and its proof backend are deliberately not specified in
full. The proposal does not claim current post-quantum spend security.

In Zakura, the relevant integration points are:

- `crates/zakura-consensus/src/transaction.rs`: Orchard and Ironwood flag
  checks, circuit-era routing, and ordinary proof/signature validation.
- `crates/zakura-consensus/src/transaction/check.rs`: cross-address
  restrictions, pool flags, canonical proof sizes, and duplicate nullifiers.
- `crates/zakura-consensus/src/primitives/halo2.rs`: preserves historical
  verification keys and selects the correct circuit for the block's era.
- `crates/zakura-chain/src/primitives/zcash_note_encryption.rs`: distinct
  Orchard and Ironwood decryption domains and plaintext-version tests.
- In `zakura-orchard` 3.0.0, `src/note.rs`, `RandomSeed::rcm_v3` hashes the
  complete note tuple, and `Note::rcm` selects V2 or V3 derivation. This
  implements preparation; it is not a post-quantum recovery spend verifier.

Do not conflate the draft ZIP's latest key-management options with everything
implemented by that dependency release. In particular, the published source
examined here still has the traditional key structures in `src/keys.rs`.

## snarkVM ownership and authorization

The account path is:

```
sk_sig = HashToScalarPSD2("AleoAccountSignatureSecretKey0", seed)
r_sig  = HashToScalarPSD2("AleoAccountSignatureRandomizer0.0", seed)
pk_sig = sk_sig * G
pr_sig = r_sig * G
sk_prf = HashToScalarPSD4(x(pk_sig), x(pr_sig))
address = pk_sig + pr_sig + sk_prf * G
view_key = sk_sig + r_sig + sk_prf
```

The derivations are in `console/account/src/private_key/try_from.rs`,
`compute_key/try_from.rs`, `compute_key/to_address.rs`, and
`view_key/try_from.rs`. A future recovery relation must constrain the complete
seed derivation. Injecting `sk_sig` and `r_sig` as unconstrained witnesses
does not establish knowledge of the original seed. Possession of a view key
is also insufficient against the specified attacker, because the address
is a fixed-base multiplication of that view key.

`console/account/src/signature/verify.rs` verifies a Schnorr-style relation
using `response * G + challenge * pk_sig`, hashes the reconstructed nonce,
compute key, address, and message, and checks the compute-key-derived address.
The circuit implementation is in `circuit/account/src/signature/verify.rs`.

`console/program/src/request/verify.rs` authenticates the program, function,
root-call status, optional program checksum, inputs, and transition context.
It checks that input-record owners match the signer. Record serial-number
logic additionally relates `gamma` to `sk_sig`. The equivalent request
signature and input checks also exist inside the circuit; changing only
`Signature::verify` would leave that authorization path in place.

Record V0 uses BHP hashing. V1 uses a BHP commitment with randomness derived
from the record view key; the BHP digest covers record fields. See
`console/program/src/data/record/to_commitment.rs` and its circuit counterpart.
BHP's elliptic-curve binding cannot simply be assumed post-quantum. Serial
numbers also use elliptic-curve operations and BHP commitments.

Public mapping permissions are program semantics. For example,
`synthesizer/program/src/resources/credits.aleo` passes `self.caller` or
`self.signer` into finalizers that update balances. A mapping keyed by an
address is not automatically a balance owned by that address. Allowances,
withdrawal addresses, staking state, program accounts, and custom asset rules
must retain their authorization semantics.

Other legacy signature paths include deployment ownership, `sign.verify`,
ECDSA instructions, block authority, Narwhal batch headers, and certificates.
Varuna/KZG proofs also rely on elliptic curves. A transaction-signature change
does not address forged proofs or validator-consensus authorization.

## Implemented preparation

`PrivateKey::from_seed` in the account circuit constrains both key components
using the exact native domains. Existing private-key injection and legacy
circuits are unchanged. Separate `Record::decrypt_from_seed` native and
circuit methods constrain/reconstruct seed-derived decryption and ownership.
They are witness helpers, not ledger membership or asset-transfer verifiers.

`ConsensusStore::write_recovery_snapshot` exports **all confirmed blocks**,
not only their elliptic-curve hashes or record commitments. Full block bytes
preserve the ciphertexts, transactions, deployments, and context needed to
analyze historical assets. Export fails if record ciphertexts are absent.
It also exports every confirmed mapping descriptor, including empty mappings,
every mapping key/value entry regardless of its schema, and the stored spent
serial-number set. This avoids silently selecting only `credits.aleo/account`.

This archival approach is an experimental alternative preparation strategy,
not a port of Ironwood's changed note-randomness derivation. Its future
recovery statement and security argument still need cryptographic review.
In particular, archiving data alone does not prove recoverable ownership.

Run export against a quiescent database or offline copy. The code rejects an
active atomic write and detects checkpoint-height/hash changes, but it does
not acquire a global database snapshot lock. A caller must prevent concurrent
writes. Payloads are streamed; the exporter retains 64-byte leaf digests and
Merkle-building storage in memory. Whole-mainnet export performance has not
been measured here.

`verify_recovery_snapshot` checks network, format, allocation bounds,
completeness markers, duplicates, and integrity against a **separately trusted
root**. It does not verify historic consensus, the semantic consistency of
mapping state with blocks, or a recovery spend. The root must be published and
authenticated before legacy cryptography becomes forgeable, or fixed by an
independently trusted upgrade checkpoint. A root supplied by the claimant is
not sufficient evidence.

A snapshot describes one checkpoint. It does not cover later transfers or
mapping changes. Preparation archives must be refreshed, and the recovery
upgrade must select an authenticated finalized freeze checkpoint with complete
state. Archived ciphertext does not make current record encryption
post-quantum secure or preserve privacy against a quantum adversary.

The wire format is:

| Component | Encoding |
| --- | --- |
| Header | ASCII `AleoRecoverySnapshot1`, network `u16 LE`, target consensus `u16 LE`, height `u32 LE`, canonical block hash |
| Frame | kind `u8`, payload length `u64 LE`, payload |
| Kind 1 | Canonically serialized full block |
| Kind 2 | Canonical program ID and mapping name |
| Kind 3 | Kind-2 descriptor, key byte length `u64 LE`, canonical key bytes, value byte length `u64 LE`, canonical value bytes |
| Kind 4 | Canonical spent serial-number field |
| Trailer | `0xff` followed by 64-byte root; trailing bytes are rejected |

Hashing uses SHA3-512 over the `AleoRecoverySnapshot1` domain, network ID,
purpose byte, and length-prefixed parts. Leaves use the frame kind as purpose.
Sorted leaf digests make the root independent of database iteration order.
Duplicate digests are rejected. Internal nodes use purpose `0x80`; an odd
node pairs with the empty digest (purpose `0x81`). The final root uses purpose
`0x82` and binds the complete header, leaf count, and Merkle root. The stored
block hash is checkpoint metadata; the complete block bytes are separately
bound by SHA3-512.

## Consensus flags and compatibility

| Version | Meaning in this branch |
| --- | --- |
| V1–V22 | Existing authorization and transaction behavior |
| V23 | Reserved preparation version; archival-format rehearsals may select it explicitly; legacy authorization stays mandatory |
| V24 | Reserved retirement gate; rejects legacy transactions, execution proofs, fees, and deployments; no replacement transaction exists yet |

Both reserved versions have activation height `u32::MAX` on every published
network and in default test heights. `u32::MAX` is treated as unscheduled,
including when looking up that exact height. `ConsensusVersion::latest()`
continues to select V22 for ordinary transaction construction. Test-chain
helpers and benchmarks select the last scheduled height rather than trying
to advance to a reserved version. Existing 22-entry custom test-height lists
remain supported; explicit 24-entry lists permit upgrade-boundary experiments.

The VM gate runs before serialization, duplicate checks, and verification
caches. Process execution, fee, and deployment entry points enforce it too.
Retirement rejects a legacy transaction; it never interprets a missing or
invalid signature as success. Historical validation still uses its historical
consensus version. Primitive signature verification and validator signatures
remain available for history and current consensus. Retiring block and
Narwhal signatures requires coordinated snarkOS/validator changes.

## Coverage and remaining recovery requirements

| Asset or account category | What preparation preserves | What a future recovery protocol must establish |
| --- | --- | --- |
| V0/V1 records under a retained standard account seed | Full ciphertext, transaction/program context, spent serials; tested local seed reconstruction | Authenticated archive membership; seed binding; exact decryption and record typing; accepted-output status; commitment and serial derivation; unspentness; authorized destination and effects |
| Direct user public balances | Every confirmed key/value and program context; seed-to-address constraints | Exact mapping membership and program authorization; replay protection; conservation; atomic state transition |
| Allowances, composite keys, staking and withdrawal state | Complete mapping bytes, without guessing ownership from keys | Preserve the program's full authorization and state invariants |
| Program-controlled assets | Ciphertexts, public state, and deployment history | Program-specific recovery authorization; a seed-only account relation cannot authorize a program account |
| Custom compute keys, FROST, hardware wallets lacking the original seed | Public archival evidence | A separately designed and previously bound recovery credential; no universal seed-based guarantee |
| Pruned or unavailable historical data | Export fails on missing checkpoint/block/ciphertext data | Restore complete data and prove snapshot completeness before relying on recovery |

Before scheduling V24, implement a reviewed post-quantum proof/authorization
backend, recovery transaction encoding, an authenticated checkpoint and
membership proofs, network/version/transaction-effect binding, deterministic
nullifiers, rejection of prior spends and duplicate recoveries, replay
protection, fees, atomic state updates, and asset-conservation checks. A future
private recovery proof must bind the seed to the claimed owner and effects
without publishing the seed. It must interpret accepted and rejected
transactions correctly. Proof of a record's occurrence in a block alone does
not prove that the record was accepted or unspent.

Existing arbitrary programs cannot be granted a new recovery authority
without evaluating their semantics. A future generic solution must preserve
those semantics through post-quantum execution proofs, or provide explicitly
specified migration adapters. There is no supported basis here for promising
that every historical asset can be recovered by every existing key format.

## Reproduction

For an offline `ConsensusStore`, export using a newly created file and retain
the returned root through an independent trusted channel:

```rust,ignore
let file = std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open("recovery.snapshot")?;
let snapshot = store.write_recovery_snapshot(
    ConsensusVersion::V23,
    std::io::BufWriter::new(file),
)?;
// Independently authenticate snapshot.root before relying on this archive.
```

The verifier takes an independently authenticated expected root and an archive
size limit chosen for the reader's resource budget. A root read from the same
untrusted file is not an independent trust anchor. Exporting with target V23
is a format rehearsal and does not change current network consensus.

Activate the installed tools in this environment:

```bash
export CARGO_HOME=/workspace/.cloud-tools/cargo
export RUSTUP_HOME=/workspace/.cloud-tools/rustup
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_BUILD_JOBS=4
cd /workspace/snarkVM
```

The focused tests are selected by `recovery` in the console network/program,
circuit account/program, ledger store, and synthesizer process crates. They
cover seed derivation and a fixed historical account vector, wrong-owner
constraints, existing record versions and visibilities, archive tampering,
domain separation, state changes, truncation, allocation limits, writer errors,
and the retirement policy. Snapshot integration uses the repository's embedded
mainnet genesis block rather than generating a replacement chain.

The independent digest vector uses Python hashlib SHA3-512 over the explicitly
framed bytes and checks the Rust implementation against that value.
Passing these tests establishes preparation behavior; it does not establish
post-quantum spending security or a completed recovery protocol.

### Validation results

- 16 focused `recovery` tests passed across the six affected test crates.
- The full console-network suite passed: 14 tests, including two of the
  focused tests above.
- Three existing account signature-verification tests passed in constant,
  public, and private modes using the freshly built account test binary.
- `cargo check --locked -p snarkvm-synthesizer -p snarkvm-ledger --features
  snarkvm-ledger/test-helpers` passed, as did checking the modified
  `check_transaction_multirecord` benchmark.
- Nightly-2026-04-02 workspace formatting checks passed.
- Clippy passed with `--no-deps --all-targets --features
  snarkvm-synthesizer/test -- -D warnings` for console network/program, circuit
  account/program, ledger store, synthesizer process, and synthesizer.
- Dependency-wide strict Clippy encountered 357 pre-existing warnings in
  `parameters/src/macros.rs`. Those unrelated files were not changed.

The RocksDB-backed testchain-generator executable was not built. Its change
only selects the last scheduled test height using the same rule checked in
the ledger helper and benchmark. No full-mainnet archival export, live network
activation, post-quantum proof, or asset-recovery transaction was executed.

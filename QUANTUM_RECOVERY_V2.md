# Recovery V2 design and implementation boundary

Status: experimental preparation primitives, not a consensus migration protocol.
V23 and V24 remain unscheduled. The initial design was recorded before implementation.

| Component | Status |
| --- | --- |
| Explicit V23 V2 codec, full opening hash and seed binding | Implemented in native code and circuits where applicable |
| V0/V1 migration witness preserving owner and entries | Implemented; no ledger mutation |
| Admission of V2 to ordinary authorization/encoding | Rejected |
| Authenticated transaction envelope and atomic on-chain migration | Not implemented |
| Recovery nullifier and cross-path double-spend enforcement | Not implemented |
| Public-mapping adapters and credential enrollment | Design requirements only |
| Post-quantum recovery proof backend and recovery transactions | Not implemented |

## Threat model and comparison with Ironwood

During preparation, signatures and Varuna are assumed sound. Later, an attacker
may compute discrete logarithms, recover viewing keys, forge legacy signatures
and Varuna proofs, and control the archive supplied to a recovery verifier.
Hash functions and a separately authenticated finalized checkpoint are assumed
secure. Neither privacy after quantum key recovery nor recovery from a checkpoint
authenticated only after legacy cryptography fails is promised.

The pinned ZIP 2005 in QUANTUM_RECOVERY.md explicitly requires the future
Recovery Protocol to enforce note-randomness derivation AND key binding. Its
legacy-key branch constrains the original secret-key derivations; its other
branch uses additional quantum key material. ZIP 229 supplies pool separation
and migration rules, not that proof system. Zakura's pinned Orchard 3.0.0
dependency implements the changed note-randomness derivation, not recovery
transactions. None of this implies that the previous snarkVM snapshot prototype
has Ironwood's recoverability guarantee.

For snarkVM, an arbitrary scalar or view key cannot replace the original seed
in an ownership proof. A future proof must constrain seed -> sk_sig/r_sig ->
compute key -> address as well as record decryption. Custom compute keys,
threshold accounts, seedless hardware wallets, and program-owned records need
separate, previously authenticated credentials. They are not covered here.

## Choice: additional full-width hash commitment

Use an additional SHA3-512 opening commitment, rather than changing BHP
randomness or replacing a field-sized record ID. This avoids importing an
unproved adaptation of Ironwood's commitment argument into snarkVM. It also
avoids silently reducing a 512-bit commitment to a roughly 253-bit field.
Existing BHP IDs and serial numbers retain their classical roles.

The additional commitment binds the network, program ID, record name, every
plaintext record field including visibility, entry order/types, owner, nonce and
version, a recovery credential, and the record view key. The recovery credential
is a domain-separated SHA3-512 hash of the original account seed. The native
and circuit seed-based opening helpers additionally check that this seed derives
the record owner and the record view key. The generic commitment helper takes a
credential so that a future sender can use an independently authenticated
recipient credential without learning the recipient seed.

Conditional argument: distinct canonical openings of an authenticated 512-bit
commitment require a SHA3-512 collision, irrespective of BHP discrete logarithms.
Credential substitution also changes that commitment. This is not a proof of
the complete protocol: independent review must address canonical encodings,
quantum hash assumptions, credential enrollment, extractability of the future
proof, and composition with the ledger. Seed search is bounded by the entropy
of the existing field-sized account seed, not by the 512-bit digest length.
An exposed record view key is not an independent recovery credential.

V2 plaintext/ciphertext records use byte variants 4/5 for public/private owner.
Their remaining byte encoding is the existing record encoding. The additional
commitment is a separate 64-byte value, NOT a new schema entry. It must be
authenticated in a future transaction envelope; the `_version=2` byte alone
does not carry it and does not establish recoverability. The 64-byte credential
is part of the private opening, already bound by that commitment. Publishing a
repeated seed credential would link records; an envelope should not publish it.
A sender needs an authenticated recipient credential, and the recipient must
check the received opening. Neither an enrollment protocol nor a sender/recipient
protocol has been implemented here.
V2 byte encoding and decoding require explicit preparation APIs; ordinary
ToBytes/FromBytes retain their historical variants and reject V2.

For a bit string x, frame(x) is LE64(bit_length(x)) || x. SHA3 input consists
of ASCII domain bytes, LE16(network), followed by the frames concatenated as
bits, then zero padding to a byte boundary. Lengths exclude this padding.
The credential domain is `AleoRecoveryCredential2`, with one seed-bit frame.
The opening domain is `AleoRecoveryRecord2`, with frames for program ID bits,
record-name bits, owner visibility (one bit), owner address, record version,
nonce, entry count (LE64), then the identifier and typed entry bits of each
entry in insertion order, then 512 credential bits and record-view-key bits.
Primitive encodings use the existing ToBitsLE contract. Each top-level entry
name and value has its own frame; this does not rely on delimiting unframed
identifier concatenations in the legacy record bit encoding. Nested plaintext
structs and arrays already encode member identifiers and values with lengths.
The explicit lengths make trailing zero padding unambiguous.

## Migration and consensus integration requirements

The implemented migration helper constructs a WITNESS only: it checks a V0/V1
source and its seed-derived owner, preserves owner and every data entry exactly,
requires a nonzero nonce distinct from the source nonce, and produces V2. The
caller must sample a new randomizer; the helper does not track prior outputs.
It moves no assets. Neither a seed
nor a plaintext migration witness should be transmitted to a node.

An actual migration MUST consume the source through the existing signed request,
inclusion proof, and serial-number checks while those remain secure. It MUST
atomically publish the V2 ciphertext and full commitment, consume
the old serial number exactly once, and apply the original program's transition
semantics. For arbitrary assets, equality of record entries is insufficient to
replace program authorization. Rejected/aborted transactions must publish no
recoverable output. A later V2 transfer must atomically consume the prior V2
identity and publish the successor; it cannot leave both spend paths live.

Required policy before scheduling preparation: historic V1-V7 retain their
historic checks, V8-V22 produce V1, V23 consumes legacy or V2 and produces only
fully authenticated V2 envelopes. V24 retires legacy spending only after the
replacement protocol is deployed. Existing deployments need an explicit circuit
era and authenticated verifying-key migration: record versions are private
circuit inputs, and adding conditional SHA3 constraints changes old circuits.
Native credits, dynamic-record translation, fees, callbacks, deployed programs,
wallets and snarkOS must agree on that era and the envelope format.

CURRENT CODE DOES NOT IMPLEMENT THAT POLICY. Ordinary authorization, execution
and fee verification still reject V2 outputs. The legacy BHP commitment helpers
retain their existing native/circuit behavior, including for nonzero version
witnesses sampled during key synthesis; computing a BHP value is not admission
of that version to ordinary transaction encoding. Experimental helpers require
explicit V23 preparation selection.
Historical circuits and keys are unchanged. Do not schedule V23 expecting live
V2 migration, or V24 expecting a recovery spend. There is no sidecar authenticated
in accepted transactions yet and no ledger migration entry point.

## Nullifiers, state authentication and public mappings

Legacy serial numbers use curve operations and BHP. A future protocol needs a
deterministic, domain-separated recovery nullifier for an authenticated V2
identity, and a checkpoint linking each V2 identity to its legacy spentness.
Reject both prior legacy spends and duplicate recoveries. Bind the network,
checkpoint, recovery transaction effects, fees and destination. Never accept
claimant-supplied roots or claimant-chosen nullifiers as authority.

The existing SHA3 archive preserves full bytes, but its root is not a consensus
state commitment. It needs pre-attack independent authentication and a finalized
freeze checkpoint. BHP state paths, block IDs and forged legacy proofs cannot
substitute for this trust anchor. Current archives contain no V2 sidecar frames;
their format must be versioned when envelopes are integrated.

Public mappings use a separate adapter protocol. Authenticate the complete
program/edition, mapping name, typed key/value, revision and checkpoint in a
hash-based state root. Register a recovery credential through the program's
existing authorization and constrain its account binding. Version that binding
on every ownership or authorization change and update it atomically with state.
An address-shaped key, the export API, or an archive membership proof grants
no withdrawal authority.

Direct balances require the original balance-update rules. Allowances require
spender limits and owner revocation. Staking requires validator/delegator and
withdrawal distinctions, bonding delays and locks. Composite keys and custom
assets require explicit program adapters; program-controlled balances require
program authorization. There is no generic mapping claim operation in this
implementation. Unsupported adapters must fail closed.

## Evidence required before activation

Native/circuit agreement, independently computed hash vectors, malformed encoding
and mutated-opening rejection, seed substitution rejection, owner/data preservation,
and legacy proof compatibility are preparation checks. They do not demonstrate
an on-chain migration or a post-quantum recovery spend.

Activation additionally requires end-to-end tests of accepted and rejected
migrations, atomic rollback, double spending across both spend paths, stale
checkpoints, replay across networks/upgrades, conservation for each supported
program, unauthorized mapping claims, real envelope/state-root persistence, and
historical proof verification under the correct keys. Independent cryptographic
and consensus review must establish the full statement and security assumptions.

## Reproduction and measured costs

Activate the Rust environment as described in QUANTUM_RECOVERY.md. No new
dependencies or feature flags are needed for the native and circuit helpers.

```sh
cargo check --locked -p snarkvm-console-program -p snarkvm-circuit-program \
  -p snarkvm-synthesizer-process -p snarkvm-synthesizer
cargo clippy --locked --no-deps --all-targets -p snarkvm-console-program \
  -p snarkvm-circuit-program -p snarkvm-synthesizer-process \
  --features snarkvm-synthesizer-process/test -- -D warnings
cargo +nightly-2026-04-02 fmt --all -- --check
cargo test --locked -p snarkvm-console-program -p snarkvm-circuit-program \
  recovery_v2 -- --nocapture
cargo test --locked -p snarkvm-synthesizer-process --features test,dev-print \
  recovery_v2_cannot_enter_legacy_authorization
cargo test --locked -p snarkvm-console-program data::record::bytes::tests
cargo test --locked -p snarkvm-circuit-program recovery_seed_
```

The opening vector below is independently constructed without snarkVM encoding
or hashing code. It uses an empty record with public zero-point owner, zero
nonce, V2, zero credential and zero view key. It checks encoding only; this
fixture has no demonstrated seed owner and is not an asset-recovery claim.

```python
import hashlib, struct
bits = lambda n, k: [bool((n >> i) & 1) for i in range(k)]
byte_bits = lambda b: [bool((v >> i) & 1) for v in b for i in range(8)]
parts = [byte_bits(b"assetaleo"), byte_bits(b"coin"), [False],
         bits(0, 253), bits(2, 8), bits(0, 253), bits(0, 64),
         bits(0, 512), bits(0, 253)]
message = byte_bits(b"AleoRecoveryRecord2" + struct.pack("<H", 0))
for part in parts:
    message += byte_bits(struct.pack("<Q", len(part))) + part
message += [False] * ((-len(message)) % 8)
encoded = bytes(sum(int(message[i+j]) << j for j in range(8))
                for i in range(0, len(message), 8))
assert len(encoded) == 274
assert hashlib.sha3_512(encoded).hexdigest() == (
    "52e29d93720dda2d72659846aa038011523ed5d475688621e8b17f1eebc8c13936"
    "f58e4bd2dd9699d1a60513853286498a26b686afc6a950651edb2a700ce4b3")
```

Two other fixed vectors check seed-credential hashing and non-byte-aligned
frames, including an empty frame. Native mutation checks cover program/name,
credential, view key, owner, nonce, entry name/type/visibility/value, source
version, malformed owners, truncated/duplicate encodings and upgrade boundaries.
Circuit checks cover valid native agreement, wrong seed, reused/zero nonce,
wrong source version and a mutated amount constrained against the original
public digest. These tests do not attempt to simulate absent ledger enforcement.

For the one-entry `amount: 100u64.private` fixture:

| Source / owner visibility | Migration constraints | Seed + opening constraints | V2 plaintext bytes |
| --- | ---: | ---: | ---: |
| V0 / private | 7,916 | 928,831 | 90 |
| V1 / public | 7,916 | 928,834 | 87 |

Counts are measured after source/seed/randomizer injection. The opening count
includes seed-derived account verification, credential hashing and the opening
hash; it is not a post-quantum proof size or a transaction cost. V2 record bytes
have the same length as the corresponding V1 encoding. The proposed envelope
adds at least 64 bytes for the full commitment, plus its framing and indexing;
no such per-record ledger storage is implemented or measured yet. Credential
bits are an opening witness and need not be published alongside each record.

The historical `test_process_execute_transfer_public_to_private` test was
attempted separately. Proving stopped at the missing
`powers-of-beta-16.usrs.84631bc` download: the network proxy returned HTTP 403
for both official parameter sources, including with escalated network access.
No checksum, TLS check, proof assertion or parameter source was changed.
The allowlist draft now includes `parameters.provable.com` and
`s3.us-west-1.amazonaws.com`; publishing that environment change is still needed
before retrying. This test is BLOCKED, not passed.

Final local results: 21 targeted tests passed (7 native V2, 5 circuit V2,
2 process policy guards, 2 existing record-byte tests, 2 existing seed/decryption
tests and 3 existing signature-verification tests). The four-crate build check,
strict Clippy for the three affected crates with the documented test feature,
nightly workspace formatting and `git diff --check` passed. The process guard
fixtures are intentionally unauthenticated: their assertions concern rejection
and verifier ordering, not successful historical proof verification. No end-to-end
ledger migration, replay/double-spend enforcement or mapping recovery test is
claimed: those protocol entry points do not exist yet.

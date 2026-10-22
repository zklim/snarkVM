# Modular recovery experiment

## Status

The follow-up private-proof evaluation is recorded in
[`recovery/INTEGRATION_STATUS.md`](recovery/INTEGRATION_STATUS.md), with the exact
target relation, backend blocker, source snapshots and independent model results.

This is an **experimental public-value ledger and signature integration**, not a
completed private Aleo recovery deployment. The existing Aleo Transaction enum,
Varuna circuits and consensus storage do not carry these experimental transactions.
No validator may activate this as a complete recovery protocol. snarkOS refuses a
scheduled V23/V24 at startup with an explicit missing-integration error. Public
activation tables remain unchanged and unscheduled.

The core and direct adapters are in `recovery/core` and `recovery/signatures` on
`quantum-recoverability-pqs`. `quantum-recoverability-aerie` contains the same core
plus `recovery/aerie`. Aerie/Akita do not occur in core types or dependencies.
The core is published on `quantum-recoverability-pqs`; the Aerie branch descends
from that core. The containing Git commit identifies each published source revision.
Source manifests preserve the publication inventory and earlier evaluation snapshots.

| Source | Exact pin |
| --- | --- |
| snarkVM base | `c493bc514f0850d4e07a0135b0e4f845e38d0c73` |
| snarkOS base / existing pinned VM integration | `5d497bf3253eec606404bee8d65c305d8cd86f76` / VM above |
| Direct ML-DSA / Falcon | `ml-dsa =0.1.1` / `fn-dsa =0.3.0` |
| Aerie | `49b6c212c209286c536196f53618823ffdf0e899` |
| Akita / jolt | `e023b6a46143f7b23199ccecb2684192baf7b640` / `c7c2d08d5bb0c7c80501f29f723e595af7fcff3c` |
| Spongefish | `ef9741346a150039427d9e0c02d6b2d73e93ec81` |

Cargo.lock pins transitive dependencies separately on each worktree. Production
snarkOS still pins the previously committed VM; its startup guard does not pretend
the experimental core has been connected to block execution.

## Protocol and trust boundary

`Ledger::from_trusted_records` explicitly imports an authenticated **public** source.
The caller, not a signature backend, must establish the provenance of this source.
Within that ledger, the core checks membership, spentness, versions, eligibility,
value conservation, transaction-identity replay exclusion and output uniqueness.
Replay protection records the full effects ID, so a copied nonce cannot block an
unrelated transaction using different inputs. It computes all
expected authorizations and performs no mutations until they all verify. Candidate
application clones state and commits only if every transaction succeeds.

Stage one admits V0/V1-to-V2 preparation during `[preparation, recovery)`, or
indefinitely if recovery is unscheduled. Each source owner supplies a classical
Aleo signature over the complete effects. Each replacement PQ key supplies a
separate proof of possession over the same effects and its output slot. Validators
never manufacture witnesses or rewrite records. Ordinary legacy spending is not
implemented in this experimental ledger. The production old-spend indexes are
not shared with it, so exclusion across production and experimental paths is **not
established**.

Stage two freezes dormant V0/V1 records. It accepts one-input/one-output V2-to-V3
migration with the same enrolled key, and V3 spending into V3 outputs. V2 migration
has no terminal deadline. Old keys authorize rotation; new keys co-authorize their
enrollment. No replacement output may reduce the highest input signature parameter set's
claimed NIST security category, including through an ordinary spend. Recipient co-signing is mandatory in this experiment, making
payments interactive. A relay can copy a fully authorized transaction, but cannot
change its recipients or fees; replaying the same effects after acceptance fails.
No ordering fairness or front-running privacy is promised. V2 can rotate in stage one; V3 can rotate in stage two.
Migration changes the record version, while rotation changes enrolled authority.

Only the public credits model is supported. The canonical program identifier is
literally `credits.aleo`; arbitrary program effects are rejected by decoding.
Fees are conserved into a public fee counter, not distributed through Aleo's
production fee program. Historical effects remain decodable, but historical
verification must use the historical state and height. No finality or authenticated
historical checkpoint is inferred from checkpoint decoding.

A quantum attacker may break historical discrete-log signatures after preparation,
but must still forge an enrolled PQ signature to spend an authenticated V2 source
in this model. Preparation must precede that compromise. The surviving secret is
the enrolled PQ signing secret, not a disclosed account seed. An attacker with that
same secret is indistinguishable from its owner. Once the legacy scheme is broken,
legacy signatures alone cannot identify the original owner; recovery then needs a
previous authenticated commitment or an independently surviving witness. SHA3-512 collision/preimage
assumptions and signature assumptions are separate; a 512-bit hash is not a claim
of 512-bit quantum security.

The `opening` field is bound to authorization and record identity but is **not
verified as a private Aleo opening**. There is no new proof of account-seed
knowledge, private membership or private balance conservation. Those relations
need a separately specified and audited proof construction, authenticated V2
on-chain enrollment, and circuit/native bindings. Aerie cannot supply them.
Existing seed/opening circuit helpers remain unchanged. Legacy BHP commitments,
serials, Varuna/KZG, DH encryption and BFT signatures remain classical.

## Canonical statement

All integers use fixed-width little endian. Byte vectors and list counts use u32
lengths. Hash framing gives each part, including its domain, a u64 byte length.
Effects encode, in order:

`AleoRecoveryEffects1 || chain/genesis digest[64] || protocol:u16 || policy:u16 ||
policy_commitment[64] || operation:u8 || valid_from:u32 || valid_until:u32 || replay[64] ||
bytes(credits.aleo) || inputs || complete outputs || fee:u64`.

A key encodes `algorithm:u16 || parameters:u16 || bytes(public_key)`. A record
encodes version, tagged owner/key, public amount, nonce[64], opening[64]. Record,
key and transaction identities have distinct SHA3-512 domains and include chain
identity where relevant. A signature statement is:

`AleoRecoveryAuthorization1 || role:u8 || slot:u16 || key || key_identity[64] ||
bytes(complete_effects)`.

Role 0 consumes an input; role 1 enrolls an output key. Input order precedes output
order. The policy commitment hashes the exact schedule and permitted profile/aggregate identifiers. The core derives source keys from state. A backend cannot choose a message,
key, fee, ownership check or member set. Unsupported versions/profiles, malformed
lengths and trailing bytes fail. Bounds: 16 inputs, 16 outputs, 40,000 effect bytes,
44,000 message bytes, 1,024 transactions per experimental candidate. Checkpoint
restore accepts at most 64 MiB and 10,000 records and 100,000 replay entries; it checks canonical
ordering and an externally expected policy and chain identity. Host-managed disk
atomicity, block anchoring, rollback and cross-store exclusion remain obligations.

## Backend capabilities

| Adapter | Accepted profile | Guarantee / limitation |
| --- | --- | --- |
| ML-DSA-65 | FIPS 204 pure, empty context; 1,952-byte PK, 3,309-byte signature | Direct signature verification; no aggregation or ownership proof |
| Falcon-512 | fn-dsa 0.3.0 padded, key-prefixed raw, empty context; 897-byte PK, 666-byte signature | Direct reference verification; no final FIPS 206 compatibility claim |
| Aerie | Above Falcon only, wire v1, per-record salt; max 32 records / 2 MiB proof | Aggregates exactly ordered signatures; no ownership or ZK claim |

Signature, legacy enrollment and aggregation are separate typed interfaces.
Policies select identifiers; nodes do not negotiate them. Missing profiles or
required aggregation backends fail at ledger initialization and verification.
Mixed-profile authorizations use direct evidence; this adapter does not aggregate
a subset while verifying the rest directly. Direct and aggregate evidence are distinct enum variants. Aggregate failure never
falls back to direct acceptance. Signing is outside aggregate production; producer
input signatures are directly verified before proof construction. Common-salt
frames, Falcon-1024, unknown parameter policies and duplicate statements fail.

Aerie is a research construction using Akita `dev-protocol`. Its paper's classical
ROM argument does not establish quantum-adversarial proof soundness. Parameter
sampling, PCS/MSIS assumptions, extraction, transcript analysis and upstream
production acceptance require independent review. Direct PQ signatures avoid
relying on aggregate proof soundness. Neither path supplies private ownership. Signing callers must use a CSPRNG and
fresh per-signature salts. A verifier cannot prove the signer used fresh entropy;
the deterministic public test fixtures are never wallet keys.

## Reproduction and evidence

Use Rust 1.96.1 and nightly-2026-04-02 rustfmt. From snarkVM:

```sh
cargo test --locked -p snarkvm-recovery-signatures --test conformance
cargo clippy --locked -p snarkvm-recovery -p snarkvm-recovery-signatures --all-targets --no-deps -- -D warnings
cargo +nightly-2026-04-02 fmt --all -- --check
# cargo-fuzz 0.13.1; the fuzz workspace has its own checked-in lockfile.
cargo +nightly-2026-04-02 fuzz run --fuzz-dir recovery/fuzz effects -- -max_total_time=30 -max_len=45000 -seed=2029536690
# On the Aerie worktree:
cargo test --locked -p snarkvm-recovery-aerie --features producer,parallel --test differential -- --nocapture
```

NIST ACVP case 44 and independently assembled Python codec/hash vectors are
checked in with provenance. Shared conformance tests use real ML-DSA and Falcon
signatures over the same core transitions, including actual Aleo enrollment
signatures. This is backend substitutability without replacing ownership/state code.
Tests and timing evidence are recorded in `RECOVERY_RESULTS.md` after validation.

This implementation provides no record privacy: amounts, keys and experimental
nullifiers are public and linkable. Existing Aleo encryption does not become PQ
secure. Seed privacy, post-compromise confidentiality, zero knowledge and fully PQ
validator consensus are not demonstrated.

## Outstanding private proof relation

A production ownership statement must bind the chain and authenticated V2 anchor,
source program/record type, source commitment, enrolled algorithm-bound key,
deterministic consumed identifier and exact replacement effects. Its private
witness must establish the original owner/seed relation where required, canonical
opening, authenticated membership, program authorization and conservation. The
ledger must check current spentness and atomically consume the same resource on
all old and new paths. Proofs cannot disclose the surviving seed. Merely adding
an Aerie signature relation or hashing an unauthenticated opening does not prove
this statement. No backend for that private relation is implemented here.

Primary references: [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204),
[Falcon specification](https://falcon-sign.info/falcon.pdf),
[Aerie paper](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/paper/aerie.pdf),
[Aerie normative profile](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/specs/falcon.md),
and [release obligations](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/specs/release-policy.md).

# Private credits recovery: construction and acceptance boundary

**Status: target relation, not an implemented proof or production protocol.** The
public-value ledger in `core` is unchanged. No private migration is accepted by
snarkOS. Backend qualification and its blocker are in
[PROOF_BACKENDS.md](PROOF_BACKENDS.md). The source and test record is in
[INTEGRATION_STATUS.md](INTEGRATION_STATUS.md).

## Threat and timing

Let H1 be preparation activation, H2 recovery activation, and Tq the first time an
adversary can forge legacy group-based authorization or proofs. Heights are policy
inputs; **all public-network H1/H2 values remain unscheduled**. The target requires
authenticated preparation and finalization before Tq and H2 no later than Tq.
Preparation performed after compromise cannot distinguish an original owner from
an adversary with equivalent legacy authority. If a transition is allowed to rely
only on legacy authorization between H1 and H2, that interval must precede Tq.

The adversary observes history and mempools, copies messages/nonces, schedules
competing transactions and partitions, and can run quantum algorithms and make
quantum queries in any claimed QROM analysis. It can eventually break discrete
logarithms, pairing-based proofs and classical BFT authentication. It cannot be
assumed to lose access to old ciphertexts. Account-seed theft and compromise of an
enrolled PQ signing secret are separate exclusions: an attacker with the owner's
surviving witness/authority is indistinguishable from the owner.

The surviving authority is a PQ key enrolled by an authenticated owner transaction
before Tq. A hidden random per-record consumption secret must also survive for
private deterministic nullifiers. A seed-derived SHA3 credential may support a
different recovery relation, but a naked digest opening supplies neither record
membership nor authority to enroll an arbitrary new key. This design does not send
the seed or consumption secret to validators or an untrusted remote prover.

The legacy seed has at most roughly 253 bits of field entropy; hashing it to 512
bits does not enlarge that entropy. Ideal quantum exhaustive search over such a
seed has a roughly 2^126.5 query upper bound, independent of the output length.
This is a generic bound, not a measured attack or a proof of achieved security.

There must be a **pre-compromise authenticated anchor** of V2 commitments and
enrollments, and an authenticated continuing state. A newly hashed archive of
untrusted legacy data does not provide one. A trusted finalized checkpoint is an
explicit additional assumption until block authentication/consensus is itself
protected against quantum forgery. This feature alone does not upgrade BFT.

Proof privacy and encryption privacy are different. Historical Aleo DH
encryption can lose confidentiality after discrete-log compromise. If V2 openings
or rho are encrypted only with that same scheme, they cannot be assumed to stay
secret from a harvest-now/decrypt-later attacker. Enrolled PQ signatures can
still protect authorization, but do not restore historical confidentiality or
private nullifier unlinkability. A pinned hybrid/PQ encryption and wallet-secret
storage design is a separate missing construction. Public keys, input/output
counts, fees, timing and proof length can also reveal information even if a
private relation eventually has a ZK argument.

## Record classes and windows

| Candidate height | Permitted target behavior |
| --- | --- |
| `< H1` | Existing V0/V1 verification and execution, under historical policy |
| `[H1,H2)` | Owner-provided V0/V1 preparation or supported credits spending; every newly created private output must be authenticated V2 with enrolled PQ authority |
| `>= H2` | Freeze unprepared V0/V1; V2-to-V3 migration preserving enrolled authority; V3 spending/authorized rotation only |

H1-to-H2 is the preparation window, not an automatic ledger rewrite. V2-to-V3
migration opens at H2 and has no deadline in the target policy. Dormant unprepared
records do not acquire new authority after H2. Changing that policy requires a new
construction and consensus decision. Historical verification uses the historical
height and state; an old proof is not a current spending authorization.

Only the exact native `credits.aleo/credits` private schema is in scope:
`owner as address.private; microcredits as u64.private`. Fixtures using an `amount`
field are not historical Aleo credits. Imported plaintext fixtures are not proof of
historical provenance. A production test must retain original ciphertext,
commitment, creating transaction/block and inclusion path from a pinned historical
implementation for **both V0 and V1**. Those end-to-end fixtures are not supplied by
the new qualification probe. Reject public-owner records, external programs,
dynamic records, unknown schemas and unsupported credits functions. No generic
program-preservation claim follows from knowing a record's owner.

The proposed first path contains prepare, migrate, private transfer and key
rotation, with explicit microcredit conservation. Bonding, public-balance
conversion, deployments and arbitrary calls need separate semantics and are out
of scope. Fees and change are exact authorized effects; no hidden fee may be
deducted and no fee output may return to a retired record format.

## Public statement and canonical encoding

The core, never an adapter, must construct the expected statement from decoded
effects, policy and authenticated state. The prospective ownership relation is:

`R(policy, chain, roots, effects, consumed, replacements; witness) = true`.

Public inputs comprise chain ID **and genesis identity**, protocol/relation
version, program/schema/function IDs, policy commitment, proof-backend/profile
and parameter digest, activation/validity window, approved input-anchor roots,
ordered input versions/consumed identifiers, ordered full replacement commitments
and enrollment commitments, fee disposition, replay nonce and complete effects
digest. They also bind encryption/ciphertext commitments if those are part of the
transaction. The verifier must pin the relation circuit/guest image ID; an adapter
must not supply a different program with the same public-output shape.

Use a new domain `AleoPrivateRecoveryStatement1`, fixed-width little-endian
integers, u32 length-prefixed bounded byte strings and lists, explicit enum tags,
and full 64-byte SHA3-512 digests. Reject unknown IDs, noncanonical values,
duplicate inputs, integer overflow and trailing bytes. Do not reduce a 512-bit
commitment to a field element. Effects identity excludes randomized signature and
proof bytes; the wire/evidence commitment includes them. Both require consensus
definitions. The existing `AleoRecoveryEffects1` public-record codec is **not**
this production envelope; no wire tag or transaction-tree layout is allocated here.

## Private witness and relation

The prover supplies canonical source plaintexts, opening randomness/view-key
material, source provenance and Merkle paths, output plaintexts/randomness and
consumption secrets, and the ownership material required by the selected branch.
No secret is a public input merely because a host-side check needs it.

| Relation requirement | Inside the ownership proof | Current-state validator check |
| --- | --- | --- |
| Historical V0/V1 source | Recompute exact historical commitment and owner relation; prove source inclusion and bind original legacy serial | Approved historical root/class; serial unspent; transaction authorized before Tq/H2 |
| V2/V3 source | Open full authenticated commitment and enrollment, prove inclusion and permitted controlling key | Root in policy-approved history; enrolled key/profile still eligible |
| Consumed resource | Prove canonical deterministic identifier from fixed per-record secret and source identity; bind any legacy serial bridge | Shared conflict index, including pending candidate spends and fee inputs |
| Program semantics | Exact private credits schema, function/owner authorization, integer range constraints and conservation | Supported function/profile; candidate-height policy; actual fee rules |
| Replacement effects | Recompute every output, key enrollment, ciphertext commitment and fee; bind ordered effects digest | Output uniqueness, valid fee recipient/rate, canonical transaction identity |
| PQ authorization | Bind expected eligible key identity to the same complete effects | Verify PQ signatures separately; exact optional aggregate member list |

Preparation must prove actual legacy owner control and authenticate the V2
replacement/enrollment in one transaction, with old authority and new-key proof
of possession over the exact effects. Recomputing an output from arbitrary host
plaintext is insufficient. The existing SHA3 helper's digest includes a seed
credential and view key but **does not bind the enrolled PQ key/profile**. An
algorithm-bound enrollment commitment and a new, specified record commitment
profile are additional work, not an interpretation of that helper.

For example, a new private record can carry hidden random `rho` committed in its
opening. Its stable consumed ID is domain-separated SHA3-512 of chain, immutable
source commitment and rho. Membership and the opening, including rho, must be
proved. A key rotation consumes the old record and creates a different record;
it cannot select a second nullifier for the old record. The precise commitment
layout and consumption-secret lifecycle are **unimplemented design obligations**.
They cannot be patched into V2 by adding an unconstrained host field.

Historical V0/V1 consumption must use the exact serial already used by execution
and private fees. If a legacy serial is also exposed for a prepared successor,
its derivation must be proof-bound and remain deterministic across authorization
paths. After a clean H2 freeze, legacy sources have no alternative migration
path. No proof of membership can establish current unspentness by itself.

Migrate V2-to-V3 preserves enrolled algorithm/profile/key. Rotation requires old
authority and new-key possession over the full effects; enforce consensus
parameter/category policy and prohibit key/algorithm substitution. A signature or
Aerie aggregate is not a substitute for any row of the ownership relation.

## Atomicity and finality contract

Decode and verify against candidate height, approved roots and a speculative
overlay. Reserve all inputs, including private fee inputs, in one shared
consumption domain. An accepted transition commits consumption, outputs,
enrollment/rotation, fees, transaction indexes, recovery root and block state as
one durable operation. On proof/authorization failure it commits nothing.

A rejected execution that charges a fee is a **different, explicitly authorized
fee-only outcome**. It must consume only its valid fee input, share the same
conflict index and obey retirement policy. It must not consume a recovery source
without creating its authorized replacements. Recovery operations without such
an authorized outcome must abort without charge. Binding a fee to a recovery
effects ID and its rejected outcome remains a production format obligation.

Dry-run speculation must not persist enrollment or consumption. Atomic checkpoints
must rewind all affected indexes. A crash must recover either the preceding
committed block or the complete new block, with consistent roots and indexes;
application-level batching alone is not evidence of crash atomicity. A new side
database needs a shared durable batch or a specified recoverable commit protocol.
Speculative rollback is supported in the target model. Reverting a finalized BFT
block is not assumed; test only the actual ledger's supported rollback, and label
conflicting finalized histories a consensus failure, not a successful reorg.

The TLA+ model checks a small abstraction of these requirements. Neither it nor a
successful signature test establishes cryptographic ownership, implementation
refinement, native/circuit parity, production durability or network finality.

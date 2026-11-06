# Two-stage disclosed Aleo recovery

This implementation targets quantum recoverability and authorization correctness.
It permits public records, values, openings and membership information; no
confidentiality, zero-knowledge or unlinkability guarantee is made. The disclosed credits path passes transaction-bearing four-validator validation,
including both activations, migration/spending, fault recovery and checked snapshot replay.
An additional two-client relay also passes. [RECOVERY_RESULTS.md](RECOVERY_RESULTS.md)
records the composed-run evidence, original interruptions, costs and remaining obligations.
Public activations remain unscheduled; no live deployment occurred.

## Construction and boundaries

Preparation accepts genuine historical `credits.aleo/credits` V0/V1 records.
The owner discloses the exact plaintext and per-record opening material. Native
checks recompute the original commitment and verify the creating transaction and
block in authenticated storage. An Aleo signature authorizes the complete
replacement effects. A classical equal-discrete-log certificate binds the
original serial to that same signature key without disclosing its reusable
exponent. Shared consumption checks cover legacy execution, private fees and
recovery. Preparation must finalize before legacy compromise.

The replacement is a native disclosed V2 credits record, with SHA3-512 identity
binding version, algorithm/profile, public key, value, nonce and context digest.
The output PQ key co-signs its exact enrollment. At the second activation, its
already-enrolled key authorizes V2-to-V3 migration and V3 spending. A public
opening never substitutes for that signature. These native V2/V3 records are a
distinct class, not reinterpreted legacy private console/circuit ciphertexts or
the earlier seed-hashing helper. No general ownership-proof backend is needed
for relations validators evaluate directly.

[recovery/OWNERSHIP_PROOF.md](recovery/OWNERSHIP_PROOF.md) specifies the complete
relation, historical classes, authority and state division.
[recovery/PROOF_BACKENDS.md](recovery/PROOF_BACKENDS.md) assesses every retained
proof/signature/aggregate separately. In particular, the preparation certificate
and historical Aleo proofs are classical. Aerie is not a historical ownership
proof and its inspected classical-ROM argument is not a concrete QROM argument.
Native consensus policy permits direct authorization only.

The recovery claim assumes a pre-compromise authenticated V2 checkpoint and
continuing authentic ledger state. No independently PQ-authenticated checkpoint
transport or quantum-safe consensus replacement is implemented; a local SHA3
root alone is not an anchor. It does not upgrade validator BFT, classical
header commitments, historical proofs or encryption. A quantum attacker who can
replace accepted finalized history defeats that state assumption. A trusted new
hash of unauthenticated history cannot repair it. An attacker with an enrolled
PQ signing secret has the same spending authority as its owner.

## Activation and program policy

| Candidate height | Native and legacy record policy |
| --- | --- |
| Before H1 | Legacy behavior; native recovery unavailable |
| H1 through H2−1 | Owner-authorized V0/V1→V2; V2 rotation; freeze all legacy record-consuming/producing paths and private fees |
| H2 onward | Freeze unprepared V0/V1; V2→V3 under the same key; V3 spend/rotation; retire legacy transaction authorization |

Migration from prepared V2 has no terminal deadline. The local profile fixes both
heights before enrollment. Scheduling H2 later after V2 state exists needs a
separate consensus-gated policy/checkpoint upgrade; it is not implemented. A node
upgrade cannot silently rebase the policy committed in existing state. Dormant old records are not
rewritten or assigned new keys. Existing legacy circuits create legacy outputs,
so they cannot remain an alternate record-spending path after H1. Record-free
legacy operations keep their applicable policy until H2. Historical decoding
remains available; re-verification requires historical state and height.

Only the exact native credits schema and prepare/migrate/spend/rotate effects are
supported. Arbitrary programs, dynamic/external record classes, bonding and
public-balance conversion are outside this native profile. Every output key
supplies proof of possession, making payments interactive. Rotation requires
old-key authorization and new-key possession; migration preserves the key.
Outputs cannot lower the highest input profile's permitted security category,
including by using ordinary spending to disguise rotation.

Historical inclusion-upgrade per-source and shared-pool limits still apply.
Native fee minimum is 1,000 microcredits plus canonical envelope bytes. Fees are
part of signed conserved effects. Invalid native operations have no accepted
fee-only outcome. Fee distribution and complete durable outcomes require the
production-path evidence listed in the results matrix.

## Core-owned canonical authorization

Integers use fixed-width little endian; vector lengths use u32. Each hash
component, including its domain, has a u64 little-endian length prefix. Effects
encode:

```text
AleoRecoveryEffects1 || chain/genesis[64] || protocol:u16 || policy:u16 ||
policy_commitment[64] || operation:u8 || valid_from:u32 || valid_until:u32 ||
replay[64] || bytes(credits.aleo) || ordered_inputs || complete_ordered_outputs || fee:u64
```

The chain digest includes native network ID and the actual full genesis bytes.
The policy commitment binds schedules and allowed profile/aggregate identifiers.
A key encodes algorithm, parameter profile and full public key. A record encodes
version, tagged owner/key, value, nonce[64] and context opening[64]. Signature
statements encode `AleoRecoveryAuthorization1`, role, slot, exact key, key
identity and complete effects. Input authorizations precede output proofs of
possession. Backends cannot choose effects or checks.

The core transaction frame adds bounded legacy authorization and either ordered
direct signatures or one aggregate variant. The production Recovery envelope
adds versioned, bounded historical sources. Canonical decoding rejects unknown
profiles/tags, invalid lengths and trailing data. Full SHA3-512 effects identity
excludes randomized evidence; full envelope identity includes evidence and
openings. Replay exclusion uses effects identity, rather than globally consuming
the replay nonce. Copying a different transaction's nonce cannot reserve its
inputs.

The surrounding Aleo transaction ID is a classical compatibility index. Its
leaf takes a field-capacity prefix of the SHA3-512 envelope digest; the existing
BHP Merkle tree then hashes that leaf to the transaction ID. This does not provide
a PQ transaction or block identity. Native authorization still binds complete
full-width effects and state identities and does not reuse a legacy positive
proof cache as authorization. The 512-bit envelope digest does not upgrade the
classical transaction/header commitment or authenticate a ledger checkpoint.

## Production components and limits

`Transaction::Recovery` and `AcceptedRecovery` carry native effects through the
normal wire/identity, admission, candidate-height, speculation, finalization and
archive paths. Native finalization records full before/after recovery roots.
The existing shared FinalizeStore batch owns snapshots, enrollment, consumption,
historical pool and fee state; source serials are also checked against the
original transition indexes. A separately persisted sidecar is not the ledger.
Candidate operations apply in order and invalid operations must leave state
unchanged. Store rollback and speculative rewind are not a license to reorganize
finalized BFT history.

Bounds are consensus profile limits, not capacity claims: 16 inputs/outputs,
40,000 effects bytes, 44,000 signature-message bytes, 2 MiB production envelope,
4,096 disclosed plaintext bytes, 10,000 retained core records, 100,000 replay
entries and 64 MiB restored state. The current implementation clones/encodes full
recovery state and retains per-height snapshots. It requires explicit scaling
work before any public activation.

## Modular authorization and branches

| Adapter | Exact profile | Responsibility |
| --- | --- | --- |
| ML-DSA | `ml-dsa =0.1.1`; ML-DSA-65, pure, empty context; PK 1,952 / signature 3,309 bytes | Direct authorization |
| Falcon | `fn-dsa =0.3.0`; Falcon-512, padded, key-prefixed raw, empty context; PK 897 / signature 666 bytes | Genuine different direct scheme; aggregate reference |
| Aerie | Separate branch, same Falcon profile; per-record salts; 32 members / 2 MiB | Optional exactly ordered aggregate; disabled in native policy |

Core typed interfaces expose explicit profiles/capabilities/limits. Aerie/Akita
have no types or dependencies in ownership/state logic. Signing, aggregate
production and aggregate verification are separate. Invalid aggregate evidence
never falls back to direct acceptance. Missing consensus-required backends must
fail before accepting incompatible state; no node-local negotiation is allowed.

| Worktree / branch | Starting revision for this extension |
| --- | --- |
| snarkVM / `quantum-recoverability-pqs` | `f0f726c7fcaed39e1f5aeb29add1875f14fecdbe` |
| snarkVM-aerie / `quantum-recoverability-aerie` | `3f56837109459653b6d90f80e473c18a5e8d463c` |
| snarkOS / `quantum-recoverability-pqs` | `aa6234fb9c69626e11c763c8e052904684c44032` |
| snarkOS-aerie / `quantum-recoverability-aerie` | `f877f8e6f964726e1f53aa063f92a2ec39cab09c` |

These are starting commits, not identities for later uncommitted changes.
Retained snapshot manifests identify exact archives and overlays. Aerie branches
derive from their core branches and retain adapters separately. Aerie pins are
listed in the backend assessment; lockfiles pin external dependencies. Local
snarkOS development uses the matching VM source tree, which must accompany any
reproduction snapshot. No new publication is implied by source modification.

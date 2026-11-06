# Disclosed-recovery review notes

Scope: source review of the uncommitted native recovery extension on 2026-10-22.
This is an internal integration review, not independent cryptographic audit or
proof that all acceptance tests pass. Sources: `recovery/{core,records,signatures}`,
`ledger/block/src/transaction/recovery.rs`, VM recovery/verification/finalization
hooks and native-store interfaces.

## Required argument

1. Before legacy compromise, the historical owner signs the exact prepared
   effects; the equal-log certificate binds the serial to the same compute key.
   This is the point at which legitimate owner and future legacy forger can be
   distinguished. Preparation after compromise cannot repair that distinction.
2. Source commitment/schema/provenance and canonical serial are checked against
   authenticated ledger state; a standalone plaintext or imported fixture is
   insufficient. The existing historical upgrade caps cannot be bypassed.
3. V2 state commits the complete algorithm/profile/key and effects. Direct PQ
   signatures authorize all later changes, including fees/rotation; an opening
   is public data, not a bearer credential.
4. All spending paths share exclusion and every transition commits atomically.
   A changed context/root, cached classical proof or alternate fee path must not
   bypass the enrolled-key signature or native current-state check.
5. Full-width native hashes do not upgrade the classical header/transaction
   index/BFT chain. A pre-compromise anchor and trustworthy continuing ledger
   are explicit assumptions. Without them, a forged finalized history can
   substitute authority regardless of local record signature correctness.

## Source findings and review obligations

- The native path correctly separates direct opening checks, classical
  preparation ownership, direct enrolled PQ signatures and optional aggregation.
  Its native policy has no allowed aggregate IDs. No Aerie QROM assumption is
  necessary for direct recovery acceptance.
- Native V2/V3 are a new disclosed credits class; existing private console/circuit
  V2 helpers are not silently reinterpreted as algorithm-bound enrollment. This
  distinction must remain visible in wallet/docs and compatibility claims.
- Both direct schemes use the same core effects, transition rules and typed
  interface. Claimed NIST category comparison is a policy rule, not a proof that
  different schemes have precisely comparable real-world security.
- Full envelope identities include evidence; effects replay identities exclude
  randomized evidence. The compatibility leaf truncates the full envelope digest to field capacity,
  then existing BHP Merkle hashing computes the legacy transaction ID; it is
  not a quantum-safe transaction/block identity. Native full checks must run even when an old proof
  cache or transaction index returns a positive result.
- Whole-state cloning, canonical restore, caps and per-height snapshots are
  bounded experimental resource policy. Passing tiny devnet tests cannot
  justify unlimited production state, fees or throughput.
- Passing VM tests now cover H1/H2 boundaries, genuine V1 historical execution,
  fee conservation, changed effects, simulated legacy compromise, ordered native
  spends and abort/reconstruction; V0 compatibility/provenance also passes.
  Storage subprocess tests pass shared batch SIGKILL/reopen checks. Remaining
  network evidence must cover real four-validator transactions, observed topology,
  persisted restarts and interrupted block finalization.
- Classical preparation certificates require fresh cryptographic nonces and
  no cross-protocol reuse with legacy signatures sharing the same exponent.
  Wallet account/PQ secrets must never be serialized in transaction evidence.
- Native arithmetic checks do not add a private circuit relation. Existing
  legacy native/circuit consistency remains necessary where those paths are
  retained; it is not evidence of a new zero-knowledge or PQ circuit proof.

Primary relation and proof assumptions are in `../../OWNERSHIP_PROOF.md` and
`../../PROOF_BACKENDS.md`. The live acceptance matrix is `../../../RECOVERY_RESULTS.md`.

## Confirmed-body membership hardening — focused regression passes

A later review found that the public unconfirmed-transaction store API, combined
with an aborted/rejected transaction-to-block index, could produce archive state
in which an output looked block-associated without actually appearing as a
confirmed output. Review found no node/network path that constructs this combined
state; no remote exploit is demonstrated. Index linkage alone is an insufficient library
boundary for authenticated historical membership.

The production helper now requires the exact record output and creating
transition in the actual charged confirmed transaction, then that exact confirmed
body in its block. Reconstructed rejected execution outputs do not provide this
membership. It does not blanket-reject rejected status, so actual charged Fee
outputs remain structurally eligible. A real proof-backed rejected execution with
private-fee change has not been exercised; this compatibility is untested.

The focused historical filter passes 3/3 in 0.35 seconds: genuine confirmed old
genesis origin accepts, while an unconfirmed archive and that archive plus an
aborted-ID block index reject. One existing unrelated historical reward test is
included. The first attempt failed metadata fixture setup before the verifier;
the corrected retry and both logs are retained in `checks`. Broader VM/storage
tests and the prior debug binary predate the fix. Fresh strict Clippy and pinned
formatting pass for both core repositories on the fixed source. Optimized build
and native network acceptance remain pending; no remote-exploit or independent-audit claim
follows from this library-state regression.

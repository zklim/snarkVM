# Ownership backend qualification

**Decision: no production ownership backend enabled.** The complete private Aleo
relation has not been implemented or justified in any inspected backend. This is
a precise dependency blocker for production migration acceptance, not a proof
that PQ private proofs are impossible. Existing experimental code is preserved.

| Candidate and exact revision | What it can express / assessed evidence | Decision for this relation |
| --- | --- | --- |
| Winterfell 0.13.1, `2f78ee9bf667a561bdfcdfa68668d0f9b18b8315` | Generic AIR/STARK; upstream warns it is research and does not provide perfect ZK; actual valid-proof witness extraction below | Reject unmasked default backend for private ownership |
| RISC Zero 3.0.6, `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` | General computation; STARK and optional curve wrapper; primary IOP paper and current privacy/security caveats inspected | Candidate for further construction; no accepted PQ/ZK ownership profile established |
| SP1 6.0.0, `f87f8d6ff005d542db22e241928319f5e96a4609` | General computation; current StackedBasefold PCS; Core/Compressed and Plonk/Groth16 modes differ | Source screening only; no Aleo proof run or qualified private/PQ profile |
| Existing Aleo Varuna/Sonic/KZG, VM `c493bc514f0850d4e07a0135b0e4f845e38d0c73` | Historical native/circuit relation under group assumptions | Historical pre-compromise use only; PQ signature wrapping does not repair ownership soundness |
| Aerie `49b6c212c209286c536196f53618823ffdf0e899` | Falcon aggregation relation, classical ROM argument, separate adapter | Does not prove the ownership relation or establish its privacy/quantum soundness |

## Executed counterexample: bare Winterfell privacy

The isolated crate [proof-evaluation/winterfell-privacy](proof-evaluation/winterfell-privacy)
pins upstream by git SHA and has its own lockfile. It is not in the VM workspace
or a consensus dependency. It proves `x*x = 9` with private `x` and a public counter.
The two witnesses `3` and `-3` satisfy the **same** public statement. Both proofs
are serialized and reconstructed solely from public bytes, then verify under the
fixed options. A changed public square is rejected. Parsing the trace query recovers the exact
witness, distinguishing the two cases. Retained output:

```text
public_square=9 valid_proof=true private_witness=3 recovered_from_proof=3 proof_bytes=12989
public_square=9 valid_proof=true private_witness=340282366920938463463374557953744961534 recovered_from_proof=340282366920938463463374557953744961534 proof_bytes=12267
qualification=REJECT unmasked_default_trace_is_not_zero_knowledge
```

These are public test constants, not wallet secrets. This demonstrates a privacy
failure for this concrete use of the default trace implementation. It is not a
forgery, an Aleo proof, or a proof that Winterfell cannot be extended with a
separately justified zero-knowledge construction. Such masking and its proof
would be new work; increasing hash length or FRI queries does not supply it.

## RISC Zero: distinguish vendor claims from a qualified profile

The pinned source includes the original paper *Scalable, Transparent Arguments of
RISC-V Integrity*. Sections 2.3, 3 and 3.4 analyze an IOP, then apply a Fiat–Shamir
heuristic using HMAC-SHA-256. Appendix A.3.1 describes random trace padding and
coset evaluation. The source security calculator separates proven list-decoding
bounds from Toy Problem and proximity conjectures. None of these passages alone
supplies a concrete quantum knowledge-soundness bound for the exact ownership
program, transcript and parameters.

The current source `website/api/security-model.md` labels the STARK provers
“Quantum Safe? Yes”, with ROM and Toy Problem assumptions. It also states:
“we have not written a mathematical argument to prove that our system is
zero-knowledge” and cautions users with critical privacy requirements. Its
96-bit estimate, the calculator's 97-bit segment estimate, and README's 98-bit
claim are **source claims with different contexts**, not a measured quantum
security level. An application must select parameters and analyze that instance.
This review neither proves an attack on RISC Zero nor dismisses STARKs as non-PQ.

Before accepting it, the construction must pin: STARK-only receipt kind and hash
suite; verifier parameters/control root; exact guest image; segment/cycle/receipt
limits; no fake/dev receipt acceptance or `circuit_debug`; rejection of unresolved
assumptions/claims; the complete private credits predicate and canonical journal;
and a justified hiding and QROM knowledge-soundness argument with explicit losses.
The generic receipt verifier also accepts Groth16 (curve-based, not PQ), and fake
receipts can verify in development mode. Using that generic API without a mode
policy would not meet this task. Composite receipts also reveal execution length;
padding/recursion privacy needs its own analysis.

No RISC Zero ownership guest, receipt or performance result is claimed here. Its
pinned toolchain is Rust 1.97 versus this environment's Rust 1.96.1; that is a
reproducibility detail, not the cryptographic blocker. Parameters/image/limits and
the relation-specific analysis remain absent, so installing another compiler
would not resolve the acceptance failure.

## Other assumptions and limits

SP1 source screening found a different current PCS from older FRI descriptions.
Its SDK's Plonk/Groth16 on-chain proof modes use BN254 and cannot supply PQ
soundness. Core/Compressed require separate privacy, Fiat–Shamir and parameter
analysis. Absence of a theorem in the inspected files is not evidence that no
theorem exists; these modes remain **unqualified in this review**, not disproved.

SHA3-512 commitments assume a suitable quantum-resistant hash/PRF model; they do
not yield 512-bit quantum security. SHA-256 or algebraic hashes inside a backend
have separate assumptions/bounds. PQ signature security, hash binding, private
proof soundness, private proof hiding and anchor/consensus authenticity are
distinct claims. Trusted setup and universal/transparent parameter generation
must be assessed for the selected mode, not inferred from a backend's name.

In idealized query models, generic n-bit hash preimage search can take about
2^(n/2) quantum queries and collision finding about 2^(n/3), subject to different
memory/resource assumptions. These are not complete backend forgery estimates.
Seed entropy can impose a lower search ceiling than the digest length, and a
Fiat–Shamir knowledge reduction can impose additional losses. The review does
not convert upstream classical conjectural bits into quantum bits by relabeling
them. No concrete end-to-end quantum security level is established here.

The concrete blocker is the lack of a validated private, quantum-sound profile
implementing [the complete relation](OWNERSHIP_PROOF.md) and its authenticated V2
enrollment/state binding. A hashing helper, caller-trusted ledger, Falcon relation
or classical proof cannot fill that interface. The task explicitly permits
preserving the demonstrated implementation when this construction cannot be
justified. Production integration and its devnet acceptance remain incomplete;
the startup refusal cannot truthfully be replaced yet.

Raw pinned excerpts, the paper, SHA256 provenance, proof output and model
counterexamples are retained under `evidence/ownership-20261022`. Direct paper and
arXiv/ePrint HTTP fetches returned 403; the RISC Zero paper was recovered from the
pinned git source and its hash verified. No unavailable paper was represented as
having been read.

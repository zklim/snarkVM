# Direct verification and retained proof assumptions

The current scope permits disclosed record data, values, openings and membership
information. The earlier private-proof qualification remains historical evidence
under `evidence/ownership-20261022`; its confidentiality findings are not blockers
for this scope. A general ownership-proof backend is unnecessary when validators
can evaluate the complete relation directly.

| Construction | Actual responsibility | Security boundary |
| --- | --- | --- |
| Direct historical commitment/schema checks | Recompute canonical disclosed source and exact native commitment; authenticate source provenance | Historical commitment binding and authenticated state before compromise |
| Preparation Aleo signature and Chaum–Pedersen certificate | Authorize exact effects and prove the original deterministic legacy serial belongs to the same signature key | Classical discrete-log and classical Fiat–Shamir assumptions; accepted only before H2/Tq |
| Native V2/V3 state, arithmetic and hashes | Authenticate enrolled key, membership, spentness, allowed semantics, conservation and exact replacement effects | SHA3-512 and authentic continuing ledger; no hidden witness or ownership SNARK |
| ML-DSA-65 direct authorization | Check enrolled key signatures and output key possession | FIPS 204's lattice/hash assumptions and pinned implementation; no implementation certification |
| Falcon-512 direct authorization | Independent modular signature path/reference for Falcon aggregates | Precise padded fn-dsa profile and lattice/hash assumptions; no final FIPS 206 compatibility claim |
| Optional Aerie adapter | Verify exactly the core-determined ordered Falcon authorization set | Separate research aggregation assumptions; not production-enabled by native policy |
| Historical Aleo Varuna/Sonic/KZG proofs | Existing historical transaction validity | Classical group/setup assumptions; a PQ signature does not make these proofs quantum sound |

The complete disclosed predicate is specified in
[OWNERSHIP_PROOF.md](OWNERSHIP_PROOF.md). A signature alone does not establish
historical record ownership, inclusion or conservation. Those relations are
checked separately before the signature adapter receives its immutable message.
No digest opening independently authorizes replacement effects.

## Preparation certificate

The certificate follows the equal-discrete-log relation of Chaum and Pedersen,
*Wallet Databases with Observers*, CRYPTO 1992, made noninteractive using a framed
SHA3-512 challenge. Challenge fields, scalar-capacity truncation, subgroup checks,
nonidentity restrictions and nonce rules are documented in
[records/README.md](records/README.md). Its soundness relies on the legacy group
remaining secure during preparation; a quantum attacker capable of discrete
logarithms can forge it. Using SHA3 does not repair that group relation. No QROM
knowledge-soundness claim or concrete quantum security level is assigned.

The reusable signature exponent never appears in the wire certificate. Fresh
CSPRNG nonces must not repeat or cross-reuse legacy signature nonces. The
surviving post-H2 secret is the enrolled PQ signing key. There is no residual
secret opening that grants substitute authority after disclosure.

## Direct signature profiles

ML-DSA uses `ml-dsa =0.1.1`, ML-DSA-65, FIPS 204 pure mode and empty context
(1,952-byte public key; 3,309-byte signature). Falcon uses `fn-dsa =0.3.0`, degree
512, padded 666-byte signatures, key-prefixed raw message and empty context
(897-byte public key). Profile identifiers are consensus-controlled and included
in commitments and complete authorization messages. Unknown profiles and
malformed keys/signatures fail. The two genuine schemes share ledger-transition
logic; their algorithms are not interchangeable under one identifier.

These are signature constructions with their own hash/random-oracle and lattice
security analyses, not generic Fiat–Shamir ownership proofs. FIPS 204
standardization does not certify this implementation, key handling, integration
or the entire protocol. Falcon's source profile and precise transcript must be
assessed independently. Secret-key theft, side channels, broken randomness and
implementation bugs remain separate risks.

## Aerie is optional and separately qualified

The separate adapter pins Aerie `49b6c212c209286c536196f53618823ffdf0e899`,
Akita `e023b6a46143f7b23199ccecb2684192baf7b640`, jolt
`c7c2d08d5bb0c7c80501f29f723e595af7fcff3c` and Spongefish
`ef9741346a150039427d9e0c02d6b2d73e93ec81`. It supports the exact Falcon profile
above, wire version 1, independent per-record salts, at most 32 authorizations
and 2 MiB proof bytes. Signing, aggregate production and aggregate verification
are separate. The core supplies the ordered complete member list, including
output proofs of possession; omissions, duplicates, reordered messages/keys,
unknown parameter policies and invalid evidence reject without direct fallback.

Aerie's inspected argument is in the classical random-oracle model. It does not
establish a concrete QROM argument for this pinned integration. PCS/MSIS
assumptions, parameter generation, extraction and transcript losses require
independent review. Its Falcon relation does not prove record membership,
legacy ownership, consumption or conservation. Native production policy has no
allowed aggregate identifiers, so demonstrated recovery must use direct
signatures and must not rely on unjustified aggregation soundness.

## Hashes, parameters and state trust

SHA3-512 supplies domain-separated full-width record, key, effects and state
identities. It does not imply 512-bit quantum security. Idealized generic quantum
query bounds and seed/key entropy impose separate limits; no concrete end-to-end
quantum bit level is established here. The recovery compatibility leaf truncates the SHA3 envelope digest to field
capacity, then the existing BHP Merkle tree computes the transaction ID. Neither
this classical index nor block/consensus authentication is a PQ commitment;
full native effects and state identities remain separate.
A trustworthy pre-compromise checkpoint and continuing authenticated ledger are
explicit assumptions, not consequences of the new hash.

Direct disclosed checks need no new trusted proof setup. Historical Aleo proof
parameters and optional Aerie parameters retain their own setup/generation and
soundness obligations. Prior Winterfell, RISC Zero and SP1 screening is retained
as historical material, not as a selected production dependency or proof that
these systems cannot support other relations. None is required by the current
disclosed authorization path.

Primary references: [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204),
[Falcon specification](https://falcon-sign.info/falcon.pdf),
[Aerie paper](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/paper/aerie.pdf),
[Aerie profile](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/specs/falcon.md),
and [upstream release obligations](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/specs/release-policy.md).

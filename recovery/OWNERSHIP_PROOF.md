# Disclosed credits recovery relation

The current acceptance scope permits disclosed record data, values, openings and
membership information. Confidentiality, zero knowledge and unlinkability are
not acceptance criteria. Reusable account and PQ signing secrets remain secret.
This removes the need to hide an ownership witness inside a general proof
backend; it does not remove any authorization or authenticated-state check.
Implementation and test status are tracked in [INTEGRATION_STATUS.md](INTEGRATION_STATUS.md).

## Threat, timing and surviving authority

Let H1 be preparation activation, H2 recovery activation, and Tq the first time
legacy group-based authorization can be forged. The design requires the accepted
V2 enrollment and its authenticated checkpoint to precede Tq. H2 must be no later
than that compromise. Public H1/H2 remain unscheduled. Owners must act during
`[H1,H2)`; validators cannot infer their witnesses or enroll keys for dormant
records. A stage-one-only local policy can leave preparation open indefinitely,
but only while its classical assumptions remain valid.

The attacker observes records and mempools, copies nonces and signed messages,
changes proposed effects, submits competing spends, chooses malformed encodings,
and can later recover legacy discrete logarithms and forge classical proofs and
signatures. After Tq it must still lack the enrolled PQ signing secret and be
unable to forge that scheme, substitute a committed key, or corrupt the assumed
authenticated ledger. Theft of the surviving PQ secret defeats authorization.
No protocol can distinguish its original owner from an attacker with that secret.

A disclosed opening supplies data, not authority. Post-H2 replacement effects
require signatures by keys already enrolled in authenticated V2/V3 state. Merely
opening SHA3-512, knowing a historical record, or wrapping a classical proof in a
PQ signature does not establish that authority.

## Authenticated state is an explicit assumption

Preparation uses normal source transaction/block indexes and the original
commitment and serial-number rules. A previously authenticated, pre-compromise
checkpoint must fix the enrolled keys, recovery state and consumed legacy
serials. Continuing state must preserve that checkpoint and enforce the same
transition rules. A fresh hash of attacker-provided old history is insufficient.

No independently PQ-authenticated checkpoint transport or quantum-safe consensus
replacement is implemented; a local SHA3 root alone is not an anchor.
This feature does not make Aleo validator consensus quantum safe. Block/header
commitments, legacy transaction indexes, BFT signatures and historical proof
systems retain classical assumptions. If quantum attackers can manufacture an
alternative accepted finalized history or control quorum authentication, enrolled
record authorization alone cannot protect the ledger. Recovery claims are
conditional on a trusted pre-compromise anchor and continuing authenticated
consensus/state, or a separately deployed mechanism that supplies those properties.
No such quantum-safe consensus upgrade is claimed here.

## Exact supported relation

The source class is historical `credits.aleo/credits` with private owner address,
one private `microcredits: u64` entry, and version V0 or V1. Reject alternate
programs, public-owner records, altered schema, dynamic/external output classes
and unsupported versions. A plaintext fixture proves no inclusion; acceptance
requires the source's creating output, transaction and block in authenticated
storage. Genuine old-version generator provenance is in
[history-tools/README.md](history-tools/README.md).

| Required relation | Deterministic or cryptographic check | Current-state responsibility |
| --- | --- | --- |
| Exact historical opening | Recompute the original native commitment from canonical disclosed plaintext and per-record view key | Locate the matching supported creating output and authenticated block |
| Historical owner authority | Verify an Aleo signature on the core-generated complete-effects source statement | Accept only before H2 and before assumed compromise |
| Canonical legacy consumption | Verify equal discrete logs linking the signature compute key to `gamma`; use native `serial_number_from_gamma` | Exclude that exact serial in both legacy and recovery indexes, including candidate transactions and fees |
| V2/V3 enrollment and ownership | Look up the full SHA3-512 record ID and exact algorithm/profile/public key in recovery state | Require unspent state and consensus-permitted profile |
| Replacement authority | Verify enrolled input PQ signatures and output key proofs of possession over core-generated effects | Enforce operation/version/window, uniqueness, policy and replay rules |
| Program semantics and conservation | Exact credits schema; checked totals equal outputs plus authorized fee | Enforce fee minimum, historical source limits and shared upgrade pool |

For V0 the historical commitment ignores the per-record view key, so disclosure
normalizes it to zero. V1 uses its commitment-bound view key. The plaintext and
per-record view key are disclosed; the account seed and reusable signature
exponent are not. The mapped source ID additionally binds network, schema,
canonical disclosed data, original commitment and value. This SHA3 mapping does
not replace the historical commitment check or canonical legacy serial.

The pre-compromise certificate proves `P=xG` and `gamma=xH(commitment)` share x:
`A=rG; B=rH; c=SHA3-512(framed statement); s=r-cx`; the verifier checks
`sG+cP=A` and `sH+c gamma=B`. The challenge binds network/genesis, native network
ID, core source authorization message, commitment, P, gamma, A and B. A fresh
CSPRNG nonce and checked subgroup encodings are required. This Chaum–Pedersen
Fiat–Shamir certificate is classical; no post-quantum soundness is attributed to
it. It is never an alternative authorization after H2. See
[records/README.md](records/README.md) for the exact construction and encoding.

Native recovery V2/V3 are a distinct disclosed credits record class. Their
full-width record IDs bind version, algorithm/profile, complete public key,
amount, nonce and context-opening digest. They are not reinterpreted legacy
private `console::Record` ciphertexts or the earlier V2 hashing helper. An
opening digest is bound metadata; arbitrary metadata is not a new ownership
witness. Membership and the enrolled key come from validated state.

## Windows and supported effects

| Candidate height | Permitted behavior |
| --- | --- |
| `< H1` | Existing legacy behavior; native recovery unavailable |
| `[H1,H2)` | Owner-authorized V0/V1 preparation to V2; V2 rotation; legacy record-consuming or producing operations and private fees frozen |
| `>= H2` | Unprepared V0/V1 frozen; V2-to-V3 migration under the same enrolled key; V3 spending and rotation |

The H1 freeze is necessary because the existing legacy circuits do not create
this authenticated native V2 class. Record-free legacy operations retain their
historical policy until H2; legacy transaction authorization is retired at H2.
V2-to-V3 migration has no terminal deadline. Both local activations are fixed
before enrollment; enabling a previously unscheduled H2 after V2 state exists
requires a separate, unimplemented consensus-gated policy/checkpoint upgrade. Preparation never occurs
implicitly. Historical decoding is retained; historical verification needs its
historical height and state and is not a current spending authorization.

The native credits path does not support arbitrary program calls, bonding,
public-balance conversion or private circuit output creation. Inputs and outputs
are ordered complete effects. Every output key co-signs its enrollment; payments
are therefore interactive. Migration preserves the enrolled key. Rotation
consumes the old record, requires its existing key's signature and the new key's
possession, and cannot reduce the permitted security category. Spending cannot
bypass that category rule. Copied fully signed transactions may be relayed, but
the relay cannot change outputs, fees or policy. Fair ordering is not promised.

Sources created at or before the existing inclusion-upgrade height retain its
limits: 10^12 microcredits per historical source and 4*10^12 cumulative shared
`credits.aleo/pool` accounting, when recovery occurs at or after that upgrade.
The full source amount counts, before native fees. Native minimum fee is 1,000
microcredits plus canonical envelope bytes; this is an initial bounded test
profile, not a measured production gas model.

## Statement, consumption and atomicity

[RECOVERY_ARCHITECTURE.md](../RECOVERY_ARCHITECTURE.md) specifies canonical
encodings. The core determines the complete statement: network plus full genesis
identity, protocol/policy and policy commitment, exact profile and key, operation,
ordered inputs/outputs, fees, validity window and replay field. Neither a signer
backend nor an aggregate producer chooses relevant effects.

Native consumption is deterministic and linkable: a domain-separated full-width
hash of chain and input ID. Historical preparation also reserves the original
legacy serial, shared with execution and private fees. An input cannot receive a
second consumption identifier through rotation or disclosure. Replay exclusion
uses the complete effects identity, so copying an unrelated nonce alone cannot
prevent another owner's valid transaction.

Speculation applies complete ordered transitions in an overlay. Successful
finalization must atomically commit consumption, replacement outputs, enrollment,
fees, native root and block/transaction indexes. Invalid native operations have
no separate fee-only accepted outcome. Rejected legacy fee outcomes must obey
retirement and shared consumption checks. Batch abort and checkpoint rewind must
restore every index. Crash safety requires durable shared storage tests, not just
an in-memory clone. See the evidence matrix for the measured implementation
status. Finalized BFT history is not freely reorganizable; speculative rewind or
store rollback does not establish network reorganization safety.

No general ownership-proof backend is retained for the disclosed relation.
Remaining Fiat–Shamir/proof assumptions, independent of direct signature
assumptions, are assessed in [PROOF_BACKENDS.md](PROOF_BACKENDS.md).

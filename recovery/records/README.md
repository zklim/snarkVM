# Disclosed historical credits authorization

This crate checks the local opening/authorization relation for native preparation.
It does not import an authenticated ledger, establish source-program provenance,
check spentness or schedule activation. The VM must perform those state checks
and accept this certificate only during preparation **before legacy compromise**.

The supported source is the exact historical `credits.aleo/credits` schema:
private address owner, one private `microcredits` u64 entry, and record version 0
or 1. Other field names, visibilities, types and versions are rejected. Historical
creation height and inclusion-migration eligibility remain VM responsibilities;
record version is not a substitute for those checks.

The wallet discloses the plaintext record and per-record view key. It keeps the
account seed, signature exponent and PQ signing keys local. For V0, the old BHP
commitment ignores the view key, so this format canonically stores zero there.
V1 retains its commitment-bound view key. Both versions recompute the exact
historical commitment using the existing native routine.

Let `x=sk_sig`, `P=xG` from the verified Aleo signature's compute key,
`H=HashToGroup(serial_domain, commitment)`, and `gamma=xH`. The certificate is a
Chaum–Pedersen equal-discrete-log proof:

```text
A = rG, B = rH
c = SHA3_512(framed domain, network/genesis identity, N::ID,
            expected core authorization message, commitment, P, gamma, A, B)
s = r - c*x
verify: sG + cP == A AND sH + c*gamma == B
```

The challenge uses the low scalar-capacity bits of the digest, an unbiased
power-of-two challenge space; it does not reduce a 512-bit record commitment to
a scalar. All hash components, including the domain, have u64 little-endian
length framing. The nonce is sampled from a caller-provided CSPRNG and resampled
if zero. Group decoding uses the existing on-curve/subgroup-checked decoder;
the verifier rejects identity keys, gamma and proof commitments.
The caller must not reset its CSPRNG or reuse this nonce in a legacy signature:
both protocols involve the same reusable signing exponent. The wallet uses one
continuing CSPRNG stream for certificate creation and ordinary signing.

An ordinary Aleo signature separately authorizes the exact core-generated source
message. Both proofs use the same signature compute key. The core's message must
bind the full transaction effects, source identity and slot. From the proven
gamma, the crate invokes `Record::serial_number_from_gamma`; tests compare it to
`Record::serial_number` with the original private key. This prevents a preparer
from selecting a different serial while leaving reusable signing material hidden.

The underlying equal-log protocol is classical (Chaum and Pedersen, *Wallet
Databases with Observers*, CRYPTO 1992). The noninteractive form assumes suitable
classical Fiat–Shamir/random-oracle behavior and discrete-log hardness during
preparation. It has **no claimed post-quantum soundness**. V2/V3 spending must use
previously authenticated PQ enrollment and direct PQ authorization instead, and
must never accept this certificate as an alternative after retirement.

The mapped core source record binds the network, fixed program/schema, exact
canonical opening, original commitment and source value. Its nonce is a SHA3-512
digest of the network and original commitment. Its opening digest binds all
canonical disclosed data. The full core record ID is computed by the recovery
core. Shared exclusion still uses the original legacy serial, independently of
the core ID, across legacy execution, recovery and fees.

Wire format: source version u8=1, bounded plaintext length u32 LE, canonical
plaintext bytes, commitment field, per-record view-key field, gamma group, A
group, B group and response scalar. Scalar/field/group encodings reuse native
canonical little-endian formats. Plaintext is limited to 4,096 bytes; the exact
frame decoder rejects oversized inputs, noncanonical encodings and trailing data.

```sh
cargo check -p snarkvm-recovery-records
cargo clippy -p snarkvm-recovery-records --all-targets --no-deps -- -D warnings
cargo test -p snarkvm-recovery-records
```

Tests exercise native serial agreement for V0 and V1, disclosure normalization,
changed authenticated effects/network/key, forged gamma/response, altered amounts
and openings, program/schema substitution and bounded malformed wire encodings.
An independently generated V0 fixture from pinned, unmodified snarkVM 3.7.1 also
checks old ciphertext decryption, commitment and serial compatibility; its source
identity and generator commands are retained under `../history-tools`.
These tests do not replace transaction-bearing ledger and validator tests.

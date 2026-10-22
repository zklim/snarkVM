# Independent vectors

`nist-44-*` are NIST ACVP ML-DSA-65 sigGen, external/pure, empty context,
deterministic, test group 3 / case 44. No secret key is included.
Source: https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json
Source SHA256: `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22`.
NIST source is public domain. These are correctness vectors, not certification.

`canonical-*` are independently assembled with Python `struct` and `hashlib`,
using the documented encoding. They are not cryptographic ownership proofs.
The all-zero ML-DSA public key is a codec fixture; no signature is claimed for it.

// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Experimental Aerie wire-v1 adapter, Falcon-512 only, per-record salts.
//! No ownership, zero-knowledge or quantum-adversarial proof-soundness claim.
#![forbid(unsafe_code)]

use aerie::falcon::{AggregationRecord, AggregationStatement, CanonicalPublicKeyBytes, Falcon512, FalconVerifierSetup};
use snarkvm_recovery::{AggregateLimits, AggregateVerifier, Error, Profile, Result, Statement};
use std::collections::BTreeSet;

pub const AERIE_FALCON_512_V1: u16 = 1;
pub const MAX_RECORDS: usize = 32;
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;

pub struct AerieFalcon512;

fn public_statement(expected: &[Statement]) -> Result<AggregationStatement<Falcon512>> {
    if expected.is_empty() || expected.len() > MAX_RECORDS {
        return Err(Error::Limit);
    }
    let mut records = Vec::with_capacity(expected.len());
    let mut seen = BTreeSet::new();
    for statement in expected {
        if statement.key().profile != Profile::FALCON_512 {
            return Err(Error::Unsupported);
        }
        if statement.message().len() > 44_000 {
            return Err(Error::Limit);
        }
        if !seen.insert((&statement.key().bytes, statement.message())) {
            return Err(Error::InvalidAggregate);
        }
        let key = CanonicalPublicKeyBytes::<Falcon512>::parse(&statement.key().bytes).map_err(|_| Error::InvalidKey)?;
        records.push(AggregationRecord::new(key, statement.message().to_vec()).map_err(|_| Error::InvalidAggregate)?);
    }
    AggregationStatement::new(records).map_err(|_| Error::InvalidAggregate)
}

fn header(proof: &[u8], records: usize) -> Result<()> {
    // Common-salt frames have a different magic and are never eligible here.
    if proof.len() < 27
        || proof.len() > MAX_PROOF_BYTES
        || &proof[..16] != b"aerie/falcon/v1p"
        || proof[16..18] != 1u16.to_le_bytes()
        || proof[18] != 9
        || proof[19..27] != (records as u64).to_le_bytes()
    {
        return Err(Error::InvalidAggregate);
    }
    Ok(())
}

impl AggregateVerifier for AerieFalcon512 {
    fn identifier(&self) -> u16 {
        AERIE_FALCON_512_V1
    }

    fn profile(&self) -> Profile {
        Profile::FALCON_512
    }

    fn limits(&self) -> AggregateLimits {
        AggregateLimits { max_records: MAX_RECORDS, max_proof_bytes: MAX_PROOF_BYTES }
    }

    fn verify(&self, expected: &[Statement], proof: &[u8]) -> Result<()> {
        header(proof, expected.len())?;
        let statement = public_statement(expected)?;
        let setup = FalconVerifierSetup::<Falcon512>::new(expected.len()).map_err(|_| Error::Unsupported)?;
        aerie::falcon::verify_aggregate(&setup, &statement, proof).map_err(|_| Error::InvalidAggregate)
    }
}

/// Aggregate production accepts already-created signatures and never signs.
/// Invalid input signatures are rejected directly before constructing a proof.
#[cfg(feature = "producer")]
pub fn produce(expected: &[Statement], signatures: &[Vec<u8>]) -> Result<Vec<u8>> {
    use aerie::falcon::{AggregationWitness, CanonicalSignatureBytes, FalconAggregateSetup};
    if expected.len() != signatures.len() {
        return Err(Error::InvalidAggregate);
    }
    let statement = public_statement(expected)?;
    let mut encoded = Vec::with_capacity(signatures.len());
    for (expected, signature) in expected.iter().zip(signatures) {
        use snarkvm_recovery::SignatureVerifier;
        snarkvm_recovery_signatures::Falcon512Verifier.verify(&expected.key().bytes, expected.message(), signature)?;
        encoded.push(CanonicalSignatureBytes::<Falcon512>::parse(signature).map_err(|_| Error::InvalidSignature)?);
    }
    let witness = AggregationWitness::new(encoded).map_err(|_| Error::InvalidAggregate)?;
    let setup = FalconAggregateSetup::<Falcon512>::new(expected.len()).map_err(|_| Error::Unsupported)?;
    let proof = aerie::falcon::prove_aggregate(&setup, &statement, &witness).map_err(|_| Error::InvalidAggregate)?;
    header(&proof, expected.len())?;
    Ok(proof)
}

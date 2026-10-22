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

use crate::{Error, Key, Profile, Result, Statement};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub public_key_bytes: usize,
    pub signature_bytes: usize,
    pub max_message_bytes: usize,
}

/// Only signature validity is delegated. Membership, key eligibility and effects
/// are decided by the ledger before this interface is called.
pub trait SignatureVerifier: Send + Sync {
    fn profile(&self) -> Profile;
    fn limits(&self) -> Limits;
    fn validate_key(&self, key: &[u8]) -> Result<()>;
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateLimits {
    pub max_records: usize,
    pub max_proof_bytes: usize,
}

/// The ordered statement slice is constructed by the core, including enrollment
/// proofs of possession. A producer cannot supply a different membership list.
pub trait AggregateVerifier: Send + Sync {
    fn identifier(&self) -> u16;
    fn profile(&self) -> Profile;
    fn limits(&self) -> AggregateLimits;
    fn verify(&self, statements: &[Statement], proof: &[u8]) -> Result<()>;
}

/// Legacy evidence authenticates a public imported source's owner before the
/// cutoff. This interface is not a post-quantum historical ownership proof.
pub trait LegacyVerifier {
    fn verify(&self, owner: &[u8], message: &[u8], evidence: &[u8]) -> Result<()>;
}

#[derive(Default)]
pub struct Backends {
    signatures: BTreeMap<Profile, Box<dyn SignatureVerifier>>,
    aggregates: BTreeMap<u16, Box<dyn AggregateVerifier>>,
}

impl Backends {
    pub fn register_signature(&mut self, backend: Box<dyn SignatureVerifier>) -> Result<()> {
        if self.signatures.contains_key(&backend.profile()) {
            return Err(Error::Policy);
        }
        self.signatures.insert(backend.profile(), backend);
        Ok(())
    }

    pub fn register_aggregate(&mut self, backend: Box<dyn AggregateVerifier>) -> Result<()> {
        if self.aggregates.contains_key(&backend.identifier()) {
            return Err(Error::Policy);
        }
        self.aggregates.insert(backend.identifier(), backend);
        Ok(())
    }

    pub fn require(&self, profiles: &[Profile], aggregates: &[u16]) -> Result<()> {
        if profiles.iter().any(|p| !self.signatures.contains_key(p))
            || aggregates.iter().any(|id| !self.aggregates.contains_key(id))
        {
            return Err(Error::MissingBackend);
        }
        Ok(())
    }

    pub fn validate_key(&self, key: &Key) -> Result<()> {
        key.validate()?;
        let backend = self.signatures.get(&key.profile).ok_or(Error::MissingBackend)?;
        if key.bytes.len() != backend.limits().public_key_bytes {
            return Err(Error::InvalidKey);
        }
        backend.validate_key(&key.bytes)
    }

    pub fn verify(&self, statement: &Statement, signature: &[u8]) -> Result<()> {
        self.validate_key(statement.key())?;
        let backend = self.signatures.get(&statement.key().profile).ok_or(Error::MissingBackend)?;
        if signature.len() != backend.limits().signature_bytes
            || statement.message().len() > backend.limits().max_message_bytes
        {
            return Err(Error::Limit);
        }
        backend.verify(&statement.key().bytes, statement.message(), signature)
    }

    pub(crate) fn verify_evidence(
        &self,
        statements: &[Statement],
        evidence: &Evidence,
        allowed_aggregates: &[u16],
    ) -> Result<()> {
        match evidence {
            Evidence::Direct(signatures) => {
                if signatures.len() != statements.len() {
                    return Err(Error::InvalidSignature);
                }
                for (statement, signature) in statements.iter().zip(signatures) {
                    self.verify(statement, signature)?;
                }
                Ok(())
            }
            Evidence::Aggregate { identifier, proof } => {
                if !allowed_aggregates.contains(identifier) {
                    return Err(Error::Policy);
                }
                let backend = self.aggregates.get(identifier).ok_or(Error::MissingBackend)?;
                let limits = backend.limits();
                if statements.is_empty()
                    || statements.len() > limits.max_records
                    || proof.len() > limits.max_proof_bytes
                {
                    return Err(Error::Limit);
                }
                for statement in statements {
                    self.validate_key(statement.key())?;
                    if statement.key().profile != backend.profile() {
                        return Err(Error::Unsupported);
                    }
                }
                // There is no alternate verification path for aggregate evidence.
                backend.verify(statements, proof)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    Direct(Vec<Vec<u8>>),
    Aggregate { identifier: u16, proof: Vec<u8> },
}

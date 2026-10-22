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

use crate::{Digest64, Error, Result, codec::Writer, digest};

pub const MAX_INPUTS: usize = 16;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_KEY_BYTES: usize = 1952;
pub const MAX_EFFECTS_BYTES: usize = 40_000;
pub const PROTOCOL_VERSION: u16 = 1;

/// Experimental consensus identifiers, not registered Aleo network identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Profile {
    pub algorithm: u16,
    pub parameters: u16,
}

impl Profile {
    /// fn-dsa 0.3.0, degree 512, padded, key-prefixed raw message, empty context.
    pub const FALCON_512: Self = Self { algorithm: 2, parameters: 1 };
    pub const ML_DSA_65: Self = Self { algorithm: 1, parameters: 1 };

    /// NIST security categories claimed by the underlying parameter sets.
    pub fn security_category(self) -> Result<u8> {
        match self {
            Self::ML_DSA_65 => Ok(3),
            Self::FALCON_512 => Ok(1),
            _ => Err(Error::Unsupported),
        }
    }

    pub fn validate(self) -> Result<()> {
        match self {
            Self::ML_DSA_65 | Self::FALCON_512 => Ok(()),
            _ => Err(Error::Unsupported),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub profile: Profile,
    pub bytes: Vec<u8>,
}

impl Key {
    pub fn validate(&self) -> Result<()> {
        self.profile.validate()?;
        let length = match self.profile {
            Profile::ML_DSA_65 => 1952,
            Profile::FALCON_512 => 897,
            _ => return Err(Error::Unsupported),
        };
        if self.bytes.len() != length {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    pub fn identity(&self, network: &Digest64) -> Digest64 {
        digest(b"AleoRecoveryExperimentalKey1", &[
            network,
            &self.profile.algorithm.to_le_bytes(),
            &self.profile.parameters.to_le_bytes(),
            &self.bytes,
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    Legacy(Vec<u8>),
    Enrolled(Key),
}

/// A public-value experimental credits record. `opening` is a hash commitment,
/// not a claim that any private Aleo record opening has been proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub version: RecordVersion,
    pub owner: Owner,
    pub amount: u64,
    pub nonce: Digest64,
    pub opening: Digest64,
}

impl Record {
    pub fn validate(&self) -> Result<()> {
        match (&self.version, &self.owner) {
            (RecordVersion::V0 | RecordVersion::V1, Owner::Legacy(owner)) if owner.len() == 32 => Ok(()),
            (RecordVersion::V2 | RecordVersion::V3, Owner::Enrolled(key)) => key.validate(),
            _ => Err(Error::Ownership),
        }
    }

    pub fn id(&self, network: &Digest64) -> Digest64 {
        let mut writer = Writer::default();
        writer.record(self);
        digest(b"AleoRecoveryExperimentalRecord1", &[network, &writer.0])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    Prepare = 0,
    Migrate = 1,
    Spend = 2,
    Rotate = 3,
}

/// All fields are transaction effects. No backend supplies or selects them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effects {
    /// Hash of chain identity including genesis, not just a human network name.
    pub network: Digest64,
    pub protocol: u16,
    pub policy: u16,
    pub policy_commitment: Digest64,
    pub operation: Operation,
    pub valid_from: u32,
    pub valid_until: u32,
    pub replay: Digest64,
    /// Program ID is fixed to credits.aleo by this experimental format.
    pub inputs: Vec<Digest64>,
    pub outputs: Vec<Record>,
    pub fee: u64,
}

impl Effects {
    pub fn validate(&self) -> Result<()> {
        if self.protocol != PROTOCOL_VERSION || self.policy != 1 || self.valid_from > self.valid_until {
            return Err(Error::Policy);
        }
        if self.inputs.is_empty()
            || self.inputs.len() > MAX_INPUTS
            || self.outputs.is_empty()
            || self.outputs.len() > MAX_OUTPUTS
        {
            return Err(Error::Limit);
        }
        for output in &self.outputs {
            output.validate()?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::default();
        writer.0.extend_from_slice(b"AleoRecoveryEffects1");
        writer.0.extend_from_slice(&self.network);
        writer.u16(self.protocol);
        writer.u16(self.policy);
        writer.0.extend_from_slice(&self.policy_commitment);
        writer.u8(self.operation as u8);
        writer.u32(self.valid_from);
        writer.u32(self.valid_until);
        writer.0.extend_from_slice(&self.replay);
        writer.bytes(b"credits.aleo");
        writer.u32(self.inputs.len() as u32);
        for input in &self.inputs {
            writer.0.extend_from_slice(input);
        }
        writer.u32(self.outputs.len() as u32);
        for output in &self.outputs {
            writer.record(output);
        }
        writer.u64(self.fee);
        Ok(writer.0)
    }

    pub fn id(&self) -> Result<Digest64> {
        Ok(digest(b"AleoRecoveryExperimentalTransaction1", &[&self.encode()?]))
    }
}

/// An immutable core-computed signature statement. Input roles are 0, enrolled
/// output proofs of possession are 1. Slots prevent reuse within the same batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    key: Key,
    message: Vec<u8>,
}

impl Statement {
    pub(crate) fn new(effects: &Effects, key: &Key, role: u8, slot: usize) -> Result<Self> {
        key.validate()?;
        let mut writer = Writer::default();
        writer.0.extend_from_slice(b"AleoRecoveryAuthorization1");
        writer.u8(role);
        writer.u16(slot.try_into().map_err(|_| Error::Limit)?);
        writer.key(key);
        writer.0.extend_from_slice(&key.identity(&effects.network));
        writer.bytes(&effects.encode()?);
        Ok(Self { key: key.clone(), message: writer.0 })
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

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

use crate::*;

pub const MAX_TRANSACTION_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_LEGACY_AUTHORIZATION_BYTES: usize = 4096;
pub const MAX_SIGNATURE_BYTES: usize = 4096;
pub const MAX_AGGREGATE_PROOF_BYTES: usize = 2 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.0.extend_from_slice(value);
    }

    pub fn key(&mut self, value: &Key) {
        self.u16(value.profile.algorithm);
        self.u16(value.profile.parameters);
        self.bytes(&value.bytes);
    }

    pub fn record(&mut self, record: &Record) {
        self.u8(record.version as u8);
        match &record.owner {
            Owner::Legacy(owner) => {
                self.u8(0);
                self.bytes(owner);
            }
            Owner::Enrolled(key) => {
                self.u8(1);
                self.key(key);
            }
        }
        self.u64(record.amount);
        self.0.extend_from_slice(&record.nonce);
        self.0.extend_from_slice(&record.opening);
    }
}

pub(crate) struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if length > self.0.len() {
            return Err(Error::Encoding);
        }
        let (value, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(value)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn count(&mut self, maximum: usize) -> Result<usize> {
        let length = usize::try_from(self.u32()?).map_err(|_| Error::Limit)?;
        if length > maximum {
            return Err(Error::Limit);
        }
        Ok(length)
    }

    pub fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>> {
        let length = self.count(maximum)?;
        Ok(self.take(length)?.to_vec())
    }

    pub fn key(&mut self) -> Result<Key> {
        let key = Key {
            profile: Profile { algorithm: self.u16()?, parameters: self.u16()? },
            bytes: self.bytes(MAX_KEY_BYTES)?,
        };
        key.validate()?;
        Ok(key)
    }

    pub fn record(&mut self) -> Result<Record> {
        let version = match self.u8()? {
            0 => RecordVersion::V0,
            1 => RecordVersion::V1,
            2 => RecordVersion::V2,
            3 => RecordVersion::V3,
            _ => return Err(Error::Unsupported),
        };
        let owner = match self.u8()? {
            0 => Owner::Legacy(self.bytes(32)?),
            1 => Owner::Enrolled(self.key()?),
            _ => return Err(Error::Unsupported),
        };
        let record = Record { version, owner, amount: self.u64()?, nonce: self.array()?, opening: self.array()? };
        record.validate()?;
        Ok(record)
    }

    pub fn finish(self) -> Result<()> {
        if self.0.is_empty() { Ok(()) } else { Err(Error::Encoding) }
    }
}

impl Effects {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_EFFECTS_BYTES {
            return Err(Error::Limit);
        }
        let mut reader = Reader(bytes);
        if reader.take(b"AleoRecoveryEffects1".len())? != b"AleoRecoveryEffects1" {
            return Err(Error::Encoding);
        }
        let network = reader.array()?;
        let protocol = reader.u16()?;
        let policy = reader.u16()?;
        let policy_commitment = reader.array()?;
        let operation = match reader.u8()? {
            0 => Operation::Prepare,
            1 => Operation::Migrate,
            2 => Operation::Spend,
            3 => Operation::Rotate,
            _ => return Err(Error::Unsupported),
        };
        let valid_from = reader.u32()?;
        let valid_until = reader.u32()?;
        let replay = reader.array()?;
        if reader.bytes(12)? != b"credits.aleo" {
            return Err(Error::Unsupported);
        }
        let count = reader.count(MAX_INPUTS)?;
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            inputs.push(reader.array()?);
        }
        let count = reader.count(MAX_OUTPUTS)?;
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            outputs.push(reader.record()?);
        }
        let effects = Self {
            network,
            protocol,
            policy,
            policy_commitment,
            operation,
            valid_from,
            valid_until,
            replay,
            inputs,
            outputs,
            fee: reader.u64()?,
        };
        reader.finish()?;
        effects.validate()?;
        Ok(effects)
    }
}

impl Transaction {
    fn validate_evidence_shape(&self) -> Result<()> {
        self.effects.validate()?;
        let legacy_count = if self.effects.operation == Operation::Prepare { self.effects.inputs.len() } else { 0 };
        if self.legacy.len() != legacy_count
            || self.legacy.iter().any(|proof| proof.is_empty() || proof.len() > MAX_LEGACY_AUTHORIZATION_BYTES)
        {
            return Err(Error::Ownership);
        }
        let signature_count = self.effects.outputs.len()
            + if self.effects.operation == Operation::Prepare { 0 } else { self.effects.inputs.len() };
        match &self.authorization {
            Evidence::Direct(signatures) => {
                if signatures.len() != signature_count
                    || signatures.iter().any(|signature| signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES)
                {
                    return Err(Error::InvalidSignature);
                }
            }
            Evidence::Aggregate { identifier, proof } => {
                if *identifier != 1 {
                    return Err(Error::Unsupported);
                }
                if proof.is_empty() || proof.len() > MAX_AGGREGATE_PROOF_BYTES {
                    return Err(Error::Limit);
                }
            }
        }
        Ok(())
    }

    /// Canonical bounded evidence envelope. Effects identity remains independent
    /// of signature randomness; a host separately commits the complete wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_evidence_shape()?;
        let mut writer = Writer::default();
        writer.0.extend_from_slice(b"AleoRecoveryTransaction1");
        writer.bytes(&self.effects.encode()?);
        writer.u32(self.legacy.len() as u32);
        for signature in &self.legacy {
            writer.bytes(signature);
        }
        match &self.authorization {
            Evidence::Direct(signatures) => {
                writer.u8(0);
                writer.u32(signatures.len() as u32);
                for signature in signatures {
                    writer.bytes(signature);
                }
            }
            Evidence::Aggregate { identifier, proof } => {
                writer.u8(1);
                writer.u16(*identifier);
                writer.bytes(proof);
            }
        }
        if writer.0.len() > MAX_TRANSACTION_BYTES {
            return Err(Error::Limit);
        }
        Ok(writer.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(Error::Limit);
        }
        let mut reader = Reader(bytes);
        if reader.take(b"AleoRecoveryTransaction1".len())? != b"AleoRecoveryTransaction1" {
            return Err(Error::Encoding);
        }
        let effects = Effects::decode(&reader.bytes(MAX_EFFECTS_BYTES)?)?;
        let count = reader.count(MAX_INPUTS)?;
        let mut legacy = Vec::with_capacity(count);
        for _ in 0..count {
            legacy.push(reader.bytes(MAX_LEGACY_AUTHORIZATION_BYTES)?);
        }
        let authorization = match reader.u8()? {
            0 => {
                let count = reader.count(MAX_INPUTS + MAX_OUTPUTS)?;
                let mut signatures = Vec::with_capacity(count);
                for _ in 0..count {
                    signatures.push(reader.bytes(MAX_SIGNATURE_BYTES)?);
                }
                Evidence::Direct(signatures)
            }
            1 => Evidence::Aggregate { identifier: reader.u16()?, proof: reader.bytes(MAX_AGGREGATE_PROOF_BYTES)? },
            _ => return Err(Error::Unsupported),
        };
        reader.finish()?;
        let transaction = Self { effects, legacy, authorization };
        transaction.validate_evidence_shape()?;
        if transaction.encode()? != bytes {
            return Err(Error::Encoding);
        }
        Ok(transaction)
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;

    fn transaction() -> Transaction {
        Transaction {
            effects: Effects {
                network: [1; 64],
                protocol: PROTOCOL_VERSION,
                policy: 1,
                policy_commitment: [2; 64],
                operation: Operation::Prepare,
                valid_from: 30,
                valid_until: 39,
                replay: [3; 64],
                inputs: vec![[4; 64]],
                outputs: vec![Record {
                    version: RecordVersion::V2,
                    owner: Owner::Enrolled(Key { profile: Profile::ML_DSA_65, bytes: vec![5; 1952] }),
                    amount: 99,
                    nonce: [6; 64],
                    opening: [7; 64],
                }],
                fee: 1,
            },
            legacy: vec![vec![8; 128]],
            authorization: Evidence::Direct(vec![vec![9; 3309]]),
        }
    }

    #[test]
    fn transaction_wire_roundtrip_and_mutations() -> Result<()> {
        let transaction = transaction();
        let encoded = transaction.encode()?;
        assert_eq!(Transaction::decode(&encoded)?, transaction);
        for cut in [0, 1, 20, encoded.len() / 2, encoded.len() - 1] {
            assert!(Transaction::decode(&encoded[..cut]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Transaction::decode(&trailing).is_err());
        let mut unknown = encoded;
        unknown[0] ^= 1;
        assert!(Transaction::decode(&unknown).is_err());
        let mut changed = transaction.clone();
        changed.effects.fee += 1;
        assert_ne!(changed.encode()?, transaction.encode()?);
        assert_ne!(changed.effects.id()?, transaction.effects.id()?);
        let mut changed = transaction.clone();
        changed.legacy[0][0] ^= 1;
        assert_ne!(changed.encode()?, transaction.encode()?);
        assert_eq!(changed.effects.id()?, transaction.effects.id()?);
        Ok(())
    }

    #[test]
    fn transaction_wire_enforces_evidence_shape_and_limits() {
        let mut tx = transaction();
        tx.legacy.clear();
        assert!(tx.encode().is_err());
        let mut tx = transaction();
        tx.authorization = Evidence::Direct(vec![]);
        assert!(tx.encode().is_err());
        let mut tx = transaction();
        tx.legacy[0] = vec![0; 4097];
        assert!(tx.encode().is_err());
        let mut tx = transaction();
        tx.authorization = Evidence::Direct(vec![vec![0; 4097]]);
        assert!(tx.encode().is_err());
        let mut tx = transaction();
        tx.effects.operation = Operation::Migrate;
        assert!(tx.encode().is_err());
        assert!(Transaction::decode(&vec![0; MAX_TRANSACTION_BYTES + 1]).is_err());
    }
}

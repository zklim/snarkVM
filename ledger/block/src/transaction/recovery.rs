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

use super::*;
use snarkvm_recovery::{Digest64, Operation};
use snarkvm_recovery_records::PreparationSource;

/// A disclosed credits transaction. Ownership and current-state checks belong to the VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery<N: Network> {
    transaction: snarkvm_recovery::Transaction,
    sources: Vec<PreparationSource<N>>,
    legacy_serial_numbers: Vec<Field<N>>,
}

impl<N: Network> Recovery<N> {
    pub const MAX_BYTES: usize = 2 * 1024 * 1024;
    pub const MAX_SOURCE_BYTES: usize = 16 * 1024;

    pub fn new(transaction: snarkvm_recovery::Transaction, sources: Vec<PreparationSource<N>>) -> Result<Self> {
        transaction.effects.validate()?;
        ensure!(sources.len() <= snarkvm_recovery::MAX_INPUTS, "Too many preparation sources");
        match transaction.effects.operation {
            Operation::Prepare => {
                ensure!(sources.len() == transaction.effects.inputs.len(), "Preparation source count mismatch")
            }
            _ => ensure!(sources.is_empty(), "Only preparation carries legacy sources"),
        }
        let legacy_serial_numbers = sources.iter().map(PreparationSource::serial_number).collect::<Result<Vec<_>>>()?;
        let recovery = Self { transaction, sources, legacy_serial_numbers };
        ensure!(recovery.to_bytes_le()?.len() <= Self::MAX_BYTES, "Recovery envelope exceeds byte limit");
        Ok(recovery)
    }

    pub fn transaction(&self) -> &snarkvm_recovery::Transaction {
        &self.transaction
    }

    pub fn sources(&self) -> &[PreparationSource<N>] {
        &self.sources
    }

    pub fn legacy_serial_numbers(&self) -> &[Field<N>] {
        &self.legacy_serial_numbers
    }

    /// The full envelope identity; the legacy transaction ID is a compatibility index.
    pub fn digest(&self) -> Result<Digest64> {
        Ok(snarkvm_recovery::digest(b"AleoNativeRecoveryEnvelope1", &[&self.to_bytes_le()?]))
    }

    /// Experimental native admission cost: a fixed 1,000 microcredits plus
    /// one microcredit per canonical envelope byte. This is not a public schedule.
    pub fn minimum_fee(&self) -> Result<u64> {
        1_000u64.checked_add(u64::try_from(self.to_bytes_le()?.len())?).ok_or_else(|| anyhow!("Recovery fee overflow"))
    }

    pub fn from_bytes_exact(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= Self::MAX_BYTES, "Recovery envelope exceeds byte limit");
        let mut reader = std::io::Cursor::new(bytes);
        let recovery = Self::read_le(&mut reader)?;
        ensure!(reader.position() == bytes.len() as u64, "Trailing recovery envelope bytes");
        Ok(recovery)
    }

    pub(crate) fn compatibility_leaf_id(&self) -> Result<Field<N>> {
        let bits = self.digest()?.to_bits_le();
        Field::from_bits_le(&bits[..Field::<N>::size_in_bits() - 1])
    }
}

impl<N: Network> ToBytes for Recovery<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let transaction = self.transaction.encode().map_err(error)?;
        if transaction.len() > Self::MAX_BYTES || self.sources.len() > snarkvm_recovery::MAX_INPUTS {
            return Err(error("Recovery envelope exceeds limits"));
        }
        let mut body = Vec::with_capacity(transaction.len() + 16);
        1u8.write_le(&mut body)?;
        u32::try_from(transaction.len()).map_err(error)?.write_le(&mut body)?;
        body.extend_from_slice(&transaction);
        u16::try_from(self.sources.len()).map_err(error)?.write_le(&mut body)?;
        for source in &self.sources {
            let bytes = source.to_bytes_le().map_err(error)?;
            if bytes.len() > Self::MAX_SOURCE_BYTES {
                return Err(error("Preparation source exceeds byte limit"));
            }
            u32::try_from(bytes.len()).map_err(error)?.write_le(&mut body)?;
            body.extend_from_slice(&bytes);
        }
        if body.len().checked_add(4).is_none_or(|size| size > Self::MAX_BYTES) {
            return Err(error("Recovery envelope exceeds byte limit"));
        }
        u32::try_from(body.len()).map_err(error)?.write_le(&mut writer)?;
        writer.write_all(&body)
    }
}

impl<N: Network> FromBytes for Recovery<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let length = u32::read_le(&mut reader)? as usize;
        if length.checked_add(4).is_none_or(|size| size > Self::MAX_BYTES) {
            return Err(error("Recovery envelope exceeds byte limit"));
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        let mut body = std::io::Cursor::new(body);
        if u8::read_le(&mut body)? != 1 {
            return Err(error("Unsupported recovery envelope version"));
        }
        let transaction_length = u32::read_le(&mut body)? as usize;
        if transaction_length > length {
            return Err(error("Invalid recovery transaction length"));
        }
        let mut transaction = vec![0; transaction_length];
        body.read_exact(&mut transaction)?;
        let transaction = snarkvm_recovery::Transaction::decode(&transaction).map_err(error)?;
        let count = usize::from(u16::read_le(&mut body)?);
        if count > snarkvm_recovery::MAX_INPUTS {
            return Err(error("Too many preparation sources"));
        }
        let mut sources = Vec::with_capacity(count);
        for _ in 0..count {
            let source_length = u32::read_le(&mut body)? as usize;
            if source_length > Self::MAX_SOURCE_BYTES || source_length > length {
                return Err(error("Preparation source exceeds byte limit"));
            }
            let mut source = vec![0; source_length];
            body.read_exact(&mut source)?;
            sources.push(PreparationSource::from_bytes_exact(&source).map_err(error)?);
        }
        if body.position() != length as u64 {
            return Err(error("Trailing recovery envelope bytes"));
        }
        Self::new(transaction, sources).map_err(error)
    }
}

impl<N: Network> Serialize for Recovery<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            self.to_bytes_le().map_err(ser::Error::custom)?.serialize(serializer)
        } else {
            ToBytesSerializer::serialize_with_size_encoding(self, serializer)
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Recovery<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RecoveryVisitor<N: Network>(std::marker::PhantomData<N>);

        impl<'de, N: Network> de::Visitor<'de> for RecoveryVisitor<N> {
            type Value = Recovery<N>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a canonical bounded recovery envelope")
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Recovery::from_bytes_exact(bytes).map_err(E::custom)
            }

            fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&bytes)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                if sequence.size_hint().is_some_and(|length| length > Recovery::<N>::MAX_BYTES) {
                    return Err(de::Error::custom("Recovery envelope exceeds byte limit"));
                }
                let mut bytes = Vec::new();
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == Recovery::<N>::MAX_BYTES {
                        return Err(de::Error::custom("Recovery envelope exceeds byte limit"));
                    }
                    bytes.push(byte);
                }
                self.visit_bytes(&bytes)
            }
        }

        let visitor = RecoveryVisitor(std::marker::PhantomData);
        if deserializer.is_human_readable() {
            deserializer.deserialize_seq(visitor)
        } else {
            deserializer.deserialize_bytes(visitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        account::{Address, PrivateKey, ViewKey},
        network::MainnetV0,
        program::{Identifier, Plaintext, ProgramID, Record as AleoRecord},
        types::Scalar,
    };
    use snarkvm_recovery::{Effects, Evidence, Key, Owner, Profile, Record, RecordVersion};

    type N = MainnetV0;

    fn sample() -> Result<Recovery<N>> {
        let key = Key { profile: Profile::ML_DSA_65, bytes: vec![7; 1952] };
        let effects = Effects {
            network: [1; 64],
            protocol: 1,
            policy: 1,
            policy_commitment: [5; 64],
            operation: Operation::Migrate,
            valid_from: 40,
            valid_until: 80,
            replay: [3; 64],
            inputs: vec![[9; 64]],
            outputs: vec![Record {
                version: RecordVersion::V3,
                owner: Owner::Enrolled(key),
                amount: 99,
                nonce: [10; 64],
                opening: [11; 64],
            }],
            fee: 1,
        };
        Recovery::new(
            snarkvm_recovery::Transaction {
                effects,
                legacy: vec![],
                authorization: Evidence::Direct(vec![vec![1; 3309], vec![2; 3309]]),
            },
            vec![],
        )
    }

    #[test]
    fn recovery_envelope_identity_and_wire() -> Result<()> {
        let recovery = sample()?;
        let bytes = recovery.to_bytes_le()?;
        assert_eq!(recovery, Recovery::from_bytes_exact(&bytes)?);
        let transaction = Transaction::from_recovery(recovery.clone())?;
        assert!(transaction.is_recovery());
        assert!(!transaction.is_execute());
        assert_eq!(transaction.transitions().count(), 0);
        assert_eq!(transaction.serial_numbers().count(), 0);
        assert_eq!(transaction.fee_amount()?, U64::new(1));
        assert_eq!(transaction.priority_fee_amount()?, U64::zero());
        assert_eq!(transaction, Transaction::read_le(transaction.to_bytes_le()?.as_slice())?);
        assert_eq!(transaction, serde_json::from_str(&serde_json::to_string(&transaction)?)?);
        assert_eq!(transaction, bincode::deserialize(&bincode::serialize(&transaction)?)?);
        assert_eq!(recovery, bincode::deserialize(&bincode::serialize(&recovery)?)?);
        let mut changed = recovery.transaction().clone();
        changed.effects.fee = 2;
        changed.effects.outputs[0].amount = 98;
        let changed = Transaction::<N>::from_recovery(Recovery::new(changed, vec![])?)?;
        assert_ne!(transaction.id(), changed.id());
        let mut changed = recovery.transaction().clone();
        if let Evidence::Direct(signatures) = &mut changed.authorization {
            signatures[0][0] ^= 1;
        }
        let changed = Transaction::<N>::from_recovery(Recovery::new(changed, vec![])?)?;
        assert_ne!(transaction.id(), changed.id());
        Ok(())
    }

    #[test]
    fn preparation_exposes_native_consumption_serials() -> Result<()> {
        // This fixture exercises wire and conflict-index plumbing. The production
        // VM separately verifies signatures, enrollment and authenticated origin.
        let key = PrivateKey::<N>::try_from(Field::from_u64(42))?;
        let owner = Address::try_from(&key)?;
        let nonce = N::g_scalar_multiply(&Scalar::from_str("7scalar")?);
        let record = AleoRecord::<N, Plaintext<N>>::from_str(&format!(
            "{{ owner: {owner}.private, microcredits: 100u64.private, _nonce: {nonce}.public, _version: 1u8.public }}"
        ))?;
        let rvk = (nonce * *ViewKey::try_from(&key)?).to_x_coordinate();
        let commitment =
            record.to_commitment(&ProgramID::from_str("credits.aleo")?, &Identifier::from_str("credits")?, &rvk)?;
        let source = PreparationSource::create(
            &key,
            record,
            rvk,
            commitment,
            &[1; 64],
            b"wire fixture",
            &mut TestRng::fixed(17),
        )?;
        let serial = AleoRecord::<N, Plaintext<N>>::serial_number(key, commitment)?;
        assert_eq!(source.serial_number()?, serial);
        let mut core = sample()?.transaction().clone();
        core.effects.operation = Operation::Prepare;
        core.effects.inputs = vec![source.source_record(&core.effects.network)?.id(&core.effects.network)];
        core.effects.outputs[0].version = RecordVersion::V2;
        core.legacy = vec![vec![1]];
        core.authorization = Evidence::Direct(vec![vec![1; 3309]]);
        let transaction = Transaction::from_recovery(Recovery::new(core, vec![source])?)?;
        assert_eq!(transaction.serial_numbers().copied().collect::<Vec<_>>(), vec![serial]);
        assert!(transaction.contains_serial_number(&serial));
        assert_eq!(transaction.clone().into_serial_numbers().collect::<Vec<_>>(), vec![serial]);
        let decoded = Transaction::<N>::read_le(transaction.to_bytes_le()?.as_slice())?;
        assert_eq!(decoded.serial_numbers().copied().collect::<Vec<_>>(), vec![serial]);
        assert_eq!(transaction, decoded);
        Ok(())
    }

    #[test]
    fn recovery_rejects_malformed_frames() -> Result<()> {
        let bytes = sample()?.to_bytes_le()?;
        let mut changed = bytes.clone();
        changed[4] = 2;
        assert!(Recovery::<N>::from_bytes_exact(&changed).is_err());
        let mut changed = bytes.clone();
        changed.extend_from_slice(&[0]);
        assert!(Recovery::<N>::from_bytes_exact(&changed).is_err());
        let length = u32::try_from(changed.len() - 4)?;
        changed[..4].copy_from_slice(&length.to_le_bytes());
        assert!(Recovery::<N>::from_bytes_exact(&changed).is_err());
        let mut malformed_binary = bincode::serialize(&sample()?)?;
        malformed_binary.push(0);
        let outer_length = u64::try_from(malformed_binary.len() - 8)?;
        malformed_binary[..8].copy_from_slice(&outer_length.to_le_bytes());
        assert!(bincode::deserialize::<Recovery<N>>(&malformed_binary).is_err());
        let transaction = Transaction::from_recovery(sample()?)?;
        let mut transaction_bytes = transaction.to_bytes_le()?;
        transaction_bytes[1] = 4;
        assert!(Transaction::<N>::read_le(transaction_bytes.as_slice()).is_err());
        let mut transaction_bytes = transaction.to_bytes_le()?;
        transaction_bytes[2] ^= 1;
        assert!(Transaction::<N>::read_le(transaction_bytes.as_slice()).is_err());
        let oversized = u32::try_from(Recovery::<N>::MAX_BYTES + 1)?.to_le_bytes();
        assert!(Recovery::<N>::from_bytes_exact(&oversized).is_err());
        for length in [0, 1, 3, 4, 5, bytes.len() - 1] {
            assert!(Recovery::<N>::from_bytes_exact(&bytes[..length]).is_err());
        }
        Ok(())
    }

    #[test]
    fn recovery_confirmation_requires_root_transition() -> Result<()> {
        let transaction = Transaction::from_recovery(sample()?)?;
        assert!(crate::ConfirmedTransaction::accepted_recovery(0, transaction.clone(), vec![]).is_err());
        assert!(crate::ConfirmedTransaction::accepted_execute(0, transaction.clone(), vec![]).is_err());
        use snarkvm_synthesizer_program::FinalizeOperation;
        let operation = FinalizeOperation::Recovery([4; 64], [5; 64]);
        let pool = FinalizeOperation::UpdateKeyValue(Field::one(), Field::one(), Field::one());
        assert!(crate::ConfirmedTransaction::accepted_recovery(0, transaction.clone(), vec![operation, pool]).is_err());
        assert!(
            crate::ConfirmedTransaction::accepted_recovery(0, transaction.clone(), vec![operation, operation]).is_err()
        );
        let with_pool = crate::ConfirmedTransaction::accepted_recovery(0, transaction.clone(), vec![pool, operation])?;
        assert_eq!(with_pool, crate::ConfirmedTransaction::read_le(with_pool.to_bytes_le()?.as_slice())?);
        let confirmed = crate::ConfirmedTransaction::accepted_recovery(0, transaction, vec![operation])?;
        assert_eq!(confirmed, crate::ConfirmedTransaction::read_le(confirmed.to_bytes_le()?.as_slice())?);
        assert_eq!(confirmed, serde_json::from_str(&serde_json::to_string(&confirmed)?)?);
        assert_eq!(confirmed.to_unconfirmed_transaction_id()?, confirmed.id());
        Ok(())
    }
}

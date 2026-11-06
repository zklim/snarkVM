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

//! Disclosed historical credits openings and pre-compromise serial authorization.
//! The Chaum–Pedersen proof is classical and must only authorize preparation
//! before legacy retirement. Membership, source-class eligibility and spentness
//! are checked by the ledger. No reusable account secret is serialized.
#![forbid(unsafe_code)]

use std::io::Cursor;

use snarkvm_console_account::{Address, ComputeKey, Field, Group, PrivateKey, Scalar, Signature};
use snarkvm_console_network::prelude::*;
use snarkvm_console_program::{Entry, Identifier, Literal, Owner, Plaintext, ProgramID, Record};
use snarkvm_recovery::{Digest64, Record as RecoveryRecord, RecordVersion, digest};

pub const MAX_SOURCE_RECORD_BYTES: usize = 4096;
pub const MAX_SOURCE_MESSAGE_BYTES: usize = 44_000;

/// Public opening and equal-discrete-log proof for one historical credits input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparationSource<N: Network> {
    pub commitment: Field<N>,
    pub record: Record<N, Plaintext<N>>,
    pub record_view_key: Field<N>,
    pub gamma: Group<N>,
    pub a: Group<N>,
    pub b: Group<N>,
    pub response: Scalar<N>,
}

/// An authenticated opening/serial relation; ledger membership remains external.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSource<N: Network> {
    pub serial: Field<N>,
    pub commitment: Field<N>,
    pub record: RecoveryRecord,
}

impl<N: Network> PreparationSource<N> {
    /// Creates a source proof using the original signing exponent locally.
    #[allow(clippy::too_many_arguments)]
    pub fn create<R: Rng + CryptoRng>(
        private_key: &PrivateKey<N>,
        record: Record<N, Plaintext<N>>,
        record_view_key: Field<N>,
        commitment: Field<N>,
        network: &Digest64,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self> {
        ensure!(message.len() <= MAX_SOURCE_MESSAGE_BYTES, "Preparation message exceeds limit");
        let (owner, _) = credits_record(&record)?;
        ensure!(owner == Address::try_from(private_key)?, "Preparation signing key does not own the record");
        ensure!(historical_commitment(&record, record_view_key)? == commitment, "Historical record opening mismatch");
        let record_view_key = normalized_view_key(&record, record_view_key);
        let compute_key = ComputeKey::try_from(private_key)?;
        let h = source_generator(commitment)?;
        ensure!(!compute_key.pk_sig().is_zero() && !h.is_zero(), "Degenerate preparation key or source generator");
        let nonce = loop {
            let candidate = Scalar::<N>::rand(rng);
            if !candidate.is_zero() {
                break candidate;
            }
        };
        let gamma = h * private_key.sk_sig();
        let a = N::g_scalar_multiply(&nonce);
        let b = h * nonce;
        let mut source = Self { commitment, record, record_view_key, gamma, a, b, response: Scalar::zero() };
        let challenge = source.challenge(network, message, compute_key.pk_sig())?;
        source.response = nonce - challenge * private_key.sk_sig();
        Ok(source)
    }

    /// Maps the exact disclosed opening to its network-bound core source record.
    pub fn source_record(&self, network: &Digest64) -> Result<RecoveryRecord> {
        Self::record_from_opening(network, &self.record, self.record_view_key, self.commitment)
    }

    /// Returns the historical commitment used for authenticated ledger lookup.
    pub const fn commitment(&self) -> &Field<N> {
        &self.commitment
    }

    /// Derives a source identity before constructing its effects-bound proof.
    pub fn record_from_opening(
        network: &Digest64,
        record: &Record<N, Plaintext<N>>,
        record_view_key: Field<N>,
        commitment: Field<N>,
    ) -> Result<RecoveryRecord> {
        let (owner, amount) = credits_record(record)?;
        ensure!(historical_commitment(record, record_view_key)? == commitment, "Historical record opening mismatch");
        let encoded = record.to_bytes_le()?;
        ensure!(encoded.len() <= MAX_SOURCE_RECORD_BYTES, "Historical source exceeds limit");
        let commitment = commitment.to_bytes_le()?;
        let view_key = normalized_view_key(record, record_view_key).to_bytes_le()?;
        let version = match **record.version() {
            0 => RecordVersion::V0,
            1 => RecordVersion::V1,
            _ => bail!("Unsupported historical record version"),
        };
        Ok(RecoveryRecord {
            version,
            owner: snarkvm_recovery::Owner::Legacy(owner.to_bytes_le()?),
            amount,
            nonce: digest(b"AleoRecoveryHistoricalSource1", &[network, &commitment]),
            opening: digest(b"AleoRecoveryDisclosedCredits1", &[
                network,
                b"credits.aleo",
                b"credits",
                &commitment,
                &encoded,
                &view_key,
            ]),
        })
    }

    /// Returns the exact serial used by ordinary Aleo record consumption.
    /// The result alone is not evidence that gamma belongs to the owner.
    pub fn serial_number(&self) -> Result<Field<N>> {
        Record::<N, Plaintext<N>>::serial_number_from_gamma(&self.gamma, self.commitment)
    }

    /// Checks opening, old-owner effects authorization and canonical serial linkage.
    /// The caller enforces the preparation window and authenticated current state.
    pub fn verify(&self, network: &Digest64, message: &[u8], signature: &Signature<N>) -> Result<VerifiedSource<N>> {
        ensure!(message.len() <= MAX_SOURCE_MESSAGE_BYTES, "Preparation message exceeds limit");
        ensure!(
            self.record_view_key == normalized_view_key(&self.record, self.record_view_key),
            "Noncanonical V0 record view key"
        );
        let record = self.source_record(network)?;
        let (owner, _) = credits_record(&self.record)?;
        ensure!(signature.verify_bytes(&owner, message), "Invalid preparation owner authorization");
        let pk = signature.compute_key().pk_sig();
        let h = source_generator(self.commitment)?;
        ensure!(
            !pk.is_zero() && !h.is_zero() && !self.gamma.is_zero() && !self.a.is_zero() && !self.b.is_zero(),
            "Degenerate preparation proof point"
        );
        let challenge = self.challenge(network, message, pk)?;
        ensure!(
            N::g_scalar_multiply(&self.response) + pk * challenge == self.a
                && h * self.response + self.gamma * challenge == self.b,
            "Invalid preparation serial linkage"
        );
        Ok(VerifiedSource { serial: self.serial_number()?, commitment: self.commitment, record })
    }

    /// Decodes one canonical bounded frame and rejects trailing bytes.
    pub fn from_bytes_exact(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_SOURCE_RECORD_BYTES + 512, "Preparation source frame exceeds limit");
        let mut reader = Cursor::new(bytes);
        let source = Self::read_le(&mut reader)?;
        ensure!(reader.position() == bytes.len() as u64, "Trailing preparation source data");
        ensure!(source.to_bytes_le()? == bytes, "Noncanonical preparation source encoding");
        Ok(source)
    }

    fn challenge(&self, network: &Digest64, message: &[u8], pk: Group<N>) -> Result<Scalar<N>> {
        let bytes = digest(b"AleoRecoveryPreparationDLEQ1", &[
            network,
            &N::ID.to_le_bytes(),
            message,
            &self.commitment.to_bytes_le()?,
            &pk.to_bytes_le()?,
            &self.gamma.to_bytes_le()?,
            &self.a.to_bytes_le()?,
            &self.b.to_bytes_le()?,
        ]);
        // The capacity-sized prefix is uniformly mapped without modular bias.
        Scalar::from_bits_le(&bytes.to_bits_le()[..Scalar::<N>::size_in_data_bits()])
    }
}

impl<N: Network> ToBytes for PreparationSource<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        credits_record(&self.record).map_err(into_io_error)?;
        if self.record_view_key != normalized_view_key(&self.record, self.record_view_key) {
            return Err(error("Noncanonical V0 record view key"));
        }
        let record = self.record.to_bytes_le().map_err(into_io_error)?;
        if record.len() > MAX_SOURCE_RECORD_BYTES {
            return Err(error("Historical source exceeds limit"));
        }
        1u8.write_le(&mut writer)?;
        (record.len() as u32).write_le(&mut writer)?;
        writer.write_all(&record)?;
        self.commitment.write_le(&mut writer)?;
        self.record_view_key.write_le(&mut writer)?;
        self.gamma.write_le(&mut writer)?;
        self.a.write_le(&mut writer)?;
        self.b.write_le(&mut writer)?;
        self.response.write_le(writer)
    }
}

impl<N: Network> FromBytes for PreparationSource<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        if u8::read_le(&mut reader)? != 1 {
            return Err(error("Unsupported preparation source encoding"));
        }
        let length = u32::read_le(&mut reader)? as usize;
        if length > MAX_SOURCE_RECORD_BYTES {
            return Err(error("Historical source exceeds limit"));
        }
        let mut encoded = vec![0u8; length];
        reader.read_exact(&mut encoded)?;
        let record = Record::<N, Plaintext<N>>::read_le(encoded.as_slice())?;
        credits_record(&record).map_err(into_io_error)?;
        if record.to_bytes_le().map_err(into_io_error)? != encoded {
            return Err(error("Noncanonical historical record encoding"));
        }
        let source = Self {
            record,
            commitment: Field::read_le(&mut reader)?,
            record_view_key: Field::read_le(&mut reader)?,
            gamma: Group::read_le(&mut reader)?,
            a: Group::read_le(&mut reader)?,
            b: Group::read_le(&mut reader)?,
            response: Scalar::read_le(reader)?,
        };
        if source.record_view_key != normalized_view_key(&source.record, source.record_view_key) {
            return Err(error("Noncanonical V0 record view key"));
        }
        Ok(source)
    }
}

fn source_generator<N: Network>(commitment: Field<N>) -> Result<Group<N>> {
    N::hash_to_group_psd2(&[N::serial_number_domain(), commitment])
}

fn normalized_view_key<N: Network>(record: &Record<N, Plaintext<N>>, view_key: Field<N>) -> Field<N> {
    if **record.version() == 0 { Field::zero() } else { view_key }
}

fn historical_commitment<N: Network>(record: &Record<N, Plaintext<N>>, view_key: Field<N>) -> Result<Field<N>> {
    record.to_commitment(&ProgramID::from_str("credits.aleo")?, &Identifier::from_str("credits")?, &view_key)
}

fn credits_record<N: Network>(record: &Record<N, Plaintext<N>>) -> Result<(Address<N>, u64)> {
    ensure!(**record.version() <= 1, "Unsupported historical record version");
    let Owner::Private(Plaintext::Literal(Literal::Address(owner), _)) = record.owner() else {
        bail!("Historical credits require a private address owner");
    };
    ensure!(record.data().len() == 1, "Unsupported historical credits schema");
    let Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) =
        record.data().get(&Identifier::from_str("microcredits")?)
    else {
        bail!("Historical credits require private u64 microcredits");
    };
    Ok((*owner, **amount))
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_account::ViewKey;

    type N = MainnetV0;
    type HistoricalFixture = (PrivateKey<N>, Record<N, Plaintext<N>>, Field<N>);
    const NETWORK: Digest64 = [37; 64];
    const MESSAGE: &[u8] = b"canonical core preparation authorization";

    fn fixture(version: u8, schema: &str, visibility: &str) -> Result<HistoricalFixture> {
        let key = PrivateKey::<N>::try_from(Field::from_u64(42))?;
        let owner = Address::try_from(&key)?;
        let nonce = N::g_scalar_multiply(&Scalar::from_str("7scalar")?);
        let record = Record::from_str(&format!(
            "{{ owner: {owner}.{visibility}, {schema}, _nonce: {nonce}.public, _version: {version}u8.public }}"
        ))?;
        let rvk = (nonce * *ViewKey::try_from(&key)?).to_x_coordinate();
        Ok((key, record, rvk))
    }

    fn source(version: u8) -> Result<(PrivateKey<N>, PreparationSource<N>, Signature<N>)> {
        let (key, record, rvk) = fixture(version, "microcredits: 100u64.private", "private")?;
        let commitment = historical_commitment(&record, rvk)?;
        let rng = &mut TestRng::fixed(77);
        let source = PreparationSource::create(&key, record, rvk, commitment, &NETWORK, MESSAGE, rng)?;
        let signature = Signature::sign_bytes(&key, MESSAGE, rng)?;
        Ok((key, source, signature))
    }

    #[test]
    fn historical_commitment_and_serial_match_native_v0_v1() -> Result<()> {
        for version in [0, 1] {
            let (key, source, signature) = source(version)?;
            let verified = source.verify(&NETWORK, MESSAGE, &signature)?;
            assert_eq!(verified.serial, Record::<N, Plaintext<N>>::serial_number(key, source.commitment)?);
            assert_eq!(verified.record.amount, 100);
            assert_eq!(verified.record.version, if version == 0 { RecordVersion::V0 } else { RecordVersion::V1 });
            if version == 0 {
                assert_eq!(source.record_view_key, Field::zero());
                assert_eq!(
                    source.source_record(&NETWORK)?,
                    PreparationSource::record_from_opening(&NETWORK, &source.record, Field::one(), source.commitment)?
                );
            }
            let encoded = source.to_bytes_le()?;
            assert_eq!(source, PreparationSource::from_bytes_exact(&encoded)?);
            assert_eq!(source, PreparationSource::read_le(encoded.as_slice())?);
        }
        Ok(())
    }

    #[test]
    fn independently_pinned_historical_v0_bytes_preserve_commitment_and_serial() -> Result<()> {
        // Produced by unmodified snarkVM 3.7.1 at the exact source revision in
        // the adjacent fixture manifest, before a record-version field existed.
        // This is serialization/native-cryptography compatibility evidence;
        // authenticated on-chain provenance is established separately by the VM.
        let record = Record::<N, Plaintext<N>>::from_bytes_le(include_bytes!(
            "../../history-tools/fixtures/v0-mainnet-native/record.bin"
        ))?;
        let ciphertext = Record::<N, snarkvm_console_program::Ciphertext<N>>::from_bytes_le(include_bytes!(
            "../../history-tools/fixtures/v0-mainnet-native/ciphertext.bin"
        ))?;
        let commitment =
            Field::<N>::from_bytes_le(include_bytes!("../../history-tools/fixtures/v0-mainnet-native/commitment.bin"))?;
        let serial =
            Field::<N>::from_bytes_le(include_bytes!("../../history-tools/fixtures/v0-mainnet-native/serial.bin"))?;
        let rvk = Field::<N>::from_bytes_le(include_bytes!(
            "../../history-tools/fixtures/v0-mainnet-native/record-view-key.bin"
        ))?;
        let key = PrivateKey::<N>::try_from(Field::from_u64(42))?;
        assert_eq!(ciphertext.decrypt(&ViewKey::try_from(&key)?)?, record);
        assert_eq!(**record.version(), 0);
        assert_eq!(historical_commitment(&record, rvk)?, commitment);
        let rng = &mut TestRng::fixed(100);
        let source = PreparationSource::create(&key, record, rvk, commitment, &NETWORK, MESSAGE, rng)?;
        let signature = Signature::sign_bytes(&key, MESSAGE, rng)?;
        let verified = source.verify(&NETWORK, MESSAGE, &signature)?;
        assert_eq!(verified.serial, serial);
        assert_eq!(verified.record.amount, 1_000_000_000);
        assert_eq!(verified.record.version, RecordVersion::V0);
        assert_eq!(source.record_view_key, Field::zero());
        Ok(())
    }

    #[test]
    fn changed_effects_network_key_and_serial_reject() -> Result<()> {
        let (key, source, signature) = source(1)?;
        let rng = &mut TestRng::fixed(88);
        let changed = b"changed replacement key or fee";
        let changed_signature = Signature::sign_bytes(&key, changed, rng)?;
        assert!(source.verify(&NETWORK, changed, &changed_signature).is_err());
        assert!(source.verify(&[38; 64], MESSAGE, &signature).is_err());
        let other = PrivateKey::<N>::try_from(Field::from_u64(43))?;
        let other_signature = Signature::sign_bytes(&other, MESSAGE, rng)?;
        assert!(source.verify(&NETWORK, MESSAGE, &other_signature).is_err());
        let mut forged = source.clone();
        forged.gamma += N::g_scalar_multiply(&Scalar::one());
        assert_ne!(source.serial_number()?, forged.serial_number()?);
        assert!(forged.verify(&NETWORK, MESSAGE, &signature).is_err());
        forged = source.clone();
        forged.response += Scalar::one();
        assert!(forged.verify(&NETWORK, MESSAGE, &signature).is_err());
        forged = source.clone();
        forged.a = Group::zero();
        assert!(forged.verify(&NETWORK, MESSAGE, &signature).is_err());
        Ok(())
    }

    #[test]
    fn opening_amount_and_program_substitution_reject() -> Result<()> {
        let (_, source, signature) = source(1)?;
        let (_, different, _) = fixture(1, "microcredits: 101u64.private", "private")?;
        let mut forged = source.clone();
        forged.record = different;
        assert!(forged.verify(&NETWORK, MESSAGE, &signature).is_err());
        forged = source.clone();
        forged.record_view_key += Field::one();
        assert!(forged.verify(&NETWORK, MESSAGE, &signature).is_err());
        forged = source.clone();
        forged.commitment = forged.record.to_commitment(
            &ProgramID::from_str("asset.aleo")?,
            &Identifier::from_str("credits")?,
            &forged.record_view_key,
        )?;
        assert!(forged.verify(&NETWORK, MESSAGE, &signature).is_err());
        Ok(())
    }

    #[test]
    fn unsupported_schema_version_and_malformed_encoding_reject() -> Result<()> {
        let rng = &mut TestRng::fixed(99);
        for (version, schema, visibility) in [
            (0, "amount: 100u64.private", "private"),
            (1, "microcredits: 100u64.public", "private"),
            (1, "microcredits: 100u32.private", "private"),
            (1, "microcredits: 100u64.private", "public"),
            (2, "microcredits: 100u64.private", "private"),
        ] {
            let (key, record, rvk) = fixture(version, schema, visibility)?;
            let commitment = historical_commitment(&record, rvk)?;
            assert!(PreparationSource::create(&key, record, rvk, commitment, &NETWORK, MESSAGE, rng).is_err());
        }
        let (_, source, _) = source(1)?;
        let bytes = source.to_bytes_le()?;
        for length in 0..bytes.len() {
            assert!(PreparationSource::<N>::from_bytes_exact(&bytes[..length]).is_err());
        }
        let mut malformed = bytes.clone();
        malformed.extend_from_slice(&[0]);
        assert!(PreparationSource::<N>::from_bytes_exact(&malformed).is_err());
        malformed = bytes.clone();
        malformed[0] = 2;
        assert!(PreparationSource::<N>::from_bytes_exact(&malformed).is_err());
        malformed = bytes;
        malformed[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PreparationSource::<N>::from_bytes_exact(&malformed).is_err());
        Ok(())
    }
}

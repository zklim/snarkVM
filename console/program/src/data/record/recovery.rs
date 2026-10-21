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
use snarkvm_console_network::ConsensusVersion;

impl<N: Network> Record<N, Plaintext<N>> {
    /// Returns the address from a well-typed plaintext owner.
    fn recovery_owner(&self) -> Result<Address<N>> {
        match &self.owner {
            Owner::Public(address) | Owner::Private(Plaintext::Literal(Literal::Address(address), ..)) => Ok(*address),
            _ => bail!("Recovery record owner must be an address"),
        }
    }

    /// Hashes bit-length-framed parts after zero alignment to a byte boundary.
    fn recovery_hash(domain: &[u8], parts: &[Vec<bool>]) -> Result<Vec<bool>> {
        let mut input = domain.to_bits_le();
        N::ID.write_bits_le(&mut input);
        for part in parts {
            u64::try_from(part.len())?.write_bits_le(&mut input);
            input.extend_from_slice(part);
        }
        input.resize(input.len().div_ceil(8) * 8, false);
        N::hash_sha3_512(&input)
    }

    /// Returns a network-separated credential for an original account seed.
    /// The seed stays private; credential enrollment requires separate authorization.
    pub fn recovery_key_from_seed(seed: &Field<N>) -> Result<Vec<bool>> {
        Self::recovery_hash(b"AleoRecoveryCredential2", &[seed.to_bits_le()])
    }

    /// Constructs a local V2 migration witness without spending or publishing a record.
    /// Ledger membership, spentness, program authorization and atomic updates are not checked here.
    pub fn prepare_recovery_record(
        &self,
        consensus_version: ConsensusVersion,
        seed: &Field<N>,
        randomizer: Scalar<N>,
    ) -> Result<Self> {
        consensus_version.ensure_legacy_transaction_authorization()?;
        ensure!(consensus_version == ConsensusVersion::V23, "V2 witnesses require recovery preparation");
        ensure!(*self.version <= 1, "Migration witness requires a V0 or V1 source");
        let key = PrivateKey::try_from(*seed)?;
        ensure!(Address::try_from(&key)? == self.recovery_owner()?, "Recovery seed does not derive the source owner");
        ensure!(!randomizer.is_zero(), "Recovery output randomizer must be nonzero");
        let nonce = N::g_scalar_multiply(&randomizer);
        ensure!(nonce != self.nonce, "Recovery output nonce must differ from the source nonce");
        Self::from_plaintext(self.owner.clone(), self.data.clone(), nonce, U8::new(2))
    }

    /// Returns the full SHA3-512 V2 opening commitment, separate from legacy record IDs.
    /// This value and the credential need authentication in a future transaction envelope.
    /// A supplied credential is not evidence of its owner's authorization.
    pub fn to_recovery_commitment(
        &self,
        consensus_version: ConsensusVersion,
        program_id: &ProgramID<N>,
        record_name: &Identifier<N>,
        credential: &[bool],
        record_view_key: &Field<N>,
    ) -> Result<Vec<bool>> {
        consensus_version.ensure_legacy_transaction_authorization()?;
        ensure!(consensus_version == ConsensusVersion::V23, "V2 openings require recovery preparation");
        ensure!(*self.version == 2, "Recovery opening requires record V2");
        ensure!(credential.len() == 512, "Recovery credential must contain exactly 512 bits");
        let mut parts = Vec::with_capacity(9 + 2 * self.data.len());
        parts.extend([
            program_id.to_bits_le(),
            record_name.to_bits_le(),
            vec![self.owner.is_private()],
            self.recovery_owner()?.to_bits_le(),
            self.version.to_bits_le(),
            self.nonce.to_bits_le(),
            u64::try_from(self.data.len())?.to_bits_le(),
        ]);
        for (identifier, entry) in &self.data {
            parts.push(identifier.to_bits_le());
            parts.push(entry.to_bits_le());
        }
        parts.push(credential.to_vec());
        parts.push(record_view_key.to_bits_le());
        Self::recovery_hash(b"AleoRecoveryRecord2", &parts)
    }

    /// Checks seed-derived ownership and computes a local V2 opening commitment.
    /// This does not establish membership, unspentness or authority to transfer an asset.
    pub fn to_recovery_commitment_from_seed(
        &self,
        consensus_version: ConsensusVersion,
        program_id: &ProgramID<N>,
        record_name: &Identifier<N>,
        seed: &Field<N>,
    ) -> Result<Vec<bool>> {
        consensus_version.ensure_legacy_transaction_authorization()?;
        ensure!(consensus_version == ConsensusVersion::V23, "V2 openings require recovery preparation");
        let key = PrivateKey::try_from(*seed)?;
        ensure!(Address::try_from(&key)? == self.recovery_owner()?, "Recovery seed does not derive the record owner");
        let view_key = ViewKey::try_from(&key)?;
        let record_view_key = (self.nonce * *view_key).to_x_coordinate();
        let credential = Self::recovery_key_from_seed(seed)?;
        self.to_recovery_commitment(consensus_version, program_id, record_name, &credential, &record_view_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::{MainnetV0, TestnetV0};

    type N = MainnetV0;

    fn source(version: u8, visibility: &str) -> Result<Record<N, Plaintext<N>>> {
        let key = PrivateKey::<N>::try_from(Field::from_u64(42))?;
        let owner = Address::try_from(&key)?;
        let nonce = N::g_scalar_multiply(&Scalar::from_str("7scalar")?);
        Record::from_str(&format!(
            "{{ owner: {owner}.{visibility}, amount: 100u64.private, _nonce: {nonce}.public, _version: {version}u8.public }}"
        ))
    }

    #[test]
    fn test_recovery_v2_migration_witness() -> Result<()> {
        let seed = Field::from_u64(42);
        let randomizer = Scalar::from_str("9scalar")?;
        for version in [0, 1] {
            for visibility in ["public", "private"] {
                let old = source(version, visibility)?;
                let new = old.prepare_recovery_record(ConsensusVersion::V23, &seed, randomizer)?;
                assert_eq!(old.owner(), new.owner());
                assert_eq!(old.data(), new.data());
                assert_eq!(**new.version(), 2);
                assert_ne!(old.nonce(), new.nonce());
                let bytes = new.to_recovery_bytes_le(ConsensusVersion::V23)?;
                assert_eq!(bytes.len(), old.to_bytes_le()?.len());
                assert_eq!(bytes[0], if visibility == "public" { 4 } else { 5 });
                assert_eq!(new, Record::read_recovery_le(ConsensusVersion::V23, bytes.as_slice())?);
                assert_eq!(new, Record::from_recovery_bytes_le(ConsensusVersion::V23, &bytes)?);
                assert!(Record::<N, Plaintext<N>>::read_le(bytes.as_slice()).is_err());
                assert!(new.to_bytes_le().is_err());
                let ciphertext = new.encrypt(randomizer)?;
                assert_eq!(new, ciphertext.decrypt_from_seed(seed)?);
                assert_eq!(
                    ciphertext,
                    Record::read_recovery_le(
                        ConsensusVersion::V23,
                        ciphertext.to_recovery_bytes_le(ConsensusVersion::V23)?.as_slice()
                    )?
                );
                assert_eq!(new, Record::from_str(&new.to_string())?);
            }
        }
        Ok(())
    }

    #[test]
    fn test_recovery_v2_migration_rejects_invalid_witnesses() -> Result<()> {
        let old = source(1, "private")?;
        let seed = Field::from_u64(42);
        let fresh = Scalar::from_str("9scalar")?;
        for version in [ConsensusVersion::V22, ConsensusVersion::V24] {
            assert!(old.prepare_recovery_record(version, &seed, fresh).is_err());
        }
        assert!(old.prepare_recovery_record(ConsensusVersion::V23, &Field::from_u64(43), fresh).is_err());
        assert!(old.prepare_recovery_record(ConsensusVersion::V23, &seed, Scalar::zero()).is_err());
        assert!(old.prepare_recovery_record(ConsensusVersion::V23, &seed, Scalar::from_str("7scalar")?).is_err());
        let new = old.prepare_recovery_record(ConsensusVersion::V23, &seed, fresh)?;
        assert!(new.prepare_recovery_record(ConsensusVersion::V23, &seed, fresh).is_err());
        let program = ProgramID::from_str("asset.aleo")?;
        let name = Identifier::from_str("coin")?;
        assert!(new.to_commitment(&program, &name, &Field::one()).is_ok());
        assert!(new.to_bytes_le().is_err());
        let malformed = Record { owner: Owner::Private(Plaintext::from(Literal::Field(Field::zero()))), ..old };
        assert!(malformed.prepare_recovery_record(ConsensusVersion::V23, &seed, fresh).is_err());
        let malformed = Record { version: U8::new(2), ..malformed };
        assert!(
            malformed
                .to_recovery_commitment(ConsensusVersion::V23, &program, &name, &[false; 512], &Field::zero())
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_recovery_v2_credential_independent_vector() -> Result<()> {
        let seed = Field::<N>::from_u64(42);
        assert_eq!(seed.to_bits_le().len(), 253);
        let bits = Record::<N, Plaintext<N>>::recovery_key_from_seed(&seed)?;
        let encoded = bits
            .chunks_exact(8)
            .map(|chunk| {
                let byte = chunk.iter().enumerate().fold(0u8, |acc, (i, bit)| acc | (u8::from(*bit) << i));
                format!("{byte:02x}")
            })
            .collect::<String>();
        // Python hashlib.sha3_512(domain + pack('<HQ', 0, 253) + (42).to_bytes(32, 'little')).
        assert_eq!(
            encoded,
            "67dfe1317374edf3eb839bd619e02918b1ab4eaf544fd2535998200ae6f937b0eaf92c9bd40833927ac0754883ad9a3c8066edb90a4d5766271abb95bcce1e66"
        );
        assert_ne!(bits, Record::<TestnetV0, Plaintext<TestnetV0>>::recovery_key_from_seed(&Field::from_u64(42))?);
        Ok(())
    }

    #[test]
    fn test_recovery_v2_unaligned_framing_independent_vector() -> Result<()> {
        let parts = [vec![true, false, true], vec![], vec![true; 9]];
        let bits = Record::<N, Plaintext<N>>::recovery_hash(b"AleoRecoveryRecord2", &parts)?;
        let bytes = bits
            .chunks_exact(8)
            .map(|chunk| {
                let byte = chunk.iter().enumerate().fold(0u8, |acc, (i, bit)| acc | (u8::from(*bit) << i));
                format!("{byte:02x}")
            })
            .collect::<String>();
        // Independently packed and hashed with Python hashlib; includes an empty frame.
        assert_eq!(
            bytes,
            "845c7ee8a75c0d0b304cfa99edae00955f0d5ea574e988e09c237980c23e038638812468b355f3d378aaa2061b54ee50aacce36e96da88112b77378de6b5911f"
        );
        assert_ne!(
            bits,
            Record::<N, Plaintext<N>>::recovery_hash(b"AleoRecoveryRecord2", &[
                vec![],
                vec![true, false, true],
                vec![true; 9]
            ])?
        );
        Ok(())
    }

    #[test]
    fn test_recovery_v2_opening_independent_vector() -> Result<()> {
        // This zero-point fixture tests the encoding; it is not an owned or recoverable asset.
        let record = Record::<N, Plaintext<N>>::from_plaintext(
            Owner::Public(Address::new(Group::zero())),
            IndexMap::new(),
            Group::zero(),
            U8::new(2),
        )?;
        let opening = record.to_recovery_commitment(
            ConsensusVersion::V23,
            &ProgramID::from_str("asset.aleo")?,
            &Identifier::from_str("coin")?,
            &[false; 512],
            &Field::zero(),
        )?;
        let encoded = opening
            .chunks_exact(8)
            .map(|chunk| {
                let byte = chunk.iter().enumerate().fold(0u8, |acc, (i, bit)| acc | (u8::from(*bit) << i));
                format!("{byte:02x}")
            })
            .collect::<String>();
        assert_eq!(
            encoded,
            "52e29d93720dda2d72659846aa038011523ed5d475688621e8b17f1eebc8c13936f58e4bd2dd9699d1a60513853286498a26b686afc6a950651edb2a700ce4b3"
        );
        Ok(())
    }

    #[test]
    fn test_recovery_v2_opening_binds_context_and_credentials() -> Result<()> {
        let seed = Field::from_u64(42);
        let record = source(1, "private")?.prepare_recovery_record(
            ConsensusVersion::V23,
            &seed,
            Scalar::from_str("9scalar")?,
        )?;
        let program = ProgramID::from_str("asset.aleo")?;
        let name = Identifier::from_str("coin")?;
        let credential = Record::<N, Plaintext<N>>::recovery_key_from_seed(&seed)?;
        let view_key = ViewKey::try_from(&PrivateKey::<N>::try_from(seed)?)?;
        let rvk = (*record.nonce() * *view_key).to_x_coordinate();
        let expected = record.to_recovery_commitment(ConsensusVersion::V23, &program, &name, &credential, &rvk)?;
        assert_eq!(expected.len(), 512);
        assert_eq!(expected, record.to_recovery_commitment_from_seed(ConsensusVersion::V23, &program, &name, &seed)?);
        let mut wrong_credential = credential.clone();
        wrong_credential[0] ^= true;
        for (p, n, c, v) in [
            (ProgramID::from_str("other.aleo")?, name, credential.clone(), rvk),
            (program, Identifier::from_str("other")?, credential.clone(), rvk),
            (program, name, wrong_credential, rvk),
            (program, name, credential.clone(), rvk + Field::one()),
        ] {
            assert_ne!(expected, record.to_recovery_commitment(ConsensusVersion::V23, &p, &n, &c, &v)?);
        }
        let other_owner = Address::try_from(&PrivateKey::<N>::try_from(Field::from_u64(43))?)?;
        let other_nonce = N::g_scalar_multiply(&Scalar::from_str("11scalar")?);
        for changed in [
            record.to_string().replace("100u64", "101u64"),
            record.to_string().replace("100u64", "100u32"),
            record.to_string().replace("100u64.private", "100u64.public"),
            record.to_string().replace("amount:", "balance:"),
            record.to_string().replace(&record.owner().to_string(), &format!("{other_owner}.private")),
            record.to_string().replace(&record.nonce().to_string(), &other_nonce.to_string()),
        ] {
            let changed = Record::from_str(&changed)?;
            assert_ne!(
                expected,
                changed.to_recovery_commitment(ConsensusVersion::V23, &program, &name, &credential, &rvk)?
            );
        }
        assert!(
            record.to_recovery_commitment(ConsensusVersion::V23, &program, &name, &credential[..511], &rvk).is_err()
        );
        assert!(
            record
                .to_recovery_commitment_from_seed(ConsensusVersion::V23, &program, &name, &Field::from_u64(43))
                .is_err()
        );
        for version in [ConsensusVersion::V22, ConsensusVersion::V24] {
            assert!(record.to_recovery_commitment_from_seed(version, &program, &name, &seed).is_err());
        }
        for version in [0, 1] {
            assert!(
                source(version, "private")?
                    .to_recovery_commitment(ConsensusVersion::V23, &program, &name, &credential, &rvk)
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn test_recovery_v2_encoding_rejects_malformed_records() -> Result<()> {
        let source = source(1, "public")?;
        let record = Record { version: U8::new(2), ..source.clone() };
        let bytes = record.to_recovery_bytes_le(ConsensusVersion::V23)?;
        let original = source.to_bytes_le()?;
        assert_eq!(original[0], 2);
        assert_eq!(bytes[0], 4);
        assert_eq!(&original[1..], &bytes[1..]);
        for version in [ConsensusVersion::V22, ConsensusVersion::V24] {
            assert!(record.to_recovery_bytes_le(version).is_err());
            assert!(Record::<N, Plaintext<N>>::read_recovery_le(version, bytes.as_slice()).is_err());
        }
        for end in 0..bytes.len() {
            assert!(Record::<N, Plaintext<N>>::read_recovery_le(ConsensusVersion::V23, &bytes[..end]).is_err());
        }
        let mut unknown = bytes.clone();
        unknown[0] = 6;
        assert!(Record::<N, Plaintext<N>>::read_recovery_le(ConsensusVersion::V23, unknown.as_slice()).is_err());
        assert!(Record::<N, Plaintext<N>>::read_recovery_le(ConsensusVersion::V23, original.as_slice()).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Record::<N, Plaintext<N>>::from_recovery_bytes_le(ConsensusVersion::V23, &trailing).is_err());

        let count_offset = 1 + (**record.owner()).to_bytes_le()?.len();
        let nonce_bytes = record.nonce().to_bytes_le()?;
        let entry = &bytes[count_offset + 1..bytes.len() - nonce_bytes.len()];
        let mut duplicate = bytes[..count_offset].to_vec();
        duplicate.push(2);
        duplicate.extend_from_slice(entry);
        duplicate.extend_from_slice(entry);
        duplicate.extend_from_slice(&nonce_bytes);
        assert!(Record::<N, Plaintext<N>>::read_recovery_le(ConsensusVersion::V23, duplicate.as_slice()).is_err());
        Ok(())
    }

    #[test]
    fn test_recovery_v2_witness_has_no_spend_state() -> Result<()> {
        let old = source(1, "private")?;
        let seed = Field::from_u64(42);
        let randomizer = Scalar::from_str("9scalar")?;
        let first = old.prepare_recovery_record(ConsensusVersion::V23, &seed, randomizer)?;
        let repeated = old.prepare_recovery_record(ConsensusVersion::V23, &seed, randomizer)?;
        let alternative = old.prepare_recovery_record(ConsensusVersion::V23, &seed, Scalar::from_str("10scalar")?)?;
        assert_eq!(first, repeated);
        assert_ne!(first, alternative);
        assert_eq!(old.data(), alternative.data());

        let program = ProgramID::from_str("asset.aleo")?;
        let name = Identifier::from_str("coin")?;
        let seed_bound_opening =
            first.to_recovery_commitment_from_seed(ConsensusVersion::V23, &program, &name, &seed)?;
        let supplied_credential_opening =
            first.to_recovery_commitment(ConsensusVersion::V23, &program, &name, &[false; 512], &Field::zero())?;
        assert_ne!(seed_bound_opening, supplied_credential_opening);
        assert!(first.to_bytes_le().is_err());
        Ok(())
    }

    #[test]
    fn test_recovery_v2_generated_migration_properties() -> Result<()> {
        let rng = &mut TestRng::fixed(0x5152_2026);
        for _ in 0..64 {
            let seed = Field::<N>::rand(rng);
            let key = PrivateKey::try_from(seed)?;
            let owner = Address::try_from(&key)?;
            let nonce = N::g_scalar_multiply(&Scalar::from_str("7scalar")?);
            let version = rng.random_range(0..=1);
            let amount: u64 = rng.random();
            let visibility = if rng.random() { "private" } else { "public" };
            let old = Record::<N, Plaintext<N>>::from_str(&format!(
                "{{ owner: {owner}.{visibility}, amount: {amount}u64.private, _nonce: {nonce}.public, _version: {version}u8.public }}"
            ))?;
            let randomizer = loop {
                let randomizer = Scalar::<N>::rand(rng);
                if !randomizer.is_zero() && N::g_scalar_multiply(&randomizer) != nonce {
                    break randomizer;
                }
            };
            let candidate = old.prepare_recovery_record(ConsensusVersion::V23, &seed, randomizer)?;
            assert_eq!(old.owner(), candidate.owner());
            assert_eq!(old.data(), candidate.data());
            assert_ne!(old.nonce(), candidate.nonce());
            assert_eq!(candidate, candidate.encrypt(randomizer)?.decrypt_from_seed(seed)?);
            assert!(candidate.to_bytes_le().is_err());
            let encoded = candidate.to_recovery_bytes_le(ConsensusVersion::V23)?;
            assert_eq!(candidate, Record::from_recovery_bytes_le(ConsensusVersion::V23, &encoded)?);
        }
        Ok(())
    }

    #[test]
    fn test_recovery_v2_bounded_mutation_fuzz() -> Result<()> {
        let rng = &mut TestRng::fixed(0x4655_5a5a);
        let candidate = source(1, "public")?.prepare_recovery_record(
            ConsensusVersion::V23,
            &Field::from_u64(42),
            Scalar::from_str("9scalar")?,
        )?;
        let encoded = candidate.to_recovery_bytes_le(ConsensusVersion::V23)?;
        let mut accepted = 0;
        let mut rejected = 0;
        for case in 0..4096 {
            let mut bytes = encoded.clone();
            match case % 4 {
                0 => {
                    let index = rng.random_range(0..bytes.len());
                    bytes[index] ^= 1 << rng.random_range(0..8);
                }
                1 => bytes.truncate(rng.random_range(0..bytes.len())),
                2 => bytes.push(rng.random()),
                _ => {
                    for byte in &mut bytes {
                        *byte = rng.random();
                    }
                }
            }
            match Record::<N, Plaintext<N>>::from_recovery_bytes_le(ConsensusVersion::V23, &bytes) {
                Ok(record) => {
                    accepted += 1;
                    assert_eq!(bytes, record.to_recovery_bytes_le(ConsensusVersion::V23)?);
                    assert!(record.to_bytes_le().is_err());
                }
                Err(_) => rejected += 1,
            }
        }
        assert!(accepted > 0);
        assert!(rejected > 0);
        println!("Mutation corpus: {accepted} canonical inputs, {rejected} rejected inputs");
        Ok(())
    }
}

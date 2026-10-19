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
use console::{ConsensusVersion, Network};
use snarkvm_utilities::ToBits as NativeToBits;

impl<A: Aleo> Record<A, Plaintext<A>> {
    /// Returns the address from a well-typed plaintext owner.
    fn recovery_owner(&self) -> Result<&snarkvm_circuit_types::Address<A>> {
        match &self.owner {
            Owner::Public(address) | Owner::Private(Plaintext::Literal(Literal::Address(address), ..)) => Ok(address),
            _ => bail!("Recovery record owner must be an address"),
        }
    }

    /// Hashes bit-length-framed parts after zero alignment to a byte boundary.
    fn recovery_hash(domain: &[u8], parts: &[Vec<Boolean<A>>]) -> Vec<Boolean<A>> {
        let mut input = domain.to_bits_le().into_iter().map(Boolean::constant).collect::<Vec<_>>();
        input.extend(A::Network::ID.to_bits_le().into_iter().map(Boolean::constant));
        for part in parts {
            let length = u64::try_from(part.len()).unwrap_or_else(|_| A::halt("Recovery opening length exceeds u64"));
            input.extend(length.to_bits_le().into_iter().map(Boolean::constant));
            input.extend_from_slice(part);
        }
        input.resize(input.len().div_ceil(8) * 8, Boolean::constant(false));
        A::hash_sha3_512(&input)
    }

    /// Constrains the network-separated credential for a private account seed.
    /// Ownership and enrollment authorization are separate constraints.
    pub fn recovery_key_from_seed(seed: &Field<A>) -> Vec<Boolean<A>> {
        Self::recovery_hash(b"AleoRecoveryCredential2", &[seed.to_bits_le()])
    }

    /// Constrains a V0/V1 to V2 migration witness without changing ledger state.
    pub fn prepare_recovery_record(
        &self,
        consensus_version: ConsensusVersion,
        seed: &Field<A>,
        randomizer: &Scalar<A>,
    ) -> Result<Self> {
        consensus_version.ensure_legacy_transaction_authorization()?;
        ensure!(consensus_version == ConsensusVersion::V23, "V2 witnesses require recovery preparation");
        A::assert(self.version.is_zero() | self.version.is_one())?;
        let key = PrivateKey::from_seed(seed);
        A::assert_eq(key.to_compute_key().to_address(), self.recovery_owner()?)?;
        A::assert(!randomizer.is_zero())?;
        let nonce = A::g_scalar_multiply(randomizer);
        A::assert(nonce.is_not_equal(&self.nonce))?;
        Self::from_plaintext(self.owner.clone(), self.data.clone(), nonce, U8::constant(console::U8::new(2)))
    }

    /// Constrains the full V2 opening commitment, separate from legacy record IDs.
    /// No ledger membership or enrollment authorization is implied by this hash.
    pub fn to_recovery_commitment(
        &self,
        consensus_version: ConsensusVersion,
        program_id: &ProgramID<A>,
        record_name: &Identifier<A>,
        credential: &[Boolean<A>],
        record_view_key: &Field<A>,
    ) -> Result<Vec<Boolean<A>>> {
        consensus_version.ensure_legacy_transaction_authorization()?;
        ensure!(consensus_version == ConsensusVersion::V23, "V2 openings require recovery preparation");
        ensure!(credential.len() == 512, "Recovery credential must contain exactly 512 bits");
        A::assert_eq(&self.version, U8::<A>::constant(console::U8::new(2)))?;
        let count =
            u64::try_from(self.data.len()).unwrap_or_else(|_| A::halt("Recovery record entry count exceeds u64"));
        let mut parts = Vec::with_capacity(9 + 2 * self.data.len());
        parts.extend([
            program_id.to_bits_le(),
            record_name.to_bits_le(),
            vec![self.owner.is_private()],
            self.recovery_owner()?.to_bits_le(),
            self.version.to_bits_le(),
            self.nonce.to_bits_le(),
            count.to_bits_le().into_iter().map(Boolean::constant).collect(),
        ]);
        for (identifier, entry) in &self.data {
            parts.push(identifier.to_bits_le());
            parts.push(entry.to_bits_le());
        }
        parts.push(credential.to_vec());
        parts.push(record_view_key.to_bits_le());
        Ok(Self::recovery_hash(b"AleoRecoveryRecord2", &parts))
    }

    /// Constrains seed-derived ownership and the complete V2 opening commitment.
    /// Membership, unspentness, transaction effects and a recovery proof backend remain required.
    pub fn to_recovery_commitment_from_seed(
        &self,
        consensus_version: ConsensusVersion,
        program_id: &ProgramID<A>,
        record_name: &Identifier<A>,
        seed: &Field<A>,
    ) -> Result<Vec<Boolean<A>>> {
        consensus_version.ensure_legacy_transaction_authorization()?;
        ensure!(consensus_version == ConsensusVersion::V23, "V2 openings require recovery preparation");
        let key = PrivateKey::from_seed(seed);
        A::assert_eq(key.to_compute_key().to_address(), self.recovery_owner()?)?;
        let view_key = key.to_view_key();
        let record_view_key = (&*view_key * &self.nonce).to_x_coordinate();
        let credential = Self::recovery_key_from_seed(seed);
        self.to_recovery_commitment(consensus_version, program_id, record_name, &credential, &record_view_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;

    type N = <Circuit as Environment>::Network;

    fn source(version: u8, visibility: &str) -> Result<console::Record<N, console::Plaintext<N>>> {
        let key = snarkvm_console_account::PrivateKey::<N>::try_from(console::Field::from_u64(42))?;
        let owner = console::Address::try_from(&key)?;
        let nonce = N::g_scalar_multiply(&console::Scalar::from_str("7scalar")?);
        console::Record::from_str(&format!(
            "{{ owner: {owner}.{visibility}, amount: 100u64.private, _nonce: {nonce}.public, _version: {version}u8.public }}"
        ))
    }

    #[test]
    fn test_recovery_v2_native_circuit_migration_and_opening() -> Result<()> {
        let native_seed = console::Field::<N>::from_u64(42);
        let native_randomizer = console::Scalar::<N>::from_str("9scalar")?;
        let program = console::ProgramID::from_str("asset.aleo")?;
        let name = console::Identifier::from_str("coin")?;
        for (version, visibility) in [(0, "private"), (1, "public")] {
            let source = source(version, visibility)?;
            let native = source.prepare_recovery_record(ConsensusVersion::V23, &native_seed, native_randomizer)?;
            let expected =
                native.to_recovery_commitment_from_seed(ConsensusVersion::V23, &program, &name, &native_seed)?;
            let source = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, source);
            let seed = Field::new(Mode::Private, native_seed);
            let randomizer = Scalar::new(Mode::Private, native_randomizer);
            let before_migration = Circuit::num_constraints();
            let migrated = source.prepare_recovery_record(ConsensusVersion::V23, &seed, &randomizer)?;
            assert_eq!(native, migrated.eject_value());
            let migration_constraints = Circuit::num_constraints() - before_migration;
            let before_opening = Circuit::num_constraints();
            let opening = migrated.to_recovery_commitment_from_seed(
                ConsensusVersion::V23,
                &ProgramID::constant(program),
                &Identifier::constant(name),
                &seed,
            )?;
            assert_eq!(expected, opening.eject_value());
            assert_eq!(opening.len(), 512);
            assert!(Circuit::is_satisfied());
            println!(
                "V{version}/{visibility}: migration={migration_constraints}, seed+opening={} constraints, private={} variables, plaintext={} bytes",
                Circuit::num_constraints() - before_opening,
                Circuit::num_private(),
                native.to_recovery_bytes_le(ConsensusVersion::V23)?.len(),
            );
            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_recovery_v2_migration_adversarial_constraints() -> Result<()> {
        for (version, seed_value, randomizer_value) in
            [(1, 43, "9scalar"), (1, 42, "0scalar"), (1, 42, "7scalar"), (2, 42, "9scalar")]
        {
            let source = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, source(version, "private")?);
            let seed = Field::new(Mode::Private, console::Field::from_u64(seed_value));
            let randomizer = Scalar::new(Mode::Private, console::Scalar::from_str(randomizer_value)?);
            let _ = source.prepare_recovery_record(ConsensusVersion::V23, &seed, &randomizer)?;
            assert!(!Circuit::is_satisfied());
            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_recovery_v2_opening_rejects_substitution() -> Result<()> {
        let native_seed = console::Field::<N>::from_u64(42);
        let native = source(1, "public")?.prepare_recovery_record(
            ConsensusVersion::V23,
            &native_seed,
            console::Scalar::from_str("9scalar")?,
        )?;
        let program = console::ProgramID::from_str("asset.aleo")?;
        let name = console::Identifier::from_str("coin")?;
        let expected = native.to_recovery_commitment_from_seed(ConsensusVersion::V23, &program, &name, &native_seed)?;
        let record = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, native);
        let wrong_seed = Field::new(Mode::Private, console::Field::from_u64(43));
        let candidate = record.to_recovery_commitment_from_seed(
            ConsensusVersion::V23,
            &ProgramID::constant(program),
            &Identifier::constant(name),
            &wrong_seed,
        )?;
        assert_ne!(expected, candidate.eject_value());
        for (candidate, expected) in candidate.iter().zip_eq(expected) {
            Circuit::assert_eq(candidate, Boolean::<Circuit>::constant(expected))?;
        }
        assert!(!Circuit::is_satisfied());
        Circuit::reset();
        Ok(())
    }

    #[test]
    fn test_recovery_v2_preparation_boundaries() -> Result<()> {
        let source = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, source(1, "private")?);
        let seed = Field::new(Mode::Private, console::Field::from_u64(42));
        let randomizer = Scalar::new(Mode::Private, console::Scalar::from_str("9scalar")?);
        for version in [ConsensusVersion::V22, ConsensusVersion::V24] {
            assert!(source.prepare_recovery_record(version, &seed, &randomizer).is_err());
        }
        assert!(Circuit::is_satisfied());
        Circuit::reset();
        Ok(())
    }

    #[test]
    fn test_recovery_v2_public_digest_rejects_mutated_amount() -> Result<()> {
        let seed_value = console::Field::<N>::from_u64(42);
        let original = source(1, "private")?.prepare_recovery_record(
            ConsensusVersion::V23,
            &seed_value,
            console::Scalar::from_str("9scalar")?,
        )?;
        let program = console::ProgramID::from_str("asset.aleo")?;
        let name = console::Identifier::from_str("coin")?;
        let expected =
            original.to_recovery_commitment_from_seed(ConsensusVersion::V23, &program, &name, &seed_value)?;
        let mutated = console::Record::from_str(&original.to_string().replace("100u64", "101u64"))?;
        let record = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, mutated);
        let seed = Field::new(Mode::Private, seed_value);
        let candidate = record.to_recovery_commitment_from_seed(
            ConsensusVersion::V23,
            &ProgramID::constant(program),
            &Identifier::constant(name),
            &seed,
        )?;
        assert!(Circuit::is_satisfied());
        assert_ne!(expected, candidate.eject_value());
        for (candidate, expected) in candidate.iter().zip_eq(expected) {
            Circuit::assert_eq(candidate, Boolean::<Circuit>::new(Mode::Public, expected))?;
        }
        assert!(!Circuit::is_satisfied());
        Circuit::reset();
        Ok(())
    }
}

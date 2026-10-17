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

impl<N: Network> Record<N, Ciphertext<N>> {
    /// Reconstructs a record from its owner's account seed for a local recovery witness.
    /// The caller must authenticate this ciphertext against an independently trusted archive
    /// and check the spent serial-number set. This method does not authorize a transaction.
    /// The seed must remain private to the witness generator.
    pub fn decrypt_from_seed(&self, seed: Field<N>) -> Result<Record<N, Plaintext<N>>> {
        let private_key = PrivateKey::try_from(seed)?;
        self.decrypt(&ViewKey::try_from(&private_key)?)
    }

    /// Decrypts `self` into plaintext using the given view key and checks that the owner matches the view key.
    pub fn decrypt(&self, view_key: &ViewKey<N>) -> Result<Record<N, Plaintext<N>>> {
        // Compute the record view key.
        let record_view_key = (self.nonce * **view_key).to_x_coordinate();
        // Decrypt the record.
        let record = self.decrypt_symmetric_unchecked(&record_view_key)?;
        // Ensure the record owner matches the view key.
        match view_key.to_address() == **record.owner() {
            true => Ok(record),
            false => bail!("Illegal operation: Record::decrypt() view key does not correspond to the record owner."),
        }
    }

    /// Decrypts `self` into plaintext using the given record view key.
    /// Note: This method does not check that the record view key corresponds to the record owner.
    /// Use `Self::decrypt` for the checked variant.
    pub fn decrypt_symmetric_unchecked(&self, record_view_key: &Field<N>) -> Result<Record<N, Plaintext<N>>> {
        // Determine the number of randomizers needed to encrypt the record.
        let num_randomizers = self.num_randomizers()?;
        // Prepare a randomizer for each field element.
        let randomizers = N::hash_many_psd8(&[N::encryption_domain(), *record_view_key], num_randomizers);
        // Decrypt the record.
        self.decrypt_with_randomizers(&randomizers)
    }

    /// Decrypts `self` into plaintext using the given randomizers.
    fn decrypt_with_randomizers(&self, randomizers: &[Field<N>]) -> Result<Record<N, Plaintext<N>>> {
        // Initialize an index to keep track of the randomizer index.
        let mut index: usize = 0;

        // Decrypt the owner.
        let owner = match self.owner.is_public() {
            true => self.owner.decrypt_with_randomizer(&[])?,
            false => self.owner.decrypt_with_randomizer(&[randomizers[index]])?,
        };

        // Increment the index if the owner is private.
        if owner.is_private() {
            index += 1;
        }

        // Decrypt the program data.
        let mut decrypted_data = IndexMap::with_capacity(self.data.len());
        for (id, entry, num_randomizers) in self.data.iter().map(|(id, entry)| (id, entry, entry.num_randomizers())) {
            // Retrieve the result for `num_randomizers`.
            let num_randomizers = num_randomizers? as usize;
            // Retrieve the randomizers for this entry.
            let randomizers = &randomizers[index..index + num_randomizers];
            // Decrypt the entry.
            let entry = match entry {
                // Constant entries do not need to be decrypted.
                Entry::Constant(plaintext) => Entry::Constant(plaintext.clone()),
                // Public entries do not need to be decrypted.
                Entry::Public(plaintext) => Entry::Public(plaintext.clone()),
                // Private entries are decrypted with the given randomizers.
                Entry::Private(private) => Entry::Private(Plaintext::from_fields(
                    &private
                        .iter()
                        .zip_eq(randomizers)
                        .map(|(ciphertext, randomizer)| *ciphertext - randomizer)
                        .collect::<Vec<_>>(),
                )?),
            };
            // Insert the decrypted entry.
            if decrypted_data.insert(*id, entry).is_some() {
                bail!("Duplicate identifier in record: {id}");
            }
            // Increment the index.
            index += num_randomizers;
        }

        // Return the decrypted record.
        Self::from_plaintext(owner, decrypted_data, self.nonce, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Literal;
    use snarkvm_console_account::PrivateKey;
    use snarkvm_console_network::MainnetV0;
    use snarkvm_console_types::Field;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_recovery_seed_record_roundtrip() -> Result<()> {
        let rng = &mut TestRng::fixed(229);
        let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
        let address = Address::try_from(&private_key)?;
        let view_key = ViewKey::try_from(&private_key)?;
        let wrong_seed = private_key.seed() + Field::one();
        let view_key_as_seed = Field::from_bits_le(&view_key.to_bits_le())?;
        for version in [0, 1] {
            for public_owner in [false, true] {
                let randomizer = Scalar::rand(rng);
                let owner = match public_owner {
                    true => Owner::Public(address),
                    false => Owner::Private(Plaintext::from(Literal::Address(address))),
                };
                let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
                    owner,
                    IndexMap::from_iter([
                        (Identifier::from_str("amount")?, Entry::Private(Plaintext::from_str("100u64")?)),
                        (Identifier::from_str("asset")?, Entry::Public(Plaintext::from_str("7field")?)),
                    ]),
                    CurrentNetwork::g_scalar_multiply(&randomizer),
                    U8::new(version),
                )?;
                let (ciphertext, record_view_key) = record.encrypt_symmetric(randomizer)?;
                let restored =
                    Record::<CurrentNetwork, Ciphertext<CurrentNetwork>>::from_bytes_le(&ciphertext.to_bytes_le()?)?;
                let recovered = restored.decrypt_from_seed(private_key.seed())?;
                assert_eq!(record, recovered);
                let program_id = ProgramID::from_str("assets.aleo")?;
                let record_name = Identifier::from_str("token")?;
                assert_eq!(
                    record.to_commitment(&program_id, &record_name, &record_view_key)?,
                    recovered.to_commitment(&program_id, &record_name, &record_view_key)?
                );
                assert!(restored.decrypt_from_seed(wrong_seed).is_err());
                assert!(restored.decrypt_from_seed(view_key_as_seed).is_err());
            }
        }
        Ok(())
    }

    fn check_encrypt_and_decrypt<N: Network>(
        view_key: ViewKey<N>,
        owner: Owner<N, Plaintext<N>>,
        rng: &mut TestRng,
    ) -> Result<()> {
        // Prepare the record.
        let randomizer = Scalar::rand(rng);
        let record = Record {
            owner,
            data: IndexMap::from_iter(vec![
                (Identifier::from_str("a")?, Entry::Private(Plaintext::from(Literal::Field(Field::rand(rng))))),
                (Identifier::from_str("b")?, Entry::Private(Plaintext::from(Literal::Scalar(Scalar::rand(rng))))),
            ]),
            nonce: N::g_scalar_multiply(&randomizer),
            version: U8::rand(rng),
        };
        // Encrypt the record.
        let ciphertext = record.encrypt(randomizer)?;
        // Decrypt the record.
        assert_eq!(record, ciphertext.decrypt(&view_key)?);

        // Generate a new random private key.
        let incorrect_private_key = PrivateKey::<N>::new(rng)?;
        // Generate a new view key.
        let incorrect_view_key = ViewKey::try_from(&incorrect_private_key)?;
        // Ensure that decrypting with the incorrect view key fails.
        assert!(ciphertext.decrypt(&incorrect_view_key).is_err());

        Ok(())
    }

    #[test]
    fn test_encrypt_and_decrypt() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a view key and address.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let view_key = ViewKey::try_from(&private_key)?;
            let address = Address::try_from(&private_key)?;

            // Public owner.
            let owner = Owner::Public(address);
            check_encrypt_and_decrypt::<CurrentNetwork>(view_key, owner, &mut rng)?;

            // Private owner.
            let owner = Owner::Private(Plaintext::from(Literal::Address(address)));
            check_encrypt_and_decrypt::<CurrentNetwork>(view_key, owner, &mut rng)?;
        }
        Ok(())
    }
}

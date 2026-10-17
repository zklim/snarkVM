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
use snarkvm_circuit_types::Field;

impl<A: Aleo> PrivateKey<A> {
    /// Derives both private key components from an account seed inside the circuit.
    ///
    /// Unlike injecting a private key, this constrains the seed-to-key relation.
    /// A recovery statement must additionally bind the derived address and the
    /// transaction effects, and use a proof system secure against its adversary.
    pub fn from_seed(seed: &Field<A>) -> Self {
        let sk_sig_domain = Field::constant(console::Field::new_domain_separator("AleoAccountSignatureSecretKey0"));
        let r_sig_domain = Field::constant(console::Field::new_domain_separator("AleoAccountSignatureRandomizer0.0"));
        Self {
            sk_sig: A::hash_to_scalar_psd2(&[sk_sig_domain, seed.clone()]),
            r_sig: A::hash_to_scalar_psd2(&[r_sig_domain, seed.clone()]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use snarkvm_circuit_types::Address;

    type CurrentNetwork = <Circuit as Environment>::Network;

    #[test]
    fn test_recovery_seed_derivation() -> anyhow::Result<()> {
        for mode in [Mode::Constant, Mode::Public, Mode::Private] {
            for seed in [console::Field::zero(), console::Field::one(), console::Field::from_u64(42)] {
                let native = console::PrivateKey::<CurrentNetwork>::try_from(seed)?;
                let expected_address = console::Address::try_from(&native)?;
                let seed = Field::<Circuit>::new(mode, seed);
                let candidate = PrivateKey::from_seed(&seed);
                assert_eq!((native.sk_sig(), native.r_sig()), candidate.eject_value());
                let address = candidate.to_compute_key().to_address();
                assert_eq!(*expected_address, address.to_group().eject_value());
                Circuit::assert(address.is_equal(&Address::constant(expected_address)))?;
                assert!(Circuit::is_satisfied());
                Circuit::reset();
            }
        }
        Ok(())
    }

    #[test]
    fn test_recovery_seed_rejects_wrong_owner() -> anyhow::Result<()> {
        let owner = console::PrivateKey::<CurrentNetwork>::try_from(console::Field::from_u64(42))?;
        let owner_address = console::Address::try_from(&owner)?;
        let other_seed = Field::<Circuit>::new(Mode::Private, console::Field::from_u64(43));
        let candidate = PrivateKey::from_seed(&other_seed).to_compute_key().to_address();
        let matches = candidate.is_equal(&Address::constant(owner_address));
        assert!(!matches.eject_value());
        Circuit::assert(matches)?;
        assert!(!Circuit::is_satisfied());
        Circuit::reset();
        Ok(())
    }

    #[test]
    fn test_recovery_seed_matches_historical_account() -> anyhow::Result<()> {
        let native = console::PrivateKey::<CurrentNetwork>::from_str(
            "APrivateKey1zkp8cC4jgHEBnbtu3xxs1Ndja2EMizcvTRDq5Nikdkukg1p",
        )?;
        let expected = console::Address::<CurrentNetwork>::from_str(
            "aleo1wvgwnqvy46qq0zemj0k6sfp3zv0mp77rw97khvwuhac05yuwscxqmfyhwf",
        )?;
        let seed = Field::<Circuit>::new(Mode::Private, native.seed());
        let candidate = PrivateKey::from_seed(&seed);
        assert_eq!((native.sk_sig(), native.r_sig()), candidate.eject_value());
        Circuit::assert(candidate.to_compute_key().to_address().is_equal(&Address::new(Mode::Public, expected)))?;
        assert!(Circuit::is_satisfied());
        Circuit::reset();
        Ok(())
    }
}

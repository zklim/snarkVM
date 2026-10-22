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

//! Direct signature adapters, independent of aggregation and ownership proofs.
#![forbid(unsafe_code)]

use fn_dsa::{DOMAIN_NONE, HASH_ID_RAW, VerifyingKey, VerifyingKey512};
use ml_dsa::{KeyInit, MlDsa65, Signature, Verifier};
use snarkvm_recovery::{Error, LegacyVerifier, Limits, Profile, Result, SignatureVerifier};

pub struct MlDsa65Verifier;

impl SignatureVerifier for MlDsa65Verifier {
    fn profile(&self) -> Profile {
        Profile::ML_DSA_65
    }

    fn limits(&self) -> Limits {
        Limits { public_key_bytes: 1952, signature_bytes: 3309, max_message_bytes: 44_000 }
    }

    fn validate_key(&self, key: &[u8]) -> Result<()> {
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(key).map_err(|_| Error::InvalidKey)?;
        ml_dsa::VerifyingKey::<MlDsa65>::new(&encoded);
        Ok(())
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        if message.len() > self.limits().max_message_bytes {
            return Err(Error::Limit);
        }
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(key).map_err(|_| Error::InvalidKey)?;
        let key = ml_dsa::VerifyingKey::<MlDsa65>::new(&encoded);
        let signature = Signature::<MlDsa65>::try_from(signature).map_err(|_| Error::InvalidSignature)?;
        key.verify(message, &signature).map_err(|_| Error::InvalidSignature)
    }
}

/// Degree 512 only; padded key-prefixed raw messages with empty context.
pub struct Falcon512Verifier;

impl SignatureVerifier for Falcon512Verifier {
    fn profile(&self) -> Profile {
        Profile::FALCON_512
    }

    fn limits(&self) -> Limits {
        Limits { public_key_bytes: 897, signature_bytes: 666, max_message_bytes: 44_000 }
    }

    fn validate_key(&self, key: &[u8]) -> Result<()> {
        VerifyingKey512::decode(key).ok_or(Error::InvalidKey).map(|_| ())
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        if message.len() > self.limits().max_message_bytes || signature.len() != 666 {
            return Err(Error::Limit);
        }
        let key = VerifyingKey512::decode(key).ok_or(Error::InvalidKey)?;
        if key.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message) { Ok(()) } else { Err(Error::InvalidSignature) }
    }
}

/// Classical pre-cutoff enrollment authorization for trusted public Aleo sources.
/// It does not verify private record membership or establish seed knowledge.
pub struct AleoLegacy<N>(std::marker::PhantomData<N>);

impl<N> Default for AleoLegacy<N> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<N: snarkvm_console_network::Network> LegacyVerifier for AleoLegacy<N> {
    fn verify(&self, owner: &[u8], message: &[u8], evidence: &[u8]) -> Result<()> {
        use snarkvm_console_account::{Address, FromBytes, Signature, ToBytes};
        let address = Address::<N>::from_bytes_le(owner).map_err(|_| Error::InvalidKey)?;
        let signature = Signature::<N>::from_bytes_le(evidence).map_err(|_| Error::InvalidSignature)?;
        if address.to_bytes_le().map_err(|_| Error::Encoding)? != owner
            || signature.to_bytes_le().map_err(|_| Error::Encoding)? != evidence
        {
            return Err(Error::Encoding);
        }
        if signature.verify_bytes(&address, message) { Ok(()) } else { Err(Error::InvalidSignature) }
    }
}

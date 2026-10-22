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

#![cfg(feature = "producer")]

use fn_dsa::{DOMAIN_NONE, HASH_ID_RAW, KeyPairGenerator, KeyPairGenerator512, SigningKey, SigningKey512};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use snarkvm_recovery::*;
use snarkvm_recovery_aerie::*;
use snarkvm_recovery_signatures::{Falcon512Verifier, MlDsa65Verifier};
use std::time::Instant;

struct NoLegacy;
impl LegacyVerifier for NoLegacy {
    fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<()> {
        Err(Error::Unsupported)
    }
}

#[test]
fn differential_exact_batch_and_fail_closed() -> Result<()> {
    let mut rng = ChaCha20Rng::from_seed([45; 32]);
    let mut private = vec![0; fn_dsa::sign_key_size(9)];
    let mut public = vec![0; fn_dsa::vrfy_key_size(9)];
    KeyPairGenerator512::default().keygen(9, &mut rng, &mut private, &mut public);
    let key = Key { profile: Profile::FALCON_512, bytes: public };
    let network = [1; 64];
    let source = Record {
        version: RecordVersion::V2,
        owner: Owner::Enrolled(key),
        amount: 100,
        nonce: [2; 64],
        opening: [3; 64],
    };
    let mut output = source.clone();
    output.version = RecordVersion::V3;
    output.amount = 99;
    output.nonce = [4; 64];
    let policy = Policy {
        preparation: Some(30),
        recovery: Some(40),
        aggregates: vec![AERIE_FALCON_512_V1],
        ..Policy::default()
    };
    let mut backends = Backends::default();
    backends.register_signature(Box::new(MlDsa65Verifier))?;
    backends.register_signature(Box::new(Falcon512Verifier))?;
    assert_eq!(
        Ledger::from_trusted_records(network, policy.clone(), vec![], &backends).err(),
        Some(Error::MissingBackend)
    );
    backends.register_aggregate(Box::new(AerieFalcon512))?;
    let policy_commitment = policy.commitment(&network);
    let mut ledger = Ledger::from_trusted_records(network, policy, vec![source.clone()], &backends)?;
    let effects = Effects {
        network,
        protocol: PROTOCOL_VERSION,
        policy: 1,
        policy_commitment,
        operation: Operation::Migrate,
        valid_from: 40,
        valid_until: 60,
        replay: [9; 64],
        inputs: vec![source.id(&network)],
        outputs: vec![output],
        fee: 1,
    };
    let expected = ledger.plan(40, &effects, &backends)?.signatures;
    let mut signer = SigningKey512::decode(&private).ok_or(Error::InvalidKey)?;
    let mut signatures = Vec::new();
    for statement in &expected {
        let mut signature = vec![0; fn_dsa::signature_size(9)];
        signer.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, statement.message(), &mut signature);
        signatures.push(signature);
    }
    let start = Instant::now();
    for (statement, signature) in expected.iter().zip(&signatures) {
        backends.verify(statement, signature)?;
    }
    let direct_time = start.elapsed();
    let start = Instant::now();
    let proof = produce(&expected, &signatures)?;
    let produce_time = start.elapsed();
    let start = Instant::now();
    AerieFalcon512.verify(&expected, &proof)?;
    let verify_time = start.elapsed();
    println!(
        "records={} direct_bytes={} aggregate_bytes={} direct_us={} produce_ms={} aggregate_verify_ms={}",
        expected.len(),
        signatures.iter().map(Vec::len).sum::<usize>(),
        proof.len(),
        direct_time.as_micros(),
        produce_time.as_millis(),
        verify_time.as_millis()
    );
    assert!(AerieFalcon512.verify(&expected[..1], &proof).is_err());
    assert!(AerieFalcon512.verify(&[expected[0].clone(), expected[0].clone()], &proof).is_err());
    let mut reversed = expected.clone();
    reversed.reverse();
    assert!(AerieFalcon512.verify(&reversed, &proof).is_err());
    let mut changed = effects.clone();
    changed.replay[0] ^= 1;
    let changed = ledger.plan(40, &changed, &backends)?.signatures;
    assert!(AerieFalcon512.verify(&changed, &proof).is_err());
    assert!(produce(&expected, &signatures[..1]).is_err());
    let mut wrong_sig = signatures.clone();
    wrong_sig[0][50] ^= 1;
    assert!(produce(&expected, &wrong_sig).is_err());
    let mut mutations = Vec::new();
    for offset in [0, 15, 16, 18, 19, 27, proof.len() - 1] {
        let mut bad = proof.clone();
        bad[offset] ^= 1;
        mutations.push(bad);
    }
    let mut common = proof.clone();
    common[15] = b'c';
    mutations.push(common);
    mutations.push(proof[..proof.len() - 1].to_vec());
    let mut trailing = proof.clone();
    trailing.push(0);
    mutations.push(trailing);
    for bad in mutations {
        assert!(AerieFalcon512.verify(&expected, &bad).is_err());
        let transaction = Transaction {
            effects: effects.clone(),
            legacy: vec![],
            authorization: Evidence::Aggregate { identifier: AERIE_FALCON_512_V1, proof: bad },
        };
        let before = ledger.clone();
        assert!(ledger.apply(40, &transaction, &NoLegacy, &backends).is_err());
        assert_eq!(ledger, before);
    }
    let mut direct = ledger.clone();
    direct.apply(
        40,
        &Transaction { effects: effects.clone(), legacy: vec![], authorization: Evidence::Direct(signatures) },
        &NoLegacy,
        &backends,
    )?;
    ledger.apply(
        40,
        &Transaction {
            effects,
            legacy: vec![],
            authorization: Evidence::Aggregate { identifier: AERIE_FALCON_512_V1, proof },
        },
        &NoLegacy,
        &backends,
    )?;
    assert_eq!(ledger, direct);
    Ok(())
}

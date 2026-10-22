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

use fn_dsa::{DOMAIN_NONE, HASH_ID_RAW, KeyPairGenerator, KeyPairGenerator512, SigningKey, SigningKey512};
use ml_dsa::{KeyExport, Keypair, MlDsa65, Signer};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use snarkvm_console_account::{Address, Field, PrivateKey, Signature, TestRng, ToBytes};
use snarkvm_console_network::MainnetV0;
use snarkvm_recovery::*;
use snarkvm_recovery_signatures::*;

const NETWORK: Digest64 = [41; 64];

enum SignerKey {
    Ml(ml_dsa::SigningKey<MlDsa65>),
    Falcon(Vec<u8>, Vec<u8>),
}

impl SignerKey {
    fn new(profile: Profile, seed: u8) -> Self {
        if profile == Profile::ML_DSA_65 {
            Self::Ml(ml_dsa::SigningKey::from_seed(&[seed; 32].into()))
        } else {
            let mut rng = ChaCha20Rng::from_seed([seed; 32]);
            let mut sk = vec![0; fn_dsa::sign_key_size(9)];
            let mut pk = vec![0; fn_dsa::vrfy_key_size(9)];
            KeyPairGenerator512::default().keygen(9, &mut rng, &mut sk, &mut pk);
            Self::Falcon(sk, pk)
        }
    }

    fn key(&self) -> Key {
        match self {
            Self::Ml(sk) => Key { profile: Profile::ML_DSA_65, bytes: sk.verifying_key().to_bytes().to_vec() },
            Self::Falcon(_, pk) => Key { profile: Profile::FALCON_512, bytes: pk.clone() },
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ml(sk) => {
                let signature: ml_dsa::Signature<MlDsa65> = sk.sign(message);
                Ok(signature.encode().to_vec())
            }
            Self::Falcon(sk, _) => {
                let mut signer = SigningKey512::decode(sk).ok_or(Error::InvalidKey)?;
                // Public deterministic fixtures are never production signing keys.
                let mut rng = ChaCha20Rng::from_seed([93; 32]);
                let mut signature = vec![0; fn_dsa::signature_size(9)];
                signer.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut signature);
                Ok(signature)
            }
        }
    }
}

fn backends() -> Result<Backends> {
    let mut result = Backends::default();
    result.register_signature(Box::new(MlDsa65Verifier))?;
    result.register_signature(Box::new(Falcon512Verifier))?;
    Ok(result)
}

fn policy() -> Policy {
    Policy { preparation: Some(30), recovery: Some(40), ..Policy::default() }
}

fn legacy_key() -> Result<PrivateKey<MainnetV0>> {
    PrivateKey::try_from(Field::from_u64(42)).map_err(|_| Error::InvalidKey)
}

fn source(version: RecordVersion) -> Result<Record> {
    let owner = Address::try_from(&legacy_key()?).map_err(|_| Error::InvalidKey)?;
    Ok(Record {
        version,
        owner: Owner::Legacy(owner.to_bytes_le().map_err(|_| Error::Encoding)?),
        amount: 100,
        nonce: [2; 64],
        opening: [3; 64],
    })
}

fn output(signer: &SignerKey, version: RecordVersion, amount: u64, nonce: u8) -> Record {
    Record { version, owner: Owner::Enrolled(signer.key()), amount, nonce: [nonce; 64], opening: [7; 64] }
}

fn effects(input: Digest64, record: Record, operation: Operation, replay: u8) -> Effects {
    Effects {
        network: NETWORK,
        protocol: PROTOCOL_VERSION,
        policy: 1,
        policy_commitment: policy().commitment(&NETWORK),
        operation,
        valid_from: 0,
        valid_until: 100,
        replay: [replay; 64],
        inputs: vec![input],
        outputs: vec![record],
        fee: 1,
    }
}

fn sign(
    ledger: &Ledger,
    height: u32,
    effects: Effects,
    keys: &[&SignerKey],
    backends: &Backends,
) -> Result<Transaction> {
    let plan = ledger.plan(height, &effects, backends)?;
    let mut legacy = Vec::new();
    let rng = &mut TestRng::fixed(4223);
    for statement in plan.legacy {
        legacy.push(
            Signature::sign_bytes(&legacy_key()?, &statement.message, rng)
                .map_err(|_| Error::InvalidSignature)?
                .to_bytes_le()
                .map_err(|_| Error::Encoding)?,
        );
    }
    let signatures = plan
        .signatures
        .iter()
        .map(|statement| {
            keys.iter().find(|key| key.key() == *statement.key()).ok_or(Error::InvalidKey)?.sign(statement.message())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Transaction { effects, legacy, authorization: Evidence::Direct(signatures) })
}

#[test]
fn shared_signature_conformance_and_binding() -> Result<()> {
    let backends = backends()?;
    let source = source(RecordVersion::V1)?;
    let ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![source.clone()], &backends)?;
    for profile in [Profile::ML_DSA_65, Profile::FALCON_512] {
        let signer = SignerKey::new(profile, 1);
        let wrong = SignerKey::new(profile, 2);
        let effects = effects(source.id(&NETWORK), output(&signer, RecordVersion::V2, 99, 4), Operation::Prepare, 1);
        let plan = ledger.plan(30, &effects, &backends)?;
        let statement = &plan.signatures[0];
        let signature = signer.sign(statement.message())?;
        backends.verify(statement, &signature)?;
        let other_network = [42; 64];
        let other_ledger = Ledger::from_trusted_records(other_network, policy(), vec![source.clone()], &backends)?;
        let mut cross_chain = effects.clone();
        cross_chain.network = other_network;
        cross_chain.policy_commitment = policy().commitment(&other_network);
        cross_chain.inputs = vec![source.id(&other_network)];
        let other_plan = other_ledger.plan(30, &cross_chain, &backends)?;
        assert!(backends.verify(&other_plan.signatures[0], &signature).is_err());
        assert!(backends.verify(statement, &wrong.sign(statement.message())?).is_err());
        let mut damaged = signature.clone();
        damaged[60] ^= 1;
        assert!(backends.verify(statement, &damaged).is_err());
        assert!(backends.verify(statement, &signature[..signature.len() - 1]).is_err());
        let mut long = signature.clone();
        long.push(0);
        assert!(backends.verify(statement, &long).is_err());
        let mut mutations = Vec::new();
        let mut changed = effects.clone();
        changed.fee += 1;
        changed.outputs[0].amount -= 1;
        mutations.push(changed);
        let mut changed = effects.clone();
        changed.replay[0] ^= 1;
        mutations.push(changed);
        let mut changed = effects.clone();
        changed.valid_until -= 1;
        mutations.push(changed);
        let mut changed = effects.clone();
        changed.outputs[0].nonce[0] ^= 1;
        mutations.push(changed);
        let mut changed = effects.clone();
        changed.outputs[0].opening[0] ^= 1;
        mutations.push(changed);
        let mut changed = effects.clone();
        changed.outputs[0].owner = Owner::Enrolled(wrong.key());
        mutations.push(changed);
        for changed in mutations {
            let plan = ledger.plan(30, &changed, &backends)?;
            assert!(backends.verify(&plan.signatures[0], &signature).is_err());
        }
    }
    Ok(())
}

#[test]
fn two_stage_rotation_persistence_atomicity_and_substitutability() -> Result<()> {
    let backends = backends()?;
    let legacy = AleoLegacy::<MainnetV0>::default();
    for version in [RecordVersion::V0, RecordVersion::V1] {
        for first in [Profile::ML_DSA_65, Profile::FALCON_512] {
            let signer = SignerKey::new(first, 5);
            let second = Profile::ML_DSA_65;
            let replacement = SignerKey::new(second, 6);
            let source = source(version)?;
            let mut ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![source.clone()], &backends)?;
            let prepared = output(&signer, RecordVersion::V2, 99, 4);
            let prepare = effects(source.id(&NETWORK), prepared.clone(), Operation::Prepare, 1);
            assert!(ledger.plan(29, &prepare, &backends).is_err());
            assert!(ledger.plan(40, &prepare, &backends).is_err());
            let prepare = sign(&ledger, 30, prepare, &[&signer], &backends)?;
            let before = ledger.clone();
            let mut forged = prepare.clone();
            forged.legacy[0][0] ^= 1;
            assert!(ledger.apply(30, &forged, &legacy, &backends).is_err());
            assert_eq!(ledger, before);
            ledger.apply(30, &prepare, &legacy, &backends)?;
            assert!(ledger.unspent(&source.id(&NETWORK)).is_none());
            assert!(ledger.apply(31, &prepare, &legacy, &backends).is_err());
            let rotated = output(&replacement, RecordVersion::V2, 98, 5);
            let rotate = sign(
                &ledger,
                39,
                effects(prepared.id(&NETWORK), rotated.clone(), Operation::Rotate, 2),
                &[&signer, &replacement],
                &backends,
            )?;
            ledger.apply(39, &rotate, &legacy, &backends)?;
            let migrated = output(&replacement, RecordVersion::V3, 97, 6);
            let migration = effects(rotated.id(&NETWORK), migrated.clone(), Operation::Migrate, 3);
            assert!(ledger.plan(39, &migration, &backends).is_err());
            let migration = sign(&ledger, 40, migration, &[&replacement], &backends)?;
            let checkpoint = ledger.checkpoint();
            let mut restored = Ledger::restore(NETWORK, policy(), &checkpoint, &backends)?;
            ledger.apply(40, &migration, &legacy, &backends)?;
            restored.apply(40, &migration, &legacy, &backends)?;
            assert_eq!(ledger, restored);
            assert!(ledger.apply(41, &migration, &legacy, &backends).is_err());
            let spent = output(&replacement, RecordVersion::V3, 96, 7);
            let spend = sign(
                &ledger,
                41,
                effects(migrated.id(&NETWORK), spent, Operation::Spend, 4),
                &[&replacement],
                &backends,
            )?;
            let before = ledger.clone();
            assert!(ledger.apply_candidate(41, &[spend.clone(), spend.clone()], &legacy, &backends).is_err());
            assert_eq!(before, ledger);
            ledger.apply(41, &spend, &legacy, &backends)?;
            assert_eq!(ledger.fees(), 4);
            assert_ne!(
                ledger.nullifier(&migrated.id(&NETWORK)),
                Ledger::from_trusted_records([42; 64], policy(), vec![], &backends)?.nullifier(&migrated.id(&NETWORK))
            );
        }
    }
    Ok(())
}

#[test]
fn substitutions_downgrades_malformed_and_missing_backends() -> Result<()> {
    let backends = backends()?;
    let signer = SignerKey::new(Profile::ML_DSA_65, 7);
    let source = source(RecordVersion::V1)?;
    let ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![source.clone()], &backends)?;
    let good = effects(source.id(&NETWORK), output(&signer, RecordVersion::V2, 99, 5), Operation::Prepare, 1);
    let bytes = good.encode()?;
    assert_eq!(Effects::decode(&bytes)?, good);
    for i in 0..bytes.len() {
        assert!(Effects::decode(&bytes[..i]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Effects::decode(&trailing).is_err());
    let mut bad = good.clone();
    bad.network[0] ^= 1;
    assert!(ledger.plan(30, &bad, &backends).is_err());
    let mut bad = good.clone();
    bad.protocol += 1;
    assert!(ledger.plan(30, &bad, &backends).is_err());
    let mut bad = good.clone();
    bad.policy += 1;
    assert!(ledger.plan(30, &bad, &backends).is_err());
    let mut bad = good.clone();
    bad.inputs.push(source.id(&NETWORK));
    assert!(ledger.plan(30, &bad, &backends).is_err());
    let mut bad = good.clone();
    bad.outputs[0].amount += 1;
    assert_eq!(ledger.plan(30, &bad, &backends).err(), Some(Error::Conservation));
    let mut bad = good.clone();
    bad.outputs[0].version = RecordVersion::V1;
    assert!(bad.encode().is_err());
    let mut bad = good.clone();
    if let Owner::Enrolled(key) = &mut bad.outputs[0].owner {
        key.profile.parameters = 2;
    }
    assert!(bad.encode().is_err());
    assert_eq!(
        Ledger::from_trusted_records(NETWORK, policy(), vec![], &Backends::default()).err(),
        Some(Error::MissingBackend)
    );
    let disabled = Policy { profiles: vec![Profile::ML_DSA_65], ..Policy::default() };
    let dormant = Ledger::from_trusted_records(NETWORK, disabled, vec![source], &backends)?;
    assert!(dormant.plan(u32::MAX, &good, &backends).is_err());
    let mut checkpoint = ledger.checkpoint();
    checkpoint.push(0);
    assert!(Ledger::restore(NETWORK, policy(), &checkpoint, &backends).is_err());
    Ok(())
}

proptest! {
    #[test]
    fn canonical_decoder_never_accepts_noncanonical(bytes in prop::collection::vec(any::<u8>(), 0..45_000)) {
        if let Ok(effects) = Effects::decode(&bytes) { prop_assert_eq!(effects.encode().expect("decoded effects are valid"), bytes); }
    }

    #[test]
    fn framed_hash_is_unambiguous(a in prop::collection::vec(any::<u8>(), 1..100), b in prop::collection::vec(any::<u8>(), 1..100)) {
        let mut joined = a.clone(); joined.extend_from_slice(&b);
        prop_assert_ne!(digest(b"d", &[&a, &b]), digest(b"d", &[&joined]));
    }
}

#[test]
fn independent_nist_ml_dsa65_vector() -> Result<()> {
    let pk = include_bytes!("vectors/nist-44-pk.bin");
    let message = include_bytes!("vectors/nist-44-message.bin");
    let signature = include_bytes!("vectors/nist-44-signature.bin");
    MlDsa65Verifier.verify(pk, message, signature)?;
    let mut wrong = *message;
    wrong[0] ^= 1;
    assert!(MlDsa65Verifier.verify(pk, &wrong, signature).is_err());
    Ok(())
}

#[test]
fn independent_canonical_statement_vector() -> Result<()> {
    let backends = backends()?;
    let source = Record {
        version: RecordVersion::V1,
        owner: Owner::Legacy(vec![42; 32]),
        amount: 100,
        nonce: [2; 64],
        opening: [3; 64],
    };
    let ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![source.clone()], &backends)?;
    let expected = Effects::decode(include_bytes!("vectors/canonical-effects.bin"))?;
    assert_eq!(expected.inputs, vec![source.id(&NETWORK)]);
    let plan = ledger.plan(30, &expected, &backends)?;
    assert_eq!(plan.signatures[0].message(), include_bytes!("vectors/canonical-statement.bin"));
    let Owner::Enrolled(key) = &expected.outputs[0].owner else {
        return Err(Error::Ownership);
    };
    let mut digests = source.id(&NETWORK).to_vec();
    digests.extend(key.identity(&NETWORK));
    digests.extend(expected.id()?);
    assert_eq!(digests, include_bytes!("vectors/canonical-digests.bin"));
    Ok(())
}

#[test]
fn rotation_downgrade_and_key_substitution_require_authority() -> Result<()> {
    let backends = backends()?;
    let signer = SignerKey::new(Profile::ML_DSA_65, 20);
    let attacker = SignerKey::new(Profile::ML_DSA_65, 21);
    let weaker = SignerKey::new(Profile::FALCON_512, 22);
    let source = output(&signer, RecordVersion::V2, 100, 2);
    let mut ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![source.clone()], &backends)?;
    let downgrade = effects(source.id(&NETWORK), output(&weaker, RecordVersion::V2, 99, 3), Operation::Rotate, 1);
    assert_eq!(ledger.plan(39, &downgrade, &backends).err(), Some(Error::Policy));
    let v3 = output(&signer, RecordVersion::V3, 100, 9);
    let v3_ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![v3.clone()], &backends)?;
    let downgrade_spend = effects(v3.id(&NETWORK), output(&weaker, RecordVersion::V3, 99, 10), Operation::Spend, 9);
    assert_eq!(v3_ledger.plan(40, &downgrade_spend, &backends).err(), Some(Error::Policy));
    let substitution = effects(source.id(&NETWORK), output(&attacker, RecordVersion::V3, 99, 3), Operation::Migrate, 1);
    assert_eq!(ledger.plan(40, &substitution, &backends).err(), Some(Error::Ownership));
    let rotate = effects(source.id(&NETWORK), output(&attacker, RecordVersion::V2, 99, 3), Operation::Rotate, 1);
    let plan = ledger.plan(39, &rotate, &backends)?;
    let forged = Transaction {
        effects: rotate.clone(),
        legacy: vec![],
        authorization: Evidence::Direct(
            plan.signatures.iter().map(|s| attacker.sign(s.message())).collect::<Result<Vec<_>>>()?,
        ),
    };
    let before = ledger.clone();
    assert!(ledger.apply(39, &forged, &AleoLegacy::<MainnetV0>::default(), &backends).is_err());
    assert_eq!(ledger, before);
    let mut valid = sign(&ledger, 39, rotate, &[&signer, &attacker], &backends)?;
    let Evidence::Direct(signatures) = &mut valid.authorization else {
        return Err(Error::Unsupported);
    };
    signatures.reverse();
    assert!(ledger.apply(39, &valid, &AleoLegacy::<MainnetV0>::default(), &backends).is_err());
    Ok(())
}

#[test]
fn independent_activation_model_and_cross_policy_replay() -> Result<()> {
    let backends = backends()?;
    let signer = SignerKey::new(Profile::ML_DSA_65, 30);
    for version in [RecordVersion::V0, RecordVersion::V1, RecordVersion::V2, RecordVersion::V3] {
        let source = if matches!(version, RecordVersion::V0 | RecordVersion::V1) {
            source(version)?
        } else {
            output(&signer, version, 100, 2)
        };
        let ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![source.clone()], &backends)?;
        for height in [0, 29, 30, 31, 39, 40, 41, 100] {
            for operation in [Operation::Prepare, Operation::Migrate, Operation::Spend, Operation::Rotate] {
                // This table is independent of the implementation's phase match.
                let allowed = match operation {
                    Operation::Prepare => {
                        (30..40).contains(&height) && matches!(version, RecordVersion::V0 | RecordVersion::V1)
                    }
                    Operation::Migrate => height >= 40 && version == RecordVersion::V2,
                    Operation::Spend => height >= 40 && version == RecordVersion::V3,
                    Operation::Rotate => {
                        ((30..40).contains(&height) && version == RecordVersion::V2)
                            || (height >= 40 && version == RecordVersion::V3)
                    }
                };
                let target = match operation {
                    Operation::Prepare => RecordVersion::V2,
                    Operation::Migrate | Operation::Spend => RecordVersion::V3,
                    Operation::Rotate => {
                        if height < 40 {
                            RecordVersion::V2
                        } else {
                            RecordVersion::V3
                        }
                    }
                };
                let effects = effects(source.id(&NETWORK), output(&signer, target, 99, 3), operation, 1);
                assert_eq!(
                    ledger.plan(height, &effects, &backends).is_ok(),
                    allowed,
                    "{height} {version:?} {operation:?}"
                );
            }
        }
    }
    let source = source(RecordVersion::V1)?;
    let other_policy = Policy { preparation: Some(31), ..policy() };
    let ledger = Ledger::from_trusted_records(NETWORK, other_policy, vec![source.clone()], &backends)?;
    let effects = effects(source.id(&NETWORK), output(&signer, RecordVersion::V2, 99, 3), Operation::Prepare, 1);
    assert_eq!(ledger.plan(39, &effects, &backends).err(), Some(Error::Policy));
    Ok(())
}

#[test]
fn direct_backend_cost_sample() -> Result<()> {
    use std::time::Instant;
    let backends = backends()?;
    let source = source(RecordVersion::V1)?;
    let ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![source.clone()], &backends)?;
    for profile in [Profile::ML_DSA_65, Profile::FALCON_512] {
        let signer = SignerKey::new(profile, 31);
        let effects = effects(source.id(&NETWORK), output(&signer, RecordVersion::V2, 99, 4), Operation::Prepare, 1);
        let plan = ledger.plan(30, &effects, &backends)?;
        let statement = &plan.signatures[0];
        let signature = signer.sign(statement.message())?;
        let start = Instant::now();
        for _ in 0..100 {
            backends.verify(statement, &signature)?;
        }
        println!(
            "profile={profile:?} public_key_bytes={} signature_bytes={} message_bytes={} mean_verify_us={}",
            signer.key().bytes.len(),
            signature.len(),
            statement.message().len(),
            start.elapsed().as_micros() / 100
        );
    }
    Ok(())
}

#[test]
fn signing_profile_context_and_framing_are_not_interchangeable() -> Result<()> {
    let message = b"AleoRecoveryAuthorization1 fixed test message";
    let ml = ml_dsa::SigningKey::<MlDsa65>::from_seed(&[35; 32].into());
    let wrong_context =
        ml.expanded_key().sign_deterministic(message, b"other-protocol").map_err(|_| Error::InvalidSignature)?;
    assert!(MlDsa65Verifier.verify(&ml.verifying_key().to_bytes(), message, &wrong_context.encode()).is_err());
    let falcon = SignerKey::new(Profile::FALCON_512, 36);
    let SignerKey::Falcon(private, public) = falcon else {
        return Err(Error::Unsupported);
    };
    let mut sk = SigningKey512::decode(&private).ok_or(Error::InvalidKey)?;
    let mut rng = ChaCha20Rng::from_seed([37; 32]);
    for (context, framing) in
        [(fn_dsa::DomainContext(b"other"), HASH_ID_RAW), (DOMAIN_NONE, fn_dsa::HASH_ID_ORIGINAL_FALCON)]
    {
        let mut signature = vec![0; 666];
        sk.sign(&mut rng, &context, &framing, message, &mut signature);
        assert!(Falcon512Verifier.verify(&public, message, &signature).is_err());
    }
    Ok(())
}

#[test]
fn copied_replay_nonce_cannot_block_an_unrelated_owner_transaction() -> Result<()> {
    let backends = backends()?;
    let signer = SignerKey::new(Profile::ML_DSA_65, 38);
    let first = source(RecordVersion::V1)?;
    let other_key = PrivateKey::<MainnetV0>::try_from(Field::from_u64(43)).map_err(|_| Error::InvalidKey)?;
    let other_owner =
        Address::try_from(&other_key).map_err(|_| Error::InvalidKey)?.to_bytes_le().map_err(|_| Error::Encoding)?;
    let mut second = first.clone();
    second.nonce = [8; 64];
    second.owner = Owner::Legacy(other_owner);
    let other_signer = SignerKey::new(Profile::ML_DSA_65, 39);
    let mut ledger = Ledger::from_trusted_records(NETWORK, policy(), vec![first.clone(), second.clone()], &backends)?;
    let a = sign(
        &ledger,
        30,
        effects(first.id(&NETWORK), output(&signer, RecordVersion::V2, 99, 4), Operation::Prepare, 1),
        &[&signer],
        &backends,
    )?;
    let b_effects =
        effects(second.id(&NETWORK), output(&other_signer, RecordVersion::V2, 99, 5), Operation::Prepare, 1);
    let plan = ledger.plan(30, &b_effects, &backends)?;
    let signature = Signature::sign_bytes(&other_key, &plan.legacy[0].message, &mut TestRng::fixed(4224))
        .map_err(|_| Error::InvalidSignature)?
        .to_bytes_le()
        .map_err(|_| Error::Encoding)?;
    let b = Transaction {
        effects: b_effects,
        legacy: vec![signature],
        authorization: Evidence::Direct(
            plan.signatures.iter().map(|s| other_signer.sign(s.message())).collect::<Result<Vec<_>>>()?,
        ),
    };
    ledger.apply(30, &a, &AleoLegacy::<MainnetV0>::default(), &backends)?;
    ledger.apply(30, &b, &AleoLegacy::<MainnetV0>::default(), &backends)?;
    assert_eq!(ledger.fees(), 2);
    Ok(())
}

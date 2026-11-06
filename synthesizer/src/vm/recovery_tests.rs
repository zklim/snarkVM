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

//! Production transaction tests under an explicitly isolated local schedule.
//! These exercise a genuine credits execution and native finalized recovery;
//! they do not claim that a beacon test chain has quantum-safe consensus.

use super::{test_helpers::*, *};
use console::{
    account::{Signature, ViewKey},
    types::Scalar,
};
use ml_dsa::{KeyExport, Keypair, MlDsa65, Signer};
use snarkvm_ledger_block::Recovery;
use snarkvm_recovery::{self as core, Backends, Effects, Evidence, Key, Operation, Owner, Profile, RecordVersion};
use snarkvm_recovery_records::PreparationSource;
use snarkvm_recovery_signatures::{Falcon512Verifier, MlDsa65Verifier};

type N = CurrentNetwork;
type TestVm = VM<N, LedgerType>;
type LegacyOpening = (PrivateKey<N>, Record<N, Plaintext<N>>, Field<N>, Field<N>);

const LOCAL_SCHEDULE: &str = "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,30,40";
const FEE: u64 = 100_000;

fn backends() -> Result<Backends> {
    let mut result = Backends::default();
    result.register_signature(Box::new(MlDsa65Verifier))?;
    result.register_signature(Box::new(Falcon512Verifier))?;
    Ok(result)
}

fn enrolled_key(signing: &ml_dsa::SigningKey<MlDsa65>) -> Key {
    Key { profile: Profile::ML_DSA_65, bytes: signing.verifying_key().to_bytes().to_vec() }
}

fn ledger(vm: &TestVm) -> Result<core::Ledger> {
    Ok(core::Ledger::restore(vm.recovery_network()?, vm.recovery_policy()?, &vm.recovery_checkpoint()?, &backends()?)?)
}

/// A wallet-side construction helper. Production verification independently
/// reconstructs the source, plan and expected effects from authenticated state.
#[allow(clippy::too_many_arguments)]
fn transaction(
    vm: &TestVm,
    operation: Operation,
    input: core::Record,
    version: RecordVersion,
    height: u32,
    nonce: u8,
    signing: &ml_dsa::SigningKey<MlDsa65>,
    opening: Option<LegacyOpening>,
    rng: &mut TestRng,
) -> Result<Transaction<N>> {
    let mut ledger = ledger(vm)?;
    if opening.is_some() {
        ledger.import_verified_source(input.clone(), &backends()?)?;
    }
    transaction_in_state(vm, operation, input, version, height, nonce, signing, opening, rng, &ledger)
}

#[allow(clippy::too_many_arguments)]
fn transaction_in_state(
    vm: &TestVm,
    operation: Operation,
    input: core::Record,
    version: RecordVersion,
    height: u32,
    nonce: u8,
    signing: &ml_dsa::SigningKey<MlDsa65>,
    opening: Option<LegacyOpening>,
    rng: &mut TestRng,
    ledger: &core::Ledger,
) -> Result<Transaction<N>> {
    let network = vm.recovery_network()?;
    let key = enrolled_key(signing);
    let output_amount = input.amount.checked_sub(FEE).ok_or_else(|| anyhow!("Test source is below fee"))?;
    let output = core::Record {
        version,
        owner: Owner::Enrolled(key.clone()),
        amount: output_amount,
        nonce: [nonce; 64],
        opening: core::digest(b"AleoDisclosedCreditsOutput1", &[
            &network,
            &[nonce; 64],
            &output_amount.to_le_bytes(),
            &key.identity(&network),
        ]),
    };
    let effects = Effects {
        network,
        protocol: core::PROTOCOL_VERSION,
        policy: 1,
        policy_commitment: vm.recovery_policy()?.commitment(&network),
        operation,
        valid_from: height,
        valid_until: 60,
        replay: [nonce; 64],
        inputs: vec![input.id(&network)],
        outputs: vec![output],
        fee: FEE,
    };
    let plan = ledger.plan(height, &effects, &backends()?)?;
    let mut sources = vec![];
    let mut legacy = vec![];
    if let Some((account, record, rvk, commitment)) = opening {
        ensure!(plan.legacy.len() == 1, "Test preparation requires one legacy statement");
        let message = &plan.legacy[0].message;
        sources.push(PreparationSource::create(&account, record, rvk, commitment, &network, message, rng)?);
        // Continue the same CSPRNG stream: never reuse the DLEQ nonce in a signature.
        legacy.push(Signature::sign_bytes(&account, message, rng)?.to_bytes_le()?);
    }
    let signatures = plan
        .signatures
        .iter()
        .map(|statement| {
            ensure!(*statement.key() == key, "Test signer does not match core statement");
            let signature: ml_dsa::Signature<MlDsa65> = signing.sign(statement.message());
            Ok(signature.encode().to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    Transaction::from_recovery(Recovery::new(
        core::Transaction { effects, legacy, authorization: Evidence::Direct(signatures) },
        sources,
    )?)
}

fn replacement(transaction: &Transaction<N>) -> core::Record {
    transaction.recovery().expect("Fixture is a native recovery transaction").transaction().effects.outputs[0].clone()
}

fn with_changed_core(
    transaction: &Transaction<N>,
    change: impl FnOnce(&mut core::Transaction),
) -> Result<Transaction<N>> {
    let envelope = transaction.recovery().ok_or_else(|| anyhow!("Expected native recovery"))?;
    let mut transaction = envelope.transaction().clone();
    change(&mut transaction);
    Transaction::from_recovery(Recovery::new(transaction, envelope.sources().to_vec())?)
}

#[test]
fn pinned_historical_v0_genesis_is_authenticated_by_current_vm() -> Result<()> {
    use console::network::TestnetV0;
    use snarkvm_ledger_store::helpers::memory::ConsensusMemory;

    type HistoricalVm = VM<TestnetV0, ConsensusMemory<TestnetV0>>;
    let (bytes, record_bytes, view_key_bytes, expected_hash): (&[u8], &[u8], &[u8], &str) =
        match TestnetV0::GENESIS_COINBASE_TARGET {
            31 => (
                include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-dev-genesis/genesis.bin"),
                include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-dev-genesis/record-0.bin"),
                include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-dev-genesis/record-view-key-0.bin"),
                "ab1njne0yg0ygw9kwyldxw942syzvhvx7gjdp87nadermkt45w4x5ps88sgkx",
            ),
            536_870_911 => (
                include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-genesis/genesis.bin"),
                include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-genesis/record-0.bin"),
                include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-genesis/record-view-key-0.bin"),
                "ab1nnulyh65kyndy2e0n4p79hg9sc0llzv4yy4d2apnpfzktc8wjgxs0s63gr",
            ),
            target => bail!("No pinned historical genesis fixture for coinbase target {target}"),
        };
    let genesis = Block::<TestnetV0>::from_bytes_le(bytes)?;
    assert_eq!(genesis.to_bytes_le()?, bytes);
    assert!(genesis.is_genesis()?);
    assert_eq!(genesis.height(), 0);
    assert_eq!(genesis.hash().to_string(), expected_hash);
    assert_eq!(genesis.coinbase_target(), TestnetV0::GENESIS_COINBASE_TARGET);
    assert_eq!(genesis.last_coinbase_target(), TestnetV0::GENESIS_COINBASE_TARGET);
    assert_eq!(genesis.proof_target(), TestnetV0::GENESIS_PROOF_TARGET);
    let vm = HistoricalVm::from(ConsensusStore::open(aleo_std::StorageMode::new_test(None))?)?;
    vm.add_next_block(&genesis)?;
    assert_eq!(vm.block_store().get_block(&genesis.hash())?, Some(genesis.clone()));
    let (commitment, _) = genesis.records().next().ok_or_else(|| anyhow!("Historical genesis has no records"))?;
    let record = Record::<TestnetV0, Plaintext<TestnetV0>>::from_bytes_le(record_bytes)?;
    let rvk = Field::<TestnetV0>::from_bytes_le(view_key_bytes)?;
    assert_eq!(**record.version(), 0);
    let source = PreparationSource::record_from_opening(&vm.recovery_network()?, &record, rvk, *commitment)?;
    assert_eq!(source.version, RecordVersion::V0);
    assert_eq!(source.amount, 1_000_000_000);
    let transition_id = vm.transition_store().find_transition_id(commitment)?;
    let transaction_id = vm
        .transaction_store()
        .find_transaction_id_from_transition_id(&transition_id)?
        .ok_or_else(|| anyhow!("Historical transaction was not authenticated"))?;
    assert_eq!(vm.block_store().find_block_hash(&transaction_id)?, Some(genesis.hash()));
    assert_eq!(vm.historical_source_height(commitment)?, 0);
    println!(
        "RECOVERY_HISTORICAL_V0 genesis={} coinbase_target={} proof_target={} commitment={commitment}",
        genesis.hash(),
        genesis.coinbase_target(),
        genesis.proof_target()
    );
    Ok(())
}

#[test]
fn historical_source_requires_confirmed_creation_not_an_aborted_index() -> Result<()> {
    use console::network::TestnetV0;
    use snarkvm_ledger_store::helpers::memory::ConsensusMemory;

    type HistoricalVm = VM<TestnetV0, ConsensusMemory<TestnetV0>>;
    let bytes: &[u8] = match TestnetV0::GENESIS_COINBASE_TARGET {
        31 => include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-dev-genesis/genesis.bin"),
        536_870_911 => include_bytes!("../../../recovery/history-tools/fixtures/v0-testnet-genesis/genesis.bin"),
        target => bail!("No pinned historical genesis fixture for coinbase target {target}"),
    };
    let genesis = Block::<TestnetV0>::from_bytes_le(bytes)?;
    let confirmed = genesis.transactions().iter().next().ok_or_else(|| anyhow!("Fixture has no transactions"))?;
    let transaction = confirmed.transaction();
    let (commitment, _) = transaction.records().next().ok_or_else(|| anyhow!("Fixture has no records"))?;
    let vm = HistoricalVm::from(ConsensusStore::open(aleo_std::StorageMode::new_test(None))?)?;

    // The public transaction-store API also supports unconfirmed archives.
    vm.transaction_store().insert(transaction)?;
    assert!(vm.transition_store().find_transition_id(commitment).is_ok());
    assert!(vm.historical_source_height(commitment).is_err());

    // Model a stored aborted transaction without running candidate consensus.
    // Its block index authenticates the abortion, not its uncommitted outputs.
    let aborted_block = Block::from_unchecked(
        genesis.hash(),
        genesis.previous_hash(),
        *genesis.header(),
        genesis.authority().clone(),
        genesis.ratifications().clone(),
        genesis.solutions().clone(),
        genesis.aborted_solution_ids().clone(),
        Transactions::from_iter(std::iter::empty::<ConfirmedTransaction<TestnetV0>>()),
        vec![transaction.id()],
    )?;
    vm.block_store().insert(&aborted_block)?;
    assert_eq!(vm.block_store().find_block_hash(&transaction.id())?, Some(aborted_block.hash()));
    assert!(vm.transaction_store().get_transaction(&transaction.id())?.is_some());
    assert!(vm.historical_source_height(commitment).is_err());
    Ok(())
}

#[test]
#[ignore = "requires isolated CONSENSUS_VERSION_HEIGHTS=0,1,...,21,30,40 and native credits proving parameters"]
fn production_credits_preparation_migration_spending_and_exclusion() -> Result<()> {
    ensure!(std::env::var("CONSENSUS_VERSION_HEIGHTS")? == LOCAL_SCHEDULE, "Run in an isolated local schedule");
    let start = std::time::Instant::now();
    let rng = &mut TestRng::fixed(90210);
    let account = sample_genesis_private_key(rng);
    let view_key = ViewKey::try_from(&account)?;
    let genesis = sample_genesis_block(rng);
    let mut vm = sample_vm_with_genesis_block(rng);
    let (_, ciphertext) = genesis.records().next().ok_or_else(|| anyhow!("Genesis has no private credits"))?;
    let original = ciphertext.decrypt(&view_key)?;

    // Generate a real, inclusion-proven credits source before retirement. Native
    // test processing creates V1 outputs; no plaintext-only source is imported.
    let split = vm.execute(
        &account,
        ("credits.aleo", "split"),
        [Value::Record(original), Value::from_str("1000000000u64")?].iter(),
        None,
        0,
        None,
        rng,
    )?;
    let split_block = sample_next_block(&vm, &account, &[split], rng)?;
    ensure!(split_block.transactions().len() == 1, "Historical split was not accepted");
    vm.add_next_block(&split_block)?;
    let (commitment, ciphertext) =
        split_block.records().next().ok_or_else(|| anyhow!("Split has no credits output"))?;
    let commitment = *commitment;
    let record = ciphertext.decrypt(&view_key)?;
    assert_eq!(**record.version(), 1);
    let rvk = (*record.nonce() * *view_key).to_x_coordinate();
    let native_serial = Record::<N, Plaintext<N>>::serial_number(account, commitment)?;
    let network = vm.recovery_network()?;
    let source = PreparationSource::record_from_opening(&network, &record, rvk, commitment)?;
    assert_eq!(source.amount, 1_000_000_000);
    assert!(!vm.contains_serial_number(&native_serial)?);

    // Retain a genuine old spend before H1. Even a party with the original
    // legacy account key cannot submit this alternate path after preparation.
    let legacy_competitor = vm.execute(
        &account,
        ("credits.aleo", "split"),
        [Value::Record(record.clone()), Value::from_str("1000000u64")?].iter(),
        None,
        0,
        None,
        rng,
    )?;
    // Fixed public test seeds are fixture material, never production key generation.
    let signing = ml_dsa::SigningKey::<MlDsa65>::from_seed(&[79; 32].into());
    let attacker = ml_dsa::SigningKey::<MlDsa65>::from_seed(&[80; 32].into());
    let opening = (account, record, rvk, commitment);
    let prepare = transaction(
        &vm,
        Operation::Prepare,
        source.clone(),
        RecordVersion::V2,
        30,
        1,
        &signing,
        Some(opening.clone()),
        rng,
    )?;
    let competing_prepare =
        transaction(&vm, Operation::Prepare, source, RecordVersion::V2, 30, 2, &signing, Some(opening), rng)?;
    assert!(
        vm.check_native_recovery(29, prepare.recovery().expect("Fixture is a native recovery transaction")).is_err()
    );
    advance_vm_to_height(&mut vm, account, 29, rng);
    let verification_start = std::time::Instant::now();
    vm.check_transaction(&prepare, None, rng)?;
    let prepare_admission_us = verification_start.elapsed().as_micros();
    vm.check_transaction(&competing_prepare, None, rng)?;

    // Reuse the exact credits inclusion-upgrade pool in a discarded candidate.
    // The genuine source fits at the boundary and fails one microcredit beyond.
    vm.finalize_store().start_atomic();
    let pool_key = Plaintext::from_str("aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc")?;
    vm.finalize_store().update_key_value(
        ProgramID::credits(),
        Identifier::from_str("pool")?,
        pool_key.clone(),
        Value::from_str("3999000000000u64")?,
    )?;
    vm.check_transaction(&prepare, None, rng)?;
    vm.finalize_store().update_key_value(
        ProgramID::credits(),
        Identifier::from_str("pool")?,
        pool_key,
        Value::from_str("3999000000001u64")?,
    )?;
    assert!(vm.check_transaction(&prepare, None, rng).is_err());
    vm.finalize_store().abort_atomic();
    vm.check_transaction(&prepare, None, rng)?;

    let root_before = vm.recovery_root()?;
    let changed = with_changed_core(&prepare, |tx| {
        tx.effects.outputs[0].amount -= 1;
        tx.effects.fee += 1;
    })?;
    assert!(vm.check_transaction(&changed, None, rng).is_err());
    let changed = with_changed_core(&prepare, |tx| {
        tx.effects.outputs[0].owner = Owner::Enrolled(enrolled_key(&attacker));
    })?;
    assert!(vm.check_transaction(&changed, None, rng).is_err());
    let changed = with_changed_core(&prepare, |tx| tx.effects.network[0] ^= 1)?;
    assert!(vm.check_transaction(&changed, None, rng).is_err());
    let changed = with_changed_core(&prepare, |tx| tx.effects.replay[0] ^= 1)?;
    assert!(vm.check_transaction(&changed, None, rng).is_err());
    // A disclosed opening cannot authorize a different source serial, even
    // when the attacker copies the source data and owner signature verbatim.
    let mut sources = prepare.recovery().expect("Fixture is a native recovery transaction").sources().to_vec();
    sources[0].gamma += N::g_scalar_multiply(&Scalar::one());
    let forged_serial = Transaction::from_recovery(Recovery::new(
        prepare.recovery().expect("Fixture is a native recovery transaction").transaction().clone(),
        sources,
    )?)?;
    assert!(vm.check_transaction(&forged_serial, None, rng).is_err());
    assert_eq!(vm.recovery_root()?, root_before);

    let block = sample_next_block(&vm, &account, &[prepare.clone(), competing_prepare.clone()], rng)?;
    assert_eq!(block.height(), 30);
    assert_eq!(block.transactions().len(), 1, "Competing preparations must consume the source exactly once");
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;
    assert!(vm.contains_serial_number(&native_serial)?);
    assert!(vm.check_transaction(&prepare, None, rng).is_err());
    assert!(vm.check_transaction(&competing_prepare, None, rng).is_err());
    assert!(vm.check_transaction(&legacy_competitor, None, rng).is_err());
    let prepared = block.transactions().iter().next().expect("Expected one accepted recovery").transaction();
    let v2 = replacement(prepared);
    assert_eq!(ledger(&vm)?.unspent(&v2.id(&network)), Some(&v2));
    assert_eq!(ledger(&vm)?.fees(), u128::from(FEE));
    assert_eq!(vm.transaction_store().get_transaction(&prepared.id())?, Some(prepared.clone()));

    let migrate = transaction(&vm, Operation::Migrate, v2.clone(), RecordVersion::V3, 40, 3, &signing, None, rng)?;
    assert!(
        vm.check_native_recovery(39, migrate.recovery().expect("Fixture is a native recovery transaction")).is_err()
    );
    // Preparation authority is permanently retired at H2, including a valid
    // legacy signature made while the account secret was still available.
    assert!(
        vm.check_native_recovery(40, competing_prepare.recovery().expect("Fixture is a native recovery transaction"))
            .is_err()
    );
    advance_vm_to_height(&mut vm, account, 39, rng);
    let verification_start = std::time::Instant::now();
    vm.check_transaction(&migrate, None, rng)?;
    let migration_admission_us = verification_start.elapsed().as_micros();
    // Simulate complete compromise of the legacy account authorization: the
    // adversary can sign each exact current statement with the original key.
    // Those signatures confer no authority over the enrolled post-quantum key.
    let migration_plan = ledger(&vm)?.plan(
        40,
        &migrate.recovery().expect("Fixture is a native recovery transaction").transaction().effects,
        &backends()?,
    )?;
    let legacy_forgeries = migration_plan
        .signatures
        .iter()
        .map(|statement| Signature::sign_bytes(&account, statement.message(), rng)?.to_bytes_le())
        .collect::<Result<Vec<_>>>()?;
    let compromised_legacy = with_changed_core(&migrate, |tx| {
        tx.authorization = Evidence::Direct(legacy_forgeries);
    })?;
    let uncompromised_root = vm.recovery_root()?;
    assert!(vm.check_transaction(&compromised_legacy, None, rng).is_err());
    assert_eq!(vm.recovery_root()?, uncompromised_root);
    let changed = with_changed_core(&migrate, |tx| {
        tx.effects.outputs[0].owner = Owner::Enrolled(enrolled_key(&attacker));
    })?;
    assert!(vm.check_transaction(&changed, None, rng).is_err());
    let changed = with_changed_core(&migrate, |tx| {
        let Evidence::Direct(signatures) = &mut tx.authorization else { unreachable!() };
        for signature in signatures {
            signature[0] ^= 1;
        }
    })?;
    assert!(vm.check_transaction(&changed, None, rng).is_err());

    // Interrupt the actual native finalize operation inside the host's batch.
    // An abandoned candidate must leave the enrolled input, fees and root intact.
    let checkpoint_before = vm.recovery_checkpoint()?;
    let root_before = vm.recovery_root()?;
    vm.finalize_store().start_atomic();
    vm.finalize_native_recovery(40, migrate.recovery().expect("Fixture is a native recovery transaction"))?;
    assert_ne!(vm.recovery_root()?, root_before);
    vm.finalize_store().abort_atomic();
    assert_eq!(vm.recovery_root()?, root_before);
    assert_eq!(vm.recovery_checkpoint()?, checkpoint_before);
    assert_eq!(ledger(&vm)?.unspent(&v2.id(&network)), Some(&v2));

    let block = sample_next_block(&vm, &account, std::slice::from_ref(&migrate), rng)?;
    assert_eq!(block.height(), 40);
    assert_eq!(block.transactions().len(), 1);
    vm.add_next_block(&block)?;
    assert!(ledger(&vm)?.unspent(&v2.id(&network)).is_none());
    let v3 = replacement(&migrate);
    assert_eq!(ledger(&vm)?.unspent(&v3.id(&network)), Some(&v3));
    assert!(vm.check_transaction(&migrate, None, rng).is_err());
    assert!(vm.check_transaction(&legacy_competitor, None, rng).is_err());

    let spend = transaction(&vm, Operation::Spend, v3.clone(), RecordVersion::V3, 41, 4, &signing, None, rng)?;
    let competing_spend = transaction(&vm, Operation::Spend, v3, RecordVersion::V3, 41, 5, &signing, None, rng)?;
    let verification_start = std::time::Instant::now();
    vm.check_transaction(&spend, None, rng)?;
    let spend_admission_us = verification_start.elapsed().as_micros();
    vm.check_transaction(&competing_spend, None, rng)?;
    let block = sample_next_block(&vm, &account, &[spend.clone(), competing_spend.clone()], rng)?;
    assert_eq!(block.transactions().len(), 1, "Competing PQ spends must consume the input exactly once");
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;
    assert!(vm.check_transaction(&spend, None, rng).is_err());
    assert!(vm.check_transaction(&competing_spend, None, rng).is_err());
    let current_ledger = ledger(&vm)?;
    assert_eq!(current_ledger.fees(), u128::from(3 * FEE));
    let spent = block.transactions().iter().next().expect("Expected one accepted recovery").transaction();
    let final_record = replacement(spent);
    assert_eq!(final_record.amount + 3 * FEE, 1_000_000_000);
    assert_eq!(current_ledger.unspent(&final_record.id(&network)), Some(&final_record));

    // Candidate speculation must verify native effects in block order. The
    // second spend is absent from the confirmed state when the block begins.
    let chain_first = transaction(&vm, Operation::Spend, final_record, RecordVersion::V3, 42, 6, &signing, None, rng)?;
    let mut candidate = current_ledger;
    candidate.apply(
        42,
        chain_first.recovery().expect("Fixture is a native recovery transaction").transaction(),
        &snarkvm_recovery_signatures::AleoLegacy::<N>::default(),
        &backends()?,
    )?;
    let chain_second = transaction_in_state(
        &vm,
        Operation::Spend,
        replacement(&chain_first),
        RecordVersion::V3,
        42,
        7,
        &signing,
        None,
        rng,
        &candidate,
    )?;
    assert!(vm.check_transaction(&chain_second, None, rng).is_err());
    let chain_block = sample_next_block(&vm, &account, &[chain_first.clone(), chain_second.clone()], rng)?;
    assert_eq!(chain_block.transactions().len(), 2, "Ordered native outputs must be spendable within a block");
    assert!(chain_block.aborted_transaction_ids().is_empty());
    vm.add_next_block(&chain_block)?;
    let final_record = replacement(&chain_second);
    assert_eq!(ledger(&vm)?.unspent(&final_record.id(&network)), Some(&final_record));
    assert_eq!(ledger(&vm)?.fees(), u128::from(5 * FEE));
    assert_eq!(final_record.amount + 5 * FEE, 1_000_000_000);

    // Reconstruct the production VM against its stored block/transaction/finalize
    // maps. Separate RocksDB process-kill tests establish durability guarantees.
    let reopened = TestVm::from(vm.store.clone())?;
    assert_eq!(reopened.recovery_checkpoint()?, vm.recovery_checkpoint()?);
    assert_eq!(reopened.recovery_root()?, vm.recovery_root()?);
    assert!(reopened.contains_serial_number(&native_serial)?);
    assert_eq!(reopened.transaction_store().get_transaction(&migrate.id())?, Some(migrate.clone()));
    assert!(reopened.check_transaction(&legacy_competitor, None, rng).is_err());
    assert!(reopened.check_transaction(&migrate, None, rng).is_err());
    println!(
        "RECOVERY_PRODUCTION_E2E source={commitment} serial={native_serial} prepare={} migrate={} spend={} chain_first={} chain_second={} final_amount={} fees={} root={} prepare_admission_us={prepare_admission_us} migration_admission_us={migration_admission_us} spend_admission_us={spend_admission_us} elapsed_ms={}",
        prepared.id(),
        migrate.id(),
        spent.id(),
        chain_first.id(),
        chain_second.id(),
        final_record.amount,
        ledger(&vm)?.fees(),
        hex::encode(vm.recovery_root()?),
        start.elapsed().as_millis()
    );
    Ok(())
}

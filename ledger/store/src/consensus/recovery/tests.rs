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
use crate::helpers::memory::ConsensusMemory;
use console::{
    account::{Address, PrivateKey},
    network::{MainnetV0, TestnetV0},
    program::{Identifier, Literal, Plaintext, ProgramID, Value},
    types::Field,
};
use snarkvm_ledger_block::Block;
use snarkvm_synthesizer_program::FinalizeStoreTrait;

type CurrentNetwork = MainnetV0;
type Store = ConsensusStore<CurrentNetwork, ConsensusMemory<CurrentNetwork>>;

fn sample_store() -> Result<Store> {
    let store = Store::open(StorageMode::new_test(None))?;
    let genesis = Block::read_le(CurrentNetwork::genesis_bytes())?;
    store.block_store().insert(&genesis)?;
    Ok(store)
}

fn add_mapping(store: &Store, name: &str, populated: bool) -> Result<()> {
    let program = ProgramID::from_str("assets.aleo")?;
    let mapping = Identifier::from_str(name)?;
    store.finalize_store().initialize_mapping(program, mapping)?;
    if populated {
        let key = Plaintext::from(Literal::Field(Field::from_u64(42)));
        let value = Value::from_str("100u64")?;
        store.finalize_store().insert_key_value(program, mapping, key, value)?;
    }
    Ok(())
}

#[test]
fn test_recovery_snapshot_roundtrip_and_mapping_coverage() -> Result<()> {
    let store = sample_store()?;
    add_mapping(&store, "balances", true)?;
    add_mapping(&store, "empty", false)?;
    let genesis = store.block_store().get_block_hash(0)?.ok_or_else(|| anyhow!("Missing genesis"))?;
    let block = store.block_store().get_block(&genesis)?.ok_or_else(|| anyhow!("Missing genesis data"))?;
    assert!(block.transactions().transitions().flat_map(|tx| tx.outputs()).any(|output| output.record().is_some()));
    let mut archive = Vec::new();
    let result = store.write_recovery_snapshot(ConsensusVersion::V23, &mut archive)?;
    let header_length = 21 + 2 + 2 + 4 + genesis.to_bytes_le()?.len();
    let mut cursor = std::io::Cursor::new(&archive[header_length..]);
    assert_eq!(u8::read_le(&mut cursor)?, 1);
    let length = u64::read_le(&mut cursor)?;
    let mut block_bytes = Vec::new();
    cursor.take(length).read_to_end(&mut block_bytes)?;
    assert_eq!(Block::<CurrentNetwork>::from_bytes_le(&block_bytes)?, block);
    assert_eq!(result.blocks, 1);
    assert_eq!(result.mappings, 2);
    assert_eq!(result.mapping_entries, 1);
    assert_eq!(result.serial_numbers, u64::try_from(store.transition_store().serial_numbers().count())?);
    let verified = verify_recovery_snapshot::<CurrentNetwork>(&archive[..], result.root, archive.len())?;
    assert_eq!(result, verified);
    Ok(())
}

#[test]
fn test_recovery_snapshot_tampering_and_truncation() -> Result<()> {
    let store = sample_store()?;
    add_mapping(&store, "balances", true)?;
    let mut archive = Vec::new();
    let result = store.write_recovery_snapshot(ConsensusVersion::V23, &mut archive)?;
    let mut tampered = archive.clone();
    // A payload byte immediately before the trailer belongs to the last archived frame.
    let index = tampered.len() - 66;
    tampered[index] ^= 1;
    assert!(verify_recovery_snapshot::<CurrentNetwork>(&tampered[..], result.root, archive.len()).is_err());
    assert!(verify_recovery_snapshot::<CurrentNetwork>(&archive[..], [0; 64], archive.len()).is_err());
    assert!(verify_recovery_snapshot::<TestnetV0>(&archive[..], result.root, archive.len()).is_err());
    assert!(verify_recovery_snapshot::<CurrentNetwork>(&archive[..], result.root, 1).is_err());
    assert!(verify_recovery_snapshot::<CurrentNetwork>(&archive[..], result.root, archive.len() - 1).is_err());
    let block_hash = store.block_store().get_block_hash(0)?.ok_or_else(|| anyhow!("Missing genesis"))?;
    let header_length = 21 + 2 + 2 + 4 + block_hash.to_bytes_le()?.len();
    let mut invalid_kind = archive.clone();
    invalid_kind[header_length] = 0x7f;
    assert!(verify_recovery_snapshot::<CurrentNetwork>(&invalid_kind[..], result.root, archive.len()).is_err());
    let mut oversized = archive.clone();
    oversized[header_length + 1..header_length + 9].fill(0xff);
    assert!(verify_recovery_snapshot::<CurrentNetwork>(&oversized[..], result.root, archive.len()).is_err());
    for length in [0, 20, 30, archive.len() - 1, archive.len() - 65] {
        assert!(verify_recovery_snapshot::<CurrentNetwork>(&archive[..length], result.root, archive.len()).is_err());
    }
    archive.push(0);
    assert!(verify_recovery_snapshot::<CurrentNetwork>(&archive[..], result.root, archive.len()).is_err());
    Ok(())
}

#[test]
fn test_recovery_snapshot_state_binding_and_canonical_order() -> Result<()> {
    let first = sample_store()?;
    add_mapping(&first, "balances", true)?;
    add_mapping(&first, "empty", false)?;
    let second = sample_store()?;
    add_mapping(&second, "empty", false)?;
    add_mapping(&second, "balances", true)?;
    let baseline = first.write_recovery_snapshot(ConsensusVersion::V23, std::io::sink())?;
    assert_eq!(baseline, second.write_recovery_snapshot(ConsensusVersion::V23, std::io::sink())?);
    let program = ProgramID::from_str("assets.aleo")?;
    let mapping = Identifier::from_str("balances")?;
    let key = Plaintext::from(Literal::Field(Field::from_u64(42)));
    second.finalize_store().update_key_value(program, mapping, key, Value::from_str("101u64")?)?;
    assert_ne!(baseline.root, second.write_recovery_snapshot(ConsensusVersion::V23, std::io::sink())?.root);
    first.finalize_store().remove_mapping(program, Identifier::from_str("empty")?)?;
    assert_ne!(baseline.root, first.write_recovery_snapshot(ConsensusVersion::V23, std::io::sink())?.root);
    Ok(())
}

#[test]
fn test_recovery_snapshot_preserves_address_and_composite_mapping_keys() -> Result<()> {
    let store = sample_store()?;
    let owner = PrivateKey::<CurrentNetwork>::try_from(Field::from_u64(42))?;
    let address = Address::try_from(&owner)?;
    let program = ProgramID::from_str("assets.aleo")?;
    let mapping = Identifier::from_str("balances")?;
    store.finalize_store().initialize_mapping(program, mapping)?;
    let direct_key = Plaintext::from(Literal::Address(address));
    let composite_key = Plaintext::from_str(&format!("{{ owner: {address}, asset: 7field }}"))?;
    store.finalize_store().insert_key_value(program, mapping, direct_key.clone(), Value::from_str("100u64")?)?;
    store.finalize_store().insert_key_value(
        program,
        mapping,
        composite_key.clone(),
        Value::from_str("{ balance: 20u64, locked: true }")?,
    )?;
    let mut archive = Vec::new();
    let result = store.write_recovery_snapshot(ConsensusVersion::V23, &mut archive)?;
    assert_eq!(result.mapping_entries, 2);
    for key in [direct_key, composite_key] {
        let bytes = key.to_bytes_le()?;
        assert!(archive.windows(bytes.len()).any(|window| window == bytes));
    }
    assert_eq!(result, verify_recovery_snapshot::<CurrentNetwork>(&archive[..], result.root, archive.len())?);
    Ok(())
}

#[test]
fn test_recovery_snapshot_domain_separation_and_duplicates() -> Result<()> {
    // SHA3-512 vector calculated independently with Python hashlib (OpenSSL).
    let expected = "28a30cd22ca398d447e0cdb51d46103c5ea45fb60cee3c9285bcb8a230fe507b181295b0c8267b075d149278550c283f6b34b4fca7c35776d167f316f3832045";
    let actual = hash::<MainnetV0>(1, &[b"abc"])?;
    assert_eq!(actual.iter().map(|byte| format!("{byte:02x}")).collect::<String>(), expected);
    assert_ne!(hash::<MainnetV0>(1, &[b"abc"])?, hash::<TestnetV0>(1, &[b"abc"])?);
    assert_ne!(hash::<MainnetV0>(1, &[b"abc"])?, hash::<MainnetV0>(2, &[b"abc"])?);
    assert_ne!(hash::<MainnetV0>(1, &[b"a", b"bc"])?, hash::<MainnetV0>(1, &[b"ab", b"c"])?);
    let leaf = hash::<MainnetV0>(1, &[b"abc"])?;
    assert!(root::<MainnetV0>(b"header", vec![leaf, leaf]).is_err());
    assert_ne!(root::<MainnetV0>(b"first", vec![leaf])?, root::<MainnetV0>(b"second", vec![leaf])?);
    Ok(())
}

#[test]
fn test_recovery_snapshot_rejects_unsupported_and_incomplete_storage() -> Result<()> {
    let store = sample_store()?;
    assert!(store.write_recovery_snapshot(ConsensusVersion::V22, std::io::sink()).is_err());
    store.start_atomic();
    assert!(store.write_recovery_snapshot(ConsensusVersion::V23, std::io::sink()).is_err());
    store.abort_atomic();
    let empty = Store::open(StorageMode::new_test(None))?;
    assert!(empty.write_recovery_snapshot(ConsensusVersion::V23, std::io::sink()).is_err());
    Ok(())
}

#[test]
fn test_recovery_snapshot_propagates_writer_errors() -> Result<()> {
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("Test writer failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(sample_store()?.write_recovery_snapshot(ConsensusVersion::V23, FailingWriter).is_err());
    Ok(())
}

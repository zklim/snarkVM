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

//! Fixtures created by the pinned pre-record-versioning implementation.
//! Public deterministic keys are for isolated tests only.
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use console::{
    account::{Address, PrivateKey, ViewKey},
    network::{MainnetV0, TestnetV0, prelude::*},
    program::{Identifier, Plaintext, ProgramID, Record},
    types::{Field, Scalar},
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const CREATOR: &str = "9741f1159a8cd18e2d676d5a095eeffad71ab52c";

fn write_file(
    out: &Path,
    name: &str,
    bytes: &[u8],
    files: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    fs::write(out.join(name), bytes)?;
    files.insert(
        name.into(),
        serde_json::json!({"bytes": bytes.len(), "sha256": format!("{:x}", Sha256::digest(bytes))}),
    );
    Ok(())
}

fn record_fixture<N: Network>(out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let key = PrivateKey::<N>::try_from(Field::from_u64(42))?;
    let owner = Address::try_from(&key)?;
    let randomizer = Scalar::<N>::from_str("7scalar")?;
    let nonce = N::g_scalar_multiply(&randomizer);
    // The historical parser has no record-version field. Its constructor creates
    // the original encoding and its original commitment implementation is used.
    let record = Record::<N, Plaintext<N>>::from_str(&format!(
        "{{ owner: {owner}.private, microcredits: 1000000000u64.private, _nonce: {nonce}.public }}"
    ))?;
    let ciphertext = record.encrypt(randomizer)?;
    let commitment = record.to_commitment(&ProgramID::from_str("credits.aleo")?, &Identifier::from_str("credits")?)?;
    let serial = Record::<N, Plaintext<N>>::serial_number(key, commitment)?;
    let rvk = (*record.nonce() * *ViewKey::try_from(&key)?).to_x_coordinate();
    let mut files = serde_json::Map::new();
    write_file(out, "record.bin", &record.to_bytes_le()?, &mut files)?;
    write_file(out, "record.txt", record.to_string().as_bytes(), &mut files)?;
    write_file(out, "ciphertext.bin", &ciphertext.to_bytes_le()?, &mut files)?;
    write_file(out, "ciphertext.txt", ciphertext.to_string().as_bytes(), &mut files)?;
    write_file(out, "commitment.bin", &commitment.to_bytes_le()?, &mut files)?;
    write_file(out, "serial.bin", &serial.to_bytes_le()?, &mut files)?;
    write_file(out, "record-view-key.bin", &rvk.to_bytes_le()?, &mut files)?;
    let manifest = serde_json::json!({"creator_repository":"https://github.com/zklim/snarkVM","creator_revision":CREATOR,"creator_package_version":"3.7.1","network_id":N::ID,"record_version":0,"program":"credits.aleo","record_name":"credits","owner":owner.to_string(),"public_fixture_seed":"42field","microcredits":1000000000u64,"commitment":commitment.to_string(),"serial":serial.to_string(),"scope":"historical constructor and commitment fixture; not an on-chain inclusion claim", "files":files});
    fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

#[cfg(feature = "genesis")]
fn genesis_fixture<N: Network>(out: &Path) -> Result<()> {
    use aleo_std::StorageMode;
    use indexmap::IndexMap;
    use ledger::{
        block::Block,
        committee::Committee,
        store::{ConsensusStore, helpers::memory::ConsensusMemory},
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;
    use synthesizer::VM;
    fs::create_dir_all(out)?;
    let mut rng = ChaChaRng::seed_from_u64(1234567890);
    let keys = (0..4).map(|_| PrivateKey::<N>::new(&mut rng)).collect::<Result<Vec<_>>>()?;
    let addresses = keys.iter().map(Address::<N>::try_from).collect::<Result<Vec<_>>>()?;
    let stake = N::STARTING_SUPPLY / 2 / 4;
    let members =
        addresses.iter().map(|address| (*address, (stake, true, rng.gen_range(0..100)))).collect::<IndexMap<_, _>>();
    let committee = Committee::<N>::new(0, members)?;
    let bonded =
        committee.members().iter().map(|(address, (stake, _, _))| (*address, (*address, *address, *stake))).collect();
    let remainder = N::STARTING_SUPPLY - committee.total_stake();
    let first = 8_000_000_000u64;
    ensure!(remainder > first, "insufficient test genesis supply");
    let other = (remainder - first) / 3;
    let mut balances = IndexMap::new();
    balances.insert(addresses[0], first);
    for address in &addresses[1..] {
        balances.insert(*address, other);
    }
    *balances.get_mut(&addresses[1]).expect("the inserted fixture address exists") += remainder - first - other * 3;
    let vm = VM::<N, ConsensusMemory<N>>::from(ConsensusStore::open(StorageMode::new_test(None))?)?;
    let block = vm.genesis_quorum(&keys[0], committee, balances, bonded, &mut rng)?;
    ensure!(block.height() == 0 && block.is_genesis(), "historical creator returned invalid genesis");
    let bytes = block.to_bytes_le()?;
    let mut files = serde_json::Map::new();
    write_file(out, "genesis.bin", &bytes, &mut files)?;
    let mut records = Vec::new();
    for (index, (commitment, ciphertext)) in
        block.transitions().cloned().flat_map(|transition| transition.into_records()).enumerate()
    {
        let record = ciphertext.decrypt(&ViewKey::try_from(&keys[0])?)?;
        let rvk = (*record.nonce() * *ViewKey::try_from(&keys[0])?).to_x_coordinate();
        write_file(out, &format!("record-{index}.bin"), &record.to_bytes_le()?, &mut files)?;
        write_file(out, &format!("ciphertext-{index}.bin"), &ciphertext.to_bytes_le()?, &mut files)?;
        write_file(out, &format!("record-view-key-{index}.bin"), &rvk.to_bytes_le()?, &mut files)?;
        records.push(serde_json::json!({"index":index,"record":record.to_string(),"commitment":commitment.to_string(),"serial":Record::<N,Plaintext<N>>::serial_number(keys[0],commitment)?.to_string()}));
    }
    ensure!(records.len() == Block::<N>::NUM_GENESIS_TRANSACTIONS, "unexpected source record count");
    let manifest = serde_json::json!({"creator_repository":"https://github.com/zklim/snarkVM","creator_revision":CREATOR,"creator_package_version":"3.7.1","network_id":N::ID,"genesis_hash":block.hash().to_string(),"validator_addresses":addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),"public_test_rng_seed":1234567890u64,"private_record_microcredits":1000000000u64,"record_version":0,"scope":"genuine historical VM-generated genesis and creating transactions; current-VM acceptance must be independently tested", "records":records,"files":files});
    fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(args.len() == 3, "usage: historical-v0-fixture <record|genesis> <mainnet|testnet> <output-directory>");
    let out = Path::new(&args[2]);
    match (args[0].as_str(), args[1].as_str()) {
        ("record", "mainnet") => record_fixture::<MainnetV0>(out),
        ("record", "testnet") => record_fixture::<TestnetV0>(out),
        #[cfg(feature = "genesis")]
        ("genesis", "mainnet") => genesis_fixture::<MainnetV0>(out),
        #[cfg(feature = "genesis")]
        ("genesis", "testnet") => genesis_fixture::<TestnetV0>(out),
        _ => anyhow::bail!("unsupported mode/network; genesis requires --features genesis"),
    }
}

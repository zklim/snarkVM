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
use std::io::{Read, Write};

#[cfg(test)]
mod tests;

/// The result of a successful archival export, not an authorization to recover assets.
/// The root needs independent authentication in a future recovery protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverySnapshot {
    pub block_height: u32,
    pub blocks: u64,
    pub mappings: u64,
    pub mapping_entries: u64,
    pub serial_numbers: u64,
    pub root: [u8; 64],
}

/// Hashes framed byte strings with a network and purpose domain.
fn hash<N: Network>(purpose: u8, parts: &[&[u8]]) -> Result<[u8; 64]> {
    let mut input = b"AleoRecoverySnapshot1".to_vec();
    N::ID.write_le(&mut input)?;
    purpose.write_le(&mut input)?;
    for part in parts {
        u64::try_from(part.len())?.write_le(&mut input)?;
        input.extend_from_slice(part);
    }
    let bits = N::hash_sha3_512(&input.to_bits_le())?;
    ensure!(bits.len() == 512, "Invalid recovery digest length");
    let mut digest = [0u8; 64];
    for (byte, bits) in digest.iter_mut().zip_eq(bits.chunks_exact(8)) {
        *byte = bits.iter().enumerate().fold(0, |acc, (index, bit)| acc | (u8::from(*bit) << index));
    }
    Ok(digest)
}

fn root<N: Network>(header: &[u8], mut leaves: Vec<[u8; 64]>) -> Result<[u8; 64]> {
    leaves.sort_unstable();
    ensure!(!leaves.windows(2).any(|pair| pair[0] == pair[1]), "Duplicate recovery snapshot leaf");
    let count = u64::try_from(leaves.len())?.to_le_bytes();
    let empty = hash::<N>(0x81, &[])?;
    while leaves.len() > 1 {
        leaves = leaves
            .chunks(2)
            .map(|pair| hash::<N>(0x80, &[&pair[0], pair.get(1).unwrap_or(&empty)]))
            .collect::<Result<Vec<_>>>()?;
    }
    hash::<N>(0x82, &[header, &count, leaves.first().unwrap_or(&empty)])
}

fn write_leaf<N: Network>(writer: &mut impl Write, kind: u8, payload: &[u8]) -> Result<[u8; 64]> {
    kind.write_le(&mut *writer)?;
    u64::try_from(payload.len())?.write_le(&mut *writer)?;
    writer.write_all(payload)?;
    hash::<N>(kind, &[payload])
}

/// Checks archival integrity against an independently authenticated root.
/// This does not validate historical consensus or authorize any recovery transaction.
/// `max_archive_bytes` bounds input size, payload allocations, and the number of leaf digests.
pub fn verify_recovery_snapshot<N: Network>(
    mut reader: impl Read,
    expected_root: [u8; 64],
    max_archive_bytes: usize,
) -> Result<RecoverySnapshot> {
    let mut magic = [0u8; 21];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == b"AleoRecoverySnapshot1", "Invalid recovery archive header");
    let network = u16::read_le(&mut reader)?;
    ensure!(network == N::ID, "Recovery archive belongs to a different network");
    let version = ConsensusVersion::read_le(&mut reader)?;
    ensure!(version.supports_recovery_preparation(), "Invalid recovery archive consensus version");
    let block_height = u32::read_le(&mut reader)?;
    let block_hash = N::BlockHash::read_le(&mut reader)?;
    let mut header = magic.to_vec();
    network.write_le(&mut header)?;
    version.write_le(&mut header)?;
    block_height.write_le(&mut header)?;
    block_hash.write_le(&mut header)?;
    let mut bytes_read = u64::try_from(header.len())?;
    let limit = u64::try_from(max_archive_bytes)?;
    ensure!(bytes_read <= limit, "Recovery archive exceeds allocation limit");
    let mut snapshot =
        RecoverySnapshot { block_height, blocks: 0, mappings: 0, mapping_entries: 0, serial_numbers: 0, root: [0; 64] };
    let mut leaves = Vec::new();
    loop {
        let kind = u8::read_le(&mut reader)?;
        bytes_read = bytes_read.checked_add(1).ok_or_else(|| anyhow!("Recovery archive size overflow"))?;
        if kind == 0xff {
            ensure!(
                bytes_read.checked_add(64).is_some_and(|length| length <= limit),
                "Recovery archive exceeds allocation limit"
            );
            reader.read_exact(&mut snapshot.root)?;
            break;
        }
        match kind {
            1 => snapshot.blocks += 1,
            2 => snapshot.mappings += 1,
            3 => snapshot.mapping_entries += 1,
            4 => snapshot.serial_numbers += 1,
            _ => bail!("Invalid recovery archive frame kind"),
        }
        let length = u64::read_le(&mut reader)?;
        bytes_read = bytes_read
            .checked_add(8)
            .and_then(|read| read.checked_add(length))
            .ok_or_else(|| anyhow!("Recovery archive size overflow"))?;
        ensure!(bytes_read <= limit, "Recovery archive exceeds allocation limit");
        let mut payload = Vec::new();
        (&mut reader).take(length).read_to_end(&mut payload)?;
        ensure!(u64::try_from(payload.len())? == length, "Truncated recovery archive frame");
        leaves.push(hash::<N>(kind, &[&payload])?);
    }
    ensure!(snapshot.blocks == u64::from(block_height) + 1, "Incomplete recovery block history");
    ensure!(reader.read(&mut [0u8; 1])? == 0, "Trailing recovery archive data");
    ensure!(snapshot.root == expected_root, "Untrusted recovery archive root");
    ensure!(root::<N>(&header, leaves)? == expected_root, "Recovery archive integrity check failed");
    Ok(snapshot)
}

impl<N: Network, C: ConsensusStorage<N>> ConsensusStore<N, C> {
    /// Exports all confirmed blocks, mappings (including empty mappings), and spent serial numbers.
    ///
    /// `target_version` selects the proposed archival format for a rehearsal; it does not
    /// activate a consensus upgrade. The caller must keep storage quiescent for the entire
    /// operation, for example by exporting an offline database copy. The height checks detect
    /// chain advancement but cannot replace a database snapshot or an exclusive writer lock.
    /// Only a successful return makes the output complete. No private key is required or exported.
    /// This archive does not implement a post-quantum proof system or asset transfers.
    pub fn write_recovery_snapshot(
        &self,
        target_version: ConsensusVersion,
        mut writer: impl Write,
    ) -> Result<RecoverySnapshot> {
        ensure!(target_version.supports_recovery_preparation(), "Recovery preparation requires Consensus V23 or later");
        ensure!(!self.is_atomic_in_progress(), "Cannot export recovery state during an atomic write");

        let block_height = self.block_store().current_block_height();
        let block_hash =
            self.block_store().get_block_hash(block_height)?.ok_or_else(|| anyhow!("Missing checkpoint block"))?;
        let mut header = b"AleoRecoverySnapshot1".to_vec();
        N::ID.write_le(&mut header)?;
        target_version.write_le(&mut header)?;
        block_height.write_le(&mut header)?;
        block_hash.write_le(&mut header)?;
        writer.write_all(&header)?;

        let mut leaves = Vec::new();
        let mut snapshot = RecoverySnapshot {
            block_height,
            blocks: 0,
            mappings: 0,
            mapping_entries: 0,
            serial_numbers: 0,
            root: [0; 64],
        };
        for height in 0..=block_height {
            let hash =
                self.block_store().get_block_hash(height)?.ok_or_else(|| anyhow!("Missing block at {height}"))?;
            let block =
                self.block_store().get_block(&hash)?.ok_or_else(|| anyhow!("Missing block data at {height}"))?;
            for output in block.transactions().transitions().flat_map(|transition| transition.outputs()) {
                use snarkvm_ledger_block::Output;
                ensure!(
                    !matches!(output, Output::Record(_, _, None, _) | Output::RecordWithDynamicID(_, _, None, _, _)),
                    "Missing record ciphertext in recovery block at {height}"
                );
            }
            leaves.push(write_leaf::<N>(&mut writer, 1, &block.to_bytes_le()?)?);
            snapshot.blocks += 1;
        }

        for (program_id, mapping_names) in self.finalize_store().recovery_mapping_names() {
            for mapping_name in mapping_names {
                let mut descriptor = program_id.to_bytes_le()?;
                mapping_name.write_le(&mut descriptor)?;
                leaves.push(write_leaf::<N>(&mut writer, 2, &descriptor)?);
                snapshot.mappings += 1;
                for (key, value) in self.finalize_store().get_mapping_confirmed(program_id, mapping_name)? {
                    let mut payload = descriptor.clone();
                    let key = key.to_bytes_le()?;
                    let value = value.to_bytes_le()?;
                    u64::try_from(key.len())?.write_le(&mut payload)?;
                    payload.extend(key);
                    u64::try_from(value.len())?.write_le(&mut payload)?;
                    payload.extend(value);
                    leaves.push(write_leaf::<N>(&mut writer, 3, &payload)?);
                    snapshot.mapping_entries += 1;
                }
            }
        }

        for serial_number in self.transition_store().serial_numbers() {
            leaves.push(write_leaf::<N>(&mut writer, 4, &serial_number.to_bytes_le()?)?);
            snapshot.serial_numbers += 1;
        }
        ensure!(!self.is_atomic_in_progress(), "Storage entered an atomic write during recovery export");
        ensure!(
            self.block_store().current_block_height() == block_height
                && self.block_store().get_block_hash(block_height)? == Some(block_hash),
            "Checkpoint changed during recovery export"
        );
        snapshot.root = root::<N>(&header, leaves)?;
        0xffu8.write_le(&mut writer)?;
        writer.write_all(&snapshot.root)?;
        writer.flush()?;
        Ok(snapshot)
    }
}

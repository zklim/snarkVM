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

use super::{FinalizeStorage, FinalizeStore};
use crate::{
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::{network::prelude::*, types::Field};
use std::collections::{BTreeMap, BTreeSet};

const CURRENT_RECOVERY_STATE: u32 = u32::MAX;
pub const MAX_RECOVERY_STATE_BYTES: usize = 64 * 1024 * 1024;

impl<N: Network, P: FinalizeStorage<N>> FinalizeStore<N, P> {
    /// Returns the current recovery state, including earlier writes in this candidate.
    pub fn recovery_state(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.storage.recovery_state_map().get_speculative(&CURRENT_RECOVERY_STATE)?.map(|bytes| bytes.into_owned()))
    }

    /// Returns the last committed recovery state.
    pub fn recovery_state_confirmed(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.storage.recovery_state_map().get_confirmed(&CURRENT_RECOVERY_STATE)?.map(|bytes| bytes.into_owned()))
    }

    /// Returns the latest speculative recovery checkpoint at or before the height.
    pub fn recovery_state_at_height(&self, height: u32) -> Result<Option<Vec<u8>>> {
        let latest =
            self.recovery_heights_speculative().into_iter().rfind(|h| *h != CURRENT_RECOVERY_STATE && *h <= height);
        match latest {
            Some(height) => {
                Ok(self.storage.recovery_state_map().get_speculative(&height)?.map(|bytes| bytes.into_owned()))
            }
            None => Ok(None),
        }
    }

    /// Stores the candidate state and its height checkpoint in the existing finalize batch.
    pub fn set_recovery_state(&self, height: u32, bytes: Vec<u8>) -> Result<()> {
        ensure!(height != CURRENT_RECOVERY_STATE, "Reserved recovery checkpoint height");
        ensure!(!bytes.is_empty() && bytes.len() <= MAX_RECOVERY_STATE_BYTES, "Invalid recovery state size");
        atomic_batch_scope!(self, {
            self.storage.recovery_state_map().insert(height, bytes.clone())?;
            self.storage.recovery_state_map().insert(CURRENT_RECOVERY_STATE, bytes)?;
            Ok(())
        })
    }

    /// Checks the shared legacy-serial exclusion index, including the current candidate.
    pub fn recovery_contains_serial(&self, serial: &Field<N>) -> Result<bool> {
        self.storage.recovery_serial_map().contains_key_speculative(serial)
    }

    /// Records a canonical legacy serial consumed by native preparation.
    pub fn recovery_mark_serial(&self, serial: Field<N>, height: u32) -> Result<()> {
        ensure!(height != CURRENT_RECOVERY_STATE, "Reserved recovery consumption height");
        ensure!(!self.recovery_contains_serial(&serial)?, "Legacy serial is already consumed by recovery");
        self.storage.recovery_serial_map().insert(serial, height)
    }

    /// Restores checkpoints and serial indexes when the caller rolls back the same blocks.
    /// This is not permission to revert BFT-finalized history.
    pub fn recovery_rewind_to_height(&self, height: u32) -> Result<()> {
        ensure!(height != CURRENT_RECOVERY_STATE, "Reserved recovery rollback height");
        let heights = self.recovery_heights_speculative();
        let previous = self.recovery_state_at_height(height)?;
        let mut serials: BTreeMap<Field<N>, u32> =
            self.storage.recovery_serial_map().iter_confirmed().map(|(serial, h)| (*serial, *h)).collect();
        for (serial, pending) in self.storage.recovery_serial_map().iter_pending() {
            match pending {
                Some(h) => {
                    serials.insert(*serial, *h);
                }
                None => {
                    serials.remove(serial.as_ref());
                }
            }
        }
        atomic_batch_scope!(self, {
            for h in heights.iter().filter(|h| **h != CURRENT_RECOVERY_STATE && **h > height) {
                self.storage.recovery_state_map().remove(h)?;
            }
            match previous {
                Some(state) => self.storage.recovery_state_map().insert(CURRENT_RECOVERY_STATE, state)?,
                None => self.storage.recovery_state_map().remove(&CURRENT_RECOVERY_STATE)?,
            }
            for (serial, _) in serials.into_iter().filter(|(_, h)| *h > height) {
                self.storage.recovery_serial_map().remove(&serial)?;
            }
            Ok(())
        })
    }

    fn recovery_heights_speculative(&self) -> BTreeSet<u32> {
        // Do not load every historical state blob to locate one checkpoint.
        let mut heights: BTreeSet<u32> =
            self.storage.recovery_state_map().keys_confirmed().map(|height| *height).collect();
        for (height, pending) in self.storage.recovery_state_map().iter_pending() {
            match pending {
                Some(_) => {
                    heights.insert(*height);
                }
                None => {
                    heights.remove(height.as_ref());
                }
            }
        }
        heights
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FinalizeMode, helpers::memory::FinalizeMemory};
    use aleo_std_storage::StorageMode;
    use console::network::MainnetV0;

    type N = MainnetV0;

    fn check_atomic_recovery<P: FinalizeStorage<N>>(store: FinalizeStore<N, P>) -> Result<()> {
        let a = Field::from_u64(1);
        let b = Field::from_u64(2);
        assert_eq!(store.recovery_state()?, None);
        assert!(store.set_recovery_state(u32::MAX, vec![1]).is_err());
        assert!(store.set_recovery_state(10, vec![]).is_err());
        let speculative = crate::atomic_finalize!(store, FinalizeMode::DryRun, {
            store.set_recovery_state(10, vec![1]).map_err(|e| e.to_string())?;
            store.recovery_mark_serial(a, 10).map_err(|e| e.to_string())?;
            Ok((
                store.recovery_state().map_err(|e| e.to_string())?,
                store.recovery_contains_serial(&a).map_err(|e| e.to_string())?,
            ))
        })?;
        assert_eq!(speculative, (Some(vec![1]), true));
        assert_eq!(store.recovery_state_confirmed()?, None);
        assert!(!store.recovery_contains_serial(&a)?);
        let failed: Result<()> = crate::atomic_finalize!(store, FinalizeMode::RealRun, {
            store.set_recovery_state(10, vec![1]).map_err(|e| e.to_string())?;
            store.recovery_mark_serial(a, 10).map_err(|e| e.to_string())?;
            Err("Injected error after candidate recovery writes".to_owned())
        });
        assert!(failed.is_err());
        assert_eq!(store.recovery_state_confirmed()?, None);
        assert!(!store.recovery_contains_serial(&a)?);
        store.start_atomic();
        store.set_recovery_state(10, vec![1])?;
        store.recovery_mark_serial(a, 10)?;
        assert_eq!(store.recovery_state()?, Some(vec![1]));
        assert_eq!(store.recovery_state_confirmed()?, None);
        store.atomic_checkpoint();
        store.set_recovery_state(10, vec![3])?;
        assert_eq!(store.recovery_state_at_height(10)?, Some(vec![3]));
        store.atomic_rewind();
        assert_eq!(store.recovery_state_at_height(10)?, Some(vec![1]));
        store.atomic_checkpoint();
        store.set_recovery_state(11, vec![2])?;
        store.recovery_mark_serial(b, 11)?;
        assert!(store.recovery_mark_serial(a, 11).is_err());
        assert_eq!(store.recovery_state()?, Some(vec![2]));
        store.atomic_rewind();
        assert_eq!(store.recovery_state()?, Some(vec![1]));
        assert!(!store.recovery_contains_serial(&b)?);
        store.finish_atomic()?;
        assert_eq!(store.recovery_state_confirmed()?, Some(vec![1]));
        assert!(store.recovery_contains_serial(&a)?);
        store.start_atomic();
        store.set_recovery_state(11, vec![2])?;
        store.recovery_mark_serial(b, 11)?;
        store.abort_atomic();
        assert_eq!(store.recovery_state_confirmed()?, Some(vec![1]));
        assert!(!store.recovery_contains_serial(&b)?);
        store.start_atomic();
        store.set_recovery_state(11, vec![2])?;
        store.recovery_mark_serial(b, 11)?;
        store.finish_atomic()?;
        assert_eq!(store.recovery_state_at_height(10)?, Some(vec![1]));
        assert_eq!(store.recovery_state_at_height(12)?, Some(vec![2]));
        store.recovery_rewind_to_height(10)?;
        assert_eq!(store.recovery_state_confirmed()?, Some(vec![1]));
        assert!(!store.recovery_contains_serial(&b)?);
        assert!(store.recovery_contains_serial(&a)?);
        store.recovery_rewind_to_height(9)?;
        assert_eq!(store.recovery_state_confirmed()?, None);
        assert!(!store.recovery_contains_serial(&a)?);
        Ok(())
    }

    #[test]
    fn test_recovery_memory_atomic_checkpoint_abort_and_rollback() -> Result<()> {
        check_atomic_recovery(FinalizeStore::<N, FinalizeMemory<N>>::open(StorageMode::Test(None))?)
    }

    #[test]
    #[cfg(feature = "rocks")]
    fn test_recovery_rocks_atomic_checkpoint_abort_and_rollback() -> Result<()> {
        let dir = std::sync::Arc::new(tempfile::tempdir()?);
        check_atomic_recovery(FinalizeStore::<N, crate::helpers::rocksdb::FinalizeDB<N>>::open(dir)?)
    }

    #[test]
    #[cfg(feature = "rocks")]
    fn test_recovery_rocks_process_child() -> Result<()> {
        let Ok(path) = std::env::var("ALEO_RECOVERY_STORE_TEST_PATH") else {
            return Ok(());
        };
        let mode = std::env::var("ALEO_RECOVERY_STORE_TEST_MODE")?;
        let store =
            FinalizeStore::<N, crate::helpers::rocksdb::FinalizeDB<N>>::open(StorageMode::Custom(path.into(), None))?;
        let a = Field::from_u64(1);
        let b = Field::from_u64(2);
        match mode.as_str() {
            "committed" => {
                store.start_atomic();
                store.set_recovery_state(10, vec![1])?;
                store.recovery_mark_serial(a, 10)?;
                store.finish_atomic()?;
            }
            "abandoned" | "partial-finalize" => {
                assert_eq!(store.recovery_state_confirmed()?, Some(vec![1]));
                store.start_atomic();
                store.set_recovery_state(11, vec![2])?;
                store.recovery_mark_serial(b, 11)?;
                if mode == "partial-finalize" {
                    // One map has serialized its writes into the database batch, but
                    // the other finalize maps have not finished. Nothing is committed.
                    store.storage.recovery_state_map().finish_atomic()?;
                    assert_eq!(store.recovery_state_confirmed()?, Some(vec![1]));
                }
            }
            "read" => {
                assert_eq!(store.recovery_state_confirmed()?, Some(vec![1]));
                assert!(store.recovery_contains_serial(&a)?);
                assert!(!store.recovery_contains_serial(&b)?);
                assert_eq!(store.recovery_state_at_height(11)?, Some(vec![1]));
            }
            _ => bail!("Unknown recovery storage test mode"),
        }
        use std::io::Write;
        println!("RECOVERY_STORE_TEST_READY");
        std::io::stdout().flush()?;
        loop {
            std::thread::park();
        }
    }

    #[test]
    #[cfg(feature = "rocks")]
    fn test_recovery_rocks_reopen_and_abandoned_candidate() -> Result<()> {
        let dir = tempfile::tempdir()?;
        use std::{io::BufRead, process::Stdio, sync::mpsc, time::Duration};
        for mode in ["committed", "abandoned", "partial-finalize", "read"] {
            let mut child = std::process::Command::new(std::env::current_exe()?)
                .args(["test_recovery_rocks_process_child", "--nocapture", "--test-threads=1"])
                .env("ALEO_RECOVERY_STORE_TEST_PATH", dir.path())
                .env("ALEO_RECOVERY_STORE_TEST_MODE", mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let stdout = child.stdout.take().ok_or_else(|| std::io::Error::other("Missing test child stdout"))?;
            let (ready_tx, ready_rx) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                let ready = std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(std::result::Result::ok)
                    .any(|line| line.contains("RECOVERY_STORE_TEST_READY"));
                let _ = ready_tx.send(ready);
            });
            let ready = ready_rx.recv_timeout(Duration::from_secs(30));
            if !matches!(ready, Ok(true)) {
                let _ = child.kill();
                let output = child.wait_with_output()?;
                reader.join().expect("Recovery store test reader panicked");
                bail!(
                    "Recovery test child failed or timed out before checkpoint ({mode}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            // Kill after the known committed or queued checkpoint, without shutdown hooks.
            child.kill()?;
            assert!(!child.wait()?.success());
            reader.join().expect("Recovery store test reader panicked");
        }
        Ok(())
    }
}

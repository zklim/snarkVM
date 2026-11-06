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

use snarkvm_console::{
    network::{ConsensusVersion, TestnetV0},
    prelude::Result,
};
use snarkvm_ledger_block::Transaction;
use snarkvm_synthesizer_process::{Process, transaction_compute_spend_in_microcredits};

#[test]
fn recovery_cost_is_available_for_parent_and_candidate_versions() -> Result<()> {
    // Public development transaction; resource estimation is separate from ownership and admission.
    let transaction: Transaction<TestnetV0> =
        serde_json::from_str(include_str!("../../../recovery/history-tools/fixtures/native-cost-boundary.json"))?;
    let process = Process::<TestnetV0>::load()?;
    let minimum = transaction.recovery().expect("Fixture is native recovery").minimum_fee()?;
    // The H1 candidate is V23 while the proposer still has a V22 parent.
    for version in [ConsensusVersion::V22, ConsensusVersion::V23, ConsensusVersion::V24] {
        assert_eq!(transaction_compute_spend_in_microcredits(&process, &transaction, version)?, minimum);
    }
    Ok(())
}

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

//! Differential phase checks against independently generated Python vectors.

use ml_dsa::{KeyExport, Keypair, MlDsa65};
use snarkvm_recovery::*;
use snarkvm_recovery_signatures::{Falcon512Verifier, MlDsa65Verifier};

#[test]
fn independent_model_phase_vectors_match_core_plan() -> Result<()> {
    let network = [17; 64];
    let policy = Policy { preparation: Some(2), recovery: Some(4), ..Policy::default() };
    let mut backends = Backends::default();
    backends.register_signature(Box::new(MlDsa65Verifier))?;
    backends.register_signature(Box::new(Falcon512Verifier))?;
    // This public deterministic key is a fixture, never a production key.
    let signer = ml_dsa::SigningKey::<MlDsa65>::from_seed(&[42; 32].into());
    let key = Key { profile: Profile::ML_DSA_65, bytes: signer.verifying_key().to_bytes().to_vec() };
    let mut checked = 0;
    for row in include_str!("../../model/vectors/disclosed-phase.tsv").lines().skip(1) {
        let cells: Vec<_> = row.split('\t').collect();
        assert_eq!(cells.len(), 4, "Malformed independent phase vector");
        let version = match cells[0] {
            "0" => RecordVersion::V0,
            "1" => RecordVersion::V1,
            "2" => RecordVersion::V2,
            "3" => RecordVersion::V3,
            _ => panic!("Unknown independent record version"),
        };
        let operation = match cells[1] {
            "prepare" => Operation::Prepare,
            "migrate" => Operation::Migrate,
            "spend" => Operation::Spend,
            "rotate" => Operation::Rotate,
            // Legacy executions and private fees are host-VM policy checks.
            "legacy" | "private_fee" => continue,
            _ => panic!("Unknown independent operation"),
        };
        let height: u32 = cells[2].parse().map_err(|_| Error::Encoding)?;
        let expected = cells[3] == "1";
        let source = Record {
            version,
            owner: match version {
                RecordVersion::V0 | RecordVersion::V1 => Owner::Legacy(vec![21; 32]),
                RecordVersion::V2 | RecordVersion::V3 => Owner::Enrolled(key.clone()),
            },
            amount: 3,
            nonce: [1; 64],
            opening: [2; 64],
        };
        let output_version = match operation {
            Operation::Prepare => RecordVersion::V2,
            Operation::Migrate | Operation::Spend => RecordVersion::V3,
            Operation::Rotate if version == RecordVersion::V2 => RecordVersion::V2,
            Operation::Rotate => RecordVersion::V3,
        };
        let ledger = Ledger::from_trusted_records(network, policy.clone(), vec![source.clone()], &backends)?;
        let effects = Effects {
            network,
            protocol: PROTOCOL_VERSION,
            policy: 1,
            policy_commitment: policy.commitment(&network),
            operation,
            valid_from: 0,
            valid_until: 100,
            replay: [0; 64],
            inputs: vec![source.id(&network)],
            outputs: vec![Record {
                version: output_version,
                owner: Owner::Enrolled(key.clone()),
                amount: 2,
                nonce: [3; 64],
                opening: [4; 64],
            }],
            fee: 1,
        };
        assert_eq!(ledger.plan(height, &effects, &backends).is_ok(), expected, "Independent vector: {row}");
        checked += 1;
    }
    assert_eq!(checked, 80);
    Ok(())
}

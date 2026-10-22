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

use crate::{
    codec::{Reader, Writer},
    *,
};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_STATE_RECORDS: usize = 10_000;
pub const MAX_STATE_REPLAYS: usize = 100_000;

/// None is unscheduled. A stage-one-only schedule permits preparation indefinitely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub preparation: Option<u32>,
    pub recovery: Option<u32>,
    pub profiles: Vec<Profile>,
    pub aggregates: Vec<u16>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            preparation: None,
            recovery: None,
            profiles: vec![Profile::ML_DSA_65, Profile::FALCON_512],
            aggregates: vec![],
        }
    }
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        match (self.preparation, self.recovery) {
            (None, Some(_)) => return Err(Error::Policy),
            (Some(first), Some(second)) if first >= second => return Err(Error::Policy),
            _ => (),
        }
        if self.profiles.is_empty()
            || self.profiles.len() > 2
            || self.aggregates.len() > 1
            || !self.profiles.windows(2).all(|w| w[0] < w[1])
            || !self.aggregates.windows(2).all(|w| w[0] < w[1])
            || self.aggregates.iter().any(|id| *id != 1)
        {
            return Err(Error::Policy);
        }
        for profile in &self.profiles {
            profile.validate()?;
        }
        if !self.aggregates.is_empty() && !self.profiles.contains(&Profile::FALCON_512) {
            return Err(Error::Policy);
        }
        Ok(())
    }

    pub fn commitment(&self, network: &Digest64) -> Digest64 {
        let mut writer = Writer::default();
        self.encode(&mut writer);
        digest(b"AleoRecoveryExperimentalPolicy1", &[network, &writer.0])
    }

    fn phase(&self, height: u32) -> u8 {
        if self.recovery.is_some_and(|start| height >= start) {
            2
        } else if self.preparation.is_some_and(|start| height >= start) {
            1
        } else {
            0
        }
    }

    fn encode(&self, writer: &mut Writer) {
        for activation in [self.preparation, self.recovery] {
            match activation {
                None => writer.u8(0),
                Some(height) => {
                    writer.u8(1);
                    writer.u32(height);
                }
            }
        }
        writer.u32(self.profiles.len() as u32);
        for profile in &self.profiles {
            writer.u16(profile.algorithm);
            writer.u16(profile.parameters);
        }
        writer.u32(self.aggregates.len() as u32);
        for id in &self.aggregates {
            writer.u16(*id);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub effects: Effects,
    /// Exactly one legacy authorization per input for Prepare, otherwise empty.
    pub legacy: Vec<Vec<u8>>,
    pub authorization: Evidence,
}

#[derive(Clone, Debug)]
pub struct LegacyStatement {
    pub owner: Vec<u8>,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub legacy: Vec<LegacyStatement>,
    pub signatures: Vec<Statement>,
}

/// No disk or host state is mutated until a complete transition verifies.
/// A host must commit this state together with its old-spend indexes and block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    network: Digest64,
    policy: Policy,
    records: BTreeMap<Digest64, Record>,
    spent: BTreeSet<Digest64>,
    replays: BTreeSet<Digest64>,
    fees: u128,
}

impl Ledger {
    /// Imports public records from an independently authenticated source.
    /// This function does not validate a historical private Aleo record proof.
    pub fn from_trusted_records(
        network: Digest64,
        policy: Policy,
        records: Vec<Record>,
        backends: &Backends,
    ) -> Result<Self> {
        policy.validate()?;
        if records.len() > MAX_STATE_RECORDS {
            return Err(Error::Limit);
        }
        backends.require(&policy.profiles, &policy.aggregates)?;
        let mut ledger = Self {
            network,
            policy,
            records: BTreeMap::new(),
            spent: BTreeSet::new(),
            replays: BTreeSet::new(),
            fees: 0,
        };
        for record in records {
            record.validate()?;
            if let Owner::Enrolled(key) = &record.owner {
                ledger.validate_key(key, backends)?;
            }
            if ledger.records.insert(record.id(&network), record).is_some() {
                return Err(Error::Replay);
            }
        }
        Ok(ledger)
    }

    fn validate_key(&self, key: &Key, backends: &Backends) -> Result<()> {
        if !self.policy.profiles.contains(&key.profile) {
            return Err(Error::Policy);
        }
        backends.validate_key(key)
    }

    pub fn unspent(&self, id: &Digest64) -> Option<&Record> {
        if self.spent.contains(id) { None } else { self.records.get(id) }
    }

    /// Public experimental nullifiers are deliberately linkable to their inputs.
    pub fn nullifier(&self, input: &Digest64) -> Digest64 {
        digest(b"AleoRecoveryExperimentalNullifier1", &[&self.network, input])
    }

    pub fn fees(&self) -> u128 {
        self.fees
    }

    /// Computes expected authorization from the current authenticated state.
    pub fn plan(&self, height: u32, effects: &Effects, backends: &Backends) -> Result<Plan> {
        effects.validate()?;
        if self.records.len() + effects.outputs.len() > MAX_STATE_RECORDS || self.replays.len() >= MAX_STATE_REPLAYS {
            return Err(Error::Limit);
        }
        backends.require(&self.policy.profiles, &self.policy.aggregates)?;
        if effects.network != self.network
            || effects.policy_commitment != self.policy.commitment(&self.network)
            || height < effects.valid_from
            || height > effects.valid_until
        {
            return Err(Error::Policy);
        }
        if self.replays.contains(&effects.id()?) {
            return Err(Error::Replay);
        }
        let phase = self.policy.phase(height);
        let (input_version, output_version) = match (phase, effects.operation) {
            (1, Operation::Prepare) => (None, RecordVersion::V2),
            (2, Operation::Migrate) => (Some(RecordVersion::V2), RecordVersion::V3),
            (2, Operation::Spend) => (Some(RecordVersion::V3), RecordVersion::V3),
            (1, Operation::Rotate) => (Some(RecordVersion::V2), RecordVersion::V2),
            (2, Operation::Rotate) => (Some(RecordVersion::V3), RecordVersion::V3),
            _ => return Err(Error::Policy),
        };
        if matches!(effects.operation, Operation::Rotate | Operation::Migrate)
            && (effects.inputs.len() != 1 || effects.outputs.len() != 1)
        {
            return Err(Error::Policy);
        }
        let encoded = effects.encode()?;
        let mut seen_inputs = BTreeSet::new();
        let mut legacy = Vec::new();
        let mut signatures = Vec::with_capacity(effects.inputs.len() + effects.outputs.len());
        let mut input_amount = 0u128;
        let mut minimum_category = 0u8;
        for (slot, id) in effects.inputs.iter().enumerate() {
            if !seen_inputs.insert(*id) {
                return Err(Error::Spent);
            }
            let record = self.unspent(id).ok_or(Error::Spent)?;
            if input_version.is_some_and(|version| record.version != version)
                || (input_version.is_none() && !matches!(record.version, RecordVersion::V0 | RecordVersion::V1))
            {
                return Err(Error::Policy);
            }
            input_amount += u128::from(record.amount);
            match &record.owner {
                Owner::Legacy(owner) => {
                    let message = digest(b"AleoRecoveryExperimentalLegacy1", &[
                        &encoded,
                        &(slot as u16).to_le_bytes(),
                        id,
                        owner,
                    ]);
                    legacy.push(LegacyStatement { owner: owner.clone(), message: message.to_vec() });
                }
                Owner::Enrolled(key) => {
                    self.validate_key(key, backends)?;
                    minimum_category = minimum_category.max(key.profile.security_category()?);
                    signatures.push(Statement::new(effects, key, 0, slot)?);
                }
            }
        }
        if matches!(effects.operation, Operation::Rotate | Operation::Migrate) {
            let source = self.unspent(&effects.inputs[0]).ok_or(Error::Spent)?;
            let (Owner::Enrolled(old), Owner::Enrolled(new)) = (&source.owner, &effects.outputs[0].owner) else {
                return Err(Error::Ownership);
            };
            if effects.operation == Operation::Migrate && old != new {
                return Err(Error::Ownership);
            }
            if effects.operation == Operation::Rotate
                && new.profile.security_category()? < old.profile.security_category()?
            {
                return Err(Error::Policy);
            }
        }
        let mut seen_outputs = BTreeSet::new();
        let mut output_amount = u128::from(effects.fee);
        for (slot, record) in effects.outputs.iter().enumerate() {
            if record.version != output_version {
                return Err(Error::Policy);
            }
            let id = record.id(&self.network);
            if self.records.contains_key(&id) || !seen_outputs.insert(id) {
                return Err(Error::Replay);
            }
            let Owner::Enrolled(key) = &record.owner else {
                return Err(Error::Ownership);
            };
            self.validate_key(key, backends)?;
            if key.profile.security_category()? < minimum_category {
                return Err(Error::Policy);
            }
            signatures.push(Statement::new(effects, key, 1, slot)?);
            output_amount += u128::from(record.amount);
        }
        if input_amount != output_amount {
            return Err(Error::Conservation);
        }
        Ok(Plan { legacy, signatures })
    }

    pub fn apply(
        &mut self,
        height: u32,
        transaction: &Transaction,
        legacy: &dyn LegacyVerifier,
        backends: &Backends,
    ) -> Result<Digest64> {
        let plan = self.plan(height, &transaction.effects, backends)?;
        if plan.legacy.len() != transaction.legacy.len() {
            return Err(Error::Ownership);
        }
        if transaction.legacy.iter().any(|proof| proof.len() > 4096) {
            return Err(Error::Limit);
        }
        for (statement, proof) in plan.legacy.iter().zip(&transaction.legacy) {
            legacy.verify(&statement.owner, &statement.message, proof)?;
        }
        backends.verify_evidence(&plan.signatures, &transaction.authorization, &self.policy.aggregates)?;
        let fees = self.fees.checked_add(u128::from(transaction.effects.fee)).ok_or(Error::Limit)?;
        let id = transaction.effects.id()?;
        for input in &transaction.effects.inputs {
            self.spent.insert(*input);
        }
        for record in &transaction.effects.outputs {
            self.records.insert(record.id(&self.network), record.clone());
        }
        self.replays.insert(id);
        self.fees = fees;
        Ok(id)
    }

    /// A complete candidate is atomic, including transactions competing inside it.
    pub fn apply_candidate(
        &mut self,
        height: u32,
        transactions: &[Transaction],
        legacy: &dyn LegacyVerifier,
        backends: &Backends,
    ) -> Result<()> {
        if transactions.len() > 1024 {
            return Err(Error::Limit);
        }
        let mut candidate = self.clone();
        for transaction in transactions {
            candidate.apply(height, transaction, legacy, backends)?;
        }
        *self = candidate;
        Ok(())
    }

    /// Canonical checkpoint for host-managed atomic persistence. It is not a
    /// consensus-authenticated root unless a host binds it into its block state.
    pub fn checkpoint(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.0.extend_from_slice(b"AleoRecoveryState1");
        writer.0.extend_from_slice(&self.network);
        self.policy.encode(&mut writer);
        writer.0.extend_from_slice(&self.fees.to_le_bytes());
        writer.u32(self.records.len() as u32);
        for record in self.records.values() {
            writer.record(record);
        }
        writer.u32(self.spent.len() as u32);
        for id in &self.spent {
            writer.0.extend_from_slice(id);
        }
        writer.u32(self.replays.len() as u32);
        for replay in &self.replays {
            writer.0.extend_from_slice(replay);
        }
        writer.0
    }

    pub fn restore(network: Digest64, policy: Policy, bytes: &[u8], backends: &Backends) -> Result<Self> {
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(Error::Limit);
        }
        let mut reader = Reader(bytes);
        if reader.take(b"AleoRecoveryState1".len())? != b"AleoRecoveryState1" || reader.array::<64>()? != network {
            return Err(Error::Encoding);
        }
        let mut expected_policy = Writer::default();
        policy.encode(&mut expected_policy);
        if reader.take(expected_policy.0.len())? != expected_policy.0 {
            return Err(Error::Policy);
        }
        let fees = u128::from_le_bytes(reader.array()?);
        let count = reader.count(MAX_STATE_RECORDS)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(reader.record()?);
        }
        let mut ledger = Self::from_trusted_records(network, policy, records, backends)?;
        ledger.fees = fees;
        let count = reader.count(MAX_STATE_RECORDS)?;
        for _ in 0..count {
            let id = reader.array()?;
            if !ledger.records.contains_key(&id) || !ledger.spent.insert(id) {
                return Err(Error::Encoding);
            }
        }
        let count = reader.count(MAX_STATE_REPLAYS)?;
        for _ in 0..count {
            if !ledger.replays.insert(reader.array()?) {
                return Err(Error::Encoding);
            }
        }
        reader.finish()?;
        if ledger.checkpoint() != bytes {
            return Err(Error::Encoding);
        }
        Ok(ledger)
    }
}

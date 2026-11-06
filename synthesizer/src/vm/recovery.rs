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

//! Consensus-native disclosed credits recovery. Classical ownership enrollment is
//! confined to the preparation window; subsequent authority is the enrolled PQ key.

use super::*;
use console::account::Signature;
use snarkvm_ledger_block::{Input, Recovery};
use snarkvm_recovery::{self as core, Backends, Digest64, Ledger as RecoveryLedger, Operation, Policy};
use snarkvm_recovery_signatures::{AleoLegacy, Falcon512Verifier, MlDsa65Verifier};

fn backends() -> Result<Backends> {
    let mut backends = Backends::default();
    backends.register_signature(Box::new(MlDsa65Verifier))?;
    backends.register_signature(Box::new(Falcon512Verifier))?;
    Ok(backends)
}

fn network_policy<N: Network>() -> Result<Policy> {
    let scheduled = |version| N::CONSENSUS_HEIGHT(version).map(|height| (height != u32::MAX).then_some(height));
    let policy = Policy {
        preparation: scheduled(ConsensusVersion::V23)?,
        recovery: scheduled(ConsensusVersion::V24)?,
        ..Policy::default()
    };
    policy.validate()?;
    Ok(policy)
}

/// Fail before ledger initialization if the consensus-required implementation is absent.
pub fn check_recovery_capabilities<N: Network>() -> Result<()> {
    let policy = network_policy::<N>()?;
    backends()?.require(&policy.profiles, &policy.aggregates)?;
    Ok(())
}

/// Initial consensus fee schedule: a fixed 1,000 microcredits plus one per encoded byte.
/// This bounds free admission; it is an experimental resource schedule, not a measured gas model.
pub fn recovery_minimum_fee<N: Network>(recovery: &Recovery<N>) -> Result<u64> {
    recovery.minimum_fee()
}

struct Application<N: Network> {
    checkpoint: Vec<u8>,
    serials: Vec<Field<N>>,
    before: Digest64,
    after: Digest64,
    historical_pool: Option<u64>,
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// The complete actual genesis bytes bind local devnets as well as public networks.
    pub fn recovery_network(&self) -> Result<Digest64> {
        let hash = self
            .block_store()
            .get_block_hash(0)?
            .ok_or_else(|| anyhow!("Recovery requires an authenticated genesis"))?;
        let genesis = self.block_store().get_block(&hash)?.ok_or_else(|| anyhow!("Genesis body is missing"))?;
        Ok(core::digest(b"AleoRecoveryChain1", &[&N::ID.to_le_bytes(), &genesis.to_bytes_le()?]))
    }

    pub fn recovery_policy(&self) -> Result<Policy> {
        network_policy::<N>()
    }

    fn recovery_ledger(&self, backends: &Backends) -> Result<RecoveryLedger> {
        let network = self.recovery_network()?;
        let policy = self.recovery_policy()?;
        Ok(match self.finalize_store().recovery_state()? {
            Some(bytes) => RecoveryLedger::restore(network, policy, &bytes, backends)?,
            None => RecoveryLedger::from_trusted_records(network, policy, vec![], backends)?,
        })
    }

    pub fn recovery_checkpoint(&self) -> Result<Vec<u8>> {
        Ok(self.recovery_ledger(&backends()?)?.checkpoint())
    }

    pub fn recovery_root(&self) -> Result<Digest64> {
        Ok(self.recovery_ledger(&backends()?)?.state_root())
    }

    /// A confirmed RPC snapshot cannot observe the interval between block insertion and finalization.
    pub fn recovery_snapshot(&self) -> Result<(Digest64, Policy, Vec<u8>, Digest64, u32)> {
        let _guard = self.recovery_snapshot_lock.read();
        let network = self.recovery_network()?;
        let policy = self.recovery_policy()?;
        let backends = backends()?;
        let ledger = match self.finalize_store().recovery_state_confirmed()? {
            Some(bytes) => RecoveryLedger::restore(network, policy.clone(), &bytes, &backends)?,
            None => RecoveryLedger::from_trusted_records(network, policy.clone(), vec![], &backends)?,
        };
        Ok((network, policy, ledger.checkpoint(), ledger.state_root(), self.block_store().current_block_height()))
    }

    /// Shared exclusion: legacy execution, private fees and native preparation use one serial domain.
    pub fn contains_serial_number(&self, serial: &Field<N>) -> Result<bool> {
        Ok(self.transition_store().contains_serial_number(serial)?
            || self.finalize_store().recovery_contains_serial(serial)?)
    }

    pub(crate) fn check_authorization_policy(
        &self,
        version: ConsensusVersion,
        transaction: &Transaction<N>,
    ) -> Result<()> {
        if transaction.is_recovery() {
            ensure!(version >= ConsensusVersion::V23, "Native recovery is not activated");
            return Ok(());
        }
        version.ensure_legacy_transaction_authorization()?;
        if version >= ConsensusVersion::V23 {
            // Include external/dynamic record classes even when they have no serial at this call site.
            let record_bearing = transaction.transitions().any(|transition| {
                transition.inputs().iter().any(|input| {
                    matches!(
                        input,
                        Input::Record(..)
                            | Input::ExternalRecord(..)
                            | Input::DynamicRecord(..)
                            | Input::RecordWithDynamicID(..)
                            | Input::ExternalRecordWithDynamicID(..)
                    )
                }) || transition.outputs().iter().any(|output| {
                    matches!(
                        output,
                        Output::Record(..)
                            | Output::ExternalRecord(..)
                            | Output::DynamicRecord(..)
                            | Output::RecordWithDynamicID(..)
                            | Output::ExternalRecordWithDynamicID(..)
                    )
                })
            });
            ensure!(!record_bearing, "Legacy record operations are retired; owner-authorized preparation is required");
        }
        Ok(())
    }

    /// Authenticate the creating transition against the actual charged transaction and block body.
    pub(super) fn historical_source_height(&self, commitment: &Field<N>) -> Result<u32> {
        let transition_id = self.transition_store().find_transition_id(commitment)?;
        let transition = self
            .transition_store()
            .get_transition(&transition_id)?
            .ok_or_else(|| anyhow!("Historical source transition is missing"))?;
        ensure!(transition.program_id() == &ProgramID::credits(), "Only native credits.aleo sources are supported");
        ensure!(
            transition.outputs().iter().any(
                |output| matches!(output, Output::Record(output_commitment, ..) if output_commitment == commitment)
            ),
            "Unsupported historical source output class"
        );
        let transaction_id = self
            .transaction_store()
            .find_transaction_id_from_transition_id(&transition_id)?
            .ok_or_else(|| anyhow!("Source transaction is not authenticated"))?;
        let confirmed = self
            .block_store()
            .get_confirmed_transaction(&transaction_id)?
            .ok_or_else(|| anyhow!("Historical source transaction is not confirmed"))?;
        // Rejected executions authenticate only their charged fee transition.
        ensure!(
            confirmed.transaction().transitions().any(|candidate| candidate == &transition),
            "Historical source transition was not committed"
        );
        let block_hash = self
            .block_store()
            .find_block_hash(&confirmed.transaction().id())?
            .ok_or_else(|| anyhow!("Source is absent from authenticated block state"))?;
        let block = self
            .block_store()
            .get_block(&block_hash)?
            .ok_or_else(|| anyhow!("Historical source block body is missing"))?;
        ensure!(
            block.transactions().iter().any(|candidate| candidate == &confirmed),
            "Historical source is absent from the committed block body"
        );
        Ok(block.height())
    }

    fn validate_recovery(&self, height: u32, envelope: &Recovery<N>) -> Result<Application<N>> {
        ensure!(
            envelope.transaction().effects.fee >= recovery_minimum_fee(envelope)?,
            "Insufficient native recovery fee"
        );
        ensure!(envelope.transaction().effects.fee <= N::MAX_FEE, "Native recovery fee exceeds the maximum limit");
        let backends = backends()?;
        let network = self.recovery_network()?;
        let mut ledger = self.recovery_ledger(&backends)?;
        let before = ledger.state_root();
        let tx = envelope.transaction();
        let preparing = tx.effects.operation == Operation::Prepare;
        ensure!(
            if preparing { envelope.sources().len() == tx.effects.inputs.len() } else { envelope.sources().is_empty() },
            "Invalid historical source set"
        );
        let mut serials = Vec::with_capacity(envelope.sources().len());
        let mut historical_amount = 0u64;
        for (source, input) in envelope.sources().iter().zip(&tx.effects.inputs) {
            let record = source.source_record(&network)?;
            ensure!(&record.id(&network) == input, "Source order or commitment differs from authorized input");
            let serial = source.serial_number()?;
            ensure!(
                !serials.contains(&serial) && !self.contains_serial_number(&serial)?,
                "Historical record is already consumed"
            );
            let source_height = self.historical_source_height(source.commitment())?;
            // The existing inclusion upgrade treats records at its boundary as historical too.
            if height >= N::INCLUSION_UPGRADE_HEIGHT()? && source_height <= N::INCLUSION_UPGRADE_HEIGHT()? {
                ensure!(record.amount <= 1_000_000_000_000, "Historical credits record exceeds upgrade limit");
                historical_amount = historical_amount
                    .checked_add(record.amount)
                    .ok_or_else(|| anyhow!("Historical amount overflow"))?;
            }
            ledger.import_verified_source(record, &backends)?;
            serials.push(serial);
        }
        let plan = ledger.plan(height, &tx.effects, &backends)?;
        ensure!(
            plan.legacy.len() == envelope.sources().len() && tx.legacy.len() == envelope.sources().len(),
            "Historical authorizations do not match sources"
        );
        for ((source, statement), evidence) in envelope.sources().iter().zip(&plan.legacy).zip(&tx.legacy) {
            let signature = Signature::<N>::from_bytes_le(evidence)?;
            source.verify(&network, &statement.message, &signature)?;
        }
        // Direct signature evidence is the only production policy. No aggregate fallback exists.
        ledger.apply(height, tx, &AleoLegacy::<N>::default(), &backends)?;
        let historical_pool = if historical_amount == 0 {
            None
        } else {
            let key = Self::historical_pool_key()?;
            let amount = match self.finalize_store().get_value_speculative(
                ProgramID::credits(),
                Identifier::from_str("pool")?,
                &key,
            )? {
                None => 0,
                Some(Value::Plaintext(Plaintext::Literal(Literal::U64(value), _))) => *value,
                _ => bail!("Invalid credits historical pool state"),
            };
            let updated = amount.checked_add(historical_amount).ok_or_else(|| anyhow!("Historical pool overflow"))?;
            ensure!(updated <= 4_000_000_000_000, "Historical credits upgrade pool is exhausted");
            Some(updated)
        };
        Ok(Application {
            checkpoint: ledger.checkpoint(),
            serials,
            before,
            after: ledger.state_root(),
            historical_pool,
        })
    }

    fn historical_pool_key() -> Result<Plaintext<N>> {
        Plaintext::from_str("aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc")
    }

    pub(crate) fn check_native_recovery(&self, height: u32, envelope: &Recovery<N>) -> Result<()> {
        self.validate_recovery(height, envelope).map(|_| ())
    }

    /// Called only inside the existing FinalizeStore atomic batch, in canonical block order.
    pub(crate) fn finalize_native_recovery(
        &self,
        height: u32,
        envelope: &Recovery<N>,
    ) -> Result<Vec<FinalizeOperation<N>>> {
        let application = self.validate_recovery(height, envelope)?;
        snarkvm_ledger_store::atomic_batch_scope!(self.finalize_store(), {
            let mut operations = Vec::with_capacity(2);
            if let Some(pool) = application.historical_pool {
                operations.push(self.finalize_store().update_key_value(
                    ProgramID::credits(),
                    Identifier::from_str("pool")?,
                    Self::historical_pool_key()?,
                    Value::from_str(&format!("{pool}u64"))?,
                )?);
            }
            self.finalize_store().set_recovery_state(height, application.checkpoint)?;
            for serial in application.serials {
                self.finalize_store().recovery_mark_serial(serial, height)?;
            }
            operations.push(FinalizeOperation::Recovery(application.before, application.after));
            Ok(operations)
        })
    }
}

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

//! Backend qualification probe: both witnesses x and -x satisfy public x^2 = y,
//! but an unmasked constant trace reveals which private witness was supplied.
//! This is not an Aleo proof and is never an accepted recovery backend.
//! Prover boilerplate follows Winterfell's MIT-licensed examples; see LICENSE.winterfell.
#![forbid(unsafe_code)]

use winterfell::{
    AcceptableOptions,
    Air,
    AirContext,
    Assertion,
    AuxRandElements,
    BatchingMethod,
    CompositionPoly,
    CompositionPolyTrace,
    ConstraintCompositionCoefficients,
    DefaultConstraintCommitment,
    DefaultConstraintEvaluator,
    DefaultTraceLde,
    EvaluationFrame,
    FieldExtension,
    PartitionOptions,
    Proof,
    ProofOptions,
    Prover,
    StarkDomain,
    TraceInfo,
    TracePolyTable,
    TraceTable,
    TransitionConstraintDegree,
    crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256},
    math::{FieldElement, StarkField, fields::f128::BaseElement},
    matrix::ColMatrix,
};

type B = BaseElement;
type H = Blake3_256<B>;

struct SquareAir {
    context: AirContext<B>,
    public_square: B,
}

impl Air for SquareAir {
    type BaseField = B;
    type PublicInputs = B;

    fn new(trace: TraceInfo, public_square: B, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new(
                trace,
                vec![
                    TransitionConstraintDegree::new(1),
                    TransitionConstraintDegree::new(2),
                    TransitionConstraintDegree::new(1),
                ],
                2,
                options,
            ),
            public_square,
        }
    }

    fn context(&self) -> &AirContext<B> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<B>>(&self, frame: &EvaluationFrame<E>, _: &[E], result: &mut [E]) {
        result[0] = frame.next()[0] - frame.current()[0];
        result[1] = frame.current()[0] * frame.current()[0] - E::from(self.public_square);
        result[2] = frame.next()[1] - frame.current()[1] - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<B>> {
        vec![
            Assertion::single(1, 0, B::ZERO),
            Assertion::single(1, self.trace_length() - 1, B::new((self.trace_length() - 1) as u128)),
        ]
    }
}

struct SquareProver(ProofOptions);

impl Prover for SquareProver {
    type Air = SquareAir;
    type BaseField = B;
    type ConstraintCommitment<E: FieldElement<BaseField = B>> = DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = B>> = DefaultConstraintEvaluator<'a, SquareAir, E>;
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<H>;
    type Trace = TraceTable<B>;
    type TraceLde<E: FieldElement<BaseField = B>> = DefaultTraceLde<E, H, Self::VC>;
    type VC = MerkleTree<H>;

    fn get_pub_inputs(&self, trace: &TraceTable<B>) -> B {
        trace.get(0, 0).square()
    }

    fn options(&self) -> &ProofOptions {
        &self.0
    }

    fn new_trace_lde<E: FieldElement<BaseField = B>>(
        &self,
        info: &TraceInfo,
        trace: &ColMatrix<B>,
        domain: &StarkDomain<B>,
        partition: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(info, trace, domain, partition)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = B>>(
        &self,
        air: &'a SquareAir,
        aux: Option<AuxRandElements<E>>,
        coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux, coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = B>>(
        &self,
        trace: CompositionPolyTrace<E>,
        columns: usize,
        domain: &StarkDomain<B>,
        partition: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(trace, columns, domain, partition)
    }
}

fn recover_witness(proof: &Proof) -> Result<B, Box<dyn std::error::Error>> {
    let (_, opened) = proof.trace_queries[0].clone().parse::<B, H, MerkleTree<H>>(
        proof.lde_domain_size(),
        usize::from(proof.num_unique_queries),
        2,
    )?;
    Ok(opened.get_row(0)[0])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options =
        ProofOptions::new(32, 8, 0, FieldExtension::None, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear);
    let prover = SquareProver(options.clone());
    let acceptable = AcceptableOptions::OptionSet(vec![options]);
    for witness in [B::new(3), -B::new(3)] {
        let mut trace = TraceTable::new(2, 64);
        trace.fill(
            |row| {
                row[0] = witness;
                row[1] = B::ZERO;
            },
            |_, row| row[1] += B::ONE,
        );
        let encoded = prover.prove(trace)?.to_bytes();
        // An observer receives only public proof bytes, not prover memory.
        let proof = Proof::from_bytes(&encoded)?;
        winterfell::verify::<SquareAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(proof.clone(), B::new(9), &acceptable)?;
        assert!(
            winterfell::verify::<SquareAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
                proof.clone(),
                B::new(10),
                &acceptable,
            )
            .is_err(),
            "proof must bind the public square"
        );
        let recovered = recover_witness(&proof)?;
        assert_eq!(witness, recovered);
        println!(
            "public_square=9 valid_proof=true private_witness={} recovered_from_proof={} proof_bytes={}",
            witness.as_int(),
            recovered.as_int(),
            encoded.len()
        );
    }
    println!("qualification=REJECT unmasked_default_trace_is_not_zero_knowledge");
    Ok(())
}

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

//! Experimental public-value recovery ledger. This is not an Aleo private-record
//! proof system and is not connected to the production transaction enum or store.
//! Authenticating its initial records requires a separately trusted import.
#![forbid(unsafe_code)]

mod backend;
mod codec;
mod ledger;
mod statement;

pub use backend::*;
pub use ledger::*;
pub use statement::*;

use sha3::{Digest, Sha3_512};

pub type Digest64 = [u8; 64];
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Limit,
    Unsupported,
    MissingBackend,
    InvalidKey,
    InvalidSignature,
    InvalidAggregate,
    Policy,
    Ownership,
    Spent,
    Replay,
    Conservation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recovery: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Every component, including the domain, has a little-endian u64 byte length.
pub fn digest(domain: &[u8], parts: &[&[u8]]) -> Digest64 {
    let mut hash = Sha3_512::new();
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

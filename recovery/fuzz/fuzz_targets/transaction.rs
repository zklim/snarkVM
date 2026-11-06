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

#![no_main]
#![forbid(unsafe_code)]

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(transaction) = snarkvm_recovery::Transaction::decode(bytes) {
        assert_eq!(transaction.encode().expect("decoded transaction is valid"), bytes);
        let effects = transaction.effects.encode().expect("decoded effects are valid");
        assert_eq!(
            snarkvm_recovery::Effects::decode(&effects).expect("encoded effects are valid"),
            transaction.effects
        );
    }
});

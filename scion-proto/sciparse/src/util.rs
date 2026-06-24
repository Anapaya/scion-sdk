// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Sciparse utility functions.

use proptest::{
    prelude::{Arbitrary, Strategy},
    strategy::ValueTree,
};

#[cfg(feature = "fuzz")]
pub mod fuzz;

/// A helper trait to generate arbitrary values of a type that implements `Arbitrary` using a seed.
pub trait ToValue {
    /// The parameters for generating arbitrary values of type `T`.
    type Params: Default;

    /// Generates an arbitrary value of type `T` using the given seed.
    fn arbitrary_value(seed: u128) -> Self;

    /// Generates an arbitrary value of type `T` using the given parameters and seed.
    fn arbitrary_value_with(params: Self::Params, seed: u128) -> Self;
}
// Allow generating arbitrary values for any type that implements `Arbitrary` using the `ToValue`
// trait.
impl<T: Arbitrary> ToValue for T {
    type Params = <T as Arbitrary>::Parameters;

    fn arbitrary_value(seed: u128) -> Self {
        Self::arbitrary_value_with(Self::Params::default(), seed)
    }

    fn arbitrary_value_with(params: Self::Params, seed: u128) -> Self {
        // XXX(ake): This is a bit hacky, but proptest does not provide a way to generate arbitrary
        // values directly.
        let rng = proptest::test_runner::TestRng::from_seed(
            proptest::test_runner::RngAlgorithm::ChaCha,
            &[seed.to_le_bytes(), [0; 16]].concat(),
        );
        let config = proptest::test_runner::Config {
            failure_persistence: None,
            ..Default::default()
        };

        let mut runner = proptest::test_runner::TestRunner::new_with_rng(config, rng);

        T::arbitrary_with(params)
            .new_tree(&mut runner)
            .unwrap()
            .current()
    }
}

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

//! Contains tests for SCION SCMP message parsing and encoding/decoding
//!
//! 1. All valid SCMP messages should roundtrip through encode/decode preserving all information and
//!    not causing any panics. One exception is that quoted offending packets may be truncated to
//!    fit within the maximum SCMP packet allowed size.
//! 2. Decoding a random buffer into an SCMP message view must not panic.
//! 3. Decoding a truncated SCMP message must not panic.

mod helpers;

use std::panic::catch_unwind;

use helpers::scmp::{
    HEADER_AND_EXTENSIONS_SIZE, ValidScmpMessageOptions, exec_every_view_function,
    test_address_header,
};
use proptest::{
    collection::vec,
    prelude::{ProptestConfig, Strategy, any},
    prop_assert, prop_assert_eq, proptest,
};
use sciparse::{
    core::view::{View, ViewConversionError},
    payload::scmp::{model::ScmpMessage, view::ScmpPayloadView},
};

#[test]
fn valid_scmp_messages_should_roundtrip_correctly() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(opts: ValidScmpMessageOptions)| {
            test_impl(opts)?;
        }
    );

    fn test_impl(opts: ValidScmpMessageOptions) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let (expected, mut buf) =
                opts.encode(&test_address_header(), HEADER_AND_EXTENSIONS_SIZE)?;

            let (view, rest) =
                ScmpPayloadView::from_mut_slice(&mut buf).expect("Creating ScmpPayloadView failed");
            prop_assert_eq!(rest.len(), 0);

            exec_every_view_function(view);

            let message_view = view.message();
            let reconstructed = ScmpMessage::from_view(&message_view);

            prop_assert_eq!(expected, reconstructed);

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!("Panic during SCMP roundtrip with options: {:#?}", opts);
                println!("---");
                println!("{:?}", panic.downcast_ref::<&str>());

                prop_assert_eq!(true, false, "Panic during SCMP roundtrip");
                Ok(())
            }
        }
    }
}

#[test]
fn parsing_random_data_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(mut data in vec(any::<u8>(), 0..=512))| {
            let unwind = catch_unwind(move || {
                match ScmpPayloadView::from_mut_slice(&mut data) {

                    Ok((view, _rest)) => {
                        exec_every_view_function(view);
                    }
                    Err(ViewConversionError::BufferTooSmall { .. })
                    | Err(ViewConversionError::Other(_)) => {}
                }

                Ok::<(), proptest::prelude::TestCaseError>(())
            });

            match unwind {
                Ok(res) => res?,
                Err(panic) => {
                    println!("{:?}", panic.downcast_ref::<&str>());
                    prop_assert!(false, "Panic during SCMP random data parsing");
                }
            }
        }
    );
}

#[test]
fn truncated_scmp_messages_must_not_panic() {
    let strategy = any::<ValidScmpMessageOptions>()
        .prop_filter_map("Encoding failed", |opts| {
            let buf = opts.encode(&test_address_header(), HEADER_AND_EXTENSIONS_SIZE);
            let buf = if let Ok((_, buf)) = buf {
                buf
            } else {
                // This should never happen, but we cannot panic inside a strategy.
                // This behavior is covered by the other tests.
                return None;
            };
            Some(buf)
        })
        .prop_flat_map(|buf| {
            (1..=buf.len()).prop_map(move |remove_bytes| (buf.clone(), remove_bytes))
        });

    proptest!(
        ProptestConfig::with_cases(5_000),
        |((mut buf, remove_bytes) in strategy)| {
            let unwind = catch_unwind(move || {
                buf.truncate(buf.len() - remove_bytes);

                match ScmpPayloadView::from_mut_slice(&mut buf) {
                    Ok((view, rest)) => {
                        prop_assert_eq!(rest.len(), 0);
                        exec_every_view_function(view);
                    }
                    Err(ViewConversionError::BufferTooSmall { .. })
                    | Err(ViewConversionError::Other(_)) => {}
                }

                Ok::<(), proptest::prelude::TestCaseError>(())
            });

            match unwind {
                Ok(res) => res?,
                Err(panic) => {
                    println!("{:?}", panic.downcast_ref::<&str>());
                    prop_assert!(false, "Panic during truncated SCMP message parsing");
                }
            }
        }
    );
}

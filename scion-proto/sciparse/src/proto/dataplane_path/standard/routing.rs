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

//! SCION standard path routing

use std::fmt::{Debug, Display};

use crate::dataplane_path::standard::{
    mac::{
        ForwardingKey,
        algo::{calculate_hop_mac, mac_beta_step},
    },
    types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
    view::{HopFieldView, InfoFieldView, StandardPathView},
};

/// Error type for failures during path advance.
#[derive(Debug, thiserror::Error)]
pub enum AdvanceError {
    /// The hop field index is out of bounds.
    #[error("hop out of bounds: {0}")]
    HopOutOfBounds(u8),
    /// The info field index is out of bounds.
    #[error("info out of bounds: {0}")]
    InfoOutOfBounds(u8),
    /// The current hop field index is in a different segment than the current info
    /// field index.
    #[error(
        "current hop field index is in segment {expected}, but info index is at segment {actual}"
    )]
    InvalidSegmentIndex {
        /// The expected segment index based on the hop field index
        expected: usize,
        /// The actual segment index
        actual: usize,
    },
    /// Generic unrecoverable error indicating that the path is in an invalid state for
    /// advancing.
    #[error("path is in invalid state for advance: {0}")]
    InvalidPathState(&'static str),
}

/// Error type for failures during path advance with validation.
#[derive(Debug, thiserror::Error)]
pub enum AdvanceValidateError<E: Debug> {
    /// The validator returned an error during validation of a hop field or segment
    /// change.
    #[error("validation failed: {0}")]
    ValidationFailed(E),
    /// The advance process failed due to an invalid path state, such as an out of
    /// bounds index.
    #[error("advance failed: {0}")]
    AdvanceFailed(#[from] AdvanceError),
}

/// Trait to allow validating hop fields and segment changes during path advance.
pub trait AdvanceValidator {
    /// The error type returned by the validator when validation fails
    type Error: Debug;

    /// Validates a hop field.
    ///
    /// This is called for each hop field required to be validated during advancing.
    ///
    /// Examples of what this function should validate include:
    /// - MAC validity
    /// - Correctness of the ingress and egress interfaces
    /// - HopField Expiry time
    ///
    /// If this returns an error, the advance process is aborted and the error is
    /// returned by the advance function.
    fn validate_hop(
        &self,
        hop_field: &HopFieldView,
        info_field: &InfoFieldView,
    ) -> Result<(), Self::Error>;

    /// Validates a segment change
    ///
    /// This is called when the path advances into a new segment, and allows validating
    /// the correctness of the transition between the two segments.
    ///
    /// Examples of what this function should validate include:
    /// - Correct link type for the transition between the two segments (e.g. no Down Segment
    ///   followed by an Up Segment)
    fn validate_segment_change(
        &self,
        current_hop_field: &HopFieldView,
        current_info_field: &InfoFieldView,
        next_hop_field: &HopFieldView,
        next_info_field: &InfoFieldView,
    ) -> Result<(), Self::Error>;
}

struct NoValidation;
impl AdvanceValidator for NoValidation {
    type Error = std::convert::Infallible;
    #[inline]
    fn validate_hop(
        &self,
        _hop_field: &HopFieldView,
        _info_field: &InfoFieldView,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline]
    fn validate_segment_change(
        &self,
        _current_hop_field: &HopFieldView,
        _current_info_field: &InfoFieldView,
        _next_hop_field: &HopFieldView,
        _next_info_field: &InfoFieldView,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Result of advancing the ingress of a path
pub struct IngressAdvanceResult {
    /// An SCMP alert was present on the packet, indicating it should be processed at
    /// the ingress router
    ///
    /// The router may choose to drop the packet after processing the alert, or it may
    /// choose to continue processing and forward the packet with the
    /// given action.
    pub scmp_alert: bool,
    /// The ingress interface according to the packet
    pub ingress_interface: u16,
    /// The action to perform with the packet after advancing
    pub action: IngressAdvanceAction,
}

/// Action to perform with the packet after advancing the ingress of a path
#[derive(Debug)]
pub enum IngressAdvanceAction {
    /// The packet should be sent out by its egress interface
    ContinueEgress {
        /// The interface through which the packet should be sent out
        egress_if: u16,
    },
    /// The packet is at the end of the path and should be processed at the local
    /// destination.
    ForwardLocal,
}

impl StandardPathView {
    /// Advances the path at ingress, without performing any validation.
    ///
    /// See [`Self::advance_ingress_with_validator`] for a version of this function that allows
    /// providing a validator to perform extended validation during the advance process.
    #[inline]
    pub fn advance_ingress(
        &mut self,
        from_internal_interface: bool,
    ) -> Result<IngressAdvanceResult, AdvanceError> {
        self.advance_ingress_with_validator(NoValidation, from_internal_interface)
            .map_err(|e| {
                match e {
                    AdvanceValidateError::AdvanceFailed(err) => err,
                    AdvanceValidateError::ValidationFailed(_) => {
                        // NoValidation cannot fail validation, so this branch should be
                        // unreachable
                        unreachable!()
                    }
                }
            })
    }

    /// Advances the path at ingress.
    ///
    /// If successful, the path is updated in-place to reflect the advance, and an
    /// [`IngressAdvanceResult`] indicating the next steps for processing the packet is
    /// returned.
    ///
    /// If the path is invalid or the advance process fails for any reason, an error is
    /// returned and the path is not modified.
    ///
    /// This function itself only performs minimal validation.
    ///
    /// Extended validation can be performed by providing a validator. An example
    /// validator is provided in the form of [`HopMacValidator`], which
    /// checks the validity of hop field MACs.
    ///
    /// To advance the path on egress, use the [`Self::advance_egress_with_validator`].
    ///
    /// ## Parameters
    /// - `validator`: A validator allowing to perform extended validation during the advance
    ///   process.
    /// - `from_internal_interface`: Indicates whether the advance is triggered by a packet arriving
    ///   from an internal interface, or if received from an external AS
    #[inline]
    pub fn advance_ingress_with_validator<ValidatorType, E>(
        &mut self,
        validator: ValidatorType,
        from_internal_interface: bool,
    ) -> Result<IngressAdvanceResult, AdvanceValidateError<E>>
    where
        ValidatorType: AdvanceValidator<Error = E>,
        E: Debug,
    {
        // Extract
        let hop_field_count = self.hop_field_count();
        let curr_hop_idx = self.curr_hop_field_idx() as usize;
        let curr_info_idx = self.curr_info_field_idx() as usize;

        let (seg_idx, end_of_segment) = self
            .calculate_segment_index(curr_hop_idx)
            .ok_or(AdvanceError::HopOutOfBounds(curr_hop_idx as u8))?;

        if seg_idx != curr_info_idx {
            return Err(AdvanceError::InvalidSegmentIndex {
                expected: seg_idx,
                actual: curr_info_idx,
            }
            .into());
        }

        let is_final_hop = curr_hop_idx + 1 >= hop_field_count as usize;

        // XXX(ake): In theory the check above guarantees that we can access the current
        // hop and info fields.
        let mut curr_hop_copy = *self
            .hop_field(curr_hop_idx)
            .ok_or(AdvanceError::HopOutOfBounds(curr_hop_idx as u8))?;

        let mut curr_info_copy = *self
            .curr_info_field()
            .ok_or(AdvanceError::InfoOutOfBounds(curr_info_idx as u8))?;

        let curr_ingress_interface = curr_hop_copy.ingress_interface(&curr_info_copy);

        let in_construction_dir = curr_info_copy.flags().contains(InfoFieldFlags::CONS_DIR);

        // Process

        // If not in construction dir, update mac before validation
        if !from_internal_interface && !in_construction_dir {
            let curr_segment_id = curr_info_copy.segment_id();
            let hop_mac = curr_hop_copy.mac();
            let new_segment_id = mac_beta_step(curr_segment_id, *hop_mac.as_bytes());
            curr_info_copy.set_segment_id(new_segment_id);
        }

        // Validate the current hop field
        validator
            .validate_hop(&curr_hop_copy, &curr_info_copy)
            .map_err(AdvanceValidateError::ValidationFailed)?;

        // Check if we have an SCMP alert at the ingress router.
        let scmp_alert = curr_hop_copy
            .flags()
            .normalized_ingress_router_alert(in_construction_dir);

        if !from_internal_interface && scmp_alert {
            // Unset the alert flag in the hop field
            let mut flags = curr_hop_copy.flags();
            match in_construction_dir {
                true => flags.remove(HopFieldFlags::CONS_INGRESS_ROUTER_ALERT),
                false => flags.remove(HopFieldFlags::CONS_EGRESS_ROUTER_ALERT),
            };
            curr_hop_copy.set_flags(flags);
        }

        let res = match (is_final_hop, end_of_segment) {
            // FINAL_HOP: process at local destination
            (true, true) => {
                IngressAdvanceResult {
                    scmp_alert,
                    ingress_interface: curr_ingress_interface,
                    action: IngressAdvanceAction::ForwardLocal,
                }
            }
            // NORMAL ADVANCE: continue to egress
            (false, false) => {
                IngressAdvanceResult {
                    scmp_alert,
                    ingress_interface: curr_ingress_interface,
                    action: IngressAdvanceAction::ContinueEgress {
                        egress_if: curr_hop_copy.egress_interface(&curr_info_copy),
                    },
                }
            }
            // SEGMENT CHANGE: advance to the next segment
            (false, true) => {
                let next_hop_field = self
                    .hop_field(curr_hop_idx + 1)
                    .ok_or(AdvanceError::HopOutOfBounds(curr_hop_idx as u8 + 1))?;
                let next_info_field = self
                    .info_field(seg_idx + 1)
                    .ok_or(AdvanceError::InfoOutOfBounds((seg_idx + 1) as u8))?;

                // Validate the segment change
                validator
                    .validate_segment_change(
                        &curr_hop_copy,
                        &curr_info_copy,
                        next_hop_field,
                        next_info_field,
                    )
                    .map_err(AdvanceValidateError::ValidationFailed)?;

                let egress_if = next_hop_field.egress_interface(next_info_field);

                // Validate the current hop field
                validator
                    .validate_hop(next_hop_field, next_info_field)
                    .map_err(AdvanceValidateError::ValidationFailed)?;

                // Advance the hop field index by one
                self.set_curr_hop_field((curr_hop_idx + 1) as u8);
                self.set_curr_info_field((seg_idx + 1) as u8);

                // NOTE: We are ignoring SCMP alerts which are set on the segment change
                // hop fields.

                IngressAdvanceResult {
                    scmp_alert,
                    ingress_interface: curr_ingress_interface,
                    action: IngressAdvanceAction::ContinueEgress { egress_if },
                }
            }
            _ => {
                unreachable!(
                    "The only case where we can have a final hop is when we are also at a segment end, which is handled by the first match arm"
                )
            }
        };

        // Commit the updated fields
        *self
            .info_field_mut(curr_info_idx)
            .expect("If we can get the current info field without mut, we can get it with mut") =
            curr_info_copy;
        *self
            .hop_field_mut(curr_hop_idx)
            .expect("If we can get the current hop field without mut, we can get it with mut") =
            curr_hop_copy;

        Ok(res)
    }
}

/// Result of advancing a path at the egress of a router.
///
/// The router may choose to drop the packet after processing the alert, or it may
/// choose to continue processing and forward the packet with the given
/// egress interface.
pub struct EgressAdvanceResult {
    /// An SCMP alert was present on the packet, indicating it should be processed at
    /// the egress router.
    pub scmp_alert: bool,
    /// The egress interface according to the packet.
    pub egress_interface: u16,
}

impl StandardPathView {
    /// Advances the path at egress, without performing any validation.
    ///
    /// See [`Self::advance_egress_with_validator`] for a version of this function that allows
    /// providing a validator to perform extended validation during the advance process.
    #[inline]
    pub fn advance_egress(&mut self) -> Result<EgressAdvanceResult, AdvanceError> {
        self.advance_egress_with_validator(NoValidation)
            .map_err(|e| {
                match e {
                    AdvanceValidateError::AdvanceFailed(err) => err,
                    AdvanceValidateError::ValidationFailed(_) => {
                        // NoValidation cannot fail validation, so this branch should be
                        // unreachable
                        unreachable!()
                    }
                }
            })
    }

    /// Advances the path at the egress of a router.
    ///
    /// This function itself only performs minimal validation.
    ///
    /// Extended validation can be performed by providing a custom validator, which can
    /// for example check the validity of the MAC, check if the segment
    /// change is allowed.
    #[inline]
    pub fn advance_egress_with_validator<ValidatorType, E>(
        &mut self,
        validator: ValidatorType,
    ) -> Result<EgressAdvanceResult, AdvanceValidateError<E>>
    where
        ValidatorType: AdvanceValidator<Error = E>,
        E: Debug + Display,
    {
        // Extract
        let hop_field_count = self.hop_field_count();
        let curr_hop_idx = self.curr_hop_field_idx() as usize;
        let curr_info_idx = self.curr_info_field_idx() as usize;

        let (seg_idx, end_of_segment) = self
            .calculate_segment_index(curr_hop_idx)
            .ok_or(AdvanceError::HopOutOfBounds(curr_hop_idx as u8))?;

        if seg_idx != curr_info_idx {
            return Err(AdvanceError::InvalidSegmentIndex {
                expected: seg_idx,
                actual: curr_info_idx,
            }
            .into());
        }

        let is_final_hop = curr_hop_idx + 1 >= hop_field_count as usize;

        // XXX(ake): In theory the check above guarantees that we can access the current
        // hop and info fields.
        let mut curr_hop_copy = *self
            .hop_field(curr_hop_idx)
            .ok_or(AdvanceError::HopOutOfBounds(curr_hop_idx as u8))?;

        let mut curr_info_copy = *self
            .curr_info_field()
            .ok_or(AdvanceError::InfoOutOfBounds(curr_info_idx as u8))?;

        let in_construction_dir = curr_info_copy.flags().contains(InfoFieldFlags::CONS_DIR);

        // Check

        if is_final_hop {
            // We are at the end of the path, we can't advance further
            return Err(AdvanceError::HopOutOfBounds(curr_hop_idx as u8 + 1).into());
        }

        if end_of_segment {
            // Segment change should never reach egress, it should have been handled at
            // ingress.
            return Err(AdvanceError::InvalidPathState(
                "Path is at segment end, which must have been handled at ingress",
            )
            .into());
        }

        if seg_idx != curr_info_idx {
            return Err(AdvanceError::InvalidSegmentIndex {
                expected: seg_idx,
                actual: curr_info_idx,
            }
            .into());
        }

        // Process

        validator
            .validate_hop(&curr_hop_copy, &curr_info_copy)
            .map_err(AdvanceValidateError::ValidationFailed)?;

        // Update segment_id if we are in construction dir
        if in_construction_dir {
            let curr_segment_id = curr_info_copy.segment_id();
            let hop_mac = curr_hop_copy.mac();
            let new_segment_id = mac_beta_step(curr_segment_id, *hop_mac.as_bytes());
            curr_info_copy.set_segment_id(new_segment_id);
        }

        // Check if we have an SCMP alert at the egress router.
        let scmp_alert = curr_hop_copy
            .flags()
            .normalized_egress_router_alert(in_construction_dir);
        if scmp_alert {
            // Unset the alert flag
            let mut flags = curr_hop_copy.flags();
            match in_construction_dir {
                true => flags.remove(HopFieldFlags::CONS_EGRESS_ROUTER_ALERT),
                false => flags.remove(HopFieldFlags::CONS_INGRESS_ROUTER_ALERT),
            };
            curr_hop_copy.set_flags(flags);
        }

        // Commit
        *self
            .info_field_mut(curr_info_idx)
            .expect("If we can get the current info field without mut, we can get it with mut") =
            curr_info_copy;
        *self
            .hop_field_mut(curr_hop_idx)
            .expect("If we can get the current hop field without mut, we can get it with mut") =
            curr_hop_copy;
        self.set_curr_hop_field((curr_hop_idx + 1) as u8);

        Ok(EgressAdvanceResult {
            scmp_alert,
            egress_interface: curr_hop_copy.egress_interface(&curr_info_copy),
        })
    }
}

/// Error type for invalid hop field MACs during validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
#[error("invalid hop field MAC: expected {expected:?}, got {actual:?}")]
pub struct InvalidMacError {
    expected: HopFieldMac,
    actual: HopFieldMac,
}
/// A validator for advancing a standard path, only checking the validity of hop field MACs.
///
/// This is not intended to be used in production, as it does not perform any other validation,
/// such as checking the validity of the ingress and egress interfaces, or checking hop field
/// expiry times.
#[derive(Clone)]
pub struct HopMacValidator {
    /// The key used for calculating the expected MACs of the hop field/s to be validated.
    pub key: ForwardingKey,
}
impl AdvanceValidator for HopMacValidator {
    type Error = InvalidMacError;

    #[inline]
    fn validate_hop(
        &self,
        hop_field: &HopFieldView,
        info_field: &InfoFieldView,
    ) -> Result<(), Self::Error> {
        let mac = hop_field.mac();
        let expected_mac = calculate_hop_mac(
            info_field.segment_id(),
            info_field.timestamp(),
            hop_field.exp_time(),
            hop_field.cons_ingress(),
            hop_field.cons_egress(),
            &self.key,
        );

        if mac.0 != expected_mac {
            Err(InvalidMacError {
                expected: expected_mac.into(),
                actual: mac,
            })
        } else {
            Ok(())
        }
    }

    #[inline]
    fn validate_segment_change(
        &self,
        _current_hop_field: &HopFieldView,
        _current_info_field: &InfoFieldView,
        _next_hop_field: &HopFieldView,
        _next_info_field: &InfoFieldView,
    ) -> Result<(), Self::Error> {
        // Note: We can't do any meaningful validation of the segment change without additional
        // information.  Like e.g. if an interface exists, what kind of interface it is
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use proptest::{prelude::Arbitrary, proptest, test_runner::Config};

    use crate::{
        core::{encode::WireEncode, view::View},
        dataplane_path::standard::{
            mac::ForwardingKey,
            model::{
                HopField, StandardPath,
                ptest::{ArbitraryForwardingKeyGenerator, ArbitraryPathContext},
            },
            routing::{HopMacValidator, IngressAdvanceAction},
            view::StandardPathView,
        },
    };

    struct StaticKeyGen;
    impl StaticKeyGen {
        pub const STATIC_KEY: ForwardingKey = [0u8; 16];
    }
    impl ArbitraryForwardingKeyGenerator for StaticKeyGen {
        fn generate(
            &self,
            _field: &HopField,
            _segment_index: usize,
            _segment_hop_index: usize,
            _segment_change: bool,
        ) -> ForwardingKey {
            Self::STATIC_KEY
        }
    }

    /// Validates that we can successfully advance through any valid path, including MAC
    /// checks, forwards and backwards.
    #[test]
    fn should_succeed_advancing_any_path() {
        proptest!(
            Config::with_cases(500),
            |(path in StandardPath::arbitrary_with(ArbitraryPathContext {
                forwarding_key_generator: Some(Arc::new(StaticKeyGen)),
                ..Default::default()
            }))| {
                test_imp(path)?;
            }
        );

        fn test_imp(path: StandardPath) -> Result<(), proptest::test_runner::TestCaseError> {
            let mut view = path.encode_to_vec()?;
            let (view, rest) = StandardPathView::from_mut_slice(view.as_mut_slice())?;
            if !rest.is_empty() {
                return Err(proptest::test_runner::TestCaseError::Fail(
                    "Encoded path has remaining bytes".into(),
                ));
            }

            advance_path(view, None)?;

            view.try_reverse()
                .expect("Reverse should succeed when we have advanced through the path");

            advance_path(view, None)?;

            Ok(())
        }
    }

    /// Validates that we can successfully reverse the path at any point, allowing it to be
    /// advanced forwards and backwards multiple times.
    #[test]
    fn should_succeed_reversing_at_any_point() {
        proptest!(
            Config::with_cases(500),
            |(
                path in StandardPath::arbitrary_with(ArbitraryPathContext {
                    forwarding_key_generator: Some(Arc::new(StaticKeyGen)),
                    ..Default::default()
                }),
                advance_seed in 0..255u8
            )| {
                test_imp(path, advance_seed)?;
            }
        );

        fn test_imp(
            path: StandardPath,
            advance_seed: u8,
        ) -> Result<(), proptest::test_runner::TestCaseError> {
            let mut view = path.encode_to_vec()?;
            let (view, rest) = StandardPathView::from_mut_slice(view.as_mut_slice())?;
            if !rest.is_empty() {
                return Err(proptest::test_runner::TestCaseError::Fail(
                    "Encoded path has remaining bytes".into(),
                ));
            }

            // Cap advance to number of hops in path
            let advance_count = advance_seed as usize % (view.hop_field_count() as usize - 1);
            advance_path(view, Some(advance_count as u8))?;

            view.try_reverse().expect(
                "Reverse should succeed when we have advanced through the
                    path",
            );

            advance_path(view, None)?;

            Ok(())
        }
    }

    /// Advances the path until we reach the end or the specified maximum number of steps,
    /// validating the MACs at each step.
    fn advance_path(
        view: &mut StandardPathView,
        max_steps: Option<u8>,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        if view.curr_hop_field_idx() == view.hop_field_count() - 1 {
            // We are at the end of the path, we can't advance further
            return Ok(());
        }

        let static_key = StaticKeyGen::STATIC_KEY;

        let validator = HopMacValidator { key: static_key };

        view.advance_ingress_with_validator(validator.clone(), true)
            .map_err(|e| {
                proptest::test_runner::TestCaseError::Fail(
                    format!("First Advance ingress failed: {e:?}").into(),
                )
            })?;

        view.advance_egress_with_validator(validator).map_err(|e| {
            proptest::test_runner::TestCaseError::Fail(
                format!("First Advance egress failed: {e:?}").into(),
            )
        })?;

        let mut steps = 1;
        loop {
            let validator = HopMacValidator { key: static_key };
            let res = view
                .advance_ingress_with_validator(validator.clone(), false)
                .map_err(|e| {
                    proptest::test_runner::TestCaseError::Fail(
                        format!("Advance failed: {e:?}").into(),
                    )
                })?;

            match res.action {
                // Continue to egress
                IngressAdvanceAction::ContinueEgress { egress_if: _ } => {}
                // We are at the end of the path, we can't advance further
                IngressAdvanceAction::ForwardLocal => {
                    break;
                }
            }

            steps += 1;

            if let Some(max) = max_steps
                && steps >= max
            {
                break;
            }

            view.advance_egress_with_validator(validator).map_err(|e| {
                proptest::test_runner::TestCaseError::Fail(format!("Advance failed: {e:?}").into())
            })?;
        }

        Ok(())
    }
}

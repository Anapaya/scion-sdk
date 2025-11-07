// Copyright 2025 Anapaya Systems
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
//! A set of non-overlapping ranges of positive integers.

use std::{
    cmp::Ordering,
    iter::Sum,
    ops::{Add, Sub},
};

use num_traits::{ConstOne, PrimInt, Unsigned};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur when removing a value from a range set.
#[derive(Debug, Error)]
pub enum RemoveError<T> {
    /// Value not in set.
    #[error("Value {0} not in set")]
    ValueNotInSet(T),
}

/// Errors that can occur when inserting a value into a range set.
#[derive(Debug, Error)]
pub enum InsertError<T> {
    /// Value already in set.
    #[error("value {0} already in set")]
    ValueAlreadyInSet(T),
}

/// Rangeset creation errors.
#[derive(Debug, Error)]
pub enum NewRangeSetError {
    /// Invalid ranges.
    #[error("ranges must be non-overlapping and sorted by start")]
    InvalidRanges,
}

/// A set of non-overlapping ranges of positive integers.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct RangeSet<T: PrimInt + ConstOne + Unsigned + Sum<T>> {
    ranges: Vec<Range<T>>,
}

impl<T: PrimInt + ConstOne + Unsigned + Sum<T>> RangeSet<T> {
    /// Create a new RangesSet from a vector of ranges. The ranges must be non-overlapping and
    /// sorted by start.
    pub fn new(ranges: Vec<Range<T>>) -> Result<Self, NewRangeSetError> {
        for i in 0..ranges.len() {
            // check if the range is valid
            if ranges[i].start >= ranges[i].end {
                return Err(NewRangeSetError::InvalidRanges);
            }
            // check if the ranges are and non-overlapping
            if i == 0 {
                continue;
            }
            if ranges[i - 1].end > ranges[i].start {
                return Err(NewRangeSetError::InvalidRanges);
            }
        }
        Ok(Self { ranges })
    }

    /// Returns true if the range set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Inserts a value into the range set.
    pub fn insert(&mut self, value: T) -> Result<(), InsertError<T>> {
        if self.ranges.is_empty() {
            self.ranges.push(Range::new(value, value + T::ONE));
            return Ok(());
        }

        // binary search for the range that contains the value
        let range = self.ranges.binary_search_by(|range| range.compare(&value));
        let i = match range {
            // If the value is already contained in a range, do nothing.
            Ok(_) => return Err(InsertError::ValueAlreadyInSet(value)),
            Err(i) => i,
        };
        assert!(i <= self.ranges.len());
        // i is the index where the new range should be inserted to keep the list sorted.
        // In other words: value < self[i].start
        if i == self.ranges.len() {
            // If the value is after the last range, we add a new range.
            if self.ranges.last().unwrap().end == value {
                self.ranges.last_mut().unwrap().end = value + T::ONE;
            } else {
                self.ranges.push(Range::new(value, value + T::ONE));
            }
        } else {
            if self.ranges[i].start == value + T::ONE {
                // a and free[i].start are adjacent, so we merge them.
                self.ranges[i].start = value;
            } else {
                // otherwise, we insert a new range.
                self.ranges.insert(i, Range::new(value, value + T::ONE));
            }

            // Merge with the previous range if it is adjacent.
            if i > 0 && self.ranges[i - 1].end == self.ranges[i].start {
                self.ranges[i - 1].end = self.ranges[i].end;
                self.ranges.remove(i);
            }
        }
        Ok(())
    }

    /// Returns the total length of all ranges in the set.
    pub fn len(&self) -> T {
        self.ranges.iter().map(|range| range.len()).sum()
    }

    /// Returns true if the value is contained in the range set.
    pub fn contains(&self, value: T) -> bool {
        self.ranges
            .binary_search_by(|range| range.compare(&value))
            .is_ok()
    }

    /// Removes a value from the range set.
    pub fn remove(&mut self, value: T) -> Result<(), RemoveError<T>> {
        let range = self.ranges.binary_search_by(|range| range.compare(&value));
        match range {
            Ok(i) => {
                if self.ranges[i].start == value {
                    // a is at the start of a range
                    self.ranges[i].start = value + T::ONE;
                    if self.ranges[i].is_empty() {
                        self.ranges.remove(i);
                    }
                } else if self.ranges[i].end - T::ONE == value {
                    // a is at the end of a range
                    self.ranges[i].end = value;
                    if self.ranges[i].is_empty() {
                        self.ranges.remove(i);
                    }
                } else {
                    // a is in the middle of a range
                    let new_range = Range::new(self.ranges[i].start, value);
                    self.ranges[i].start = value + T::ONE;
                    self.ranges.insert(i, new_range);
                }
                Ok(())
            }
            // If the value is not in any range, do nothing.
            Err(_) => Err(RemoveError::ValueNotInSet(value)),
        }
    }

    /// return the nth free value in the set.
    pub fn nth(&self, mut n: T) -> Option<T> {
        for range in self.ranges.iter() {
            if n < range.len() {
                return Some(range.nth(n).unwrap());
            }
            n = n - range.len();
        }
        None
    }

    /// Returns the ranges in the set.
    pub fn ranges(&self) -> &[Range<T>] {
        &self.ranges
    }
}

/// A half-open range of positive integers.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct Range<T: Ord + Sub<Output = T> + Add<Output = T> + Copy + Unsigned> {
    /// Start of the range.
    pub start: T,
    /// End of the range.
    pub end: T,
}

impl<T: Ord + Sub<Output = T> + Add<Output = T> + Copy + Unsigned> Range<T> {
    /// Creates a new range.
    pub fn new(start: T, end: T) -> Self {
        Self { start, end }
    }

    /// Compare the range to a value.
    pub fn compare(&self, other: &T) -> Ordering {
        if self.start <= *other && self.end > *other {
            Ordering::Equal
        } else if self.start > *other {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    /// Return the length of the range.
    pub fn len(&self) -> T {
        self.end - self.start
    }

    /// Returns true if the range is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns the n-th value in the range.
    pub fn nth(&self, n: T) -> Option<T> {
        if n >= self.len() {
            None
        } else {
            Some(self.start + n)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    // Utility function to check invariants on RangesSet
    fn check_rangeset_invariants<T: PrimInt + ConstOne + Unsigned + Sum<T> + std::fmt::Debug>(
        rangeset: &RangeSet<T>,
    ) {
        let ranges = rangeset.ranges();

        // Check that ranges are ordered and non-overlapping
        for i in 1..ranges.len() {
            // Ranges should be ordered
            assert!(
                ranges[i - 1].start < ranges[i].start,
                "Ranges not ordered: {:?} and {:?}",
                ranges[i - 1],
                ranges[i]
            );

            // Ranges should be disjoint
            assert!(
                ranges[i - 1].end <= ranges[i].start,
                "Ranges not disjoint: {:?} and {:?}",
                ranges[i - 1],
                ranges[i]
            );

            // Each range should be valid (start < end)
            assert!(
                ranges[i].start < ranges[i].end,
                "Invalid range: {:?}",
                ranges[i]
            );
        }
    }

    // Generic test function for random operations
    fn test_random_operations_generic<T, R: Rng>(rng: &mut R, start: T, end: T, type_name: &str)
    where
        T: PrimInt
            + ConstOne
            + Unsigned
            + Sum<T>
            + std::fmt::Debug
            + TryFrom<u128>
            + std::convert::Into<u128>,
        <T as std::convert::TryFrom<u128>>::Error: std::fmt::Debug,
    {
        println!("Running random operations test for {type_name}");

        let mut rangeset = RangeSet::new(vec![Range::new(start, end)]).unwrap();
        let mut allocated = Vec::new();

        // Calculate initial capacity
        let initial_capacity: T = end - start;
        let mut remaining = initial_capacity;

        // Test random allocations (removals from the set)
        for _i in 0..1000 {
            // Generate a random index within the current range length
            let range_len: u128 = rangeset.len().into();
            let random_index = rng.random_range(0..range_len);
            let n = T::try_from(random_index).unwrap();

            let value = rangeset.nth(n).unwrap();

            // Remove the value
            rangeset.remove(value).expect("Failed to remove value");
            check_rangeset_invariants(&rangeset);

            // Verify the value is no longer in the set
            assert!(
                !rangeset.contains(value),
                "Value should not be in set after removal"
            );

            // Track allocated value
            allocated.push(value);
            remaining = remaining - T::ONE;

            // Verify remaining capacity
            assert_eq!(rangeset.len(), remaining, "Remaining capacity mismatch");
        }

        // Test insertions (freeing previously allocated values)
        for value in allocated.iter() {
            rangeset.insert(*value).expect("Failed to insert value");
            check_rangeset_invariants(&rangeset);

            // Verify the value is now in the set
            assert!(
                rangeset.contains(*value),
                "Value should be in set after insertion"
            );

            // Update remaining
            remaining = remaining + T::ONE;
            assert_eq!(
                rangeset.len(),
                remaining,
                "Remaining capacity mismatch after insertion"
            );
        }

        // After all operations, we should be back to the initial state with a single range
        assert_eq!(
            rangeset.ranges().len(),
            1,
            "Expected single range after all operations"
        );
        assert_eq!(
            rangeset.len(),
            initial_capacity,
            "Expected full capacity after all operations"
        );
    }

    #[test]
    fn random_operations_maintain_invariants() {
        // Create RNGs with different seeds for each test
        let mut rng_u16 = ChaCha8Rng::seed_from_u64(42);
        let mut rng_u32 = ChaCha8Rng::seed_from_u64(43);
        let mut rng_u128 = ChaCha8Rng::seed_from_u64(44);

        // For u16, we'll use a smaller range to keep tests faster
        test_random_operations_generic(&mut rng_u16, 1, u16::MAX, "u16");

        // For u32, we'll use a moderately sized range
        test_random_operations_generic(&mut rng_u32, 1, u32::MAX, "u32");

        // For u128, we'll use a range that demonstrates the large capacity
        test_random_operations_generic(&mut rng_u128, 1, u128::MAX, "u128");
    }

    #[test]
    fn nth_returns_correct_element() {
        let rangeset: RangeSet<u16> = RangeSet::new(vec![
            Range::new(1, 5),   // 1,2,3,4
            Range::new(10, 15), // 10,11,12,13,14
        ])
        .unwrap();

        // Check that nth returns values in order
        assert_eq!(rangeset.nth(0), Some(1));
        assert_eq!(rangeset.nth(1), Some(2));
        assert_eq!(rangeset.nth(2), Some(3));
        assert_eq!(rangeset.nth(3), Some(4));
        assert_eq!(rangeset.nth(4), Some(10));
        assert_eq!(rangeset.nth(5), Some(11));
        assert_eq!(rangeset.nth(6), Some(12));
        assert_eq!(rangeset.nth(7), Some(13));
        assert_eq!(rangeset.nth(8), Some(14));
        assert_eq!(rangeset.nth(9), None); // No 10th element
    }

    #[test]
    fn boundary_values_handled_correctly() {
        // Test boundary values
        let test_cases = [
            (1u32, 10),  // Small range
            (1u32, 100), // Medium range
            (1u32, 200), // Non-starting range
        ];

        for (start, end) in test_cases {
            let mut rangeset = RangeSet::new(vec![Range::new(start, end)]).unwrap();
            let original_len = rangeset.len();

            // Test lower boundary
            assert!(rangeset.contains(start), "Lower boundary should be in set");
            assert!(
                !rangeset.contains(start - 1),
                "Value before lower boundary should not be in set"
            );

            // Test upper boundary
            assert!(
                !rangeset.contains(end),
                "Upper boundary should not be in set (half-open range)"
            );
            assert!(
                rangeset.contains(end - 1),
                "Value just before upper boundary should be in set"
            );

            // Remove lower boundary
            rangeset
                .remove(start)
                .expect("Failed to remove lower boundary");
            assert!(
                !rangeset.contains(start),
                "Lower boundary should be removed"
            );
            assert_eq!(
                rangeset.len(),
                original_len - 1,
                "Length should decrease by 1"
            );

            // Remove upper boundary
            rangeset
                .remove(end - 1)
                .expect("Failed to remove upper boundary - 1");
            assert!(
                !rangeset.contains(end - 1),
                "Upper boundary - 1 should be removed"
            );

            // Try to remove values outside the range
            assert!(
                rangeset.remove(start - 1).is_err(),
                "Should fail to remove value outside lower boundary"
            );
            assert!(
                rangeset.remove(end).is_err(),
                "Should fail to remove value at upper boundary"
            );
            assert!(
                rangeset.remove(end + 1).is_err(),
                "Should fail to remove value beyond upper boundary"
            );

            // Re-insert boundaries
            rangeset
                .insert(start)
                .expect("Failed to insert lower boundary");
            rangeset
                .insert(end - 1)
                .expect("Failed to insert upper boundary - 1");

            // Verify restored state
            assert_eq!(
                rangeset.len(),
                original_len,
                "Should restore original length"
            );
            check_rangeset_invariants(&rangeset);
        }
    }

    #[test]
    fn adjacent_ranges_merge_on_insert() {
        let mut rangeset = RangeSet::new(vec![
            Range::new(1u32, 5), // 1,2,3,4
            Range::new(10, 15),  // 10,11,12,13,14
        ])
        .unwrap();

        // Insert value that bridges the gap
        rangeset
            .insert(5)
            .expect("Failed to insert value at start of gap");
        check_rangeset_invariants(&rangeset);

        // Should still be separate ranges
        assert_eq!(rangeset.ranges().len(), 2);

        // Insert values to fill the gap
        for val in 6..=9 {
            rangeset.insert(val).expect("Failed to insert gap value");
            check_rangeset_invariants(&rangeset);
        }

        // Ranges should now be merged
        assert_eq!(
            rangeset.ranges().len(),
            1,
            "Ranges should merge when gap is filled"
        );
        assert_eq!(rangeset.ranges()[0].start, 1);
        assert_eq!(rangeset.ranges()[0].end, 15);
    }

    #[test]
    fn remove_splits_ranges_correctly() {
        let mut rangeset = RangeSet::new(vec![Range::new(1u32, 10)]).unwrap();

        // Remove a value from the middle, splitting the range
        rangeset.remove(5).expect("Failed to remove middle value");
        check_rangeset_invariants(&rangeset);

        // Should now have two ranges
        assert_eq!(
            rangeset.ranges().len(),
            2,
            "Range should split when middle value is removed"
        );
        assert_eq!(rangeset.ranges()[0].start, 1);
        assert_eq!(rangeset.ranges()[0].end, 5);
        assert_eq!(rangeset.ranges()[1].start, 6);
        assert_eq!(rangeset.ranges()[1].end, 10);

        // Remove values from edges, shouldn't cause splits
        rangeset.remove(1).expect("Failed to remove start value");
        check_rangeset_invariants(&rangeset);
        rangeset.remove(9).expect("Failed to remove end value");
        check_rangeset_invariants(&rangeset);

        // Still two ranges, just smaller
        assert_eq!(
            rangeset.ranges().len(),
            2,
            "Should still have 2 ranges after edge removals"
        );
    }
}

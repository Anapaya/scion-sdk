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

use std::time::Duration;

/// Exponential decay: value halves every `half_life`.
/// Formula: N(t) = N0 * 2^(-t / half_life)
pub fn exponential_decay(base: f32, time_delta: Duration, half_life: Duration) -> f32 {
    if base == 0.0 {
        return 0.0;
    }

    let half_life_secs = half_life.as_secs_f32();
    let elapsed_secs = time_delta.as_secs_f32();

    // Safety check
    if half_life_secs <= 0.0 {
        return 0.0;
    }

    let decay_factor = 2f32.powf(-elapsed_secs / half_life_secs);
    base * decay_factor
}

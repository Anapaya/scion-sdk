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
//! # Packet Fragmentation
//!
//! This module provides a [crate::fragmenting::Fragmenter] and
//! [crate::fragmenting::Defragmenter]
//!
//! These can split and reassemble a Packet to/from multiple
//! [crate::fragmenting::FragmentFrameRef].
//!
//! ## Protocol:
//!
//! De/Fragmenter communicate through following Frame Header
//!
//! 0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! .-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-.
//! |                                                               |
//! .                         stream offset                         .
//! |                                                               |
//! .-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-.
//! |       frame offset            |L|            reserved         |
//! .-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-.
//! |                                                               |
//! .                     ...  payload  ...                         .
//! |                                                               |
//! .................................................................
//!
//! stream offset: 64 bits - The offset in bytes of the start of the packet in the stream.
//! frame offset: 16 bits - The offset in bytes of the start of the fragment in the packet.
//! L: 1 bit - Last fragment flag.
//! payload: variable length - The fragment payload.
//!
//! ## Logic
//!
//! The [crate::fragmenting::Fragmenter] splits an outgoing packet into one or
//! more fragments, each prefixed with a
//! [crate::fragmenting::proto::FragmentFrameHeader]. The payload size of each
//! fragment is determined by the configured MTU minus the header size. The last
//! fragment is marked with the `L` (LAST) flag.
//!
//! Each fragment is emitted sequentially via the provided sink callback, carrying:
//! - the absolute stream offset (monotonically increasing across packets),
//! - the per-packet frame offset (starting at zero),
//! - the payload bytes for that fragment.
//!
//! The [crate::fragmenting::Defragmenter] receives individual fragments,
//! possibly out of order, and reassembles them into complete packets. It
//! maintains multiple reassembly queues to handle concurrent or interleaved
//! packet streams.
//!
//! Each reassembly queue tracks:
//! - the target stream offset of the packet,
//! - a bitmask indicating which fragments have been received,
//! - a buffer for reassembly,
//! - and the expected number of frames (once determinable).
//!
//! When all expected frames have been received, the queue yields a complete
//! [crate::fragmenting::PacketRef] referencing the reassembled payload. The
//! queue then becomes idle and reusable.
//!
//! If all queues are occupied and a new fragment arrives for a stream offset older than
//! the oldest active queue, it is rejected with a
//! [`crate::fragmenting::DefragmentInsertError::TooOld`] error.
//! Otherwise, the oldest queue is evicted to make space for the new packet.
//!
//! The implementation enforces strict upper bounds:
//! - No more than [crate::fragmenting::MAX_FRAMES] fragments per packet.
//! - No payload exceeding [crate::fragmenting::MAX_PACKET_SIZE].
//! - No MTU below [crate::fragmenting::MIN_MTU] or above [crate::fragmenting::MAX_MTU].
//!
//! This ensures constant memory usage, bounded runtime behavior,
//! and deterministic fragment handling under all conditions.

use std::fmt::Debug;

use scion_sdk_observability::metrics::registry::MetricsRegistry;
use thiserror::Error;

use crate::fragmenting::{
    metrics::{DefragmentMetrics, FragmentMetrics},
    proto::{FragmentFlags, FragmentFrameHeader},
};

// Bitmap Parameters for tracking received frames in defragmenter
type BitmaskType = u128;
const BITMASK_ENTRY_BITS: usize = BitmaskType::BITS as usize;
const BITMASK_ENTRY_COUNT: usize = 2;

/// Max Packet Size, the Defragmenter will keep multiple buffers of this size
pub const MAX_PACKET_SIZE: usize = u16::MAX as usize;
/// Limits the number of frames, allowing is to use a bitmask to track received frames
pub const MAX_FRAMES: usize = BITMASK_ENTRY_BITS * BITMASK_ENTRY_COUNT;
/// The largest MTU we will ever use, a buffer on stack is reserved for this size
pub const MAX_MTU: usize = 9000;
/// The smallest MTU that can send MAX_PACKET_SIZE in MAX_FRAMES
pub const MIN_MTU: usize =
    (MAX_PACKET_SIZE + proto::FragmentFrameHeader::SIZE * MAX_FRAMES).div_ceil(MAX_FRAMES);
/// The minimum possible payload size of a fragment, does not apply to last fragments
pub const MIN_PAYLOAD_SIZE: usize = MIN_MTU - proto::FragmentFrameHeader::SIZE;

/// Interval for updating the busy queue count histogram
const HISTOGRAM_UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// A Fragmenter splitting up data into fragments
#[derive(Clone)]
pub struct Fragmenter {
    mtu: usize,
    stream_offset: u64,
    metrics: FragmentMetrics,
}
impl Fragmenter {
    /// Create a new [`Fragmenter`] with the given MTU and metrics.
    pub fn new(mtu: usize, metrics: FragmentMetrics) -> Self {
        let mut this = Self {
            mtu: 0,
            stream_offset: 0,
            metrics,
        };

        this.set_mtu(mtu);
        this
    }

    /// Create a new [`Fragmenter`] with the given MTU and no external metrics.
    pub fn new_unobserved(mtu: usize) -> Self {
        Self::new(mtu, FragmentMetrics::new(&MetricsRegistry::new()))
    }

    /// Returns the maximum number of frames a single packet can be split up into
    pub fn max_frame_count(&self) -> usize {
        MAX_FRAMES
    }

    /// Sets the mtu to use, capped at [MIN_MTU] and [MAX_MTU].
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = std::cmp::min(mtu, MAX_MTU);
        self.mtu = std::cmp::max(self.mtu, MIN_MTU);
    }

    /// Returns the current mtu.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Sends data by fragmenting it into multiple frames if necessary.
    ///
    /// Returns the stream offset of the data sent.
    ///
    /// If the data length exceeds [MAX_PACKET_SIZE], the data is not sent and
    /// the function returns None.
    pub fn send(
        &mut self,
        data: &[u8],
        mut sink_cb: impl FnMut(FragmentFrameRef<'_>),
    ) -> Result<u64, FragmenterSendError> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(FragmenterSendError::PacketTooLarge);
        }
        if data.is_empty() {
            return Err(FragmenterSendError::EmptyPacket);
        }

        // Calculate number of frames needed
        let packet_stream_offset = self.stream_offset;
        let payload_fragment_size = self.mtu - proto::FragmentFrameHeader::SIZE;
        let frame_count = data.len().div_ceil(payload_fragment_size);
        for frame_index in 0..frame_count {
            let offset = frame_index * payload_fragment_size;
            let this_fragment_size = std::cmp::min(payload_fragment_size, data.len() - offset);
            let fragment_data = &data[offset..offset + this_fragment_size];

            let mut header = proto::FragmentFrameHeader {
                stream_offset: self.stream_offset,
                frame_offset: offset as u16,
                flags: 0,
            };

            if frame_index == frame_count - 1 {
                // Last frame
                header.flags |= FragmentFlags::LAST as u16;
            }

            let fragment = FragmentFrameRef {
                header,
                fragment: fragment_data,
            };

            sink_cb(fragment);
        }

        // Update stream offset
        self.stream_offset = self.stream_offset.wrapping_add(data.len() as u64);

        self.metrics.packets_processed.inc();
        self.metrics.frames_sent.inc_by(frame_count as u64);

        Ok(packet_stream_offset)
    }
}

/// Error returned by [`Fragmenter::send`] when a packet cannot be fragmented.
#[derive(Error, Clone, Debug, PartialEq, Eq)]
pub enum FragmenterSendError {
    /// The packet is too large to be sent.
    #[error("packet exceeds maximum size of {MAX_PACKET_SIZE} bytes")]
    PacketTooLarge,

    /// The packet is empty.
    #[error("packet is empty")]
    EmptyPacket,
}

/// Defragmenter reassembling fragmented packets.
///
/// It maintains multiple reassembly queues to handle out-of-order fragments.
/// Each queue can reassemble one packet at a time.
///
/// If all queues are busy, the oldest queue is evicted to make room for a new
/// packet.
pub struct Defragmenter {
    inner: DefragmenterInner,
    metrics: DefragmentMetrics,
}
impl Defragmenter {
    /// Creates a new instance and registers the metrics to the given registry
    pub fn new(queue_count: usize, metrics: DefragmentMetrics) -> Self {
        Self {
            inner: DefragmenterInner::new(queue_count),
            metrics,
        }
    }

    /// Create a new [`Defragmenter`] with no external metrics.
    pub fn new_unobserved(queue_count: usize) -> Self {
        Defragmenter::new(queue_count, DefragmentMetrics::new(&MetricsRegistry::new()))
    }

    /// Return a reference to the defragmenter's metrics.
    pub fn metrics(&self) -> &DefragmentMetrics {
        &self.metrics
    }

    /// Receives a fragment frame and attempts to reassemble a packet.
    ///
    /// If a packet is fully reassembled, it is returned as PacketRef.
    /// If the fragment could not be inserted, an error is returned.
    #[inline]
    pub fn recv<'this, 'buf: 'this>(
        &'this mut self,
        frame: &'buf [u8],
    ) -> Result<Option<PacketRef<'this>>, DefragmentInsertError> {
        self.inner.recv(&self.metrics, frame)
    }
}

struct DefragmenterInner {
    queues: Vec<DefragQueue>,
    last_histogram_update: std::time::Instant,
}
impl DefragmenterInner {
    pub fn new(defrag_queue_count: usize) -> Self {
        Self {
            queues: (0..defrag_queue_count)
                .map(|_| DefragQueue::new())
                .collect(),
            last_histogram_update: std::time::Instant::now(),
        }
    }

    /// Receives a fragment frame and attempts to reassemble a packet.
    ///
    /// If a packet is fully reassembled, it is returned as PacketRef.
    /// If the fragment could not be inserted, an error is returned.
    #[inline]
    pub fn recv<'this, 'buf: 'this>(
        &'this mut self,
        metrics: &DefragmentMetrics,
        frame: &'buf [u8],
    ) -> Result<Option<PacketRef<'this>>, DefragmentInsertError> {
        metrics.frames_recv.inc();

        // Update busy queue count histogram periodically
        if self.last_histogram_update.elapsed() > HISTOGRAM_UPDATE_INTERVAL {
            let busy_queues = self.queues.iter().filter(|q| !q.is_idle()).count() as i64;
            let busy_ratio = busy_queues as f64 / self.queues.len() as f64;
            metrics.busy_queue_ratio.observe(busy_ratio);

            self.last_histogram_update = std::time::Instant::now();
        }
        self.recv_fallible(metrics, frame)
            .inspect(|maybe_packet| {
                if maybe_packet.is_some() {
                    metrics.packets_reassembled.inc();
                }
            })
            .inspect_err(|err| {
                metrics.errors.with_label_values(&[err.label()]).inc();
            })
    }

    fn recv_fallible<'this, 'buf: 'this>(
        &'this mut self,
        metrics: &DefragmentMetrics,
        data: &'buf [u8],
    ) -> Result<Option<PacketRef<'this>>, DefragmentInsertError> {
        // Parse the fragment frame
        let frame =
            FragmentFrameRef::from_slice(data).ok_or(DefragmentInsertError::InvalidHeader)?;

        // Fast path for single-frame packets
        if frame.header.is_last() && frame.header.frame_offset == 0 {
            return Ok(Some(PacketRef {
                stream_offset: frame.header.stream_offset,
                payload: frame.fragment,
            }));
        }

        let queue = match self.select_queue(metrics, &frame) {
            Some(q) => q,
            None => return Err(DefragmentInsertError::TooOld(frame.header)),
        };

        // Track out-of-order frames
        if queue.next_frame_offset != frame.header.frame_offset {
            metrics.out_of_order_recv.inc();
        }

        queue.ingest_frame(&frame)
    }

    /// Selects a defragmentation queue for the given frame.
    ///
    /// If a queue for the stream offset already exists, it is returned.
    /// Otherwise, an idle queue is returned, or the oldest queue is evicted.
    ///
    /// If the frame is older than the oldest queue and no idle queue exists, None is returned.
    fn select_queue<'this>(
        &'this mut self,
        metrics: &DefragmentMetrics,
        frame: &FragmentFrameRef<'_>,
    ) -> Option<&'this mut DefragQueue> {
        let mut lowest_queue_offset = u64::MAX;
        let mut lowest_queue_index: usize = 0;
        let mut idle_queue = None;
        for (i, queue) in self.queues.iter().enumerate() {
            // If we found an existing queue for this stream_offset use it
            if queue.stream_offset == frame.header.stream_offset {
                // need use index access, otherwise rust can't prove we have unique access
                return Some(&mut self.queues[i]);
            }

            // If a queue is idle, select it for use, keep iterating in case we have an existing
            // queue
            if queue.is_idle() {
                idle_queue = Some(i);
            }

            // Track the oldest queue
            // XXX: we use u64::MAX to indicate a queue that has never been used, since a unused
            // queue is idle, this does not cause issues
            if lowest_queue_offset > queue.stream_offset {
                lowest_queue_offset = queue.stream_offset;
                lowest_queue_index = i;
            }
        }

        // If we found no idle or existing queue, do not accept frames that are older than the
        // oldest queue
        if idle_queue.is_none() && (frame.header.stream_offset < lowest_queue_offset) {
            return None;
        }

        // Either reuse an idle queue, or evict the oldest one
        let selected_queue = match idle_queue {
            Some(i) => i,
            None => {
                // Evict the oldest queue
                metrics.queues_evicted.inc();
                lowest_queue_index
            }
        };

        // Safety: selected_queue is always set with a valid index
        let queue = &mut self.queues[selected_queue];

        queue.init(frame);

        Some(queue)
    }
}

/// A reusable defragmentation queue reassembling a single packet.
struct DefragQueue {
    /// The stream offset of the packet being reassembled.
    /// u64::MAX indicates the queue has never been used.
    stream_offset: u64,
    /// The offset of the next expected frame on in order delivery.
    next_frame_offset: u16,
    /// Assembly buffer, kept on heap to keep stack size reasonable.
    assembly_buffer: Box<[u8; MAX_PACKET_SIZE]>,
    /// Bitmask tracking received frames.
    recv_mask: [BitmaskType; BITMASK_ENTRY_COUNT],
    /// The size of each normal frame's payload, if known.
    frame_window_size: Option<usize>,
    /// The final packet size, if known.
    final_packet_size: Option<usize>,
    /// The expected number of frames, if known.
    expected_frames: Option<usize>,
    /// The offset of the last frame, if known.
    last_frame_offset: Option<u16>,
    /// Whether the queue is idle and can be used by a new packet.
    idle: bool,
}
impl DefragQueue {
    fn new() -> Self {
        Self {
            assembly_buffer: Box::new([0; MAX_PACKET_SIZE]),
            recv_mask: [0; BITMASK_ENTRY_COUNT],
            stream_offset: u64::MAX, // Indicates the queue has never been used
            frame_window_size: None,
            final_packet_size: None,
            expected_frames: None,
            last_frame_offset: None,
            idle: true,
            next_frame_offset: 0,
        }
    }
}
impl DefragQueue {
    pub fn init(&mut self, frame: &FragmentFrameRef<'_>) {
        self.recv_mask = [0; BITMASK_ENTRY_COUNT];
        self.frame_window_size = None;
        self.final_packet_size = None;
        self.expected_frames = None;
        self.idle = false;
        self.stream_offset = frame.header.stream_offset;
    }

    /// Ingest a frame into the defragmentation queue.
    /// Returns a reference to the reassembled packet, if complete.
    ///
    /// If the frame was not accepted, an error is returned.
    pub fn ingest_frame<'this>(
        &'this mut self,
        frame: &FragmentFrameRef<'_>,
    ) -> Result<Option<PacketRef<'this>>, DefragmentInsertError> {
        if self.idle {
            return Err(DefragmentInsertError::QueueNotAccepting);
        }

        // Check no out of bound writes
        if frame.header.frame_offset as usize + frame.fragment.len() > MAX_PACKET_SIZE {
            // Packet will never be assembled, set to true so queue can be reused
            self.idle = true;

            return Err(DefragmentInsertError::OutOfBounds(frame.header));
        }

        let frame_index = match frame.header.is_last() {
            // Operation only on the last frame
            true => {
                // If we receive the last frame, we know the final packet size.
                let final_packet_size = frame.header.frame_offset as usize + frame.fragment.len();
                self.final_packet_size = Some(final_packet_size);
                self.last_frame_offset = Some(frame.header.frame_offset);

                if final_packet_size > MAX_PACKET_SIZE {
                    // Packet will never be assembled, set to true so queue can be reused
                    self.idle = true;

                    return Err(DefragmentInsertError::InvalidHeaderValue(
                        frame.header,
                        "last_packet_size_exceeds_max_packet_size",
                    ));
                }

                MAX_FRAMES - 1 // Use a special index for the last frame
            }
            // Operations for every other frame
            false => {
                // Check for consistent frame size
                if self.frame_window_size.is_some()
                    && self.frame_window_size != Some(frame.fragment.len())
                {
                    // Packet will never be assembled, set to true so queue can be reused
                    self.idle = true;
                    return Err(DefragmentInsertError::InvalidHeaderValue(
                        frame.header,
                        "inconsistent_frame_size",
                    ));
                } else {
                    // Otherwise we know the frame window size.
                    self.frame_window_size = Some(frame.fragment.len());
                }

                if !frame
                    .header
                    .frame_offset
                    .is_multiple_of(frame.fragment.len() as u16)
                {
                    // Packet will never be assembled, set to true so queue can be reused
                    self.idle = true;
                    return Err(DefragmentInsertError::InvalidHeaderValue(
                        frame.header,
                        "offset_alignment_invalid",
                    ));
                }

                // Check frame size is valid - if is below MIN_PAYLOAD_SIZE, we get too many frames
                if frame.fragment.len() < MIN_PAYLOAD_SIZE {
                    // Packet will never be assembled, set to true so queue can be reused
                    self.idle = true;
                    return Err(DefragmentInsertError::InvalidHeaderValue(
                        frame.header,
                        "frame_too_small",
                    ));
                }

                let frame_index = frame.header.frame_offset as usize / frame.fragment.len();

                // Check index is in bounds (-1 because last index is reserved for the last frame)
                if frame_index >= MAX_FRAMES - 1 {
                    // Packet will never be assembled, set to true so queue can be reused
                    self.idle = true;
                    return Err(DefragmentInsertError::InvalidHeaderValue(
                        frame.header,
                        "frame_idx_exceeds_max_frames",
                    ));
                }

                frame_index
            }
        };

        // One time Operation after we received last and any middle frame
        if let (Some(final_packet_size), Some(frame_window_size), Some(last_frame_offset), None) = (
            self.final_packet_size,
            self.frame_window_size,
            self.last_frame_offset,
            self.expected_frames,
        ) {
            // Check for consistent frame alignment
            if !(last_frame_offset as usize).is_multiple_of(frame_window_size) {
                self.idle = true;
                return Err(DefragmentInsertError::InvalidHeaderValue(
                    FragmentFrameHeader {
                        stream_offset: self.stream_offset,
                        frame_offset: last_frame_offset,
                        flags: FragmentFlags::LAST as u16,
                    },
                    "last_frame_offset_alignment_invalid",
                ));
            }

            // Only after we have received the last frame, and any middle frame, we know how many
            // frames to expect and the final packet size.
            let expected_frames = final_packet_size.div_ceil(frame_window_size);
            // expected_frames is guaranteed to be <= MAX_FRAMES
            // because final_packet_size <= MAX_PACKET_SIZE
            // and     frame_window_size >= MIN_PAYLOAD_SIZE

            self.expected_frames = Some(expected_frames);
        };

        let mask_index = frame_index / BITMASK_ENTRY_BITS;
        let frame_bit_position = frame_index % BITMASK_ENTRY_BITS;
        let frame_bit_mask = 1 << frame_bit_position;

        // Check for duplicate frame
        // Safety: mask_index is guaranteed to be in range because of the MAX_FRAMES check above
        if (self.recv_mask[mask_index] & frame_bit_mask) != 0 {
            return Err(DefragmentInsertError::Duplicate(frame.header));
        }

        // Copy payload
        let offset = frame.header.frame_offset as usize;
        // Safety: offset + fragment_len was checked to be <= MAX_PACKET_SIZE
        self.assembly_buffer[offset..offset + frame.fragment.len()].copy_from_slice(frame.fragment);
        self.recv_mask[mask_index] |= 1 << frame_bit_position;

        // Update next expected frame offset if frames are in order
        self.next_frame_offset = frame.header.frame_offset + frame.fragment.len() as u16;

        // Check if we have received all frames
        if let Some(expected_frames) = self.expected_frames
            && self.received_frames() == expected_frames
        {
            self.idle = true;
            let packet_size = self.final_packet_size.unwrap_or(MAX_PACKET_SIZE);
            let packet = PacketRef {
                stream_offset: self.stream_offset,
                payload: &self.assembly_buffer[..packet_size],
            };
            return Ok(Some(packet));
        }

        Ok(None)
    }

    fn received_frames(&self) -> usize {
        self.recv_mask.iter().map(|m| m.count_ones() as usize).sum()
    }

    pub fn is_idle(&self) -> bool {
        self.idle
    }
}

/// Error returned when a fragment frame cannot be inserted into a reassembly queue.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DefragmentInsertError {
    /// The frame could not be inserted because the queue doesn't accept new frames.
    #[error("queue does not accept new frames")]
    QueueNotAccepting,
    /// The frame could not be parsed.
    #[error("invalid frame header")]
    InvalidHeader,
    /// The frame header contains invalid data.
    #[error("invalid frame header value: {1}")]
    InvalidHeaderValue(proto::FragmentFrameHeader, &'static str),
    /// The frame is too large to fit in the packet.
    #[error("frame offset + size was out of bounds")]
    OutOfBounds(proto::FragmentFrameHeader),
    /// A duplicate frame was received.
    #[error("duplicate frame")]
    Duplicate(proto::FragmentFrameHeader),
    /// The frame is too old and no idle queue exists
    #[error("frame is too old")]
    TooOld(proto::FragmentFrameHeader),
}
impl DefragmentInsertError {
    fn label(&self) -> &'static str {
        match self {
            DefragmentInsertError::QueueNotAccepting => "queue_idle",
            DefragmentInsertError::InvalidHeader => "invalid_header",
            DefragmentInsertError::InvalidHeaderValue(_, msg) => msg,
            DefragmentInsertError::OutOfBounds(_) => "segment_out_of_bounds",
            DefragmentInsertError::Duplicate(_) => "duplicate_segment",
            DefragmentInsertError::TooOld(_) => "segment_too_old",
        }
    }
}

/// Reference to a Fragment Frame created by the [Fragmenter]
pub struct FragmentFrameRef<'b> {
    /// The fragment header.
    pub header: proto::FragmentFrameHeader,
    /// The fragment payload.
    pub fragment: &'b [u8],
}
impl<'b> FragmentFrameRef<'b> {
    /// Parses a FragmentFrameRef from the given byte slice.
    ///
    /// Returns None if the slice is too short.
    pub fn from_slice(bytes: &'b [u8]) -> Option<Self> {
        if bytes.len() < proto::FragmentFrameHeader::SIZE {
            return None;
        }
        Some(Self {
            header: proto::FragmentFrameHeader::from_slice_unchecked(bytes),
            fragment: &bytes[proto::FragmentFrameHeader::SIZE..],
        })
    }

    /// Returns the wire length of the fragment frame.
    pub fn encoded_len(&self) -> usize {
        proto::FragmentFrameHeader::SIZE + self.fragment.len()
    }

    /// Encodes the fragment frame into the given byte slice.
    pub fn write_to_slice(&self, buf: &mut [u8]) {
        assert!(buf.len() >= proto::FragmentFrameHeader::SIZE + self.fragment.len());
        self.header
            .copy_to_slice(&mut buf[..proto::FragmentFrameHeader::SIZE]);
        buf[proto::FragmentFrameHeader::SIZE
            ..proto::FragmentFrameHeader::SIZE + self.fragment.len()]
            .copy_from_slice(self.fragment);
    }

    /// Encodes the fragment frame into a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = vec![0u8; proto::FragmentFrameHeader::SIZE + self.fragment.len()];
        self.write_to_slice(&mut buf);
        buf
    }
}

/// A non-owned reassembled packet.
pub struct PacketRef<'b> {
    /// The stream offset of the packet.
    pub stream_offset: u64,
    /// The packet payload.
    pub payload: &'b [u8],
}
impl Debug for PacketRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketRef")
            .field("stream_offset", &self.stream_offset)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}
impl PacketRef<'_> {
    /// Encodes the packet into a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.payload.to_vec()
    }
}

/// Low-level wire-format types for the fragment frame header.
pub mod proto {
    use byteorder::{BigEndian, ByteOrder};

    /// Header prefixed to every fragment frame on the wire.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FragmentFrameHeader {
        /// Byte offset of this frame's payload within the original packet's byte stream.
        pub stream_offset: u64,
        /// Index of this frame within the current packet.
        pub frame_offset: u16,
        /// Bit-field of protocol flags (see [`FragmentFlags`]).
        pub flags: u16,
    }

    /// Protocol flags
    #[repr(u16)]
    pub enum FragmentFlags {
        /// Is the last frame of a fragmented packet
        LAST = 0x1 << 15,
    }

    impl FragmentFrameHeader {
        /// Wire encoded size
        pub const SIZE: usize = 16;

        const STREAM_OFFSET_RANGE: std::ops::Range<usize> = 0..8;
        const FRAME_OFFSET_RANGE: std::ops::Range<usize> = 8..10;
        const FLAGS_RANGE: std::ops::Range<usize> = 10..12;

        /// Returns true if the fragment header contains the LAST flag.
        pub fn is_last(&self) -> bool {
            (self.flags & FragmentFlags::LAST as u16) != 0
        }

        /// Creates a FragmentFrameHeader from a byte slice
        /// Returns None if the slice is too short.
        pub fn from_slice(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < Self::SIZE {
                return None;
            }
            Some(Self::from_slice_unchecked(bytes))
        }

        /// Creates a FragmentFrameHeader from a byte slice without checking its length.
        ///
        /// ## Panics
        /// Panics if the slice is shorter than [Self::SIZE].
        pub fn from_slice_unchecked(bytes: &[u8]) -> Self {
            Self {
                stream_offset: BigEndian::read_u64(&bytes[Self::STREAM_OFFSET_RANGE]),
                frame_offset: BigEndian::read_u16(&bytes[Self::FRAME_OFFSET_RANGE]),
                flags: BigEndian::read_u16(&bytes[Self::FLAGS_RANGE]),
            }
        }

        /// Copies the FragmentFrameHeader into the given byte slice.
        ///
        /// ## Panics
        /// Panics if the slice is shorter than [Self::SIZE].
        pub fn copy_to_slice(&self, bytes: &mut [u8]) {
            debug_assert!(bytes.len() >= Self::SIZE);
            BigEndian::write_u64(&mut bytes[Self::STREAM_OFFSET_RANGE], self.stream_offset);
            BigEndian::write_u16(&mut bytes[Self::FRAME_OFFSET_RANGE], self.frame_offset);
            BigEndian::write_u16(&mut bytes[Self::FLAGS_RANGE], self.flags);
        }
    }
}

/// Prometheus metrics for the fragmenter and defragmenter.
pub mod metrics {
    use prometheus::{Histogram, IntCounter, IntCounterVec};
    use scion_sdk_observability::metrics::registry::MetricsRegistry;

    /// Metrics for the Fragmenter
    ///
    /// These Metrics are shared between all Fragmenter instances.
    #[derive(Debug, Clone)]
    pub struct FragmentMetrics {
        /// Total packets processed
        pub packets_processed: IntCounter,
        /// Total frames sent
        pub frames_sent: IntCounter,
    }
    impl FragmentMetrics {
        /// Create and register fragmenter metrics in `metrics_registry`.
        pub fn new(metrics_registry: &MetricsRegistry) -> Self {
            Self {
                packets_processed: metrics_registry.int_counter(
                    "edgetun_frag_packets_processed_total",
                    "Total number of packets processed by the fragmenter",
                ),
                frames_sent: metrics_registry.int_counter(
                    "edgetun_frag_frames_sent_total",
                    "Total number of frames sent by the fragmenter",
                ),
            }
        }
    }

    /// Metrics for the Defragmenter
    ///
    /// These Metrics are shared between all Defragmenter instances.
    #[derive(Debug, Clone)]
    pub struct DefragmentMetrics {
        /// Total fragment frames received.
        pub frames_recv: IntCounter,
        /// Total packets fully reassembled.
        pub packets_reassembled: IntCounter,
        /// Total out-of-order fragment frames received.
        pub out_of_order_recv: IntCounter,
        /// Reassembly errors, labelled by reason.
        pub errors: IntCounterVec,
        /// Total reassembly queues evicted before completion.
        pub queues_evicted: IntCounter,
        /// Histogram of the ratio of busy reassembly queues.
        pub busy_queue_ratio: Histogram,
    }
    impl DefragmentMetrics {
        /// Create and register defragmenter metrics in `metrics_registry`.
        pub fn new(metrics_registry: &MetricsRegistry) -> Self {
            Self {
                frames_recv: metrics_registry.int_counter(
                    "edgetun_defrag_frames_recv_total",
                    "Total number of frames received by the defragmenter",
                ),
                packets_reassembled: metrics_registry.int_counter(
                    "edgetun_defrag_packets_reassembled_total",
                    "Total number of packets reassembled by the defragmenter",
                ),
                errors: metrics_registry.int_counter_vec(
                    "edgetun_defrag_reassembly_errors_total",
                    "Total number of reassembly errors",
                    &["reason"],
                ),
                queues_evicted: metrics_registry.int_counter(
                    "edgetun_defrag_queues_evicted_total",
                    "Total number of queues evicted before completing reassembly",
                ),
                busy_queue_ratio: metrics_registry.histogram(
                    "edgetun_defrag_busy_queue_ratio",
                    "Percentage of busy queues",
                    vec![0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
                ),
                out_of_order_recv: metrics_registry.int_counter(
                    "edgetun_defrag_out_of_order_frames_recv_total",
                    "Total number of out-of-order frames received by the defragmenter",
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    const TEST_QUEUE_COUNT: usize = 5;

    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use super::*;

    /// Creates a deterministic RNG for testing
    fn test_rng() -> XorShiftRng {
        XorShiftRng::seed_from_u64(123812350914872019)
    }

    mod fragmenter {

        use rand::Rng;

        use super::*;

        fn prepare_data(mtu: usize, expected_frames: usize, tail_data: usize) -> (Vec<u8>, usize) {
            let payload_size = mtu - proto::FragmentFrameHeader::SIZE;
            let mut rng = test_rng();
            let mut data = vec![0u8; payload_size * expected_frames + tail_data];

            rng.fill_bytes(&mut data[..]);
            (data, payload_size)
        }
        fn reassemble(
            expected_frames: usize,
            payload_size: usize,
            frames: std::cell::Ref<'_, Vec<Vec<u8>>>,
            total_payload: &mut Vec<u8>,
        ) {
            for (i, frame_bytes) in frames.iter().enumerate() {
                let f = FragmentFrameRef::from_slice(frame_bytes).unwrap();
                assert_eq!(f.header.stream_offset, 0);
                assert_eq!(f.header.frame_offset, (i * payload_size) as u16);
                if i == expected_frames - 1 {
                    assert!(f.header.is_last());
                } else {
                    assert!(!f.header.is_last());
                }
                total_payload.extend_from_slice(f.fragment);
            }
        }
        #[test]
        fn should_split_packet_into_correct_fragments() {
            let mut fragmenter = Fragmenter::new_unobserved(MIN_MTU);
            let expected_frames = 4;
            let (data, payload_size) = prepare_data(MIN_MTU, expected_frames, 0);

            let captured = RefCell::new(Vec::new());

            fragmenter
                .send(&data, |frame| {
                    captured.borrow_mut().push(frame.to_vec());
                })
                .unwrap();

            let frames = captured.borrow();
            assert_eq!(frames.len(), expected_frames);

            let mut total_payload = Vec::new();
            reassemble(expected_frames, payload_size, frames, &mut total_payload);

            assert_eq!(total_payload, data);
        }

        #[test]
        fn should_split_packet_with_one_extra_byte() {
            let mut fragmenter = Fragmenter::new_unobserved(MIN_MTU);
            let expected_frames = 2;
            let (data, payload_size) = prepare_data(MIN_MTU, 1, 1);

            let captured = RefCell::new(Vec::new());
            fragmenter
                .send(&data, |frame| {
                    captured.borrow_mut().push(frame.to_vec());
                })
                .unwrap();

            let frames = captured.borrow();
            assert_eq!(frames.len(), expected_frames);

            let mut total_payload = Vec::new();
            reassemble(expected_frames, payload_size, frames, &mut total_payload);

            assert_eq!(total_payload, data);
        }

        #[test]
        fn should_handle_single_fragment_packet() {
            let mut fragmenter = Fragmenter::new_unobserved(MAX_MTU);
            let (data, _) = prepare_data(MAX_MTU, 1, 0);
            let captured = RefCell::new(Vec::new());

            fragmenter
                .send(&data, |frame| {
                    captured.borrow_mut().push(frame.to_vec());
                })
                .unwrap();

            let frames = captured.borrow();
            assert_eq!(frames.len(), 1);
            let frame = FragmentFrameRef::from_slice(&frames[0]).unwrap();

            assert_eq!(frame.header.stream_offset, 0);
            assert!(frame.header.is_last());
            assert_eq!(frame.fragment, data.as_slice());
        }

        #[test]
        fn should_discard_packet_too_large() {
            let mut fragmenter = Fragmenter::new_unobserved(MAX_MTU);
            let data = vec![0u8; MAX_PACKET_SIZE + 1];
            let mut called = false;
            let res = fragmenter.send(&data, |_| {
                called = true;
            });
            assert_eq!(res, Err(FragmenterSendError::PacketTooLarge));
            assert!(!called);
        }

        #[test]
        fn should_allow_packet_exactly_max_packet_size() {
            let mut fragmenter = Fragmenter::new_unobserved(MAX_MTU);
            let data = vec![0u8; MAX_PACKET_SIZE];
            let mut count = 0;
            let res = fragmenter.send(&data, |_| {
                count += 1;
            });
            assert!(res.is_ok());
            assert!(count > 0);
        }

        #[test]
        fn should_clamp_mtu_to_max_fragment_size() {
            let mut fragmenter = Fragmenter::new_unobserved(999_999);
            assert_eq!(fragmenter.mtu(), MAX_MTU);
            fragmenter.set_mtu(999_999);
            assert_eq!(fragmenter.mtu(), MAX_MTU);
        }

        #[test]
        fn should_clamp_mtu_to_min_fragment_size() {
            let mut fragmenter = Fragmenter::new_unobserved(1);
            assert_eq!(fragmenter.mtu(), MIN_MTU);
            fragmenter.set_mtu(1);
            assert_eq!(fragmenter.mtu(), MIN_MTU);
        }

        #[test]
        fn should_not_accept_0_byte_packet() {
            let mut fragmenter = Fragmenter::new_unobserved(MAX_MTU);
            let data = vec![];
            let mut count = 0;
            let res = fragmenter.send(&data, |_| {
                count += 1;
            });
            assert_eq!(res, Err(FragmenterSendError::EmptyPacket));
            assert_eq!(count, 0);
        }
    }

    mod defragmenter {
        use std::collections::HashMap;

        use rand::{Rng, TryRng, seq::SliceRandom};

        use super::*;

        struct GeneratedStreams {
            frames: Vec<Vec<u8>>,
            /// Original packets keyed by stream offset
            original_packets: HashMap<u64, Vec<u8>>,
        }
        impl GeneratedStreams {
            fn duplicate_fragments(self, dup_fn: fn(Vec<Vec<u8>>) -> Vec<Vec<u8>>) -> Self {
                Self {
                    frames: dup_fn(self.frames),
                    original_packets: self.original_packets,
                }
            }

            fn check(&self, defragger: &mut Defragmenter) {
                let mut reassembled_packets: Vec<(u64, Vec<u8>)> = Vec::new();

                for fragment in &self.frames {
                    match defragger.recv(fragment) {
                        Ok(Some(packet)) => {
                            reassembled_packets.push((packet.stream_offset, packet.to_vec()));
                        }
                        Ok(None) => {
                            // Fragment accepted, but no packet reassembled yet
                        }
                        Err(_e) => {}
                    }
                }

                assert_eq!(
                    reassembled_packets.len(),
                    self.original_packets.len(),
                    "
                    Expected to reassemble {} packets, got {}",
                    self.original_packets.len(),
                    reassembled_packets.len()
                );

                for packet in reassembled_packets {
                    let offset = packet.0;
                    let original = self
                        .original_packets
                        .get(&offset)
                        .expect("Received a packet with unknown offset");

                    if original.len() != packet.1.len() {
                        panic!(
                            "Reassembled packet length does not match original: {} != {}",
                            packet.1.len(),
                            original.len()
                        );
                    }

                    if packet.1 != *original {
                        panic!("Reassembled packet data does not match original");
                    }
                }
            }
        }

        /// Generates a stream of fragments for packets of varying sizes and MTUs.
        ///
        /// `packet_gen` generates the MTU and size for each packet. (mtu, size)
        /// `fragment_sort` sorts the fragments for each packet, allowing to test
        ///  different arrival orders.
        /// `fragment_total_sort` sorts the entire fragment stream, allowing to test
        ///  interleaving of packets.
        #[allow(clippy::type_complexity)]
        fn generate_fragment_stream(
            fragmenter: &mut Fragmenter,
            packet_count: usize,
            packet_gen: fn(usize) -> (usize, usize),
            fragment_sort: fn((usize, Vec<Vec<u8>>)) -> Vec<Vec<u8>>,
            frame_sort: fn(Vec<Vec<u8>>) -> Vec<Vec<u8>>,
        ) -> GeneratedStreams {
            let mut all_frames: Vec<Vec<u8>> = Vec::new();

            let mut original_packets: HashMap<u64, Vec<u8>> = HashMap::new();

            for packet_index in 0..packet_count {
                let (mtu, size) = packet_gen(packet_index);
                fragmenter.set_mtu(mtu);

                let mut data = vec![packet_index as u8; size];
                let mut rnd = test_rng();
                rnd.fill_bytes(&mut data[..]);

                let mut frames: Vec<Vec<u8>> = Vec::new();
                let Ok(offset) = fragmenter.send(&data, |frame| {
                    frames.push(frame.to_vec());
                }) else {
                    panic!("fragmenter rejected packet");
                };

                original_packets.insert(offset, data);

                let sorted_frames = fragment_sort((packet_index, frames));
                all_frames.extend(sorted_frames);
            }

            GeneratedStreams {
                frames: frame_sort(all_frames),
                original_packets,
            }
        }

        fn fragments_in_order((_, frames): (usize, Vec<Vec<u8>>)) -> Vec<Vec<u8>> {
            frames
        }

        fn fragments_in_reverse_order((_, mut frames): (usize, Vec<Vec<u8>>)) -> Vec<Vec<u8>> {
            frames.reverse();
            frames
        }

        fn fragments_in_random_order((_, mut frames): (usize, Vec<Vec<u8>>)) -> Vec<Vec<u8>> {
            frames.shuffle(&mut test_rng());
            frames
        }

        fn pkt_interleave_none(frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
            frames
        }

        fn pkt_interleave_random(mut frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
            frames.shuffle(&mut test_rng());
            frames
        }

        fn pkg_gen_exact_max_mtu(_i: usize) -> (usize, usize) {
            (MAX_MTU, MAX_MTU - proto::FragmentFrameHeader::SIZE)
        }

        fn packet_gen_max_size(_i: usize) -> (usize, usize) {
            (MAX_MTU, MAX_PACKET_SIZE)
        }

        fn packet_gen_max_frames(_i: usize) -> (usize, usize) {
            (MIN_MTU, MAX_PACKET_SIZE)
        }

        fn packet_gen_varying_mtu(i: usize) -> (usize, usize) {
            let mtu = MIN_MTU + (i * 100).min(MAX_MTU - MIN_MTU);
            let size = mtu * 3;
            (mtu, size)
        }

        fn make_frame(offset: u64, frame_offset: u16, flags: u16, payload_len: usize) -> Vec<u8> {
            let mut buf = vec![0u8; proto::FragmentFrameHeader::SIZE + payload_len];
            let hdr = proto::FragmentFrameHeader {
                stream_offset: offset,
                frame_offset,
                flags,
            };
            hdr.copy_to_slice(&mut buf[..proto::FragmentFrameHeader::SIZE]);
            buf
        }

        mod accept {
            use super::*;

            #[test]
            fn should_reassemble_single_fragment_packet() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    1,
                    pkg_gen_exact_max_mtu,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                assert!(streams.frames.len() == 1, "Expected exactly one fragment");
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_packet_in_order() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    1,
                    packet_gen_max_size,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_packet_out_of_order_reverse() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    1,
                    packet_gen_varying_mtu,
                    fragments_in_reverse_order,
                    pkt_interleave_none,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_packet_out_of_order_random() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    1,
                    packet_gen_varying_mtu,
                    fragments_in_random_order,
                    pkt_interleave_none,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_packets_with_duplicates() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    TEST_QUEUE_COUNT,
                    packet_gen_varying_mtu,
                    fragments_in_random_order,
                    pkt_interleave_random,
                )
                .duplicate_fragments(|fragments| {
                    // Randomly duplicate fragments and shuffle them
                    let mut rng = test_rng();
                    let mut duplicates = fragments.clone();
                    for fragment in fragments {
                        if rng.try_next_u32().unwrap().is_multiple_of(3) {
                            duplicates.push(fragment.clone());
                        }
                    }
                    duplicates.shuffle(&mut rng);
                    duplicates
                });

                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_multiple_packets_in_a_row() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    TEST_QUEUE_COUNT,
                    packet_gen_varying_mtu,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_multiple_packets_interleaved() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    TEST_QUEUE_COUNT,
                    packet_gen_varying_mtu,
                    fragments_in_order,
                    pkt_interleave_random,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_max_packet_size() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    1,
                    packet_gen_max_size,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_max_frames_packet() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    1,
                    packet_gen_max_frames,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reassemble_packets_with_different_mtus() {
                let streams = generate_fragment_stream(
                    &mut Fragmenter::new_unobserved(MAX_MTU),
                    4,
                    packet_gen_varying_mtu,
                    fragments_in_order,
                    pkt_interleave_random,
                );
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                streams.check(&mut defragger);
            }

            #[test]
            fn should_reuse_idle_queues() {
                let mut fragmenter = Fragmenter::new_unobserved(MAX_MTU);
                // First wave fills all queues
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                let first_streams = generate_fragment_stream(
                    &mut fragmenter,
                    TEST_QUEUE_COUNT,
                    pkg_gen_exact_max_mtu,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                first_streams.check(&mut defragger);

                // Second wave reuses them
                let second_streams = generate_fragment_stream(
                    &mut fragmenter,
                    TEST_QUEUE_COUNT,
                    pkg_gen_exact_max_mtu,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                second_streams.check(&mut defragger);
            }

            #[test]
            fn should_evict_stuck_old_queues() {
                let mut fragmenter = Fragmenter::new_unobserved(MAX_MTU);

                // Send an incomplete packet to reserve a queue
                let mut first_packet = Vec::new();
                fragmenter
                    .send(&vec![0u8; MAX_PACKET_SIZE], |frame| {
                        first_packet.push(frame.to_vec());
                    })
                    .unwrap();
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                defragger.recv(&first_packet[0]).unwrap();

                // Following packets should evict the stuck queue
                let first_streams = generate_fragment_stream(
                    &mut fragmenter,
                    TEST_QUEUE_COUNT,
                    pkg_gen_exact_max_mtu,
                    fragments_in_order,
                    pkt_interleave_none,
                );
                first_streams.check(&mut defragger);
            }

            #[test]
            fn should_handle_empty_frame() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                let empty = make_frame(0, 0, FragmentFlags::LAST as u16, 0);
                let res = defragger.recv(&empty);
                match res {
                    Ok(Some(packet)) => {
                        assert_eq!(packet.stream_offset, 0);
                        assert!(packet.payload.is_empty());
                    }
                    _ => panic!("expected successful reassembly of empty packet"),
                }
            }
        }

        mod reject {

            use super::*;
            use crate::fragmenting::proto::FragmentFlags;

            #[test]
            fn should_reject_invalid_header_too_short() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                let short = vec![0u8; proto::FragmentFrameHeader::SIZE - 1];
                let res = defragger.recv(&short);
                assert!(matches!(res, Err(DefragmentInsertError::InvalidHeader)));
            }

            /// A non last frame with < MAX_PACKET_SIZE size suggests > MAX_FRAMES frames
            #[test]
            fn should_reject_too_small_frame() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);

                // Forge an unrealistically small MTU so frame_window_size = 1 byte
                // Simulate a packet implying > MAX_FRAMES frames.
                let frame = make_frame(0, 0, 0, MIN_PAYLOAD_SIZE - 1);

                // Feed last frame declaring final size too big
                let res = defragger.recv(&frame);
                assert!(
                    matches!(
                        res,
                        Err(DefragmentInsertError::InvalidHeaderValue(
                            _,
                            "frame_too_small"
                        ))
                    ),
                    "unexpected result = {res:?}"
                );
            }

            #[test]
            fn should_reject_out_of_bounds_frame() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);

                let frame = make_frame(
                    0,
                    (MAX_PACKET_SIZE - MIN_PAYLOAD_SIZE + 1) as u16,
                    FragmentFlags::LAST as u16,
                    MIN_PAYLOAD_SIZE,
                );

                let res = defragger.recv(&frame);
                assert!(
                    matches!(res, Err(DefragmentInsertError::OutOfBounds(_))),
                    "unexpected result = {res:?}"
                );

                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);

                // Also test with a non-last frame
                let frame = make_frame(
                    0,
                    (MAX_PACKET_SIZE - MIN_PAYLOAD_SIZE + 1) as u16,
                    0,
                    MIN_PAYLOAD_SIZE,
                );
                let res = defragger.recv(&frame);
                assert!(
                    matches!(res, Err(DefragmentInsertError::OutOfBounds(_))),
                    "unexpected result = {res:?}"
                );
            }

            #[test]
            fn should_reject_duplicate_frame() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                let frame = make_frame(0, 0, 0, MIN_PAYLOAD_SIZE);
                let first = defragger.recv(&frame);
                assert!(first.is_ok());
                let dup = defragger.recv(&frame);
                assert!(matches!(dup, Err(DefragmentInsertError::Duplicate(_))));
            }

            #[test]
            fn should_reject_frame_to_idle_queue() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                let frame = make_frame(0, 0, 0, MIN_PAYLOAD_SIZE - 1);

                // Init queue and directly complete it by erroring
                let first = defragger.recv(&frame);
                assert!(first.is_err(), "expected error, got {first:?}");
                let second = defragger.recv(&frame);
                assert!(
                    matches!(second, Err(DefragmentInsertError::QueueNotAccepting)),
                    "unexpected result = {second:?}"
                );
            }

            #[test]
            fn should_reject_too_old_segment() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                // Fill all queues with distinct offsets
                for i in 0..8 {
                    let _ = defragger.recv(&make_frame(i as u64 + 1000, 0, 0, MIN_PAYLOAD_SIZE));
                }

                // Send an older fragment with smaller stream_offset
                let old = make_frame(0, 0, 0, MIN_PAYLOAD_SIZE);
                let res = defragger.recv(&old);
                assert!(
                    matches!(res, Err(DefragmentInsertError::TooOld(_))),
                    "unexpected result = {res:?}"
                );
            }

            #[test]
            fn should_reject_duplicate_last_frame() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                let frame = make_frame(
                    0,
                    (MIN_PAYLOAD_SIZE * 3) as u16,
                    FragmentFlags::LAST as u16,
                    MIN_PAYLOAD_SIZE,
                );
                let first = defragger.recv(&frame);
                assert!(first.is_ok());
                let dup = defragger.recv(&frame);
                assert!(matches!(dup, Err(DefragmentInsertError::Duplicate(_))));
            }

            #[test]
            fn should_reject_unaligned_frames() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                // alignment is MIN_PAYLOAD_SIZE
                let frame = make_frame(0, (MIN_PAYLOAD_SIZE * 3) as u16, 0, MIN_PAYLOAD_SIZE);
                let first = defragger.recv(&frame);
                assert!(first.is_ok());

                let frame = make_frame(0, (MIN_PAYLOAD_SIZE * 2) as u16 + 1, 0, MIN_PAYLOAD_SIZE);
                let res = defragger.recv(&frame);
                assert!(
                    matches!(
                        res,
                        Err(DefragmentInsertError::InvalidHeaderValue(
                            _,
                            "offset_alignment_invalid"
                        ))
                    ),
                    "unexpected result = {res:?}"
                );
            }

            #[test]
            fn should_reject_unaligned_last_frame() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                // alignment is MIN_PAYLOAD_SIZE
                let frame = make_frame(0, (MIN_PAYLOAD_SIZE * 3) as u16, 0, MIN_PAYLOAD_SIZE);
                let first = defragger.recv(&frame);
                assert!(first.is_ok());

                let frame = make_frame(
                    0,
                    (MIN_PAYLOAD_SIZE * 4) as u16 + 1,
                    FragmentFlags::LAST as u16,
                    MIN_PAYLOAD_SIZE,
                );
                let res = defragger.recv(&frame);
                assert!(
                    matches!(
                        res,
                        Err(DefragmentInsertError::InvalidHeaderValue(
                            _,
                            "last_frame_offset_alignment_invalid"
                        ))
                    ),
                    "unexpected result = {res:?}"
                );
            }

            #[test]
            fn should_reject_unaligned_last_frame_but_last_frame_first() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                // alignment is MIN_PAYLOAD_SIZE
                let frame = make_frame(
                    0,
                    (MIN_PAYLOAD_SIZE * 4) as u16 + 1,
                    FragmentFlags::LAST as u16,
                    MIN_PAYLOAD_SIZE,
                );
                let first = defragger.recv(&frame);
                assert!(first.is_ok());

                let frame = make_frame(0, (MIN_PAYLOAD_SIZE * 3) as u16, 0, MIN_PAYLOAD_SIZE);
                let res = defragger.recv(&frame);
                assert!(
                    matches!(
                        res,
                        Err(DefragmentInsertError::InvalidHeaderValue(
                            _,
                            "last_frame_offset_alignment_invalid"
                        ))
                    ),
                    "unexpected result = {res:?}"
                );
            }

            #[test]
            fn should_reject_inconsistent_frame_sizes() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                let frame = make_frame(0, 0, 0, MIN_PAYLOAD_SIZE);
                let first = defragger.recv(&frame);
                assert!(first.is_ok());

                let frame = make_frame(0, MIN_PAYLOAD_SIZE as u16, 0, MIN_PAYLOAD_SIZE + 1);
                let res = defragger.recv(&frame);
                assert!(
                    matches!(
                        res,
                        Err(DefragmentInsertError::InvalidHeaderValue(
                            _,
                            "inconsistent_frame_size"
                        ))
                    ),
                    "unexpected result = {res:?}"
                );
            }

            // We only expect no panic - without adding a timeout to queues, this will not leave
            // the defragmenter in a usable state.
            #[test]
            fn should_not_panic_on_random_noise() {
                let mut defragger = Defragmenter::new_unobserved(TEST_QUEUE_COUNT);
                for _ in 0..1000 {
                    let len = rand::random_range(0..MAX_PACKET_SIZE);
                    let mut noise = vec![0u8; len];
                    test_rng().try_fill_bytes(&mut noise).unwrap();
                    let _ = defragger.recv(&noise);
                }
            }
        }
    }
}

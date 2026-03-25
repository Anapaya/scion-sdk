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

//! Helpers for batched UDP receive and transmit operations used by SNAP tunnel I/O.
//!
//! `UdpBatchReceiver` batches receive-side work with a fixed compile-time batch size,
//! while `UdpBatchSender` batches same-sized datagrams to the same destination so the
//! underlying socket can take advantage of UDP segmentation offload when available.
//!
//! Both helpers are intended to be created once per socket and reused. They keep
//! batch-sized scratch state alive so repeated calls can reuse packet buffers and
//! socket state instead of rebuilding that state for every receive or flush cycle.

use std::{collections::VecDeque, io, io::IoSliceMut, net::SocketAddr};

use ana_gotatun::packet::{Packet, PacketBufPool};
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::{io::Interest, net::UdpSocket};

const MAX_BATCH_SIZE: usize = 64;

/// Errors returned while receiving and processing a UDP batch.
pub enum RecvBatchError<E> {
    /// The socket operation itself failed.
    Io(io::Error),
    /// The caller-provided packet handler failed.
    Handler(E),
}

/// Errors returned while queueing packets for batched transmission.
#[derive(Debug)]
pub enum QueuePacketError {
    /// The sender queue is full and cannot accept another packet right now.
    Full {
        /// The unsent packet.
        packet: Packet,
        /// The original target address of the unsent packet.
        target: SocketAddr,
    },
    /// The packet is larger than the configured sender scratch budget.
    PacketTooLarge {
        /// The oversized packet.
        packet: Packet,
        /// The original target address of the oversized packet.
        target: SocketAddr,
        /// The packet length in bytes.
        packet_len: usize,
        /// The configured maximum packet size.
        max_packet_size: usize,
    },
}

/// UdpBatchReceiver wraps a standard UDP socket and provides batched receive operations.
///
/// It receives up to `BATCH_SIZE` UDP datagrams in one socket read cycle and is
/// intended to be reused for as long as that socket is active. Reusing it keeps
/// the receive slots checked out from the pool so repeated receive calls can stay
/// on the fast path.
///
/// `BUFFER_SIZE` controls the size of packet buffers drawn from the provided pool.
/// `BATCH_SIZE * BUFFER_SIZE` bytes of memory will be reserved for the receive buffer.
pub struct UdpBatchReceiver<const BATCH_SIZE: usize, const BUFFER_SIZE: usize = 4096> {
    state: UdpSocketState,
    recv_meta: [RecvMeta; BATCH_SIZE],
    recv_slots: [Packet; BATCH_SIZE],
}

impl<const BATCH_SIZE: usize, const BUFFER_SIZE: usize> UdpBatchReceiver<BATCH_SIZE, BUFFER_SIZE> {
    /// Creates a receiver configured for a fixed compile-time batch size.
    ///
    /// The receiver keeps `BATCH_SIZE` packet buffers checked out from `pool` until
    /// it is dropped, so callers should typically create one receiver per socket and
    /// reuse it across receive calls.
    pub fn new(socket: &UdpSocket, pool: &PacketBufPool<BUFFER_SIZE>) -> io::Result<Self> {
        assert!(
            BATCH_SIZE > 0,
            "UdpBatchReceiver BATCH_SIZE must be greater than zero"
        );
        assert!(
            BATCH_SIZE <= MAX_BATCH_SIZE,
            "UdpBatchReceiver BATCH_SIZE must not exceed MAX_BATCH_SIZE"
        );
        let state = UdpSocketState::new(UdpSockRef::from(socket))?;
        let recv_slots = std::array::from_fn(|_| pool.get());
        Ok(Self {
            state,
            recv_meta: std::array::from_fn(|_| RecvMeta::default()),
            recv_slots,
        })
    }

    /// Receives a batch of packets and invokes `handler` for each decoded datagram.
    pub async fn recv_batch<E, F>(
        &mut self,
        socket: &UdpSocket,
        pool: &PacketBufPool<BUFFER_SIZE>,
        mut handler: F,
    ) -> Result<(), RecvBatchError<E>>
    where
        F: FnMut(Packet, SocketAddr) -> Result<(), E>,
    {
        let received = loop {
            socket.readable().await.map_err(RecvBatchError::Io)?;
            match socket.try_io(Interest::READABLE, || self.try_recv(socket)) {
                Ok(count) => break count,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Err(RecvBatchError::Io(err)),
            }
        };

        for index in 0..received {
            self.handle_received(index, pool, &mut handler)
                .map_err(RecvBatchError::Handler)?;
        }

        Ok(())
    }

    fn handle_received<E, F>(
        &mut self,
        index: usize,
        pool: &PacketBufPool<BUFFER_SIZE>,
        handler: &mut F,
    ) -> Result<(), E>
    where
        F: FnMut(Packet, SocketAddr) -> Result<(), E>,
    {
        // `quinn_udp` can report one large receive buffer together with a stride
        // when the kernel coalesced multiple datagrams. Split that back into
        // logical packets here so downstream code keeps its usual one-packet-at-a-time view.
        let meta = self.recv_meta[index];
        if meta.len == 0 {
            return Ok(());
        }
        let stride = if meta.stride == 0 {
            meta.len
        } else {
            meta.stride
        };
        if stride >= meta.len {
            // Hand ownership of the filled slot to the caller and immediately put a
            // fresh buffer back into the slot so the next batch can reuse the same layout.
            let mut packet = std::mem::replace(&mut self.recv_slots[index], pool.get());
            packet.truncate(meta.len);
            handler(packet, meta.addr)?;
            return Ok(());
        }

        // Keep the receive slots permanently populated and carve a coalesced buffer
        // into individually owned segments only when the kernel told us multiple
        // datagrams were packed into one receive slot.
        let packet = std::mem::replace(&mut self.recv_slots[index], pool.get());
        for chunk in packet[..meta.len].chunks(stride) {
            let mut segment = pool.get();
            segment[..chunk.len()].copy_from_slice(chunk);
            segment.truncate(chunk.len());
            handler(segment, meta.addr)?;
        }
        Ok(())
    }

    fn try_recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        // Keep the receive slots alive across calls and hand them directly to the
        // socket so a steady-state receive loop does not need to re-acquire buffers
        // from the pool on every readiness notification.
        let mut bufs_uninit: [std::mem::MaybeUninit<IoSliceMut<'_>>; BATCH_SIZE] =
            std::array::from_fn(|_| std::mem::MaybeUninit::uninit());
        for (index, packet) in self.recv_slots.iter_mut().enumerate() {
            bufs_uninit[index].write(IoSliceMut::new(packet.as_mut()));
        }
        // SAFETY: Every element of `bufs_uninit` was written in the loop above, so
        // all `BATCH_SIZE` slots are fully initialised. `MaybeUninit<T>` is guaranteed
        // to have the same size and alignment as `T`, so reinterpreting the
        // pointer as `*mut IoSliceMut<'_>` is sound. The resulting slice covers
        // exactly the `BATCH_SIZE` elements that were initialised, and the backing
        // array lives for the duration of this function.
        let bufs = unsafe {
            std::slice::from_raw_parts_mut(
                bufs_uninit.as_mut_ptr() as *mut IoSliceMut<'_>,
                BATCH_SIZE,
            )
        };
        self.state
            .recv(UdpSockRef::from(socket), bufs, &mut self.recv_meta)
    }
}

/// Queues up to `BATCH_SIZE` packets for batched UDP transmission.
///
/// The sender is intended to be reused for the lifetime of a socket. It keeps a
/// reusable scratch buffer and a small transmit queue so successive flushes do not
/// need to rebuild that state from scratch.
///
/// `MAX_PACKET_SIZE` determines the capacity reserved for the transmit scratch buffer.
pub struct UdpBatchSender<const BATCH_SIZE: usize, const MAX_PACKET_SIZE: usize = 4096> {
    state: UdpSocketState,
    queued_packets: VecDeque<(SocketAddr, Packet)>,
    scratch: Vec<u8>,
}

impl<const BATCH_SIZE: usize, const MAX_PACKET_SIZE: usize>
    UdpBatchSender<BATCH_SIZE, MAX_PACKET_SIZE>
{
    /// Creates a sender configured for a fixed compile-time batch size.
    ///
    /// Callers should generally create one sender per socket and reuse it across
    /// queue/flush cycles so the queue and scratch storage stay hot.
    pub fn new(socket: &UdpSocket) -> io::Result<Self> {
        assert!(
            BATCH_SIZE > 0,
            "UdpBatchSender BATCH_SIZE must be greater than zero"
        );
        assert!(
            BATCH_SIZE <= MAX_BATCH_SIZE,
            "UdpBatchSender BATCH_SIZE must not exceed MAX_BATCH_SIZE"
        );
        Ok(Self {
            state: UdpSocketState::new(UdpSockRef::from(socket))?,
            queued_packets: VecDeque::with_capacity(BATCH_SIZE),
            scratch: Vec::with_capacity(MAX_PACKET_SIZE * BATCH_SIZE),
        })
    }

    /// Returns whether no packets are currently queued for transmission.
    pub fn is_empty(&self) -> bool {
        self.queued_packets.is_empty()
    }

    /// Returns whether the sender queue has reached its configured capacity.
    pub fn is_full(&self) -> bool {
        self.queued_packets.len() == BATCH_SIZE
    }

    /// Queues one packet for transmission to `target`.
    ///
    /// Returns an error when the sender queue is full or when `packet` exceeds
    /// `MAX_PACKET_SIZE`, which would otherwise force the scratch buffer to grow.
    pub fn try_queue_packet(
        &mut self,
        packet: Packet,
        target: SocketAddr,
    ) -> Result<(), QueuePacketError> {
        let packet_len = packet.len();
        if packet.len() > MAX_PACKET_SIZE {
            return Err(QueuePacketError::PacketTooLarge {
                packet,
                target,
                packet_len,
                max_packet_size: MAX_PACKET_SIZE,
            });
        }
        if self.is_full() {
            return Err(QueuePacketError::Full { packet, target });
        }
        self.queued_packets.push_back((target, packet));
        Ok(())
    }

    /// Attempts to flush queued packets without waiting for the socket to become writable.
    pub fn try_flush_best_effort(&mut self, socket: &UdpSocket) -> io::Result<()> {
        while !self.is_empty() {
            match socket.try_io(Interest::WRITABLE, || self.try_send_next(socket)) {
                Ok(sent) => self.drop_prefix(sent),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Err(err),
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Flushes queued packets, waiting asynchronously until the socket becomes writable.
    pub async fn flush(&mut self, socket: &UdpSocket) -> io::Result<()> {
        while !self.is_empty() {
            socket.writable().await?;
            match socket.try_io(Interest::WRITABLE, || self.try_send_next(socket)) {
                Ok(sent) => self.drop_prefix(sent),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn drop_prefix(&mut self, count: usize) {
        self.queued_packets.drain(..count);
    }

    fn try_send_next(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        self.scratch.clear();
        let (target, first_packet) = self
            .queued_packets
            .front()
            .expect("try_send_next requires a non-empty queue");
        let target = *target;
        let segment_size = first_packet.len();
        let mut segments = 0;
        let max_segments = self.state.max_gso_segments().min(BATCH_SIZE);

        // Only coalesce the segments at the front with matching destination and
        // segment size so queue order stays intact and we can drop exactly the
        // packets that were handed to the kernel.
        for (queued_target, packet) in self.queued_packets.iter().take(max_segments) {
            if *queued_target != target || packet.len() != segment_size {
                break;
            }
            self.scratch.extend_from_slice(&packet[..]);
            segments += 1;
        }

        let transmit = Transmit {
            destination: target,
            ecn: None,
            contents: &self.scratch,
            segment_size: (segments > 1).then_some(segment_size),
            src_ip: None,
        };
        self.state.try_send(UdpSockRef::from(socket), &transmit)?;
        Ok(segments)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use ana_gotatun::packet::PacketBufPool;
    use tokio::net::UdpSocket;

    use super::{MAX_BATCH_SIZE, UdpBatchReceiver, UdpBatchSender};

    const TEST_PACKET_SIZE: usize = 128;

    fn packet_pool() -> PacketBufPool<TEST_PACKET_SIZE> {
        PacketBufPool::new(MAX_BATCH_SIZE)
    }

    async fn bound_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    fn packet_from_bytes(
        pool: &PacketBufPool<TEST_PACKET_SIZE>,
        bytes: &[u8],
    ) -> ana_gotatun::packet::Packet {
        let mut packet = pool.get();
        packet[..bytes.len()].copy_from_slice(bytes);
        packet.truncate(bytes.len());
        packet
    }

    #[tokio::test]
    async fn flushes_partially_full_sender_batch() {
        let sender_socket = bound_socket().await;
        let receiver_socket = bound_socket().await;
        let pool = packet_pool();
        let mut sender =
            UdpBatchSender::<MAX_BATCH_SIZE, TEST_PACKET_SIZE>::new(&sender_socket).unwrap();

        sender
            .try_queue_packet(
                packet_from_bytes(&pool, b"one"),
                receiver_socket.local_addr().unwrap(),
            )
            .unwrap();
        sender
            .try_queue_packet(
                packet_from_bytes(&pool, b"two"),
                receiver_socket.local_addr().unwrap(),
            )
            .unwrap();

        sender.flush(&sender_socket).await.unwrap();

        let mut buf = [0u8; TEST_PACKET_SIZE];
        let (n1, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let first = buf[..n1].to_vec();
        let (n2, _) = receiver_socket.recv_from(&mut buf).await.unwrap();
        let second = buf[..n2].to_vec();

        assert!(sender.is_empty());
        assert_eq!(vec![first, second], vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[tokio::test]
    async fn flushes_sender_batch_with_mixed_targets() {
        let sender_socket = bound_socket().await;
        let first_target = bound_socket().await;
        let second_target = bound_socket().await;
        let pool = packet_pool();
        let mut sender =
            UdpBatchSender::<MAX_BATCH_SIZE, TEST_PACKET_SIZE>::new(&sender_socket).unwrap();

        sender
            .try_queue_packet(
                packet_from_bytes(&pool, b"alpha"),
                first_target.local_addr().unwrap(),
            )
            .unwrap();
        sender
            .try_queue_packet(
                packet_from_bytes(&pool, b"beta"),
                second_target.local_addr().unwrap(),
            )
            .unwrap();
        sender
            .try_queue_packet(
                packet_from_bytes(&pool, b"gamma"),
                first_target.local_addr().unwrap(),
            )
            .unwrap();

        sender.flush(&sender_socket).await.unwrap();

        let mut buf = [0u8; TEST_PACKET_SIZE];
        let (n_first_a, _) = first_target.recv_from(&mut buf).await.unwrap();
        let first_a = buf[..n_first_a].to_vec();
        let (n_second, _) = second_target.recv_from(&mut buf).await.unwrap();
        let second = buf[..n_second].to_vec();
        let (n_first_b, _) = first_target.recv_from(&mut buf).await.unwrap();
        let first_b = buf[..n_first_b].to_vec();

        assert_eq!(first_a, b"alpha".to_vec());
        assert_eq!(second, b"beta".to_vec());
        assert_eq!(first_b, b"gamma".to_vec());
    }

    #[tokio::test]
    async fn receive_with_stride_smaller_than_length_splits_segments() {
        let socket = bound_socket().await;
        let pool = packet_pool();
        let mut receiver =
            UdpBatchReceiver::<MAX_BATCH_SIZE, TEST_PACKET_SIZE>::new(&socket, &pool).unwrap();
        let source = "127.0.0.1:30000".parse::<SocketAddr>().unwrap();

        receiver.recv_meta[0].addr = source;
        receiver.recv_meta[0].len = 10;
        receiver.recv_meta[0].stride = 4;
        receiver.recv_slots[0][..10].copy_from_slice(b"abcdefghij");

        let mut seen = Vec::new();
        receiver
            .handle_received(0, &pool, &mut |packet, addr| {
                seen.push((packet[..].to_vec(), addr));
                Ok::<(), ()>(())
            })
            .unwrap();

        assert_eq!(
            seen,
            vec![
                (b"abcd".to_vec(), source),
                (b"efgh".to_vec(), source),
                (b"ij".to_vec(), source),
            ]
        );
    }

    #[tokio::test]
    async fn receive_with_stride_at_least_length_uses_single_packet() {
        let socket = bound_socket().await;
        let pool = packet_pool();
        let mut receiver =
            UdpBatchReceiver::<MAX_BATCH_SIZE, TEST_PACKET_SIZE>::new(&socket, &pool).unwrap();
        let source = "127.0.0.1:30001".parse::<SocketAddr>().unwrap();

        receiver.recv_meta[0].addr = source;
        receiver.recv_meta[0].len = 5;
        receiver.recv_meta[0].stride = 5;
        receiver.recv_slots[0][..5].copy_from_slice(b"hello");

        let mut seen = Vec::new();
        receiver
            .handle_received(0, &pool, &mut |packet, addr| {
                seen.push((packet[..].to_vec(), addr));
                Ok::<(), ()>(())
            })
            .unwrap();

        assert_eq!(seen, vec![(b"hello".to_vec(), source)]);
    }

    #[test]
    fn refuses_to_grow_beyond_batch_capacity() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let socket = bound_socket().await;
            let pool = packet_pool();
            let mut sender =
                UdpBatchSender::<MAX_BATCH_SIZE, TEST_PACKET_SIZE>::new(&socket).unwrap();

            for _ in 0..MAX_BATCH_SIZE {
                sender
                    .try_queue_packet(packet_from_bytes(&pool, b"x"), socket.local_addr().unwrap())
                    .unwrap();
            }

            assert!(
                sender
                    .try_queue_packet(
                        packet_from_bytes(&pool, b"overflow"),
                        socket.local_addr().unwrap()
                    )
                    .is_err()
            );
        });
    }
}

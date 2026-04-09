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
//! Gateway

use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ana_gotatun::{
    noise::{TunnResult, rate_limiter::RateLimiter},
    packet::{Packet, WgKind},
    x25519,
};
use sciparse::{
    address::{addr::ScionAddr, host_addr::ScionHostAddr},
    core::{
        encode::{EncodeError, WireEncode},
        view::View as _,
    },
    header::model::{AddressHeader, Path},
    identifier::isd_asn::IsdAsn,
    packet::model::ScionPacketScmpRef,
    payload::scmp::{self, types::ScmpParameterProblemCode},
};
use snap_tun::{
    server::{SnapTunAuthorization, SnapTunServer},
    udp_batch::{QueuePacketError, RecvBatchError, UdpBatchReceiver, UdpBatchSender},
};
use tokio::{net::UdpSocket, sync::mpsc::Receiver, time::interval};
use tokio_util::sync::CancellationToken;

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{
        dispatcher::TunnelGatewayDispatcherReceiver,
        packet_policy::{PacketPolicyError, inbound_datagram_check},
    },
};

// The size of the buffer for receiving and sending packets. This should be large
// enough to accommodate jumbo frames, which can be up to 9 KiB = 9216 Bytes.
pub(crate) const PACKET_BUF_SIZE: usize = 9216;
// The batch size for receiving and sending packets.
pub(crate) const BATCH_SIZE: usize = 64;
// Assuming a packet size of 1 KiB, 50*1024*1024 Bytes = 50 MiB ~= 500 Mbps.
pub(crate) const PACKET_PER_SEC_LIMIT: u64 = 50 * 1024;

pub(crate) type PacketPool = ana_gotatun::packet::PacketBufPool<PACKET_BUF_SIZE>;

/// The tunnel gateway.
pub struct TunnelGateway<A, D> {
    /// The socket shared by the server (which in our case is just handling
    /// inbound traffic) and the dispatcher (which processes outbound traffic).
    socket: tokio::net::UdpSocket,
    static_server_secret: x25519::StaticSecret,
    authz: Arc<A>,
    pool: PacketPool,
    /// The receiving end of the outbound queue, containing SCION packets
    /// dispatched to endhosts. The first entry of the pair is the socket
    /// address that the packet should be sent to.
    outbound_queue: Receiver<(SocketAddr, Packet)>,
    dispatcher: Arc<D>,
}

impl<A, D> TunnelGateway<A, D>
where
    D: Dispatcher + 'static,
    A: SnapTunAuthorization + 'static,
{
    /// Create new tunnel gateway exposed on `socket`.
    pub fn new(
        socket: tokio::net::UdpSocket,
        static_server_secret: x25519::StaticSecret,
        authz: Arc<A>,
        dispatcher: Arc<D>,
        tun_dispatcher_rx: TunnelGatewayDispatcherReceiver,
    ) -> Self {
        let TunnelGatewayDispatcherReceiver {
            pool,
            outbound_queue,
        } = tun_dispatcher_rx;
        Self {
            socket,
            static_server_secret,
            authz,
            pool,
            outbound_queue,
            dispatcher,
        }
    }

    /// start the server
    pub async fn start_server(mut self, cancel: CancellationToken) {
        let pubkey = x25519::PublicKey::from(&self.static_server_secret);
        let rate_limiter = Arc::new(RateLimiter::new(&pubkey, PACKET_PER_SEC_LIMIT));
        let mut snaptun_srv =
            SnapTunServer::new(self.static_server_secret, rate_limiter, self.authz);
        let mut timer = interval(Duration::from_millis(250));
        let socket = self.socket;
        let local_addr = ScionHostAddr::from(
            socket
                .local_addr()
                .map(|s| s.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        );
        let server_task = async move {
            let mut send_to_network: VecDeque<WgKind> = Default::default();
            let mut receiver: UdpBatchReceiver<BATCH_SIZE, PACKET_BUF_SIZE> =
                match UdpBatchReceiver::new(&socket, &self.pool) {
                    Ok(receiver) => receiver,
                    Err(err) => {
                        tracing::error!(err=?err, "could not initialize batched UDP receiver");
                        return;
                    }
                };
            let mut sender = match UdpBatchSender::<BATCH_SIZE, PACKET_BUF_SIZE>::new(&socket) {
                Ok(sender) => sender,
                Err(err) => {
                    tracing::error!(err=?err, "could not initialize batched UDP sender");
                    return;
                }
            };
            loop {
                tokio::select! {
                    recv_res = receiver.recv_batch(&socket, &self.pool, |in_pkt, from| {
                        let res = snaptun_srv.handle_incoming_packet(in_pkt, from, &mut send_to_network);

                        while let Some(pkt) = send_to_network.pop_front() {
                            Self::try_queue_batched_packet(
                                &socket,
                                &mut sender,
                                Self::wg_kind_to_bytes(pkt),
                                from,
                            );
                        }

                        match res {
                            TunnResult::Done => {},
                            TunnResult::Err(wire_guard_error) => {
                                tracing::error!(err=?wire_guard_error, "wireguard error on incoming packet");
                            },
                            TunnResult::WriteToNetwork(_wg_kind) => {
                                tracing::error!(
                                    "unexpected TunnResult::WriteToNetwork for incoming packet; \
                                     expected Done, Err, or WriteToTunnel; dropping packet"
                                );
                            },
                            TunnResult::WriteToTunnel(packet) => {
                                match inbound_datagram_check(&packet[..], from.ip()) {
                                    Ok(view) => {
                                        self.dispatcher.try_dispatch(view);
                                    }
                                    Err(e) => {
                                        tracing::debug!(err=%e, "Inbound datagram check failed");
                                        // Use the first assigned address for the SCMP reply.
                                        let mut target_buf =  self.pool.get();
                                        match Self::create_scmp_error(
                                            e,
                                            local_addr,
                                            // XXX: the SNAP generating SCMP errors is a bit bogus,
                                            // as the SNAP technically is not a node in the
                                            // SCION-network.
                                            ScionAddr::new(IsdAsn::WILDCARD, from.ip().into()),
                                            &mut target_buf
                                        ) {
                                            Ok(n) => {
                                            // XXX: `handle_outgoing_packet` allocates a new packet
                                            // for the response (see comment in impl)
                                            target_buf.truncate(n);
                                            if let Some(out_pkt) = snaptun_srv.handle_outgoing_packet(target_buf, from) {
                                                Self::try_queue_batched_packet(
                                                    &socket,
                                                    &mut sender,
                                                    Self::wg_kind_to_bytes(out_pkt),
                                                    from,
                                                );
                                            }
                                            },
                                            Err(e) => {
                                                tracing::error!(err=?e, "Failed to create SCMP error packet");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(())
                    }) => {
                        match recv_res {
                            Ok(()) => Self::try_flush_batch_log_err(&socket, &mut sender),
                            Err(RecvBatchError::Io(e)) => {
                                tracing::error!(err=?e, "i/o error on batched udp recv");
                            }
                            Err(RecvBatchError::Handler(())) => {}
                        }
                    },
                    outbound = self.outbound_queue.recv() => {
                        let Some((target, packet)) = outbound else {
                            tracing::info!("outbound channel closed");
                            break;
                        };

                        if let Some(out_pkt) = snaptun_srv.handle_outgoing_packet(packet, target) {
                            Self::try_queue_batched_packet(
                                &socket,
                                &mut sender,
                                Self::wg_kind_to_bytes(out_pkt),
                                target,
                            );
                        }
                        while !sender.is_full() {
                            let Ok((target, packet)) = self.outbound_queue.try_recv() else {
                                break;
                            };
                            let Some(out_pkt) = snaptun_srv.handle_outgoing_packet(packet, target) else { continue };
                            Self::try_queue_batched_packet(
                                &socket,
                                &mut sender,
                                Self::wg_kind_to_bytes(out_pkt),
                                target,
                            );
                        }
                        Self::try_flush_batch_log_err(&socket, &mut sender);
                    }
                    _ = timer.tick() => {
                        // Update timers inside SnapTun server.
                        for (addr, action) in snaptun_srv.update_timers() {
                            Self::try_send_log_err(&socket, &Self::wg_kind_to_bytes(action), addr);
                        }
                    }
                }
            }
        };

        cancel.run_until_cancelled_owned(server_task).await;
    }

    #[inline]
    fn wg_kind_to_bytes(wg_kind: WgKind) -> Packet {
        match wg_kind {
            WgKind::HandshakeInit(packet) => packet.into_bytes(),
            WgKind::HandshakeResp(packet) => packet.into_bytes(),
            WgKind::CookieReply(packet) => packet.into_bytes(),
            WgKind::Data(packet) => packet.into_bytes(),
        }
    }

    #[inline]
    fn try_send_log_err(socket: &UdpSocket, data: &[u8], target: SocketAddr) {
        if let Err(e) = socket.try_send_to(data, target) {
            tracing::error!(data_len=data.len(), err=?e, ?target, "could not send to network");
        }
    }

    fn try_flush_batch_log_err(
        socket: &UdpSocket,
        sender: &mut UdpBatchSender<BATCH_SIZE, PACKET_BUF_SIZE>,
    ) {
        if let Err(e) = sender.try_flush_best_effort(socket) {
            tracing::error!(err=?e, "could not flush batched udp packets to network");
        }
    }

    fn try_queue_batched_packet(
        socket: &UdpSocket,
        sender: &mut UdpBatchSender<BATCH_SIZE, PACKET_BUF_SIZE>,
        packet: Packet,
        target: SocketAddr,
    ) {
        if let Err(error) = sender.try_queue_packet(packet, target) {
            match error {
                QueuePacketError::Full { packet, target } => {
                    let err = sender.try_flush_best_effort(socket);
                    if let Err(ref flush_err) = err
                        && flush_err.kind() != std::io::ErrorKind::WouldBlock
                    {
                        tracing::error!(err=?flush_err, "could not flush batched udp packets to network");
                    }
                    if sender.try_queue_packet(packet, target).is_err() {
                        tracing::debug!(
                            ?target,
                            "dropping outbound packet because batched sender remains full"
                        );
                    }
                }
                QueuePacketError::PacketTooLarge {
                    packet_len,
                    max_packet_size,
                    ..
                } => {
                    tracing::debug!(
                        packet_len,
                        max_packet_size,
                        "dropping outbound packet because it exceeds the batched sender max"
                    );
                }
            }
        }
    }

    fn create_scmp_error(
        err: PacketPolicyError,
        local_addr: ScionHostAddr,
        dst_addr: ScionAddr,
        target_buf: &mut Packet,
    ) -> Result<usize, EncodeError> {
        let scmp_message = create_inbound_scmp_error(err);
        let scmp_packet_model = ScionPacketScmpRef::new_from_parts(
            AddressHeader {
                src_ia: dst_addr.isd_asn(),
                src_host_addr: local_addr.into(),
                dst_ia: dst_addr.isd_asn(),
                dst_host_addr: dst_addr.host().into(),
            },
            Path::Empty,
            &scmp_message,
        );
        scmp_packet_model.encode(target_buf)
    }
}

fn create_inbound_scmp_error(err: PacketPolicyError) -> scmp::model::ScmpMessage {
    match err {
        PacketPolicyError::MalformedPacket(offending_packet, _) => {
            scmp::model::ScmpParameterProblem::new(
                ScmpParameterProblemCode::InvalidCommonHeader,
                0,
                offending_packet.to_vec(),
            )
            .into()
        }
        PacketPolicyError::InvalidSourceAddress(offending_packet_view) => {
            scmp::model::ScmpParameterProblem::new(
                ScmpParameterProblemCode::InvalidSourceAddress,
                offending_packet_view
                    .header()
                    .src_host_addr_range()
                    .containing_byte_range()
                    .start as u16,
                offending_packet_view.as_bytes().to_vec(),
            )
            .into()
        }
        PacketPolicyError::InvalidPathType(offending_packet_view, _type) => {
            scmp::model::ScmpParameterProblem::new(
                ScmpParameterProblemCode::UnknownPathType,
                offending_packet_view
                    .header()
                    .path_type_range()
                    .containing_byte_range()
                    .start as u16,
                offending_packet_view.as_bytes().to_vec(),
            )
            .into()
        }
    }
}

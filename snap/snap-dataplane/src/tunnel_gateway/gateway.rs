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
    dataplane_path::model::DpPath,
    identifier::isd_asn::IsdAsn,
    packet::{model::ScionScmpPacket, view::ScionPacketView},
    payload::scmp::{self, types::ScmpParameterProblemCode},
};
use snap_tun::{
    server::{HandleIncomingPacketResult, SnapTunAuthorization, SnapTunServer},
    udp_batch::{QueuePacketError, RecvBatchError, UdpBatchReceiver, UdpBatchSender},
};
use tokio::{net::UdpSocket, sync::mpsc::Receiver, time::interval};
use tokio_util::sync::CancellationToken;

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{
        ObservedPacketDirection, ObservedPacketMeta, TunnelGatewayObserver,
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
pub struct TunnelGateway<A, D, O: ?Sized> {
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
    observer: Arc<O>,
}

impl<A, D, O: ?Sized> TunnelGateway<A, D, O>
where
    D: Dispatcher + 'static,
    A: SnapTunAuthorization + 'static,
    O: TunnelGatewayObserver<A::SessionData> + 'static,
{
    /// Create new tunnel gateway exposed on `socket`.
    pub fn new(
        socket: tokio::net::UdpSocket,
        static_server_secret: x25519::StaticSecret,
        authz: Arc<A>,
        dispatcher: Arc<D>,
        observer: Arc<O>,
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
            observer,
        }
    }

    fn handle_outgoing_packet(
        observer: &O,
        snaptun_srv: &mut SnapTunServer<A>,
        packet: Packet,
        target: SocketAddr,
    ) -> Option<WgKind> {
        let packet_meta = Self::outbound_packet_meta(&packet);
        let handled = snaptun_srv.handle_outgoing_packet_with_session(packet, target)?;

        if let Some(packet_meta) = packet_meta {
            observer.observe_packet(
                handled.processed_at,
                handled.session_data.as_ref(),
                packet_meta,
            );
        }

        handled.network_packet
    }

    fn observed_packet_meta(
        packet: &ScionPacketView,
        direction: ObservedPacketDirection,
    ) -> ObservedPacketMeta {
        let header = packet.header();

        ObservedPacketMeta {
            src_ia: header.src_ia(),
            dst_ia: header.dst_ia(),
            packet_len: header.header_len() as usize + packet.payload().len(),
            direction,
        }
    }

    fn outbound_packet_meta(packet: &Packet) -> Option<ObservedPacketMeta> {
        // Outbound queue entries are copied from packets that already passed
        // dispatcher classification, so the egress accounting path only needs a
        // zero-copy SCION header parse to recover src/dst IA and packet length
        // before ownership of the buffer moves into WireGuard encapsulation.
        let (view, _) = ScionPacketView::try_from_slice(&packet[..]).ok()?;

        Some(Self::observed_packet_meta(
            view,
            ObservedPacketDirection::Egress,
        ))
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
                        let handled = snaptun_srv.handle_incoming_packet_with_session(
                            in_pkt,
                            from,
                            &mut send_to_network,
                        );

                        while let Some(pkt) = send_to_network.pop_front() {
                            Self::try_queue_batched_packet(
                                &socket,
                                &mut sender,
                                Self::wg_kind_to_bytes(pkt),
                                from,
                            );
                        }

                        match handled {
                            HandleIncomingPacketResult::Result {
                                result: TunnResult::Done,
                            } => {},
                            HandleIncomingPacketResult::Result {
                                result: TunnResult::Err(wire_guard_error),
                            } => {
                                tracing::error!(err=?wire_guard_error, "wireguard error on incoming packet");
                            },
                            HandleIncomingPacketResult::Result {
                                result: TunnResult::WriteToNetwork(_wg_kind),
                            } => {
                                tracing::error!(
                                    "unexpected TunnResult::WriteToNetwork for incoming packet; \
                                     expected Done, Err, or WriteToTunnel; dropping packet"
                                );
                            },
                            HandleIncomingPacketResult::Forwarded {
                                packet,
                                processed_at,
                                session_data,
                            } => {
                                match inbound_datagram_check(&packet[..], from.ip()) {
                                    Ok(view) => {
                                        self.observer.observe_packet(
                                            processed_at,
                                            session_data.as_ref(),
                                            Self::observed_packet_meta(
                                                view,
                                                ObservedPacketDirection::Ingress,
                                            ),
                                        );
                                        self.dispatcher.try_dispatch(view);
                                    }
                                    Err(e) => {
                                        tracing::debug!(err=%e, "Inbound datagram check failed");
                                        // Use the first assigned address for the SCMP reply.
                                        let mut target_buf = self.pool.get();
                                        match Self::create_scmp_error(
                                            e,
                                            local_addr,
                                            // XXX: the SNAP generating SCMP errors is a bit bogus,
                                            // as the SNAP technically is not a node in the
                                            // SCION-network.
                                            ScionAddr::new(IsdAsn::WILDCARD, from.ip().into()),
                                            &mut target_buf,
                                        ) {
                                            Ok(n) => {
                                                // XXX: `handle_outgoing_packet` allocates a new packet
                                                // for the response (see comment in impl)
                                                target_buf.truncate(n);
                                                if let Some(out_pkt) =
                                                    snaptun_srv.handle_outgoing_packet(target_buf, from)
                                                {
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
                            HandleIncomingPacketResult::Result {
                                result: TunnResult::WriteToTunnel(_packet),
                            } => {
                                tracing::error!(
                                    "unexpected plain WriteToTunnel result from incoming packet handling; \
                                     expected forwarded packet metadata; dropping packet"
                                );
                            },
                        }
                        Ok::<(), std::convert::Infallible>(())
                    }) => {
                        match recv_res {
                            Ok(()) => Self::try_flush_batch_log_err(&socket, &mut sender),
                            Err(RecvBatchError::Io(e)) => {
                                tracing::error!(err=?e, "i/o error on batched udp recv");
                            }
                        }
                    }
                    outbound = self.outbound_queue.recv() => {
                        let Some((target, packet)) = outbound else {
                            tracing::info!("outbound channel closed");
                            break;
                        };

                        if let Some(out_pkt) = Self::handle_outgoing_packet(
                            self.observer.as_ref(),
                            &mut snaptun_srv,
                            packet,
                            target,
                        ) {
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
                            let Some(out_pkt) = Self::handle_outgoing_packet(
                                self.observer.as_ref(),
                                &mut snaptun_srv,
                                packet,
                                target,
                            ) else {
                                continue;
                            };
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
        let scmp_packet_model = ScionScmpPacket::new(
            ScionAddr::new(dst_addr.isd_asn(), local_addr),
            dst_addr,
            DpPath::Empty,
            scmp_message,
        );
        scmp_packet_model.try_encode(target_buf)
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
                offending_packet_view.as_slice().to_vec(),
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
                offending_packet_view.as_slice().to_vec(),
            )
            .into()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Instant,
    };

    use ana_gotatun::{
        noise::{Tunn, TunnResult, rate_limiter::RateLimiter},
        packet::WgKind,
        x25519,
    };
    use sciparse::{
        address::{addr::ScionAddr, host_addr::ScionHostAddr},
        core::encode::WireEncode,
        identifier::isd_asn::IsdAsn as ProtoIsdAsn,
        packet::model::ScionRawPacket,
        payload::ProtocolNumber,
    };
    use snap_tun::server::{SnapTunAuthorization, SnapTunServer};

    use super::*;

    struct NoopDispatcher;

    impl Dispatcher for NoopDispatcher {
        fn try_dispatch(&self, _packet: &ScionPacketView) {}
    }

    type TestTunnelGateway = TunnelGateway<TestAuthz, NoopDispatcher, RecordingObserver>;

    struct TestAuthz;

    impl SnapTunAuthorization for TestAuthz {
        type SessionData = ();

        fn is_authorized(
            &self,
            _now: Instant,
            _identity: &[u8; 32],
        ) -> Option<Arc<Self::SessionData>> {
            Some(Arc::new(()))
        }
    }

    #[derive(Default)]
    struct RecordingObserver {
        observed: Mutex<Vec<ObservedPacketMeta>>,
    }

    impl TunnelGatewayObserver<()> for RecordingObserver {
        fn observe_packet(&self, _now: Instant, _session_data: &(), packet: ObservedPacketMeta) {
            self.observed.lock().unwrap().push(packet);
        }
    }

    fn test_packet_bytes(src_ia: &str, dst_ia: &str) -> Vec<u8> {
        let src_ia: ProtoIsdAsn = src_ia.parse().unwrap();
        let dst_ia: ProtoIsdAsn = dst_ia.parse().unwrap();
        let src = ScionAddr::new(src_ia, ScionHostAddr::V4("127.0.0.1".parse().unwrap()));
        let dst = ScionAddr::new(dst_ia, ScionHostAddr::V4("127.0.0.2".parse().unwrap()));
        let packet = ScionRawPacket::new(
            src,
            dst,
            DpPath::Empty,
            ProtocolNumber::Udp,
            b"payload".to_vec(),
        );
        let mut raw = vec![0; packet.required_size()];
        packet
            .try_encode(&mut raw)
            .expect("failed to encode SCION packet");
        raw
    }

    #[test]
    fn outbound_packet_meta_extracts_src_and_dst_ia() {
        let raw = test_packet_bytes("1-ff00:0:110", "1-ff00:0:111");
        let packet = Packet::copy_from(raw.as_slice());

        let metadata =
            TestTunnelGateway::outbound_packet_meta(&packet).expect("expected packet metadata");

        assert_eq!(metadata.src_ia, "1-ff00:0:110".parse().unwrap());
        assert_eq!(metadata.dst_ia, "1-ff00:0:111".parse().unwrap());
        assert_eq!(metadata.packet_len, raw.len());
        assert_eq!(metadata.direction, ObservedPacketDirection::Egress);
    }

    #[test]
    fn outbound_packet_meta_returns_none_for_malformed_packet() {
        let packet = Packet::copy_from(&b"not a scion packet"[..]);

        assert!(TestTunnelGateway::outbound_packet_meta(&packet).is_none());
    }

    #[test]
    fn handle_outgoing_packet_observes_successful_encapsulation() {
        let observer = RecordingObserver::default();
        let client_addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let server_addr: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let static_client = x25519::StaticSecret::from([0u8; 32]);
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);
        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let mut server =
            SnapTunServer::new(static_server, rate_limiter.clone(), Arc::new(TestAuthz));
        let mut send_to_network = VecDeque::<WgKind>::new();

        let bootstrap_raw = test_packet_bytes("1-ff00:0:110", "1-ff00:0:111");
        let mut client = Tunn::new(
            static_client,
            static_server_public,
            None,
            None,
            0,
            rate_limiter,
            server_addr,
        );

        let Some(WgKind::HandshakeInit(hs_init)) =
            client.handle_outgoing_packet(Packet::copy_from(bootstrap_raw.as_slice()))
        else {
            panic!("expected handshake init")
        };

        server.handle_incoming_packet(hs_init.into_bytes(), client_addr, &mut send_to_network);
        dispatch_one(&mut client, &mut send_to_network);

        let Some(WgKind::Data(client_data)) = client.get_queued_packets().next() else {
            panic!("expected packet to be queued");
        };
        let TunnResult::WriteToTunnel(_) = server.handle_incoming_packet(
            client_data.into_bytes(),
            client_addr,
            &mut send_to_network,
        ) else {
            panic!("expected packet to be processed")
        };

        let outbound_raw = test_packet_bytes("1-ff00:0:111", "1-ff00:0:110");
        let expected_len = outbound_raw.len();
        let outbound_wg = TestTunnelGateway::handle_outgoing_packet(
            &observer,
            &mut server,
            Packet::copy_from(outbound_raw.as_slice()),
            client_addr,
        )
        .expect("expected packet to be encapsulated");

        let TunnResult::WriteToTunnel(plaintext) = client.handle_incoming_packet(outbound_wg)
        else {
            panic!("expected packet to be delivered back to client")
        };
        assert_eq!(&plaintext[..], outbound_raw.as_slice());

        let observations = observer.observed.lock().unwrap();
        assert_eq!(
            observations.as_slice(),
            &[ObservedPacketMeta {
                src_ia: "1-ff00:0:111".parse().unwrap(),
                dst_ia: "1-ff00:0:110".parse().unwrap(),
                packet_len: expected_len,
                direction: ObservedPacketDirection::Egress,
            }]
        );
    }

    #[test]
    fn handle_outgoing_packet_skips_observation_without_active_tunnel() {
        let observer = RecordingObserver::default();
        let client_addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);
        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let mut server = SnapTunServer::new(static_server, rate_limiter, Arc::new(TestAuthz));
        let raw = test_packet_bytes("1-ff00:0:111", "1-ff00:0:110");
        let packet = Packet::copy_from(raw.as_slice());

        assert!(
            TestTunnelGateway::handle_outgoing_packet(&observer, &mut server, packet, client_addr,)
                .is_none()
        );
        assert!(observer.observed.lock().unwrap().is_empty());
    }

    #[test]
    fn incoming_processing_can_flush_previously_queued_outbound_data() {
        let client_addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let server_addr: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let static_client = x25519::StaticSecret::from([0u8; 32]);
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);
        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let mut server =
            SnapTunServer::new(static_server, rate_limiter.clone(), Arc::new(TestAuthz));
        let mut send_to_network = VecDeque::<WgKind>::new();

        let bootstrap_raw = test_packet_bytes("1-ff00:0:110", "1-ff00:0:111");
        let outbound_raw = test_packet_bytes("1-ff00:0:111", "1-ff00:0:110");
        let mut client = Tunn::new(
            static_client,
            static_server_public,
            None,
            None,
            0,
            rate_limiter,
            server_addr,
        );

        let Some(WgKind::HandshakeInit(hs_init)) =
            client.handle_outgoing_packet(Packet::copy_from(bootstrap_raw.as_slice()))
        else {
            panic!("expected handshake init")
        };

        let HandleIncomingPacketResult::Result {
            result: TunnResult::Done,
        } = server.handle_incoming_packet_with_session(
            hs_init.into_bytes(),
            client_addr,
            &mut send_to_network,
        )
        else {
            panic!("expected handshake init to return Done")
        };
        assert!(matches!(
            send_to_network.front(),
            Some(WgKind::HandshakeResp(_))
        ));

        let queued_outgoing = server
            .handle_outgoing_packet_with_session(
                Packet::copy_from(outbound_raw.as_slice()),
                client_addr,
            )
            .expect("expected authorized outgoing packet");
        assert_eq!(queued_outgoing.session_data.as_ref(), &());
        assert!(!matches!(
            queued_outgoing.network_packet,
            Some(WgKind::Data(_))
        ));

        let handshake_response = send_to_network
            .pop_front()
            .expect("expected handshake response");
        let mut client_to_server = VecDeque::new();
        match client.handle_incoming_packet(handshake_response) {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(packet) => client_to_server.push_back(packet),
            result => panic!("unexpected client handshake result: {result:?}"),
        }
        client_to_server.extend(client.get_queued_packets());
        assert!(!client_to_server.is_empty());

        for packet in client_to_server {
            let result = server.handle_incoming_packet_with_session(
                TestTunnelGateway::wg_kind_to_bytes(packet),
                client_addr,
                &mut send_to_network,
            );
            assert!(matches!(
                result,
                HandleIncomingPacketResult::Forwarded { .. }
                    | HandleIncomingPacketResult::Result {
                        result: TunnResult::Done
                    }
            ));
        }

        assert!(
            send_to_network
                .iter()
                .any(|packet| matches!(packet, WgKind::Data(_))),
            "expected queued outbound data to be flushed during incoming processing"
        );
    }

    #[test]
    fn handle_outgoing_packet_observes_payload_before_queued_delivery() {
        let observer = RecordingObserver::default();
        let client_addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let server_addr: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let static_client = x25519::StaticSecret::from([0u8; 32]);
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);
        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let mut server =
            SnapTunServer::new(static_server, rate_limiter.clone(), Arc::new(TestAuthz));
        let mut send_to_network = VecDeque::<WgKind>::new();

        let bootstrap_raw = test_packet_bytes("1-ff00:0:110", "1-ff00:0:111");
        let outbound_raw = test_packet_bytes("1-ff00:0:111", "1-ff00:0:110");
        let mut client = Tunn::new(
            static_client,
            static_server_public,
            None,
            None,
            0,
            rate_limiter,
            server_addr,
        );

        let Some(WgKind::HandshakeInit(hs_init)) =
            client.handle_outgoing_packet(Packet::copy_from(bootstrap_raw.as_slice()))
        else {
            panic!("expected handshake init")
        };

        let HandleIncomingPacketResult::Result {
            result: TunnResult::Done,
        } = server.handle_incoming_packet_with_session(
            hs_init.into_bytes(),
            client_addr,
            &mut send_to_network,
        )
        else {
            panic!("expected handshake init to return Done")
        };

        let _outbound_wg = TestTunnelGateway::handle_outgoing_packet(
            &observer,
            &mut server,
            Packet::copy_from(outbound_raw.as_slice()),
            client_addr,
        );

        {
            let observations = observer.observed.lock().unwrap();
            assert_eq!(
                observations.as_slice(),
                &[ObservedPacketMeta {
                    src_ia: "1-ff00:0:111".parse().unwrap(),
                    dst_ia: "1-ff00:0:110".parse().unwrap(),
                    packet_len: outbound_raw.len(),
                    direction: ObservedPacketDirection::Egress,
                }]
            );
        }

        assert_eq!(
            observer.observed.lock().unwrap().len(),
            1,
            "expected enqueue-time observation before any queued delivery"
        );

        let handshake_response = send_to_network
            .pop_front()
            .expect("expected handshake response");
        let mut client_to_server = VecDeque::new();
        match client.handle_incoming_packet(handshake_response) {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(packet) => client_to_server.push_back(packet),
            result => panic!("unexpected client handshake result: {result:?}"),
        }
        client_to_server.extend(client.get_queued_packets());
        assert!(!client_to_server.is_empty());

        for packet in client_to_server {
            let _ = server.handle_incoming_packet_with_session(
                TestTunnelGateway::wg_kind_to_bytes(packet),
                client_addr,
                &mut send_to_network,
            );
            while send_to_network.pop_front().is_some() {}
        }

        assert_eq!(observer.observed.lock().unwrap().len(), 1);
    }

    fn dispatch_one(tunn: &mut Tunn, packets: &mut VecDeque<WgKind>) -> TunnResult {
        if let Some(packet) = packets.pop_front() {
            return tunn.handle_incoming_packet(packet);
        }
        TunnResult::Done
    }
}

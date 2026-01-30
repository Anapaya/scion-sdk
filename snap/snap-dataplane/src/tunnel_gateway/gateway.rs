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
use bytes::Bytes;
use scion_proto::{
    address::{EndhostAddr, HostAddr, IsdAsn, ScionAddr},
    packet::{ByEndpoint, ScionPacketScmp, ScmpEncodeError, layout::ScionPacketOffset},
    path::DataPlanePath,
    scmp::{ParameterProblemCode, ScmpMessage, ScmpParameterProblem},
    wire_encoding::WireEncodeVec,
};
use snap_tun::server::{SnapTunAuthorization, SnapTunNgServer};
use tokio::{net::UdpSocket, sync::mpsc::Receiver, time::interval};
use tokio_util::sync::CancellationToken;

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{
        dispatcher::TunnelGatewayDispatcherReceiver,
        packet_policy::{PacketPolicyError, inbound_datagram_check},
    },
};

// XXX(dsd): Assume jumbo frames up to 9KiB = 9216 Bytes.
pub(crate) type PacketPool = ana_gotatun::packet::PacketBufPool<9216>;
// Assuming a packet size of 1 KiB, 50*1024*1024 Bytes = 50 MiB ~= 500 Mbps.
pub(crate) const PACKET_PER_SEC_LIMIT: u64 = 50 * 1024;

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
            SnapTunNgServer::new(self.static_server_secret, rate_limiter, self.authz);
        let mut timer = interval(Duration::from_millis(250));
        let socket = self.socket;
        let local_addr = HostAddr::from(
            socket
                .local_addr()
                .map(|s| s.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        );
        let server_task = async move {
            let mut send_to_network: VecDeque<WgKind> = Default::default();
            loop {
                let mut in_pkt = self.pool.get();

                tokio::select! {
                    recv_res = socket.recv_from(in_pkt.as_mut()) => {
                        let (n, from) = match recv_res {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::error!(err=?e, "i/o error on udp socket recv_from()");
                                continue;
                            }
                        };

                        in_pkt.truncate(n);

                        let res = snaptun_srv.handle_incoming_packet(in_pkt, from, &mut send_to_network);

                        // first, process whatever needs to be returned
                        while let Some(pkt) = send_to_network.pop_front() {
                            Self::try_send_log_err(&socket, &Self::wg_kind_to_bytes(pkt), from);
                        }

                        match res {
                            TunnResult::Done => continue,
                            TunnResult::Err(wire_guard_error) => {
                                tracing::error!(err=?wire_guard_error, "wireguard error on incoming packet");
                            },
                            TunnResult::WriteToNetwork(_wg_kind) => {
                                // This variant is not expected for inbound packets. The gateway expects
                                // `Done`, `Err`, or `WriteToTunnel` from `handle_incoming_packet`.
                                // Log and drop the packet so we can diagnose protocol/state issues
                                // without crashing the process.
                                tracing::error!(
                                    "unexpected TunnResult::WriteToNetwork for incoming packet; \
                                     expected Done, Err, or WriteToTunnel; dropping packet"
                                );
                            },
                            TunnResult::WriteToTunnel(packet) => {
                            match inbound_datagram_check(&packet[..], from.ip()) {
                                Ok(pkt) => {
                                    self.dispatcher.try_dispatch(pkt);
                                }
                                Err(e) => {
                                    tracing::debug!(err=%e, "Inbound datagram check failed");
                                    // Use the first assigned address for the SCMP reply.
                                    let (mut temp_buf, mut target_buf) = (self.pool.get(), self.pool.get());
                                    if Self::create_scmp_error(
                                        e,
                                        Bytes::copy_from_slice(&packet[..]),
                                        local_addr,
                                        // XXX: the SNAP generating SCMP errors
                                        // is a bit bogus, as the SNAP
                                        // technically is not a node in the
                                        // SCION-network.
                                        EndhostAddr::new(IsdAsn::from(0), from.ip()),
                                        &mut temp_buf,
                                        &mut target_buf
                                    ) {
                                        // XXX: `handle_outgoing_packet`
                                        // allocates a new packet for the
                                        // response (see comment in impl)
                                        let Some(out_pkt) = snaptun_srv.handle_outgoing_packet(target_buf, from) else {continue};
                                        Self::try_send_log_err(&socket, &Self::wg_kind_to_bytes(out_pkt), from);
                                    }

                                }
                            }
                            },
                        }

                    },
                    outbound = self.outbound_queue.recv() => {
                        let Some((target, packet)) = outbound else {
                            tracing::info!("outbound channel closed");
                            break;
                        };

                        let Some(out_pkt) = snaptun_srv.handle_outgoing_packet(packet, target) else {continue};
                        Self::try_send_log_err(&socket, &Self::wg_kind_to_bytes(out_pkt), target);
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

    fn create_scmp_error(
        err: PacketPolicyError,
        data: Bytes,
        local_addr: HostAddr,
        dst_addr: EndhostAddr,
        temp_buf: &mut Packet,
        target_buf: &mut Packet,
    ) -> bool {
        let scmp_message = match create_inbound_scmp_error(err, data) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error=%e, "Error creating SCMP message");
                return false;
            }
        };

        // Create AS-local empty path for SCMP packet
        let path = DataPlanePath::EmptyPath;

        let endpoint = ByEndpoint {
            source: ScionAddr::new(dst_addr.isd_asn(), local_addr),
            destination: dst_addr.into(),
        };

        let scmp_packet = match ScionPacketScmp::new(endpoint, path, scmp_message) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error=%e, "Error creating SCMP packet");
                return false;
            }
        };

        // XXX(dsd): WHY?
        wire_encode(&scmp_packet, temp_buf, target_buf);
        true
    }
}

fn create_inbound_scmp_error(
    err: PacketPolicyError,
    offending_packet: Bytes,
) -> Result<ScmpMessage, ScmpEncodeError> {
    let scmp_message = match err {
        PacketPolicyError::InvalidCommonHeader(_error) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidCommonHeader,
                0,
                offending_packet,
            ))
        }
        PacketPolicyError::InvalidAddressHeader(_error) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidAddressHeader,
                ScionPacketOffset::address_header().base().bytes(),
                offending_packet,
            ))
        }
        PacketPolicyError::InvalidSourceAddress => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidSourceAddress,
                ScionPacketOffset::address_header()
                    .src_host_addr(&offending_packet)
                    .bytes(),
                offending_packet,
            ))
        }
        PacketPolicyError::InvalidPathType(_type) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::UnknownPathType,
                ScionPacketOffset::common_header().path_type().bytes(),
                offending_packet,
            ))
        }
        PacketPolicyError::InvalidPath(_error, offset) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidPath,
                offset,
                offending_packet,
            ))
        }
        PacketPolicyError::InconsistentPathLength(offset) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidPath,
                offset,
                offending_packet,
            ))
        }
        PacketPolicyError::PacketEmptyOrTruncated(offset) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidPacketSize,
                offset,
                offending_packet,
            ))
        }
    };

    Ok(scmp_message)
}

// XXX(dsd): This function exists to avoid unnecessary vec-allocations when
// dealing with the scion-proto API.
//
// # Arguments
// * `packet`: the packet to be serialized
// * `temp_buf`: a temporary buffer that is used for internal packet assembly
// * `target_buf`: the buffer that will contain the final result
#[inline]
pub(crate) fn wire_encode<W, const N: usize>(
    packet: &W,
    temp_buf: &mut Packet,
    target_buf: &mut Packet,
) where
    W: WireEncodeVec<N>,
{
    temp_buf.truncate(0);
    let parts = packet.encode_with_unchecked(temp_buf.buf_mut());

    let mut n = 0;
    parts.iter().for_each(|x| {
        target_buf.as_mut()[n..(n + x.len())].copy_from_slice(x);
        n += x.len();
    });
    target_buf.truncate(n);
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ana_gotatun::packet::PacketBufPool;
    use bytes::Bytes;
    use scion_proto::{
        address::{HostAddr, IsdAsn, ScionAddr},
        packet::{ByEndpoint, ScionPacketScmp},
        path::DataPlanePath,
        scmp::{ScmpEchoRequest, ScmpMessage},
        wire_encoding::WireDecode,
    };

    use crate::tunnel_gateway::gateway::wire_encode;

    #[test]
    fn wire_encode_decode_scion_packet_scmp_succeeds() {
        let pool = PacketBufPool::<2048>::new(2);

        // 1. Build a simple SCMP echo request message
        let echo = ScmpEchoRequest::new(42, 7, Bytes::copy_from_slice(b"hello"));
        let msg: ScmpMessage = echo.into();

        // 2. Build trivial endhost addresses (loopback, arbitrary ports) Adjust IA / address
        //    constructors as needed for your test setup.
        let src_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let dst_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let src = ScionAddr::new(IsdAsn::from(0), HostAddr::from(src_ip));
        let dst = ScionAddr::new(IsdAsn::from(0), HostAddr::from(dst_ip));

        let endhosts = ByEndpoint {
            source: src,
            destination: dst,
        };

        // 3. Use an empty standard path (or a suitable path for your tests)
        let path = DataPlanePath::EmptyPath; // or DataPlanePath::Standard(...)

        // 4. Build the SCMP packet (this also sets the checksum correctly)
        let packet =
            ScionPacketScmp::new(endhosts, path, msg).expect("failed to build SCMP packet");

        let mut buf = pool.get();
        buf.truncate(0);
        let mut second_buf = pool.get();
        wire_encode(&packet, &mut buf, &mut second_buf);

        let decoded = ScionPacketScmp::decode(&mut second_buf.as_ref())
            .expect("failed to decode SCMP packet");

        assert_eq!(packet.headers.common, decoded.headers.common);
        assert_eq!(packet.message, decoded.message);
    }
}

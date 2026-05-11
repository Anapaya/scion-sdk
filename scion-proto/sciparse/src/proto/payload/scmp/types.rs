use crate::core::{read::FromUnalignedRead, write::IntoUnalignedWrite};

/// SCMP message types.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ScmpMessageType {
    /// Destination Unreachable message.
    DestinationUnreachable = 1,
    /// Packet Too Big message.
    PacketTooBig = 2,
    /// Parameter Problem message.
    ParameterProblem = 4,
    /// External Interface Down message.
    ExternalInterfaceDown = 5,
    /// Internal Connectivity Down message.
    InternalConnectivityDown = 6,
    /// Echo Request message.
    EchoRequest = 128,
    /// Echo Reply message.
    EchoReply = 129,
    /// Traceroute Request message.
    TracerouteRequest = 130,
    /// Traceroute Reply message.
    TracerouteReply = 131,
    /// Unknown message type.
    Unknown(u8),
}
impl From<u8> for ScmpMessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => ScmpMessageType::DestinationUnreachable,
            2 => ScmpMessageType::PacketTooBig,
            4 => ScmpMessageType::ParameterProblem,
            5 => ScmpMessageType::ExternalInterfaceDown,
            6 => ScmpMessageType::InternalConnectivityDown,
            128 => ScmpMessageType::EchoRequest,
            129 => ScmpMessageType::EchoReply,
            130 => ScmpMessageType::TracerouteRequest,
            131 => ScmpMessageType::TracerouteReply,
            other => ScmpMessageType::Unknown(other),
        }
    }
}
impl From<ScmpMessageType> for u8 {
    fn from(value: ScmpMessageType) -> Self {
        match value {
            ScmpMessageType::DestinationUnreachable => 1,
            ScmpMessageType::PacketTooBig => 2,
            ScmpMessageType::ParameterProblem => 4,
            ScmpMessageType::ExternalInterfaceDown => 5,
            ScmpMessageType::InternalConnectivityDown => 6,
            ScmpMessageType::EchoRequest => 128,
            ScmpMessageType::EchoReply => 129,
            ScmpMessageType::TracerouteRequest => 130,
            ScmpMessageType::TracerouteReply => 131,
            ScmpMessageType::Unknown(value) => value,
        }
    }
}
impl FromUnalignedRead for ScmpMessageType {
    fn from_unaligned_read(value: u128) -> Self {
        (value as u8).into()
    }
}
impl IntoUnalignedWrite for ScmpMessageType {
    fn into_write_value(v: Self) -> u128 {
        u8::from(v) as u128
    }
}

/// Destination Unreachable Codes for SCMP Destination Unreachable messages.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ScmpDestinationUnreachableCode {
    /// No Route to Destination.
    NoRouteToDestination = 0,
    /// Communication Administratively Denied.
    CommunicationAdministrativelyDenied = 1,
    /// Beyond Scope of Source Address.
    BeyondScopeOfSourceAddress = 2,
    /// Address Unreachable.
    AddressUnreachable = 3,
    /// Port Unreachable.
    PortUnreachable = 4,
    /// Source Address Failed Ingress/Egress Policy.
    SourceAddressFailedIngressEgressPolicy = 5,
    /// Reject Route to Destination.
    RejectRouteToDestination = 6,
    /// Unassigned code.
    Unassigned(u8),
}
impl From<u8> for ScmpDestinationUnreachableCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ScmpDestinationUnreachableCode::NoRouteToDestination,
            1 => ScmpDestinationUnreachableCode::CommunicationAdministrativelyDenied,
            2 => ScmpDestinationUnreachableCode::BeyondScopeOfSourceAddress,
            3 => ScmpDestinationUnreachableCode::AddressUnreachable,
            4 => ScmpDestinationUnreachableCode::PortUnreachable,
            5 => ScmpDestinationUnreachableCode::SourceAddressFailedIngressEgressPolicy,
            6 => ScmpDestinationUnreachableCode::RejectRouteToDestination,
            other => ScmpDestinationUnreachableCode::Unassigned(other),
        }
    }
}
impl From<ScmpDestinationUnreachableCode> for u8 {
    fn from(value: ScmpDestinationUnreachableCode) -> Self {
        match value {
            ScmpDestinationUnreachableCode::NoRouteToDestination => 0,
            ScmpDestinationUnreachableCode::CommunicationAdministrativelyDenied => 1,
            ScmpDestinationUnreachableCode::BeyondScopeOfSourceAddress => 2,
            ScmpDestinationUnreachableCode::AddressUnreachable => 3,
            ScmpDestinationUnreachableCode::PortUnreachable => 4,
            ScmpDestinationUnreachableCode::SourceAddressFailedIngressEgressPolicy => 5,
            ScmpDestinationUnreachableCode::RejectRouteToDestination => 6,
            ScmpDestinationUnreachableCode::Unassigned(value) => value,
        }
    }
}
impl FromUnalignedRead for ScmpDestinationUnreachableCode {
    fn from_unaligned_read(value: u128) -> Self {
        (value as u8).into()
    }
}
impl IntoUnalignedWrite for ScmpDestinationUnreachableCode {
    fn into_write_value(v: Self) -> u128 {
        u8::from(v) as u128
    }
}

/// Parameter Problem Codes for SCMP Parameter Problem messages.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ScmpParameterProblemCode {
    /// Erroneous Header Field.
    ErroneousHeaderField = 0,
    /// Unknown Next Header Type.
    UnknownNextHdrType = 1,
    /// Invalid Common Header.
    InvalidCommonHeader = 16,
    /// Unknown SCION Version.
    UnknownScionVersion = 17,
    /// Flow ID Required.
    FlowIdRequired = 18,
    /// Invalid Packet Size.
    InvalidPacketSize = 19,
    /// Unknown Path Type.
    UnknownPathType = 20,
    /// Unknown Address Format.
    UnknownAddressFormat = 21,
    /// Invalid Address Header.
    InvalidAddressHeader = 32,
    /// Invalid Source Address.
    InvalidSourceAddress = 33,
    /// Invalid Destination Address.
    InvalidDestinationAddress = 34,
    /// Non-Local Delivery.
    NonLocalDelivery = 35,
    /// Invalid Path.
    InvalidPath = 48,
    /// Unknown Hop Field Cons Ingress Interface.
    UnknownHopFieldConsIngressInterface = 49,
    /// Unknown Hop Field Cons Egress Interface.
    UnknownHopFieldConsEgressInterface = 50,
    /// Invalid Hop Field MAC.
    InvalidHopFieldMac = 51,
    /// Path Expired.
    PathExpired = 52,
    /// Invalid Segment Change.
    InvalidSegmentChange = 53,
    /// Invalid Extension Header.
    InvalidExtensionHeader = 64,
    /// Unknown Hop-by-Hop Option.
    UnknownHopByHopOption = 65,
    /// Unknown End-to-End Option.
    UnknownEndToEndOption = 66,
    /// Unassigned code.
    Unassigned(u8),
}
impl From<u8> for ScmpParameterProblemCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ScmpParameterProblemCode::ErroneousHeaderField,
            1 => ScmpParameterProblemCode::UnknownNextHdrType,
            16 => ScmpParameterProblemCode::InvalidCommonHeader,
            17 => ScmpParameterProblemCode::UnknownScionVersion,
            18 => ScmpParameterProblemCode::FlowIdRequired,
            19 => ScmpParameterProblemCode::InvalidPacketSize,
            20 => ScmpParameterProblemCode::UnknownPathType,
            21 => ScmpParameterProblemCode::UnknownAddressFormat,
            32 => ScmpParameterProblemCode::InvalidAddressHeader,
            33 => ScmpParameterProblemCode::InvalidSourceAddress,
            34 => ScmpParameterProblemCode::InvalidDestinationAddress,
            35 => ScmpParameterProblemCode::NonLocalDelivery,
            48 => ScmpParameterProblemCode::InvalidPath,
            49 => ScmpParameterProblemCode::UnknownHopFieldConsIngressInterface,
            50 => ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface,
            51 => ScmpParameterProblemCode::InvalidHopFieldMac,
            52 => ScmpParameterProblemCode::PathExpired,
            53 => ScmpParameterProblemCode::InvalidSegmentChange,
            64 => ScmpParameterProblemCode::InvalidExtensionHeader,
            65 => ScmpParameterProblemCode::UnknownHopByHopOption,
            66 => ScmpParameterProblemCode::UnknownEndToEndOption,
            other => ScmpParameterProblemCode::Unassigned(other),
        }
    }
}
impl From<ScmpParameterProblemCode> for u8 {
    fn from(value: ScmpParameterProblemCode) -> Self {
        match value {
            ScmpParameterProblemCode::ErroneousHeaderField => 0,
            ScmpParameterProblemCode::UnknownNextHdrType => 1,
            ScmpParameterProblemCode::InvalidCommonHeader => 16,
            ScmpParameterProblemCode::UnknownScionVersion => 17,
            ScmpParameterProblemCode::FlowIdRequired => 18,
            ScmpParameterProblemCode::InvalidPacketSize => 19,
            ScmpParameterProblemCode::UnknownPathType => 20,
            ScmpParameterProblemCode::UnknownAddressFormat => 21,
            ScmpParameterProblemCode::InvalidAddressHeader => 32,
            ScmpParameterProblemCode::InvalidSourceAddress => 33,
            ScmpParameterProblemCode::InvalidDestinationAddress => 34,
            ScmpParameterProblemCode::NonLocalDelivery => 35,
            ScmpParameterProblemCode::InvalidPath => 48,
            ScmpParameterProblemCode::UnknownHopFieldConsIngressInterface => 49,
            ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface => 50,
            ScmpParameterProblemCode::InvalidHopFieldMac => 51,
            ScmpParameterProblemCode::PathExpired => 52,
            ScmpParameterProblemCode::InvalidSegmentChange => 53,
            ScmpParameterProblemCode::InvalidExtensionHeader => 64,
            ScmpParameterProblemCode::UnknownHopByHopOption => 65,
            ScmpParameterProblemCode::UnknownEndToEndOption => 66,
            ScmpParameterProblemCode::Unassigned(value) => value,
        }
    }
}
impl FromUnalignedRead for ScmpParameterProblemCode {
    fn from_unaligned_read(value: u128) -> Self {
        (value as u8).into()
    }
}
impl IntoUnalignedWrite for ScmpParameterProblemCode {
    fn into_write_value(v: Self) -> u128 {
        u8::from(v) as u128
    }
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    // note: can't use derive because of the `Unknown` variants, so we implement `Arbitrary`
    // manually

    use proptest::prelude::*;

    use super::*;

    /// Configuration for generating arbitrary [`ScmpMessageType`] values.
    ///
    /// Controls the relative probability of each variant being generated.
    ///
    /// Default weights: all known types = 1, unknown = 1.
    #[derive(Debug, Clone)]
    pub struct ArbitraryScmpMessageTypeParams {
        /// Weight for DestinationUnreachable.
        pub destination_unreachable: u32,
        /// Weight for PacketTooBig.
        pub packet_too_big: u32,
        /// Weight for ParameterProblem.
        pub parameter_problem: u32,
        /// Weight for ExternalInterfaceDown.
        pub external_interface_down: u32,
        /// Weight for InternalConnectivityDown.
        pub internal_connectivity_down: u32,
        /// Weight for EchoRequest.
        pub echo_request: u32,
        /// Weight for EchoReply.
        pub echo_reply: u32,
        /// Weight for TracerouteRequest.
        pub traceroute_request: u32,
        /// Weight for TracerouteReply.
        pub traceroute_reply: u32,
        /// Weight for Unknown (random byte not matching known types).
        pub unknown: u32,
    }
    impl Default for ArbitraryScmpMessageTypeParams {
        fn default() -> Self {
            Self {
                destination_unreachable: 1,
                packet_too_big: 1,
                parameter_problem: 1,
                external_interface_down: 1,
                internal_connectivity_down: 1,
                echo_request: 1,
                echo_reply: 1,
                traceroute_request: 1,
                traceroute_reply: 1,
                unknown: 1,
            }
        }
    }

    impl Arbitrary for ScmpMessageType {
        type Parameters = ArbitraryScmpMessageTypeParams;
        type Strategy = BoxedStrategy<Self>;
        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                params.destination_unreachable => Just(ScmpMessageType::DestinationUnreachable),
                params.packet_too_big => Just(ScmpMessageType::PacketTooBig),
                params.parameter_problem => Just(ScmpMessageType::ParameterProblem),
                params.external_interface_down => Just(ScmpMessageType::ExternalInterfaceDown),
                params.internal_connectivity_down => Just(ScmpMessageType::InternalConnectivityDown),
                params.echo_request => Just(ScmpMessageType::EchoRequest),
                params.echo_reply => Just(ScmpMessageType::EchoReply),
                params.traceroute_request => Just(ScmpMessageType::TracerouteRequest),
                params.traceroute_reply => Just(ScmpMessageType::TracerouteReply),
                params.unknown => any::<u8>().prop_map(|v| {
                    let mut v = v;
                    while !matches!(ScmpMessageType::from(v), ScmpMessageType::Unknown(_)) {
                        v = v.wrapping_add(1);
                    }
                    ScmpMessageType::Unknown(v)
                }),
            ]
            .boxed()
        }
    }

    /// Configuration for generating arbitrary [`ScmpDestinationUnreachableCode`] values.
    ///
    /// Controls the relative probability of known vs unknown codes.
    ///
    /// Default weights: `known = 7, unknown = 1`.
    #[derive(Debug, Clone)]
    pub struct ArbitraryScmpDestinationUnreachableCodeParams {
        /// Weight for generating any of the known destination unreachable codes (uniformly).
        pub known: u32,
        /// Weight for generating unknown (unassigned) codes.
        pub unknown: u32,
    }
    impl Default for ArbitraryScmpDestinationUnreachableCodeParams {
        fn default() -> Self {
            Self {
                known: 7,
                unknown: 1,
            }
        }
    }

    impl Arbitrary for ScmpDestinationUnreachableCode {
        type Parameters = ArbitraryScmpDestinationUnreachableCodeParams;
        type Strategy = BoxedStrategy<Self>;
        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                params.known => prop::sample::select(vec![
                    ScmpDestinationUnreachableCode::NoRouteToDestination,
                    ScmpDestinationUnreachableCode::CommunicationAdministrativelyDenied,
                    ScmpDestinationUnreachableCode::BeyondScopeOfSourceAddress,
                    ScmpDestinationUnreachableCode::AddressUnreachable,
                    ScmpDestinationUnreachableCode::PortUnreachable,
                    ScmpDestinationUnreachableCode::SourceAddressFailedIngressEgressPolicy,
                    ScmpDestinationUnreachableCode::RejectRouteToDestination,
                ]),
                params.unknown => (7u8..=255)
                    .prop_map(ScmpDestinationUnreachableCode::Unassigned),
            ]
            .boxed()
        }
    }

    /// Configuration for generating arbitrary [`ScmpParameterProblemCode`] values.
    ///
    /// Controls the relative probability of known vs unknown codes.
    ///
    /// Default weights: `known = 5, unknown = 1`.
    #[derive(Debug, Clone)]
    pub struct ArbitraryScmpParameterProblemCodeParams {
        /// Weight for generating any of the known parameter problem codes (uniformly).
        pub known: u32,
        /// Weight for generating unknown codes.
        pub unknown: u32,
    }
    impl Default for ArbitraryScmpParameterProblemCodeParams {
        fn default() -> Self {
            Self {
                known: 5,
                unknown: 1,
            }
        }
    }

    impl Arbitrary for ScmpParameterProblemCode {
        type Parameters = ArbitraryScmpParameterProblemCodeParams;
        type Strategy = BoxedStrategy<Self>;
        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                params.known => prop::sample::select(vec![
                    ScmpParameterProblemCode::ErroneousHeaderField,
                    ScmpParameterProblemCode::UnknownNextHdrType,
                    ScmpParameterProblemCode::InvalidCommonHeader,
                    ScmpParameterProblemCode::UnknownScionVersion,
                    ScmpParameterProblemCode::FlowIdRequired,
                    ScmpParameterProblemCode::InvalidPacketSize,
                    ScmpParameterProblemCode::UnknownPathType,
                    ScmpParameterProblemCode::UnknownAddressFormat,
                    ScmpParameterProblemCode::InvalidAddressHeader,
                    ScmpParameterProblemCode::InvalidSourceAddress,
                    ScmpParameterProblemCode::InvalidDestinationAddress,
                    ScmpParameterProblemCode::NonLocalDelivery,
                    ScmpParameterProblemCode::InvalidPath,
                    ScmpParameterProblemCode::UnknownHopFieldConsIngressInterface,
                    ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface,
                    ScmpParameterProblemCode::InvalidHopFieldMac,
                    ScmpParameterProblemCode::PathExpired,
                    ScmpParameterProblemCode::InvalidSegmentChange,
                    ScmpParameterProblemCode::InvalidExtensionHeader,
                    ScmpParameterProblemCode::UnknownHopByHopOption,
                    ScmpParameterProblemCode::UnknownEndToEndOption,
                ]),
                params.unknown => any::<u8>().prop_map(|v| {
                    let mut v = v;
                    while !matches!(
                        ScmpParameterProblemCode::from(v),
                        ScmpParameterProblemCode::Unassigned(_)
                    ) {
                        v = v.wrapping_add(1);
                    }
                    ScmpParameterProblemCode::Unassigned(v)
                }),
            ]
            .boxed()
        }
    }
}

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

//! PocketSCION I/O configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use sciparse::identifier::isd_asn::IsdAsn;

use crate::comp::{
    endhost_api::EndhostApiId, endhost_api_discovery::EndhostApiDiscoveryApiId, router::RouterId,
    snap::SnapId,
};

helper::io_config! {
    /// I/O configuration for PocketSCION components.
    ///
    /// This struct contains the socket addresses for all components of PocketSCION.
    /// These addresses map to real socket addresses on the host, and are used to configure the I/O of the components.
    ///
    /// If no specific address is configured for a component, it binds to an ephemeral port on
    /// `bind_ip`, or on localhost when `bind_ip` is not set. The network forwarder is the
    /// exception and binds to all interfaces. The actual bound address is written back into this
    /// configuration.
    ///
    /// `advertised_ip` replaces the IP of the addresses handed to clients in one AS, keeping the
    /// port. This applies to explicitly configured addresses as well, not only to automatically
    /// bound ones: it defines how clients see the host, not how components bind. Use it when
    /// clients reach the host through a different IP than the one components bind, for example an
    /// Android emulator that reaches the host loopback as `10.0.2.2`.
    ///
    /// Per AS rather than for the whole topology, because a process can be both the host of a
    /// topology and a client inside it. A test server whose own HTTP/3 server sits in one AS while
    /// an emulator attaches to another needs the emulator's AS rewritten and its own left alone:
    /// the two clients reach the host by different routes, and no single IP suits both. Set
    /// [`IsdAsn::WILDCARD`] to rewrite every AS, which is what a client that is entirely outside
    /// this host wants; an entry for a specific AS wins over it.
    struct IoConfig;
    addr_map(router_socket: RouterId),
    addr_map(endhost_api: EndhostApiId),
    addr_map(anapaya_ead_api: EndhostApiDiscoveryApiId),
    addr_map(snap_control: SnapId),
    addr_map(snap_data_plane: SnapId),
    addr_map(daemon_service: IsdAsn),
    addr_map(control_service: IsdAsn),
    addr_map_keyed(external_as_interface: (isd_asn: IsdAsn, interface_id: u16)),
    addr_map_keyed(network_forwarder: (isd_asn: IsdAsn, ip_addr: IpAddr)),
    addr_singleton(auth_server),
    ip_singleton(bind_ip),
    ip_map(advertised_ip: IsdAsn),
}

impl IoConfig {
    /// Returns `addr` as a client in `isd_as` must see it: with the IP replaced by the advertised
    /// IP that applies to that AS, and unchanged when none does. The port is always kept. The
    /// replacement is unconditional: it does not matter whether `addr` was configured explicitly
    /// or bound automatically.
    pub fn advertise(&self, isd_as: IsdAsn, addr: SocketAddr) -> SocketAddr {
        match self.advertised_ip_for(isd_as) {
            Some(ip) => SocketAddr::new(ip, addr.port()),
            None => addr,
        }
    }

    /// As [`advertise`](Self::advertise), for a component that serves several ASes at once.
    ///
    /// The first of them with an advertised IP decides. A component shared between an AS that needs
    /// the rewrite and one that does not cannot satisfy both, and a client that needs it is the one
    /// that cannot reach the component at all otherwise.
    pub fn advertise_any(
        &self,
        isd_ases: impl IntoIterator<Item = IsdAsn>,
        addr: SocketAddr,
    ) -> SocketAddr {
        match isd_ases
            .into_iter()
            .find_map(|ia| self.advertised_ip_for(ia))
        {
            Some(ip) => SocketAddr::new(ip, addr.port()),
            None => addr,
        }
    }

    /// The advertised IP that applies to `isd_as`: the most specific entry that matches it.
    ///
    /// Most specific rather than first, and the difference is not academic. An entry may wildcard
    /// its ISD, its AS number, or both, so several can match one AS at once, and the map's own
    /// order puts the *least* specific first: a wildcard is zero. `1-0` alongside `0-0` would
    /// otherwise resolve to `0-0` for every AS in ISD 1, which is the opposite of what
    /// configuring `1-0` asks for. Two entries of equal specificity that both match are
    /// ambiguous however they are ordered; the later one in key order wins, deterministically.
    fn advertised_ip_for(&self, isd_as: IsdAsn) -> Option<IpAddr> {
        self.read()
            .advertised_ip
            .iter()
            .filter(|(configured, _)| configured.matches(isd_as))
            .max_by_key(|(configured, _)| specificity(**configured))
            .map(|(_, ip)| *ip)
    }

    /// Returns the IP that components bind to when no explicit address is configured for them:
    /// `bind_ip`, or localhost when `bind_ip` is not set.
    pub fn default_bind_ip(&self) -> IpAddr {
        self.bind_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}

/// How narrowly an [IoConfig] key selects an AS: one point for each half it does not wildcard.
fn specificity(isd_as: IsdAsn) -> u8 {
    u8::from(!isd_as.isd().is_wildcard()) + u8::from(!isd_as.asn().is_wildcard())
}

mod helper {
    /// Macro to generate I/O configuration struct
    ///
    /// - addr_map: generates a BTreeMap<$Key, SocketAddr> field with the given name, and
    ///   getter/setter methods to access it.
    /// - addr_map_keyed: like addr_map but with named tuple components, flattened into the function
    ///   signatures instead of a single tuple parameter.
    /// - addr_singleton: generates an Option<SocketAddr> field with the given name, and
    ///   getter/setter methods to access it.
    /// - ip_singleton: generates an Option<IpAddr> field with the given name, and getter/setter
    ///   methods to access it.
    /// - ip_map: generates a BTreeMap<$Key, IpAddr> field with the given name, and getter/setter
    ///   methods to access it. The getter matches the key exactly; interpreting wildcards is the
    ///   caller's business.
    /// - custom_map: generates a BTreeMap<$Key, $Val> field with the given name, without any
    ///   getter/setter methods.
    macro_rules! io_config {
        (
            $(#[$meta:meta])*
            struct $StructName:ident;
            $(addr_map($field:ident : $Key:ty),)*
            $(addr_map_keyed($field4:ident : ($($kname:ident : $KTy:ty),+)),)*
            $(addr_singleton($field2:ident),)*
            $(ip_singleton($field5:ident),)*
            $(ip_map($field6:ident : $Key6:ty),)*
            $(custom_map($field3:ident : $Key3:ty => $Val:ty),)*
        ) => {
            paste::paste! {
                // --- Inner data struct ---
                #[derive(
                    ::std::default::Default,
                    ::std::fmt::Debug,
                    ::std::cmp::PartialEq,
                    ::std::clone::Clone,
                    ::serde::Serialize,
                    ::serde::Deserialize,
                    ::utoipa::ToSchema,
                )]
                $(#[$meta])*
                pub struct [<$StructName Inner>] {
                    $(
                        #[schema(value_type = ::std::collections::BTreeMap<String, String>)]
                        $field: ::std::collections::BTreeMap<$Key, ::std::net::SocketAddr>,
                    )*
                    $(
                        #[schema(value_type = ::std::collections::BTreeMap<String, String>)]
                        $field4: ::std::collections::BTreeMap<($($KTy,)+), ::std::net::SocketAddr>,
                    )*
                    $(
                        #[schema(value_type = String, nullable = true)]
                        $field2: ::std::option::Option<::std::net::SocketAddr>,
                    )*
                    $(
                        #[schema(value_type = String, nullable = true)]
                        $field5: ::std::option::Option<::std::net::IpAddr>,
                    )*
                    $(
                        #[schema(value_type = ::std::collections::BTreeMap<String, String>)]
                        $field6: ::std::collections::BTreeMap<$Key6, ::std::net::IpAddr>,
                    )*
                    $(
                        $field3: ::std::collections::BTreeMap<$Key3, $Val>,
                    )*
                }

                // --- Shared wrapper ---
                #[derive(::std::clone::Clone, ::std::default::Default)]
                $(#[$meta])*
                pub struct $StructName {
                    inner: ::std::sync::Arc<::std::sync::RwLock<[<$StructName Inner>]>>,
                }

                impl ::std::fmt::Debug for $StructName {
                    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                        self.inner.read().unwrap().fmt(f)
                    }
                }

                impl $StructName {
                    /// Creates a new, empty instance.
                    pub fn new() -> Self {
                        Self::default()
                    }

                    /// Creates a new instance from the given inner data.
                    pub fn from_inner(inner: [<$StructName Inner>]) -> Self {
                        Self {
                            inner: ::std::sync::Arc::new(::std::sync::RwLock::new(inner)),
                        }
                    }

                    /// Returns a clone of the inner data.
                    pub fn to_inner(&self) -> [<$StructName Inner>] {
                        self.inner.read().unwrap().clone()
                    }

                    /// Returns a read guard over the inner data.
                    pub fn read(&self) -> ::std::sync::RwLockReadGuard<'_, [<$StructName Inner>]> {
                        self.inner.read().unwrap()
                    }

                    /// Returns a write guard over the inner data.
                    pub fn write(&self) -> ::std::sync::RwLockWriteGuard<'_, [<$StructName Inner>]> {
                        self.inner.write().unwrap()
                    }

                    // addr_map methods
                    $(
                        /// Returns the socket address for the given ID, if it exists.
                        pub fn [<$field:snake _addr>](&self, id: $Key) -> ::std::option::Option<::std::net::SocketAddr> {
                            self.inner.read().unwrap().$field.get(&id).cloned()
                        }

                        /// Sets the socket address for the given ID, returning the previous value if any.
                        pub fn [<set_ $field:snake _addr>](&self, id: $Key, addr: ::std::net::SocketAddr) -> ::std::option::Option<::std::net::SocketAddr> {
                            self.inner.write().unwrap().$field.insert(id, addr)
                        }
                    )*

                    // addr_map_keyed methods
                    $(
                        /// Returns the socket address for the given key components, if it exists.
                        pub fn [<$field4:snake _addr>](&self, $($kname: $KTy,)+) -> ::std::option::Option<::std::net::SocketAddr> {
                            self.inner.read().unwrap().$field4.get(&($($kname,)+)).cloned()
                        }

                        /// Sets the socket address for the given key components, returning the previous value if any.
                        pub fn [<set_ $field4:snake _addr>](&self, $($kname: $KTy,)+ addr: ::std::net::SocketAddr) -> ::std::option::Option<::std::net::SocketAddr> {
                            self.inner.write().unwrap().$field4.insert(($($kname,)+), addr)
                        }
                    )*

                    // addr_singleton methods
                    $(
                        /// Returns the socket address if it exists.
                        pub fn [<$field2:snake _addr>](&self) -> ::std::option::Option<::std::net::SocketAddr> {
                            self.inner.read().unwrap().$field2
                        }

                        /// Sets the socket address, returning the previous value if any.
                        pub fn [<set_ $field2:snake _addr>](&self, addr: ::std::net::SocketAddr) -> ::std::option::Option<::std::net::SocketAddr> {
                            self.inner.write().unwrap().$field2.replace(addr)
                        }
                    )*

                    // ip_singleton methods
                    $(
                        /// Returns the configured IP if it exists.
                        pub fn [<$field5:snake>](&self) -> ::std::option::Option<::std::net::IpAddr> {
                            self.inner.read().unwrap().$field5
                        }

                        /// Sets the IP, returning the previous value if any.
                        pub fn [<set_ $field5:snake>](&self, ip: ::std::net::IpAddr) -> ::std::option::Option<::std::net::IpAddr> {
                            self.inner.write().unwrap().$field5.replace(ip)
                        }
                    )*

                    // ip_map methods
                    $(
                        /// Returns the IP configured for exactly the given key, if any.
                        pub fn [<$field6:snake>](&self, key: $Key6) -> ::std::option::Option<::std::net::IpAddr> {
                            self.inner.read().unwrap().$field6.get(&key).copied()
                        }

                        /// Sets the IP for the given key, returning the previous value if any.
                        pub fn [<set_ $field6:snake>](&self, key: $Key6, ip: ::std::net::IpAddr) -> ::std::option::Option<::std::net::IpAddr> {
                            self.inner.write().unwrap().$field6.insert(key, ip)
                        }
                    )*
                }
            }
        };
    }
    pub(crate) use io_config;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::topologies::{IA132, IA212};

    #[test]
    fn advertise_replaces_ip_and_keeps_port() {
        let io = IoConfig::new();
        let addr: SocketAddr = "127.0.0.1:8041".parse().unwrap();
        assert_eq!(io.advertise(IA132, addr), addr);

        io.set_advertised_ip(IA132, "10.0.2.2".parse().unwrap());
        assert_eq!(io.advertise(IA132, addr), "10.0.2.2:8041".parse().unwrap());
    }

    #[test]
    fn advertise_leaves_the_ases_it_was_not_set_for_alone() {
        let io = IoConfig::new();
        let addr: SocketAddr = "127.0.0.1:8041".parse().unwrap();

        io.set_advertised_ip(IA132, "10.0.2.2".parse().unwrap());
        assert_eq!(io.advertise(IA212, addr), addr);
    }

    #[test]
    fn a_wildcard_covers_every_as_and_loses_to_a_specific_one() {
        let io = IoConfig::new();
        let addr: SocketAddr = "127.0.0.1:8041".parse().unwrap();

        io.set_advertised_ip(IsdAsn::WILDCARD, "192.0.2.1".parse().unwrap());
        assert_eq!(io.advertise(IA132, addr), "192.0.2.1:8041".parse().unwrap());
        assert_eq!(io.advertise(IA212, addr), "192.0.2.1:8041".parse().unwrap());

        // The wildcard is zero and therefore sorts first, so this is the case a lookup that took
        // the map's own order would get wrong.
        io.set_advertised_ip(IA132, "10.0.2.2".parse().unwrap());
        assert_eq!(io.advertise(IA132, addr), "10.0.2.2:8041".parse().unwrap());
        assert_eq!(io.advertise(IA212, addr), "192.0.2.1:8041".parse().unwrap());
    }

    #[test]
    fn a_partial_wildcard_beats_a_full_one() {
        let io = IoConfig::new();
        let addr: SocketAddr = "127.0.0.1:8041".parse().unwrap();
        let isd_of_132: IsdAsn = "1-0".parse().unwrap();

        io.set_advertised_ip(IsdAsn::WILDCARD, "192.0.2.1".parse().unwrap());
        io.set_advertised_ip(isd_of_132, "198.51.100.1".parse().unwrap());

        // IA132 is in ISD 1, so both entries match it and the narrower one has to win. Taking the
        // map's first match would answer 192.0.2.1 here, since the full wildcard is zero.
        assert_eq!(
            io.advertise(IA132, addr),
            "198.51.100.1:8041".parse().unwrap()
        );
        // IA212 is in ISD 2, which only the full wildcard covers.
        assert_eq!(io.advertise(IA212, addr), "192.0.2.1:8041".parse().unwrap());

        // And an entry for the AS itself is narrower again.
        io.set_advertised_ip(IA132, "10.0.2.2".parse().unwrap());
        assert_eq!(io.advertise(IA132, addr), "10.0.2.2:8041".parse().unwrap());
    }

    #[test]
    fn advertise_any_takes_the_first_as_that_has_one() {
        let io = IoConfig::new();
        let addr: SocketAddr = "127.0.0.1:8041".parse().unwrap();
        assert_eq!(io.advertise_any([IA132, IA212], addr), addr);

        io.set_advertised_ip(IA212, "10.0.2.2".parse().unwrap());
        assert_eq!(
            io.advertise_any([IA132, IA212], addr),
            "10.0.2.2:8041".parse().unwrap()
        );
    }

    #[test]
    fn default_bind_ip_falls_back_to_localhost() {
        let io = IoConfig::new();
        assert_eq!(io.default_bind_ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        io.set_bind_ip("127.0.0.2".parse().unwrap());
        assert_eq!(io.default_bind_ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
    }
}

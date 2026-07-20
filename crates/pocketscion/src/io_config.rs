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

use std::net::IpAddr;

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
    /// If no specific address is configured for a component, it will bind to a random port to all interfaces.
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
    /// - custom_map: generates a BTreeMap<$Key, $Val> field with the given name, without any
    ///   getter/setter methods.
    macro_rules! io_config {
        (
            $(#[$meta:meta])*
            struct $StructName:ident;
            $(addr_map($field:ident : $Key:ty),)*
            $(addr_map_keyed($field4:ident : ($($kname:ident : $KTy:ty),+)),)*
            $(addr_singleton($field2:ident),)*
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
                }
            }
        };
    }
    pub(crate) use io_config;
}

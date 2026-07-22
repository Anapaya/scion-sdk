---
title: Addressing
description: How SCION addresses work. The ISD-AS model, how an endpoint is named, and the SDK types you use.
sidebar_position: 2
---

import ScionAddress from './fig/scion-address.drawio.svg';

To send a datagram you need an address for the destination. A SCION address carries more than an IP
address does. It names *which network* the destination is in, not just a host within an assumed one.
Understanding that extra piece is most of what there is to SCION addressing.

## The address model

The Internet you know addresses a host by an IP and a port. It has no notion of *which* network that
host belongs to. Routing to the target is the network's problem, decided hop by hop by BGP. SCION
makes the network explicit and part of the address.

A SCION network is organized into **Isolation Domains (ISDs)**, each containing **Autonomous Systems
(ASes)**. An AS is identified globally by its **ISD-AS**, written `ISD-AS`, for example
`1-ff00:0:110` (ISD `1`, AS `ff00:0:110`). A full endpoint address then adds the host and port
*inside* that AS:

<ScionAddress className="svg-diagram" role="img" aria-label="Anatomy of a SCION address" />

The ISD-AS names the network. The host and port name the endpoint within it. This is what makes
SCION *path-aware*: because the destination network is named explicitly, the SDK can look up and
choose among the paths that lead to it (see [Paths and path policies](./paths-and-policies.md)).

## Working with addresses in the SDK

The address types live in the `sciparse` crate, which `scion-stack` re-exports, so an application
that depends only on `scion-stack` reaches them as `scion_stack::sciparse::…`. Two types cover almost
everything you do:

- [`IsdAsn`](https://docs.rs/sciparse/latest/sciparse/scion/identifier/isd_asn/struct.IsdAsn.html)
  identifies an AS. It parses from and displays as the `1-ff00:0:110` form, and exposes the ISD and
  AS parts.
- [`ScionSocketIpAddr`](https://docs.rs/sciparse/latest/sciparse/scion/address/ip_socket_addr/struct.ScionSocketIpAddr.html)
  is the full `ISD-AS + host + port` endpoint address, the type you pass to
  [`send_to`](https://docs.rs/scion-stack/latest/scion_stack/struct.UdpScionSocket.html#method.send_to)
  and get back from
  [`recv_from`](https://docs.rs/scion-stack/latest/scion_stack/struct.UdpScionSocket.html#method.recv_from).
  It parses from and displays as `1-ff00:0:110,[fd00::1]:443` (an IPv4 host drops the brackets, for
  example `1-ff00:0:110,192.0.2.1:443`).

For the full type surface (accessors, conversions from `std::net` types, service addresses), see the
[`sciparse` reference](https://docs.rs/sciparse).

## Wildcards

The ISD-AS `0` (all-zero) is the **wildcard**, available as `IsdAsn::WILDCARD`. It expresses "any
AS", for instance to bind without pinning a specific local AS, or in path-policy matching. It is a
match-any value, not a real address to send to.

## Where to go next

- **[Paths and path policies](./paths-and-policies.md):** once you can name a destination AS, this is
  how the SDK finds and chooses routes to it.
- **[The ScionStack model](./scionstack-model.md):** where addressing fits among the stack's
  responsibilities.

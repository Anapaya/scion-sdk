---
title: Transport underlays
description: How your SCION packets physically reach the network. The UDP and SNAP underlays, and how to choose between them.
sidebar_position: 4
---

A SCION packet still has to travel over a real network to reach the SCION infrastructure. The
**transport underlay** is that bottom layer: how the SDK moves your packets between your host and the
SCION network. The SDK supports two underlays. This page explains what they are and when to use
each.

## What an underlay is

Your [`ScionStack`](https://docs.rs/scion-stack/latest/scion_stack/stack/struct.ScionStack.html) produces
SCION packets. The underlay carries them to a device that can forward them into the SCION network.
The stack abstracts over more than one underlay so the same socket code works whether you have
direct SCION connectivity or reach the network through an access point. You pick which underlay to
prefer when you build the stack. The choice is otherwise invisible to your application code.

```mermaid
flowchart LR
    App["Your app<br/>(ScionStack)"]
    App -->|"UDP underlay:<br/>direct UDP/IP"| R["SCION routers"]
    App -->|"SNAP underlay:<br/>authenticated tunnel"| DP["SNAP data plane"]
    DP --> R2["SCION routers"]
    R --> NET["SCION network"]
    R2 --> NET
```

### The UDP underlay

The UDP underlay sends SCION packets directly to the SCION routers in the local AS over UDP/IP. It is
the simplest option and adds nothing between you and the routers: no tunnel and no authentication.
Use it when you have direct SCION connectivity.

### The SNAP underlay

A **SNAP** (SCION Network Access Point) is the edge of the SCION network for endhosts. The SNAP
underlay carries your SCION packets through an authenticated tunnel to a SNAP *data plane*, which
forwards them on to the SCION routers. Use it when you reach SCION through an access point rather
than directly. It is designed to work from behind NAT and across changing networks, and because it
is authenticated it lets the operator authorize and account for your traffic. This is the underlay
you use on real deployments, and the one that requires a SNAP token (see
[Access and authentication](./access-and-authentication.md)).

### Choosing an underlay

Prefer an underlay when you build the stack, with
[`with_preferred_underlay`](https://docs.rs/scion-stack/latest/scion_stack/stack/builder/struct.ScionStackBuilder.html#method.with_preferred_underlay)
([`PreferredUnderlay::Snap`](https://docs.rs/scion-stack/latest/scion_stack/stack/builder/enum.PreferredUnderlay.html)
or `Udp`; the default is `Udp`). The stack then selects a matching underlay for the destination AS.
Per-underlay settings live in
[`SnapUnderlayConfig`](https://docs.rs/scion-stack/latest/scion_stack/stack/builder/struct.SnapUnderlayConfig.html)
and [`UdpUnderlayConfig`](https://docs.rs/scion-stack/latest/scion_stack/stack/builder/struct.UdpUnderlayConfig.html);
see the
[`ScionStackBuilder` reference](https://docs.rs/scion-stack/latest/scion_stack/stack/builder/struct.ScionStackBuilder.html).

PocketSCION can simulate **either** underlay so you can develop against both locally: its topology
helpers take an `UnderlayType` (`Snap` or `Udp`). The examples that ship with the SDK build their
network with `UnderlayType::Snap`, so they exercise the SNAP underlay end to end.

## Using the SNAP underlay: tokens

To use the SNAP underlay, the stack must show a valid **SNAP token** to the SNAP. The stack gets the
token from a **token source** that you give it when you build the stack. The Anapaya AA is one token
source. [Access and authentication](./access-and-authentication.md) explains what a SNAP token is,
how token sources work, and how you get an API key for the Anapaya AA.

## Where to go next

- **[The ScionStack model](./scionstack-model.md):** where the underlay fits among the stack's
  responsibilities.
- **[Addressing](./addressing.md)** and **[Paths and path policies](./paths-and-policies.md):** what
  rides on top of the underlay once it is established.
- **[From a local SCION network to a real network](../example-application/real-network.md):**
  how the chat example application moves from a development token to an API key.
- **[Access and authentication](./access-and-authentication.md):** subscriptions, API keys, and
  the SNAP token that the SNAP underlay needs.

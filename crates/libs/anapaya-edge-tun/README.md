# Edgetun

Tunnel packets through a QUIC/SCION connection.

## Synopsis

This crate provides a server and a client implementation in `src/server.rs` and
`src/client.rs` respectively. The handling of QUIC-connections is separated from
edgetun. That is, an implementor has to accept/create QUIC connection and then
hand them over to either `Server::accept()` or `EdgeTunBuilder::build`
respectively.

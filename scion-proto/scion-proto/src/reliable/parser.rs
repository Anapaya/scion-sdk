// Copyright 2025 Mysten Labs
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

use bytes::{Buf, BytesMut};

use super::{
    Packet,
    common_header::{CommonHeader, DecodeError, DecodedHeader},
};

/// A parser to decode [`CommonHeader`]s and payloads from a [`BytesMut`].
#[derive(Debug, Default)]
pub struct StreamParser {
    header: Option<DecodedHeader>,
}

impl StreamParser {
    /// Creates a new empty [`StreamParser`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode and store the next partial or common header available from the data.
    fn try_decode_header(&mut self, data: &mut BytesMut) -> Result<(), DecodeError> {
        match self.header {
            None if data.remaining() >= CommonHeader::MIN_LENGTH => {
                self.header = Some(CommonHeader::decode(data)?);
            }
            Some(DecodedHeader::Partial(header)) if data.remaining() >= header.required_bytes() => {
                self.header = Some(DecodedHeader::Full(header.finish_decoding(data)));
            }
            _ => (),
        };

        Ok(())
    }

    /// Parses data that is available in the buffer and returns the parsed Packet.
    pub fn parse(&mut self, data: &mut BytesMut) -> Result<Option<Packet>, DecodeError> {
        self.try_decode_header(data)?;

        if let Some(DecodedHeader::Full(ref header)) = self.header
            && data.remaining() >= header.payload_size()
        {
            let header = self.header.take().unwrap().take_full();

            return Ok(Some(Packet {
                last_host: header.destination,
                content: data.split_to(header.payload_size()).freeze(),
            }));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::test_utils::parse;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PACKET: [u8; 35] = [
        0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 80, b'R', b'U', b'S', b'T',
    ];
    const BAD_PACKET: [u8; 35] = [
        0xbe, 2, 0xef, 3, 0xde, 0, 0xad, 1, 2, 0, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 80, b'R', b'U', b'S', b'T',
    ];

    #[test]
    fn full_packet() -> TestResult {
        let mut data = BytesMut::from(PACKET.as_slice());
        let mut parser = StreamParser::new();

        let packet = parser.parse(&mut data)?.expect("to be some packet");
        assert_eq!(packet.last_host, Some(parse!("[2001:db8::1]:80")));
        assert_eq!(packet.content, Bytes::from_static(b"RUST"));

        Ok(())
    }

    #[test]
    fn bad_packet() {
        let mut data = BytesMut::from(BAD_PACKET.as_slice());
        let mut parser = StreamParser::new();

        let err = parser.parse(&mut data).expect_err("should fail");

        assert_eq!(err, DecodeError::InvalidCookie(0xbe02ef03de00ad01));
    }

    #[test]
    fn incremental_data() -> TestResult {
        let mut data = BytesMut::new();
        let mut parser = StreamParser::new();
        let mut packet = None;

        const MIN_LENGTH: usize = CommonHeader::MIN_LENGTH;

        for (lower, upper) in [
            (0, MIN_LENGTH - 1),
            (MIN_LENGTH - 1, MIN_LENGTH + 1),
            (MIN_LENGTH + 1, PACKET.len()),
        ] {
            assert!(packet.is_none());

            data.extend_from_slice(&PACKET[lower..upper]);
            packet = parser.parse(&mut data)?;
        }
        assert!(packet.is_some());

        let packet = packet.unwrap();
        assert_eq!(packet.last_host, Some(parse!("[2001:db8::1]:80")));
        assert_eq!(packet.content, Bytes::from_static(b"RUST"));

        Ok(())
    }
}

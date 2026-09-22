//! TCP length-prefix framing.
//!
//! RFC 4571 Section 2 defines the ICE shim: every packet on the stream carries
//! a 16-bit big-endian length field. RFC 6062 Section 3 reuses that shim
//! verbatim for TURN over TCP, and RFC 6544 Section 1 puts ICE itself on top of
//! it. So there is exactly one framing implementation in this workspace, and it
//! lives here (workspace-layout §3.2 rule 2: framing must never appear in
//! `quickrelay-binding`).
//!
//! The decoder is incremental. One call drains as many complete packets as the
//! buffer holds, reports each through a callback, and reports how many leading
//! octets are now consumed. The partial tail (nothing, a half header, or a
//! header with an incomplete payload) is left alone; the caller compacts it to
//! the front of its window and reads more.
//!
//! [`decode_with`] and [`encode`] are the allocation-free primitives the event
//! loop uses; [`decode_to_vec`] and [`encode_all`] exist so the framing logic
//! can be tested and driven by the tests without a live socket.

use crate::{FRAME_PREFIX_LEN, FrameError, MAX_FRAME_PAYLOAD};

/// The outcome of an incremental decode call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOutcome {
    /// The number of leading octets that were consumed by complete packets.
    pub consumed: usize,
    /// How many complete packets were accepted.
    pub packets: usize,
    /// Whether the input is exhausted, i.e. `read` returned EOF.
    pub eof: bool,
}

impl DecodeOutcome {
    /// Nothing decodable and no EOF.
    pub const fn idle() -> Self {
        DecodeOutcome { consumed: 0, packets: 0, eof: false }
    }

    /// Whether anything happened at all.
    pub const fn is_idle(self) -> bool {
        self.consumed == 0 && self.packets == 0
    }
}

/// Read the 16-bit big-endian length prefix from `buf` and validate it.
///
/// Only the size and the declared length are checked here; that is all the
/// framing layer is allowed to know. Whether the payload is a legal STUN
/// datagram is the `quickrelay-protocol` job.
pub fn read_length_prefix(buf: &[u8]) -> Result<usize, FrameError> {
    if buf.len() < FRAME_PREFIX_LEN {
        return Err(FrameError::IncompleteHeader);
    }
    let [hi, lo] = [buf[0], buf[1]];
    let len = u16::from_be_bytes([hi, lo]) as usize;
    if len > MAX_FRAME_PAYLOAD {
        return Err(FrameError::LengthTooLarge);
    }
    Ok(len)
}

/// Write the length prefix for a payload of `payload.len()` octets.
///
/// Fails with [`FrameError::BufferTooSmall`] when `out` cannot hold the prefix
/// and the payload together — the caller must check this before deciding
/// whether to drop a send.
pub fn write_length_prefix(out: &mut [u8], payload: &[u8]) -> Result<usize, FrameError> {
    let len = u16::try_from(payload.len()).map_err(|_| FrameError::LengthTooLarge)?;
    let need = FRAME_PREFIX_LEN.checked_add(payload.len()).ok_or(FrameError::BufferTooSmall)?;
    if out.len() < need {
        return Err(FrameError::BufferTooSmall);
    }
    out[..FRAME_PREFIX_LEN].copy_from_slice(&len.to_be_bytes());
    Ok(FRAME_PREFIX_LEN)
}

/// Encode one packet into `buf`, prefix included.
///
/// This is the only place the 16-bit field is produced for transmission, so
/// every caller — a TURN-over-TCP command, a Binding reply over a control
/// connection, relayed data — gets the same byte order for free.
pub fn encode(payload: &[u8], buf: &mut [u8]) -> Result<usize, FrameError> {
    let written = write_length_prefix(buf, payload)?;
    buf[FRAME_PREFIX_LEN..FRAME_PREFIX_LEN + payload.len()].copy_from_slice(payload);
    Ok(written + payload.len())
}

/// Incrementally decode `buf`, calling `f` once per complete packet.
///
/// `buf` is read only: the consumed count in the return value tells the caller
/// how much to compact away. `eof` says the read side saw end of stream, which
/// the caller needs to distinguish "wait for more" from "the peer is gone".
///
/// A declared length above [`MAX_FRAME_PAYLOAD`] is refused and not consumed:
/// the prefix stays put and `f` is not called, so the caller closes the
/// connection. The field is 16 bits, so a legitimate peer can never trip it —
/// the guard exists so a future widening of the field cannot silently accept a
/// bogus value.
///
/// `f` may reject a packet (anything that is not a STUN datagram, or a
/// datagram it chooses not to answer). A rejected packet is consumed but not
/// counted in [`DecodeOutcome::packets`], and decoding stops there so the
/// caller can decide whether to close.
pub fn decode_with<F>(buf: &[u8], eof: bool, mut f: F) -> DecodeOutcome
where
    F: FnMut(&[u8], usize) -> Result<(), FrameError>,
{
    let mut consumed = 0usize;
    let mut packets = 0usize;

    loop {
        let remaining = &buf[consumed..];
        if remaining.len() < FRAME_PREFIX_LEN {
            return DecodeOutcome { consumed, packets, eof };
        }
        let [hi, lo] = [remaining[0], remaining[1]];
        let len = u16::from_be_bytes([hi, lo]) as usize;
        if len > MAX_FRAME_PAYLOAD {
            return DecodeOutcome { consumed, packets, eof };
        }
        let need = FRAME_PREFIX_LEN + len;
        if remaining.len() < need {
            return DecodeOutcome { consumed, packets, eof };
        }
        let payload = &remaining[FRAME_PREFIX_LEN..need];
        if f(payload, need).is_err() {
            consumed += need;
            return DecodeOutcome { consumed, packets, eof };
        }
        consumed += need;
        packets += 1;
    }
}

/// Decode `buf`, collecting every complete payload.
///
/// Convenience for tests and the loopback integration suite: the event loop
/// uses [`decode_with`], which needs no allocation.
pub fn decode_to_vec(buf: &[u8], out: &mut Vec<Vec<u8>>) -> DecodeOutcome {
    decode_with(buf, false, |payload, _need| {
        out.push(payload.to_vec());
        Ok(())
    })
}

/// How many octets a framed packet of `len` needs in flight.
pub const fn frame_wire_size(len: usize) -> usize {
    FRAME_PREFIX_LEN + len
}

/// The largest payload [`frame_wire_size`] can describe.
pub const MAX_ENCODE_BUFFER: usize = FRAME_PREFIX_LEN + MAX_FRAME_PAYLOAD;

/// Write one complete framed packet to `stream`, retrying until it all goes
/// out. `scratch` must hold the prefix and the payload together; a payload that
/// does not fit returns [`FrameError::BufferTooSmall`] without touching the
/// stream.
///
/// A short write is retried rather than reported: `write_all` keeps one frame
/// contiguous on the wire, which is the whole point of the shim. Returns the
/// number of octets sent.
pub fn encode_all<R: std::io::Write>(
    stream: &mut R,
    payload: &[u8],
    scratch: &mut [u8],
) -> std::io::Result<usize> {
    let total = encode(payload, scratch)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    stream.write_all(&scratch[..total])?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_UDP_DATAGRAM;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn read_prefix_reports_incomplete() {
        assert_eq!(read_length_prefix(&[]), Err(FrameError::IncompleteHeader));
        assert_eq!(read_length_prefix(&[0x00]), Err(FrameError::IncompleteHeader));
    }

    #[test]
    fn read_prefix_parses_big_endian() {
        assert_eq!(read_length_prefix(&[0x00, 0x04, 0x01, 0x02, 0x03]), Ok(4));
        assert_eq!(read_length_prefix(&[0x00, 0x00]), Ok(0));
    }

    #[test]
    fn read_prefix_max_is_accepted() {
        // 0xFFFF is the largest value the 16-bit field can name, and it is legal.
        assert_eq!(read_length_prefix(&[0xFF, 0xFF]), Ok(MAX_FRAME_PAYLOAD));
    }

    #[test]
    fn encode_writes_prefix_and_payload() {
        let mut buf = [0u8; 16];
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(encode(&payload, &mut buf), Ok(6));
        assert_eq!(&buf[..6], &[0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn encode_rejects_a_small_buffer() {
        let mut buf = [0u8; 4];
        assert_eq!(encode(&[1, 2, 3], &mut buf), Err(FrameError::BufferTooSmall));
        let mut buf = [0u8; 0];
        assert_eq!(encode(&[], &mut buf), Err(FrameError::BufferTooSmall));
    }

    #[test]
    fn encode_refuses_an_overlarge_payload() {
        let mut buf = [0u8; MAX_ENCODE_BUFFER + 1];
        let payload = vec![0u8; MAX_ENCODE_BUFFER];
        assert_eq!(encode(&payload, &mut buf), Err(FrameError::LengthTooLarge));
    }

    #[test]
    fn null_packet_round_trips() {
        // RFC 4571 Section 2: zero is a valid length and means "null packet".
        let mut buf = [0u8; 2];
        assert_eq!(encode(&[], &mut buf), Ok(2));
        assert_eq!(&buf, &[0x00, 0x00]);

        let mut out = Vec::new();
        let o = decode_to_vec(&[0x00, 0x00], &mut out);
        assert_eq!(o.packets, 1);
        assert_eq!(o.consumed, 2);
        assert_eq!(out, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn decode_two_packets_with_a_partial_tail() {
        // 00 02 AB CD | 00 03 01 02 03 | 00 07 0A 0B   (last is partial)
        let raw = hex("0002abcd000301020300070a0b");
        let mut out = Vec::new();
        let o = decode_to_vec(&raw, &mut out);
        assert_eq!(o.packets, 2);
        assert_eq!(o.consumed, 9);
        assert_eq!(out, vec![hex("abcd"), hex("010203")]);
    }

    #[test]
    fn decode_holds_back_a_partial_header() {
        let mut out = Vec::new();
        let o = decode_to_vec(&[0x00], &mut out);
        assert_eq!(o, DecodeOutcome::idle());
        assert!(out.is_empty());
    }

    #[test]
    fn decode_max_payload_length_is_accepted() {
        let mut raw = Vec::with_capacity(FRAME_PREFIX_LEN + MAX_FRAME_PAYLOAD);
        raw.extend_from_slice(&u16::MAX.to_be_bytes());
        raw.resize(FRAME_PREFIX_LEN + MAX_FRAME_PAYLOAD, 0);
        let mut out = Vec::new();
        let o = decode_to_vec(&raw, &mut out);
        assert_eq!(o.packets, 1);
        assert_eq!(out[0].len(), MAX_FRAME_PAYLOAD);
    }

    #[test]
    fn decode_holds_back_a_length_it_cannot_honor() {
        // The declared length is longer than what arrived; the prefix is left
        // unconsumed and the next `read` fills behind it.
        let raw = [0x00u8, 0x03, 0xAB];
        let mut got = Vec::new();
        let o = decode_with(&raw, false, |p, _n| {
            got.push(p.to_vec());
            Ok(())
        });
        assert_eq!(o.packets, 0);
        assert!(got.is_empty());
        assert_eq!(o.consumed, 0);
        assert!(!o.eof);
    }

    #[test]
    fn decode_decodes_two_complete_frames() {
        // 00 01 AA | 00 01 BB
        let raw = [0x00u8, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        let mut got = Vec::new();
        let o = decode_with(&raw, false, |p, _n| {
            got.push(p.to_vec());
            Ok(())
        });
        assert_eq!(o.packets, 2);
        assert_eq!(o.consumed, 6);
        assert_eq!(got, vec![vec![0xAAu8], vec![0xBBu8]]);
    }

    #[test]
    fn decode_stops_when_the_callback_rejects() {
        // The first packet is not STUN: it is consumed but not counted, and
        // the second one is never looked at.
        let raw = hex("0002abcd0003010203");
        let mut accepted = Vec::new();
        let o = decode_with(&raw, false, |p, _n| {
            accepted.push(p.to_vec());
            Err(FrameError::BufferTooSmall)
        });
        assert_eq!(o.packets, 0);
        assert_eq!(accepted, vec![hex("abcd")]);
        assert_eq!(o.consumed, 4);
    }

    #[test]
    fn decode_reports_eof_from_the_caller() {
        let o = decode_with(&[], true, |_p, _| Ok(()));
        assert!(o.eof);
        assert!(o.is_idle());
    }

    #[test]
    fn frame_wire_size_adds_the_prefix() {
        assert_eq!(frame_wire_size(0), 2);
        assert_eq!(frame_wire_size(MAX_FRAME_PAYLOAD), MAX_ENCODE_BUFFER);
    }

    #[test]
    fn encode_all_round_trips_through_decode_with() {
        let payload = b"abcdef";
        let mut scratch = [0u8; MAX_ENCODE_BUFFER];
        let mut sink: Vec<u8> = Vec::new();
        let n = encode_all(&mut sink, payload, &mut scratch).unwrap();
        assert_eq!(n, frame_wire_size(payload.len()));

        let mut got = Vec::new();
        let o = decode_with(&sink, false, |p, _| {
            got.push(p.to_vec());
            Ok(())
        });
        assert_eq!(o.packets, 1);
        assert_eq!(o.consumed, sink.len());
        assert_eq!(got, vec![payload.to_vec()]);
    }

    #[test]
    fn encode_all_does_not_write_when_the_scratch_is_short() {
        let payload = vec![0u8; MAX_UDP_DATAGRAM + 1];
        let mut scratch = [0u8; 16];
        let mut sink: Vec<u8> = Vec::new();
        assert!(encode_all(&mut sink, &payload, &mut scratch).is_err());
        assert!(sink.is_empty(), "a refused frame must not touch the stream");
    }
}

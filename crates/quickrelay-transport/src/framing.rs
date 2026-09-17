//! 16-bit big-endian length-prefix framing (RFC 8656 §3.2, §4.3; RFC 6544).
//!
//! This is the *only* framing code in the workspace: `binding` must not read
//! or write a `u16::from_be` length prefix, and `server` routes its
//! responses through these functions.

use std::io;

use crate::{FrameError, FRAME_PREFIX_LEN, MAX_FRAME_PAYLOAD};

/// The state of one framed read.
pub enum FrameRead<'a> {
    /// A complete frame was decoded from `buf`.
    ///
    /// The payload is the byte range `buf[..len]`; `len` is the payload
    /// length declared by the length prefix, never the buffer length.
    Frame { len: usize },
    /// Not enough bytes yet: `want` more octets are needed for one complete
    /// frame.
    Incomplete { want: usize },
    /// The frame is invalid and the connection must be reported through
    /// [`BindingHandler::on_tcp_error`](crate::BindingHandler::on_tcp_error).
    Error { err: FrameError },
}

/// Decode one frame from the head of `buf`.
///
/// `buf` must hold the undelivered prefix octets followed by whatever payload
/// the peer has sent so far. Only the head of `buf` is interpreted, so the
/// caller is responsible for sliding the buffer over consumed frames.
pub fn frame_read(buf: &[u8]) -> FrameRead<'_> {
    if buf.len() >= FRAME_PREFIX_LEN {
        let declared = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if declared > MAX_FRAME_PAYLOAD as usize {
            return FrameRead::Error {
                err: FrameError::OversizedPayload {
                    declared: declared as u32,
                },
            };
        }
        let need = FRAME_PREFIX_LEN + declared;
        if buf.len() >= need {
            return FrameRead::Frame { len: declared };
        }
        return FrameRead::Incomplete { want: need - buf.len() };
    }
    FrameRead::Incomplete {
        want: FRAME_PREFIX_LEN - buf.len(),
    }
}

/// Encode `payload` into `out` by prefixing it with its 16-bit big-endian
/// length.
///
/// `out` must have at least `FRAME_PREFIX_LEN + payload.len()` octets of
/// space; the returned slice is the framed message.
pub fn frame_write(payload: &[u8], out: &mut [u8]) -> Result<&mut [u8], FrameError> {
    let total = FRAME_PREFIX_LEN.checked_add(payload.len()).ok_or(FrameError::OversizedPayload {
        declared: payload.len() as u32,
    })?;
    if total > out.len() {
        return Err(FrameError::OversizedPayload {
            declared: payload.len() as u32,
        });
    }
    out[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[2..total].copy_from_slice(payload);
    Ok(&mut out[..total])
}

/// Whether `payload` cannot be framed at all.
///
/// Kept separate from the reader because the writer can refuse to frame
/// without having a connection attached.
pub fn frame_payload_too_large(payload_len: usize) -> bool {
    payload_len > MAX_FRAME_PAYLOAD as usize
}

/// A reusable framing buffer for one connection's reads.
///
/// The buffer is sized once for the largest legal frame, so a connection that
/// lives for minutes does not re-allocate on every message.
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// The largest payload this reader accepts.
    pub const CAPACITY: usize = MAX_FRAME_PAYLOAD as usize;

    /// Allocate a fresh reader sized for one maximum-length frame.
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(FRAME_PREFIX_LEN + Self::CAPACITY),
        }
    }

    /// Append `data` to the pending bytes and return the complete frames now
    /// present.
    ///
    /// Every returned `(payload, size)` pair borrows from this reader and
    /// stays valid until the next `append`; callers that need to outlive that
    /// must copy.
    pub fn append<'r>(&'r mut self, data: &[u8]) -> io::Result<Vec<FrameResult<'r>>> {
        self.buf.extend_from_slice(data);
        Ok(self.drain())
    }

    /// Drain all complete frames already buffered.
    pub fn drain<'r>(&'r mut self) -> Vec<FrameResult<'r>> {
        let mut out = Vec::new();
        loop {
            let base = self.buf.len();
            match frame_read(&self.buf) {
                FrameRead::Frame { len } => {
                    let consumed = FRAME_PREFIX_LEN + len;
                    let frame = &self.buf[..consumed];
                    out.push(FrameResult::Ok {
                        payload: &frame[FRAME_PREFIX_LEN..],
                    });
                    // Compact in place so the reader does not grow unbounded
                    // between messages.
                    self.buf.drain(..consumed);
                }
                FrameRead::Incomplete { .. } => break,
                FrameRead::Error { err } => {
                    let err = FrameResult::Err(err);
                    out.clear();
                    self.buf.clear();
                    out.push(err);
                    break;
                }
            }
            debug_assert!(self.buf.len() < base);
        }
        out
    }

    /// Number of pending, not-yet-framed octets.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Drop all pending bytes.
    pub fn reset(&mut self) {
        self.buf.clear();
    }
}

/// One frame decoded by [`FrameReader::append`] / [`FrameReader::drain`].
pub enum FrameResult<'a> {
    /// A legal frame; `payload` is the message bytes after the length prefix.
    Ok { payload: &'a [u8] },
    /// The frame was invalid; the connection must be reported and closed.
    Err(FrameError),
}

/// A reusable framing buffer for one connection's writes.
pub struct FrameWriter {
    buf: Vec<u8>,
}

impl FrameWriter {
    /// Allocate a fresh writer sized for one maximum-length frame.
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(FRAME_PREFIX_LEN + MAX_FRAME_PAYLOAD as usize),
        }
    }

    /// Frame `payload` in place and return the framed slice, including the
    /// length prefix.
    pub fn write_frame<'w>(&'w mut self, payload: &[u8]) -> Result<&'w [u8], FrameError> {
        if frame_payload_too_large(payload.len()) {
            return Err(FrameError::OversizedPayload {
                declared: payload.len() as u32,
            });
        }
        self.buf.clear();
        self.buf
            .reserve(FRAME_PREFIX_LEN + payload.len());
        frame_write(payload, &mut self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_big_endian_and_payload_is_verbatim() {
        let mut out = [0u8; 8];
        let frame = frame_write(&[1, 2, 3, 4, 5], &mut out).unwrap();
        assert_eq!(frame, &[3, 5, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn reader_roundtrips_a_single_frame() {
        let mut reader = FrameReader::new();
        let mut scratch = [0u8; 64];
        let frame = frame_write(b"hello world", &mut scratch).unwrap();
        let mut got = reader.append(frame).unwrap();
        assert_eq!(got.len(), 1);
        match &got[0] {
            FrameResult::Ok { payload } => assert_eq!(payload, b"hello world"),
            FrameResult::Err(e) => panic!("unexpected error {e}"),
        }
        match frame_read(frame) {
            FrameRead::Frame { len } => assert_eq!(len, 11),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn reader_accumulates_until_a_frame_completes() {
        let mut out = [0u8; 4];
        let frame = frame_write(b"abcd", &mut out).unwrap();
        let mut reader = FrameReader::new();
        assert!(reader.append(&frame[..1]).unwrap().is_empty());
        assert!(reader.append(&frame[1..3]).unwrap().is_empty());
        assert_eq!(reader.pending(), 3);
        let frames = reader.append(&frame[3..]).unwrap();
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            FrameResult::Ok { payload } => assert_eq!(payload, b"abcd"),
            FrameResult::Err(e) => panic!("unexpected error {e}"),
        }
        assert_eq!(reader.pending(), 0);
    }

    #[test]
    fn a_length_prefix_above_the_maximum_is_a_frame_error() {
        let mut reader = FrameReader::new();
        let frames = reader.append(&[0x01, 0x00]).unwrap();
        assert_eq!(frames.len(), 1);
        match frames[0] {
            FrameResult::Err(FrameError::OversizedPayload { declared }) => {
                assert_eq!(declared, 65536);
            }
            other => panic!("expected oversize error, got {other:?}"),
        }
        assert!(frame_payload_too_large(65_536));
        assert!(!frame_payload_too_large(65_535));
        assert!(frame_payload_too_large(usize::MAX));
    }

    #[test]
    fn two_frames_in_one_read_are_returned_in_order() {
        let mut reader = FrameReader::new();
        let mut first = [0u8; 3];
        let mut second = [0u8; 6];
        let f1 = frame_write(b"ab", &mut first).unwrap();
        let f2 = frame_write(b"cd e", &mut second).unwrap();
        let mut all = Vec::new();
        all.extend_from_slice(f1);
        all.extend_from_slice(f2);
        let frames = reader.append(&all).unwrap();
        let payloads: Vec<&[u8]> = frames
            .iter()
            .map(|f| match f {
                FrameResult::Ok { payload } => *payload,
                FrameResult::Err(e) => panic!("unexpected {e}"),
            })
            .collect();
        assert_eq!(payloads, [b"ab", b"cd e"]);
    }

    #[test]
    fn an_empty_payload_is_a_legal_empty_frame() {
        let mut reader = FrameReader::new();
        let frames = reader.append(&[0, 0]).unwrap();
        match &frames[..] {
            [FrameResult::Ok { payload }] => assert_eq!(payload, b""),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_writer_refuses_frames_it_cannot_emit() {
        let mut writer = FrameWriter::new();
        assert!(writer.write_frame(&vec![0u8; 65_536]).is_err());
        let frame = writer.write_frame(&[7, 8, 9]).unwrap();
        assert_eq!(frame, &[0, 3, 7, 8, 9]);
        // The buffer is reused, not grown by repeated frames.
        assert!(writer.write_frame(b"").is_ok());
    }

    #[test]
    fn partial_then_error_clears_the_buffer() {
        let mut reader = FrameReader::new();
        reader.append(&[0x00, 0x10]).unwrap();
        assert!(reader.pending() > 0);
        reader.reset();
        assert_eq!(reader.pending(), 0);
        assert!(reader.drain().is_empty());
    }
}

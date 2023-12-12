//! Reader trait.

pub(crate) mod nested;
#[cfg(feature = "pem")]
pub(crate) mod pem;
pub(crate) mod slice;

use core::ops::Range;

pub(crate) use nested::NestedDecoder;

use crate::{Error, ErrorKind, Length, Result};

/// Reader trait which reads DER-encoded input.
pub trait Reader<'r>: Sized {
    /// Get the length of the input.
    fn input_len(&self) -> Length;

    /// Peek at most 8 bytes (3 byte tag + 5 length)
    fn peek_bytes(&self) -> &[u8];

    // /// Peek forward in the input data, attempting to decode a [`Header`] from
    // /// the data at the current position in the decoder.
    // ///
    // /// Does not modify the decoder's state.
    // fn peek_header(&self) -> Result<Header>;

    /// Get the position within the buffer.
    fn position(&self) -> Length;

    /// Attempt to read data borrowed directly from the input as a slice,
    /// updating the internal cursor position.
    ///
    /// # Returns
    /// - `Ok(slice)` on success
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    /// - `Err(ErrorKind::Reader)` if the reader can't borrow from the input
    fn read_slice(&mut self, len: Length) -> Result<&'r [u8]>;

    /// Creates initial nesting-checked decoder
    fn root_nest(self) -> NestedDecoder<Self> {
        let len = self.remaining_len();
        // Should never fail if reader impl is consistent
        NestedDecoder::new(self, len).unwrap()
    }

    /// Returns current position and input length indices
    fn readable(&self) -> Range<Length> {
        self.position()..self.input_len()
    }

    /// Return an error with the given [`ErrorKind`], annotating it with
    /// context about where the error occurred.
    fn error(&mut self, kind: ErrorKind) -> Error {
        kind.at(self.position())
    }

    /// Finish decoding, returning the given value if there is no
    /// remaining data, or an error otherwise
    fn finish<T>(self, value: T) -> Result<T> {
        if !self.is_finished() {
            Err(ErrorKind::TrailingData {
                decoded: self.position(),
                remaining: self.remaining_len(),
            }
            .at(self.position()))
        } else {
            Ok(value)
        }
    }

    /// Have we read all of the input data?
    fn is_finished(&self) -> bool {
        self.remaining_len().is_zero()
    }

    /// Attempt to read input data, writing it into the provided buffer, and
    /// returning a slice on success.
    ///
    /// # Returns
    /// - `Ok(slice)` if there is sufficient data
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o [u8]> {
        let input = self.read_slice(buf.len().try_into()?)?;
        buf.copy_from_slice(input);
        Ok(buf)
    }

    /// Get the number of bytes still remaining in the buffer.
    fn remaining_len(&self) -> Length {
        debug_assert!(self.position() <= self.input_len());
        self.input_len().saturating_sub(self.position())
    }
}

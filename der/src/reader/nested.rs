//! Reader type for consuming nested TLV records within a DER document.

use core::ops::Range;

use crate::{
    asn1::ContextSpecific, reader::Reader, Decode, DecodeValue, Encode, Error, ErrorKind, FixedTag,
    Header, Length, Result, SliceReader, Tag, TagMode, TagNumber,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Reader type used by [`Reader::read_nested`].
pub struct NestedDecoder<R> {
    /// Inner reader type.
    inner: R,

    /// Index of first byte that we can't read
    end_pos: Length,
}

impl<'r, R: Reader<'r>> NestedDecoder<R> {
    /// Create a new nested reader which can read the given [`Length`].
    pub(crate) fn new(inner: R, len: Length) -> Result<Self> {
        Self::is_out_of_bounds(inner.readable(), len)?;

        Ok(Self {
            end_pos: (inner.position() + len)?,
            inner,
        })
    }

    /// Returns readable range of current nest (not the underlaying reader)
    fn readable(&self) -> Range<Length> {
        self.inner.position()..self.end_pos
    }

    /// Move the position cursor by the given length, returning an error if there
    /// isn't enough remaining data in the nested input.
    ///
    /// Returns: new end position
    fn check_out_of_bounds(&self, len: Length) -> Result<Length> {
        Self::is_out_of_bounds(self.readable(), len)
    }

    /// Returns: new end position
    fn is_out_of_bounds(readable: Range<Length>, additional_len: Length) -> Result<Length> {
        let new_end = (readable.start + additional_len)?;

        if new_end > readable.end {
            return Err(ErrorKind::Incomplete {
                expected_len: new_end,
                actual_len: readable.end,
            }
            .at(readable.start));
        }
        Ok(new_end)
    }

    /// Peek at the next byte of input without modifying the cursor.
    pub fn peek_byte(&self) -> Option<u8> {
        if self.is_finished() {
            None
        } else {
            self.inner.peek_bytes().get(0).cloned()
        }
    }

    /// Get the position within the buffer.
    pub fn position(&self) -> Length {
        self.inner.position()
    }

    /// Attempt to read data borrowed directly from the input as a slice,
    /// updating the internal cursor position.
    ///
    /// # Returns
    /// - `Ok(slice)` on success
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    /// - `Err(ErrorKind::Reader)` if the reader can't borrow from the input
    pub fn read_slice(&mut self, len: Length) -> Result<&'r [u8]> {
        self.check_out_of_bounds(len)?;
        self.inner.read_slice(len)
    }

    /// Return an error with the given [`ErrorKind`], annotating it with
    /// context about where the error occurred.
    pub fn error(&mut self, kind: ErrorKind) -> Error {
        self.inner.error(kind)
    }

    /// Attempt to read input data, writing it into the provided buffer, and
    /// returning a slice on success.
    ///
    /// # Returns
    /// - `Ok(slice)` if there is sufficient data
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    pub fn read_into<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        let len = Length::try_from(out.len())?;
        self.check_out_of_bounds(len)?;
        self.inner.read_into(out)
    }

    /// Have we read all of the input data?
    pub fn is_finished(&self) -> bool {
        self.remaining_len().is_zero()
    }

    /// Get the number of bytes still remaining in the buffer.
    pub fn remaining_len(&self) -> Length {
        debug_assert!(self.end_pos >= self.position());
        self.end_pos.saturating_sub(self.position())
    }

    /// Finish decoding, returning the given value if there is no
    /// remaining data, or an error otherwise
    pub fn finish<T>(&self, value: T) -> Result<T> {
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

    /// Read nested data of the given length.
    pub fn read_nested<T, F>(&mut self, len: Length, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        // Save current position
        let old_end: Length = self.end_pos;

        // Swap end boundary with current nest
        let nest_end = self.check_out_of_bounds(len)?;
        self.end_pos = nest_end;

        let ret = f(self);

        debug_assert!(self.end_pos == nest_end);

        // Check remaining bytes before resetting nested position
        let result = self.finish(ret?);

        // Revert end position
        self.end_pos = old_end;

        result
    }

    /// Read an ASN.1 `SEQUENCE`, creating a nested [`Reader`] for the body and
    /// calling the provided closure with it.
    pub fn sequence<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        let header = Header::decode(self)?;
        header.tag.assert_eq(Tag::Sequence)?;
        self.read_nested(header.length, f)
    }

    /// Attempt to decode an ASN.1 `CONTEXT-SPECIFIC` field with the
    /// provided [`TagNumber`].
    pub fn context_specific<T>(
        &mut self,
        tag_number: TagNumber,
        tag_mode: TagMode,
    ) -> Result<Option<T>>
    where
        T: DecodeValue<'r> + FixedTag,
    {
        Ok(match tag_mode {
            TagMode::Explicit => ContextSpecific::<T>::decode_explicit(self, tag_number)?,
            TagMode::Implicit => ContextSpecific::<T>::decode_implicit(self, tag_number)?,
        }
        .map(|field| field.value))
    }

    /// Read a byte vector of the given length.
    #[cfg(feature = "alloc")]
    pub fn read_vec(&mut self, len: Length) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; usize::try_from(len)?];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Read a single byte.
    pub fn read_byte(&mut self) -> Result<u8> {
        let mut buf = [0];
        self.read_into(&mut buf)?;
        Ok(buf[0])
    }

    /// Peek at the next byte in the decoder and attempt to decode it as a
    /// [`Tag`] value.
    ///
    /// Does not modify the decoder's state.
    pub fn peek_tag(&self) -> Result<Tag> {
        match self.peek_byte() {
            Some(byte) => byte.try_into(),
            None => Err(Error::incomplete(self.inner.input_len())),
        }
    }

    /// Reads header on a temporary reader, so current reader's position will not be changed
    pub fn peek_header(&self) -> Result<Header> {
        if self.is_finished() {
            Err(Error::incomplete(self.position()))
        } else {
            // Create reader on peeked bytes
            let peeked = self.inner.peek_bytes();
            let mut decoder = SliceReader::new(peeked)?.root_nest();
            let header: Header = Header::decode(&mut decoder)?;

            // Length of header is equal to number of bytes the reader advanced
            let header_len = decoder.position();
            self.check_out_of_bounds(header_len)?;

            Ok(header)
        }
    }

    /// Obtain a slice of bytes contain a complete TLV production suitable for parsing later.
    pub fn read_tlv_bytes(&mut self) -> Result<&'r [u8]> {
        let header = self.peek_header()?;
        let header_len = header.encoded_len()?;
        self.read_slice((header_len + header.length)?)
    }

    /// Decode a value which impls the [`Decode`] trait.
    pub fn decode<T: Decode<'r>>(&mut self) -> Result<T> {
        T::decode(self)
    }

    /// Returns inner reader. Discards current nesting limit
    pub fn into_inner(self) -> R {
        self.inner
    }
}

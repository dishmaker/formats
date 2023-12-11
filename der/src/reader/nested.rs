//! Reader type for consuming nested TLV records within a DER document.

use crate::{reader::Reader, Decode, Encode, Error, ErrorKind, Header, Length, Result, Tag};

/// Reader type used by [`Reader::read_nested`].
pub struct NestedDecoder<'i, R> {
    /// Inner reader type.
    inner: &'i mut R,

    /// Index of first byte that we can't read
    end_pos: Length,
}

impl<'i, 'r, R: Reader<'r>> NestedDecoder<'i, R> {
    /// Create a new nested reader which can read the given [`Length`].
    pub(crate) fn new(inner: &'i mut R, len: Length) -> Result<Self> {
        if len <= inner.remaining_len() {
            Ok(Self {
                inner,
                end_pos: (inner.position() + len)?,
            })
        } else {
            Err(ErrorKind::Incomplete {
                expected_len: (inner.offset() + len)?,
                actual_len: (inner.offset() + inner.remaining_len())?,
            }
            .at(inner.offset()))
        }
    }

    /// Move the position cursor by the given length, returning an error if there
    /// isn't enough remaining data in the nested input.
    fn check_out_of_bounds(&mut self, len: Length) -> Result<()> {
        let new_position = (self.position() + len)?;

        if new_position >= self.end_pos {
            return Err(ErrorKind::Incomplete {
                expected_len: (self.inner.offset() + len)?,
                actual_len: (self.inner.offset() + self.remaining_len())?,
            }
            .at(self.inner.offset()));
        }
        Ok(())
    }

    pub fn peek_byte(&self) -> Option<u8> {
        if self.is_finished() {
            None
        } else {
            self.inner.peek_byte()
        }
    }

    // fn peek_header(&self) -> Result<Header> {
    //
    // }

    pub fn position(&self) -> Length {
        self.inner.position()
    }

    pub fn read_slice(&mut self, len: Length) -> Result<&'r [u8]> {
        self.check_out_of_bounds(len)?;
        self.inner.read_slice(len)
    }

    pub fn error(&mut self, kind: ErrorKind) -> Error {
        self.inner.error(kind)
    }

    pub fn offset(&self) -> Length {
        self.inner.offset()
    }

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
    pub fn finish<T>(self, value: T) -> Result<T> {
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
    pub fn read_nested<'n, T, F>(&'n mut self, len: Length, f: F) -> Result<T>
    where
        F: FnOnce(&mut NestedDecoder<'n, R>) -> Result<T>,
    {
        let mut reader = NestedDecoder::new(self.inner, len)?;
        let ret = f(&mut reader)?;
        reader.finish(ret)
    }

    /// Read an ASN.1 `SEQUENCE`, creating a nested [`Reader`] for the body and
    /// calling the provided closure with it.
    pub fn sequence<'n, F, T>(&'n mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut NestedDecoder<'n, R>) -> Result<T>,
    {
        let header = Header::decode(self)?;
        header.tag.assert_eq(Tag::Sequence)?;
        self.read_nested(header.length, f)
    }



    // TODO: make only available for Clone
    //
    // impl<'i, 'r, R: Reader<'r> + Clone> NestedDecoder<'i, R> {
    pub fn peek_header(&self) -> Result<Header> {
        if self.is_finished() {
            Err(Error::incomplete(self.offset()))
        } else {
            // TODO(tarcieri): handle peeking past nested length
            Header::decode(&mut self.clone())
        }
    }

    /// Obtain a slice of bytes contain a complete TLV production suitable for parsing later.
    pub fn read_tlv_bytes(&mut self) -> Result<&'r [u8]> {
        let header = self.peek_header()?;
        let header_len = header.encoded_len()?;
        self.read_slice((header_len + header.length)?)
    }
}

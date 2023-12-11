//! Reader trait.

pub(crate) mod nested;
#[cfg(feature = "pem")]
pub(crate) mod pem;
pub(crate) mod slice;

pub(crate) use nested::NestedDecoder;

use crate::{
    asn1::ContextSpecific, DecodeValue, Error, ErrorKind, FixedTag, Length,
    Result, Tag, TagMode, TagNumber,
};



/// Reader trait which reads DER-encoded input.
pub trait Reader<'r>: Sized + Clone {

    fn nested_decoder(self) -> NestedDecoder<'r, Self> {
        NestedDecoder::new(&mut self, self.input_len()).unwrap()
    }

    /// Get the length of the input.
    fn input_len(&self) -> Length;

    /// Peek at the next byte of input without modifying the cursor.
    fn peek_byte(&self) -> Option<u8>;

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

    /// Attempt to decode an ASN.1 `CONTEXT-SPECIFIC` field with the
    /// provided [`TagNumber`].
    fn context_specific<T>(&mut self, tag_number: TagNumber, tag_mode: TagMode) -> Result<Option<T>>
    where
        T: DecodeValue<'r> + FixedTag,
    {
        Ok(match tag_mode {
            TagMode::Explicit => ContextSpecific::<T>::decode_explicit(self, tag_number)?,
            TagMode::Implicit => ContextSpecific::<T>::decode_implicit(self, tag_number)?,
        }
        .map(|field| field.value))
    }

    // /// Decode a value which impls the [`Decode`] trait.
    // fn decode<T: Decode<'r>>(&mut self) -> Result<T> {
    //     T::decode(self).map_err(|e| e.nested(self.position()))
    // }

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

    /// Offset within the original input stream.
    ///
    /// This is used for error reporting, and doesn't need to be overridden
    /// by any reader implementations (except for the built-in `NestedReader`,
    /// which consumes nested input messages)
    fn offset(&self) -> Length {
        self.position()
    }

    /// Peek at the next byte in the decoder and attempt to decode it as a
    /// [`Tag`] value.
    ///
    /// Does not modify the decoder's state.
    fn peek_tag(&self) -> Result<Tag> {
        match self.peek_byte() {
            Some(byte) => byte.try_into(),
            None => Err(Error::incomplete(self.input_len())),
        }
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

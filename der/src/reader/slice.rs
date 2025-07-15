//! Slice reader.

use crate::{BytesRef, Decode, EncodingRules, Error, ErrorKind, Length, Reader};

/// [`Reader`] which consumes an input byte slice.
#[derive(Clone, Debug)]
pub struct SliceReader<'a> {
    /// Byte slice being decoded.
    bytes: &'a BytesRef,

    /// Encoding rules to apply when decoding the input.
    #[cfg(feature = "slow_slice_rdr")]
    encoding_rules: EncodingRules,

    /// Did the decoding operation fail?
    #[cfg(feature = "slow_slice_rdr")]
    failed: bool,

    /// Position within the decoded slice.
    #[cfg(feature = "slow_slice_rdr")]
    position: Length,
}

impl<'a> SliceReader<'a> {
    /// Create a new slice reader for the given byte slice.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::new_with_encoding_rules(bytes, EncodingRules::default())
    }

    /// Create a new slice reader with the given encoding rules.
    pub fn new_with_encoding_rules(
        bytes: &'a [u8],
        encoding_rules: EncodingRules,
    ) -> Result<Self, Error> {
        Ok(Self {
            bytes: BytesRef::new(bytes)?,
            #[cfg(feature = "slow_slice_rdr")]
            encoding_rules,
            #[cfg(feature = "slow_slice_rdr")]
            failed: false,
            #[cfg(feature = "slow_slice_rdr")]
            position: Length::ZERO,
        })
    }

    /// Return an error with the given [`ErrorKind`], annotating it with
    /// context about where the error occurred.
    pub fn error(&mut self, kind: ErrorKind) -> Error {
        #[cfg(feature = "slow_slice_rdr")]
        {
            self.failed = true;
        }
        #[cfg(feature = "slow_slice_rdr")]
        {
            kind.at(self.position)
        }
        #[cfg(not(feature = "slow_slice_rdr"))]
        {
            kind.into()
        }
    }

    #[cfg(not(feature = "slow_slice_rdr"))]
    fn advance(&mut self, len: usize) {
        self.bytes = BytesRef::new_unchecked(&self.bytes.as_slice()[len..]);
    }

    /// Did the decoding operation fail due to an error?
    #[cfg(feature = "slow_slice_rdr")]
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Obtain the remaining bytes in this slice reader from the current cursor
    /// position.
    pub(crate) fn remaining(&self) -> Result<&'a [u8], Error> {
        #[cfg(feature = "slow_slice_rdr")]
        if self.is_failed() {
            return Err(ErrorKind::Failed.at(self.position));
        }
        #[cfg(feature = "slow_slice_rdr")]
        {
            self.bytes
                .as_slice()
                .get(self.position.try_into()?..)
                .ok_or_else(|| Error::incomplete(self.input_len()))
        }
        #[cfg(not(feature = "slow_slice_rdr"))]
        {
            Ok(self.bytes.as_slice())
        }
    }
    /// Creates new [`SliceReader`] without advancing current reader.
    pub(crate) fn new_nested_reader(&mut self, len: Length) -> Result<Self, Error> {
        #[cfg(feature = "slow_slice_rdr")]
        {
            let prefix_len = (self.position + len)?;
            let mut nested_reader = self.clone();
            nested_reader.bytes = self.bytes.prefix(prefix_len)?;
            Ok(nested_reader)
        }

        #[cfg(not(feature = "slow_slice_rdr"))]
        {
            Ok(SliceReader {
                bytes: self.bytes.prefix(len)?,
            })
        }
    }
}

impl<'a> Reader<'a> for SliceReader<'a> {
    fn encoding_rules(&self) -> EncodingRules {
        #[cfg(feature = "slow_slice_rdr")]
        {
            self.encoding_rules
        }

        #[cfg(not(feature = "slow_slice_rdr"))]
        EncodingRules::Der
    }

    fn input_len(&self) -> Length {
        self.bytes.len()
    }

    #[cfg(not(feature = "slow_slice_rdr"))]
    fn read_byte(&mut self) -> Result<u8, Error> {
        self.bytes
            .as_slice()
            .get(0)
            .copied()
            .ok_or_else(|| {
                ErrorKind::Incomplete {
                    expected_len: Length::new(1),
                    actual_len: Length::new(0),
                }
                .into()
            })
            .inspect(|_| self.advance(1))
    }

    fn position(&self) -> Length {
        #[cfg(feature = "slow_slice_rdr")]
        {
            self.position
        }

        #[cfg(not(feature = "slow_slice_rdr"))]
        {
            Length::new(0)
        }
    }

    /// Read nested data of the given length.
    fn read_nested<T, F, E>(&mut self, len: Length, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<Error>,
    {
        let mut nested_reader = self.new_nested_reader(len)?;
        let ret = f(&mut nested_reader);
        #[cfg(feature = "slow_slice_rdr")]
        {
            self.position = nested_reader.position;
            self.failed = nested_reader.failed;
        }
        #[cfg(not(feature = "slow_slice_rdr"))]
        {
            self.advance(usize::try_from(len)?);
        }
        match ret {
            Ok(value) => {
                nested_reader.finish().inspect_err(|_e| {
                    #[cfg(feature = "slow_slice_rdr")]
                    {
                        self.failed = true;
                    }
                })?;
                Ok(value)
            }
            Err(err) => Err(err),
        }
    }

    fn read_slice(&mut self, len: Length) -> Result<&'a [u8], Error> {
        #[cfg(feature = "slow_slice_rdr")]
        if self.is_failed() {
            return Err(self.error(ErrorKind::Failed));
        }

        let len_usize = len.try_into()?;
        match self.remaining()?.get(..len_usize) {
            Some(result) => {
                #[cfg(feature = "slow_slice_rdr")]
                {
                    self.position = (self.position + len)?;
                }
                #[cfg(not(feature = "slow_slice_rdr"))]
                {
                    self.advance(len_usize);
                }
                Ok(result)
            }
            None => Err(self.error(ErrorKind::Incomplete {
                #[cfg(feature = "slow_slice_rdr")]
                expected_len: (self.position + len)?,

                #[cfg(not(feature = "slow_slice_rdr"))]
                expected_len: len,

                actual_len: self.input_len(),
            })),
        }
    }

    fn decode<T: Decode<'a>>(&mut self) -> Result<T, T::Error> {
        #[cfg(feature = "slow_slice_rdr")]
        if self.is_failed() {
            return Err(self.error(ErrorKind::Failed).into());
        }

        T::decode(self).inspect_err(|_| {
            #[cfg(feature = "slow_slice_rdr")]
            {
                self.failed = true;
            }
        })
    }

    fn error(&mut self, kind: ErrorKind) -> Error {
        #[cfg(feature = "slow_slice_rdr")]
        {
            self.failed = true;
        }
        //kind.at(self.position)
        kind.into()
    }

    fn finish(self) -> Result<(), Error> {
        #[cfg(feature = "slow_slice_rdr")]
        if self.is_failed() {
            return Err(ErrorKind::Failed.at(self.position));
        }
        if !self.is_finished() {
            return Err(ErrorKind::TrailingData {
                #[cfg(feature = "slow_slice_rdr")]
                decoded: self.position,
                #[cfg(not(feature = "slow_slice_rdr"))]
                decoded: Length::new(0),

                remaining: self.remaining_len(),
            }
            .into());
        }
        Ok(())
    }

    fn remaining_len(&self) -> Length {
        #[cfg(feature = "slow_slice_rdr")]
        {
            debug_assert!(self.position <= self.input_len());
            self.input_len().saturating_sub(self.position)
        }

        #[cfg(not(feature = "slow_slice_rdr"))]
        {
            self.input_len()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::SliceReader;
    use crate::{Decode, ErrorKind, Length, Reader};
    use hex_literal::hex;

    // INTEGER: 42
    const EXAMPLE_MSG: &[u8] = &hex!("02012A00");

    #[test]
    fn empty_message() {
        let mut reader = SliceReader::new(&[]).unwrap();
        let err = bool::decode(&mut reader).err().unwrap();
        assert_eq!(Some(Length::ZERO), err.position());

        match err.kind() {
            ErrorKind::Incomplete {
                expected_len,
                actual_len,
            } => {
                assert_eq!(actual_len, 0u8.into());
                assert_eq!(expected_len, 1u8.into());
            }
            other => panic!("unexpected error kind: {:?}", other),
        }
    }

    #[test]
    fn invalid_field_length() {
        const MSG_LEN: usize = 2;

        let mut reader = SliceReader::new(&EXAMPLE_MSG[..MSG_LEN]).unwrap();
        let err = i8::decode(&mut reader).err().unwrap();
        assert_eq!(Some(Length::from(2u8)), err.position());

        match err.kind() {
            ErrorKind::Incomplete {
                expected_len,
                actual_len,
            } => {
                assert_eq!(actual_len, MSG_LEN.try_into().unwrap());
                assert_eq!(expected_len, (MSG_LEN + 1).try_into().unwrap());
            }
            other => panic!("unexpected error kind: {:?}", other),
        }
    }

    #[test]
    fn trailing_data() {
        let mut reader = SliceReader::new(EXAMPLE_MSG).unwrap();
        let x = i8::decode(&mut reader).unwrap();
        assert_eq!(42i8, x);

        let err = reader.finish().err().unwrap();
        assert_eq!(Some(Length::from(3u8)), err.position());

        assert_eq!(
            ErrorKind::TrailingData {
                decoded: 3u8.into(),
                remaining: 1u8.into(),
            },
            err.kind()
        );
    }
}

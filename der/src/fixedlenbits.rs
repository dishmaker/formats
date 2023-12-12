use core::ops::RangeInclusive;

use crate::{Error, ErrorKind, NestedDecoder, Reader, Tag};

/// BitString, but implemented as bool fields, eg.
/// Hence it has fixed bit-length.
///
/// ```
/// /// Bit length of 2
/// struct MyBitString {
///     flag1: bool,
///     flag2: bool,
/// }
/// ```
pub trait FixedLenBitString {
    /// Implementer must specify how many bits are allowed
    const BIT_LEN: RangeInclusive<u16>;

    /// Returns an error if the bitstring is not in expected length range
    fn check_bit_len<'a, R: Reader<'a>>(
        _decoder: &mut NestedDecoder<R>,
        bit_len: usize,
    ) -> Result<(), Error> {
        let expected_bits = Self::BIT_LEN;
        let bit_len = bit_len as u16;

        // TODO(dishmaker): force allowed range to eg. 3..=4
        if bit_len > *expected_bits.end() {
            //if !expected_bits.contains(&(bit_len as u16)) {

            Err(ErrorKind::Length {
                tag: Tag::BitString,
            }
            .into())
        } else {
            Ok(())
        }
    }
}

//! ASN.1 tags.
#![cfg_attr(feature = "arbitrary", allow(clippy::arithmetic_side_effects))]

mod class;
mod mode;
mod number;

pub use self::{class::Class, mode::TagMode, number::TagNumber};
pub use self::{class::CLASS_APPLICATION, class::CLASS_CONTEXT_SPECIFIC, class::CLASS_PRIVATE};

use crate::{Decode, DerOrd, Encode, Error, ErrorKind, Length, Reader, Result, Writer};
use core::{cmp::Ordering, fmt};

/// Indicator bit for constructed form encoding (i.e. vs primitive form)
const CONSTRUCTED_FLAG: u8 = 0b100000;

/// Types which have a constant ASN.1 [`Tag`].
pub trait FixedTag {
    /// ASN.1 tag
    const TAG: Tag;
}

/// Types which have an ASN.1 [`Tag`].
pub trait Tagged {
    /// Get the ASN.1 tag that this type is encoded with.
    fn tag(&self) -> Tag;
}

/// Types which are [`FixedTag`] always have a known [`Tag`] type.
impl<T: FixedTag + ?Sized> Tagged for T {
    fn tag(&self) -> Tag {
        T::TAG
    }
}

/// ASN.1 tags.
///
/// Tags are the leading identifier octet of the Tag-Length-Value encoding
/// used by ASN.1 DER and identify the type of the subsequent value.
///
/// They are described in X.690 Section 8.1.2: Identifier octets, and
/// structured as follows:
///
/// ```text
/// | Class | P/C | Tag Number |
/// ```
///
/// - Bits 8/7: [`Class`]
/// - Bit 6: primitive (0) or constructed (1)
/// - Bits 5-1: tag number
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Tag {
    /// `BOOLEAN` tag: `1`.
    Boolean,

    /// `INTEGER` tag: `2`.
    Integer,

    /// `BIT STRING` tag: `3`.
    BitString,

    /// `OCTET STRING` tag: `4`.
    OctetString,

    /// `NULL` tag: `5`.
    Null,

    /// `OBJECT IDENTIFIER` tag: `6`.
    ObjectIdentifier,

    /// `REAL` tag: `9`.
    Real,

    /// `ENUMERATED` tag: `10`.
    Enumerated,

    /// `UTF8String` tag: `12`.
    Utf8String,

    /// `SEQUENCE` tag: `16`.
    Sequence,

    /// `SET` and `SET OF` tag: `17`.
    Set,

    /// `NumericString` tag: `18`.
    NumericString,

    /// `PrintableString` tag: `19`.
    PrintableString,

    /// `TeletexString` tag: `20`.
    TeletexString,

    /// `VideotexString` tag: `21`.
    VideotexString,

    /// `IA5String` tag: `22`.
    Ia5String,

    /// `UTCTime` tag: `23`.
    UtcTime,

    /// `GeneralizedTime` tag: `24`.
    GeneralizedTime,

    /// `VisibleString` tag: `26`.
    VisibleString,

    /// `GeneralString` tag: `27`.
    GeneralString,

    /// `BMPString` tag: `30`.
    BmpString,

    /// Application tag.
    Application {
        /// Is this tag constructed? (vs primitive).
        constructed: bool,

        /// Tag number.
        number: TagNumber,
    },

    /// Context-specific tag.
    ContextSpecific {
        /// Is this tag constructed? (vs primitive).
        constructed: bool,

        /// Tag number.
        number: TagNumber,
    },

    /// Private tag number.
    Private {
        /// Is this tag constructed? (vs primitive).
        constructed: bool,

        /// Tag number.
        number: TagNumber,
    },
}

impl Tag {
    /// Maximum number of octets in a DER encoding of a [`Tag`] using the
    /// rules implemented by this crate.
    pub(crate) const MAX_SIZE: usize = 4;

    /// Peek at the next bytes in the reader and attempt to decode it as a [`Tag`] value.
    ///
    /// Does not modify the reader's state.
    pub fn peek<'a>(reader: &impl Reader<'a>) -> Result<Self> {
        Self::peek_optional(reader)?.ok_or_else(|| Error::incomplete(reader.input_len()))
    }

    pub(crate) fn peek_optional<'a>(reader: &impl Reader<'a>) -> Result<Option<Self>> {
        let mut buf = [0u8; Self::MAX_SIZE];

        if reader.peek_into(&mut buf[0..1]).is_err() {
            return Ok(None);
        };

        if let Ok(tag) = Self::from_der(&buf[0..1]) {
            return Ok(Some(tag));
        }

        for i in 2..Self::MAX_SIZE {
            let slice = &mut buf[0..i];
            if reader.peek_into(slice).is_err() {
                continue;
            }
            if let Ok(tag) = Self::from_der(slice) {
                return Ok(Some(tag));
            }
        }

        Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()))
    }

    /// Assert that this [`Tag`] matches the provided expected tag.
    ///
    /// On mismatch, returns an [`Error`] with [`ErrorKind::TagUnexpected`].
    pub fn assert_eq(self, expected: Tag) -> Result<Tag> {
        if self == expected {
            Ok(self)
        } else {
            Err(self.unexpected_error(Some(expected)))
        }
    }

    /// Get the [`Class`] that corresponds to this [`Tag`].
    pub const fn class(self) -> Class {
        match self {
            Tag::Application { .. } => Class::Application,
            Tag::ContextSpecific { .. } => Class::ContextSpecific,
            Tag::Private { .. } => Class::Private,
            _ => Class::Universal,
        }
    }

    /// Get the [`TagNumber`] for this tag.
    pub fn number(self) -> TagNumber {
        match self {
            Tag::Boolean => TagNumber(1),
            Tag::Integer => TagNumber(2),
            Tag::BitString => TagNumber(3),
            Tag::OctetString => TagNumber(4),
            Tag::Null => TagNumber(5),
            Tag::ObjectIdentifier => TagNumber(6),
            Tag::Real => TagNumber(9),
            Tag::Enumerated => TagNumber(10),
            Tag::Utf8String => TagNumber(12),
            Tag::Sequence => TagNumber(16),
            Tag::Set => TagNumber(17),
            Tag::NumericString => TagNumber(18),
            Tag::PrintableString => TagNumber(19),
            Tag::TeletexString => TagNumber(20),
            Tag::VideotexString => TagNumber(21),
            Tag::Ia5String => TagNumber(22),
            Tag::UtcTime => TagNumber(23),
            Tag::GeneralizedTime => TagNumber(24),
            Tag::VisibleString => TagNumber(26),
            Tag::GeneralString => TagNumber(27),
            Tag::BmpString => TagNumber(30),
            Tag::Application { number, .. } => number,
            Tag::ContextSpecific { number, .. } => number,
            Tag::Private { number, .. } => number,
        }
    }

    /// Does this tag represent a constructed (as opposed to primitive) field?
    pub const fn is_constructed(self) -> bool {
        match self {
            Tag::Sequence | Tag::Set => true,
            Tag::Application { constructed, .. }
            | Tag::ContextSpecific { constructed, .. }
            | Tag::Private { constructed, .. } => constructed,
            _ => false,
        }
    }

    /// Is this an application tag?
    pub const fn is_application(self) -> bool {
        matches!(self, Tag::Application { .. })
    }

    /// Is this a context-specific tag?
    pub const fn is_context_specific(self) -> bool {
        matches!(self, Tag::ContextSpecific { .. })
    }

    /// Is this a private tag?
    pub const fn is_private(self) -> bool {
        matches!(self, Tag::Private { .. })
    }

    /// Is this a universal tag?
    pub const fn is_universal(self) -> bool {
        !matches!(
            self,
            Tag::Application { .. } | Tag::ContextSpecific { .. } | Tag::Private { .. }
        )
    }

    /// Create an [`Error`] for an invalid [`Length`].
    pub fn length_error(self) -> Error {
        ErrorKind::Length { tag: self }.into()
    }

    /// Create an [`Error`] for an non-canonical value with the ASN.1 type
    /// identified by this tag.
    pub fn non_canonical_error(self) -> Error {
        ErrorKind::Noncanonical { tag: self }.into()
    }

    /// Create an [`Error`] because the current tag was unexpected, with an
    /// optional expected tag.
    pub fn unexpected_error(self, expected: Option<Self>) -> Error {
        ErrorKind::TagUnexpected {
            expected,
            actual: self,
        }
        .into()
    }

    /// Create an [`Error`] for an invalid value with the ASN.1 type identified
    /// by this tag.
    pub fn value_error(self) -> Error {
        ErrorKind::Value { tag: self }.into()
    }
}

impl<'a> Decode<'a> for Tag {
    type Error = Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self> {
        let first_byte = reader.read_byte()?;

        let tag = match first_byte {
            0x01 => Tag::Boolean,
            0x02 => Tag::Integer,
            0x03 => Tag::BitString,
            0x04 => Tag::OctetString,
            0x05 => Tag::Null,
            0x06 => Tag::ObjectIdentifier,
            0x09 => Tag::Real,
            0x0A => Tag::Enumerated,
            0x0C => Tag::Utf8String,
            0x12 => Tag::NumericString,
            0x13 => Tag::PrintableString,
            0x14 => Tag::TeletexString,
            0x15 => Tag::VideotexString,
            0x16 => Tag::Ia5String,
            0x17 => Tag::UtcTime,
            0x18 => Tag::GeneralizedTime,
            0x1A => Tag::VisibleString,
            0x1B => Tag::GeneralString,
            0x1E => Tag::BmpString,
            0x30 => Tag::Sequence, // constructed
            0x31 => Tag::Set,      // constructed
            0x40..=0x7F => {
                let (constructed, number) = parse_parts(first_byte, reader)?;

                Tag::Application {
                    constructed,
                    number,
                }
            }
            0x80..=0xBF => {
                let (constructed, number) = parse_parts(first_byte, reader)?;

                Tag::ContextSpecific {
                    constructed,
                    number,
                }
            }
            0xC0..=0xFF => {
                let (constructed, number) = parse_parts(first_byte, reader)?;

                Tag::Private {
                    constructed,
                    number,
                }
            }
            byte => return Err(ErrorKind::TagUnknown { byte }.into()),
        };

        Ok(tag)
    }
}

fn parse_parts<'a, R: Reader<'a>>(first_byte: u8, reader: &mut R) -> Result<(bool, TagNumber)> {
    let constructed = first_byte & CONSTRUCTED_FLAG != 0;
    let first_number_part = first_byte & TagNumber::MASK;

    if first_number_part != TagNumber::MASK {
        return Ok((constructed, TagNumber::new(first_number_part.into())));
    }

    let mut multi_byte_tag_number: u16 = 0;

    for _ in 0..Tag::MAX_SIZE - 1 {
        multi_byte_tag_number = multi_byte_tag_number
            .checked_mul(0x80)
            .ok_or_else(|| Error::new(ErrorKind::TagNumberInvalid, reader.position()))?;

        let byte = reader.read_byte()?;
        multi_byte_tag_number |= u16::from(byte & 0x7F);

        if byte & 0x80 == 0 {
            return Ok((constructed, TagNumber::new(multi_byte_tag_number)));
        }
    }

    Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()))
}

fn tag_length(tag_number: u16) -> Length {
    if tag_number <= 30 {
        Length::ONE
    } else if tag_number < 0x80 {
        Length::new(2)
    } else if tag_number < 0x80 * 0x80 {
        Length::new(3)
    } else {
        Length::new(4)
    }
}

#[allow(clippy::cast_possible_truncation)]
fn tag_number_bytes(first_byte: u8, num: u16, buf: &mut [u8; Tag::MAX_SIZE]) -> &[u8] {
    if num <= 30 {
        buf[0] = first_byte | num as u8;
        &buf[..1]
    } else if num < 0x80 {
        buf[0] = first_byte | 0x1F;
        buf[1] = num as u8;
        &buf[..2]
    } else if num < 0x80 * 0x80 {
        buf[0] = first_byte | 0x1F;
        buf[1] = 0x80 | (num >> 7) as u8;
        buf[2] = (num & 0x7F) as u8;
        &buf[..3]
    } else {
        buf[0] = first_byte | 0x1F;
        buf[1] = 0x80 | (num >> 14) as u8;
        buf[2] = 0x80 | (num >> 7) as u8;
        buf[3] = (num & 0x7F) as u8;
        &buf[..4]
    }
}

impl Encode for Tag {
    fn encoded_len(&self) -> Result<Length> {
        Ok(tag_length(self.number().value()))
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        let mut first_byte = self.class() as u8;
        if self.is_constructed() {
            first_byte |= CONSTRUCTED_FLAG;
        }
        let num = self.number().value();

        let mut buf = [0u8; Tag::MAX_SIZE];
        let tag_bytes = tag_number_bytes(first_byte, num, &mut buf);
        writer.write(tag_bytes)
    }
}

impl DerOrd for Tag {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        Ok(self
            .class()
            .cmp(&other.class())
            .then_with(|| self.is_constructed().cmp(&other.is_constructed()))
            .then_with(|| self.number().cmp(&other.number())))
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const FIELD_TYPE: [&str; 2] = ["primitive", "constructed"];

        match *self {
            Tag::Boolean => f.write_str("BOOLEAN"),
            Tag::Integer => f.write_str("INTEGER"),
            Tag::BitString => f.write_str("BIT STRING"),
            Tag::OctetString => f.write_str("OCTET STRING"),
            Tag::Null => f.write_str("NULL"),
            Tag::ObjectIdentifier => f.write_str("OBJECT IDENTIFIER"),
            Tag::Real => f.write_str("REAL"),
            Tag::Enumerated => f.write_str("ENUMERATED"),
            Tag::Utf8String => f.write_str("UTF8String"),
            Tag::Set => f.write_str("SET"),
            Tag::NumericString => f.write_str("NumericString"),
            Tag::PrintableString => f.write_str("PrintableString"),
            Tag::TeletexString => f.write_str("TeletexString"),
            Tag::VideotexString => f.write_str("VideotexString"),
            Tag::Ia5String => f.write_str("IA5String"),
            Tag::UtcTime => f.write_str("UTCTime"),
            Tag::GeneralizedTime => f.write_str("GeneralizedTime"),
            Tag::VisibleString => f.write_str("VisibleString"),
            Tag::GeneralString => f.write_str("GeneralString"),
            Tag::BmpString => f.write_str("BMPString"),
            Tag::Sequence => f.write_str("SEQUENCE"),
            Tag::Application {
                constructed,
                number,
            } => write!(
                f,
                "APPLICATION [{}] ({})",
                number,
                FIELD_TYPE[usize::from(constructed)]
            ),
            Tag::ContextSpecific {
                constructed,
                number,
            } => write!(
                f,
                "CONTEXT-SPECIFIC [{}] ({})",
                number,
                FIELD_TYPE[usize::from(constructed)]
            ),
            Tag::Private {
                constructed,
                number,
            } => write!(
                f,
                "PRIVATE [{}] ({})",
                number,
                FIELD_TYPE[usize::from(constructed)]
            ),
        }
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag(0x{:02x}: {})", self.number().value(), self)
    }
}

#[cfg(test)]
mod tests {
    use super::{Class, Tag, TagNumber};
    use crate::{Decode, Encode, Length, Reader, SliceReader};

    #[test]
    fn tag_class() {
        assert_eq!(Tag::Boolean.class(), Class::Universal);
        assert_eq!(Tag::Integer.class(), Class::Universal);
        assert_eq!(Tag::BitString.class(), Class::Universal);
        assert_eq!(Tag::OctetString.class(), Class::Universal);
        assert_eq!(Tag::Null.class(), Class::Universal);
        assert_eq!(Tag::ObjectIdentifier.class(), Class::Universal);
        assert_eq!(Tag::Real.class(), Class::Universal);
        assert_eq!(Tag::Enumerated.class(), Class::Universal);
        assert_eq!(Tag::Utf8String.class(), Class::Universal);
        assert_eq!(Tag::Set.class(), Class::Universal);
        assert_eq!(Tag::NumericString.class(), Class::Universal);
        assert_eq!(Tag::PrintableString.class(), Class::Universal);
        assert_eq!(Tag::TeletexString.class(), Class::Universal);
        assert_eq!(Tag::VideotexString.class(), Class::Universal);
        assert_eq!(Tag::Ia5String.class(), Class::Universal);
        assert_eq!(Tag::UtcTime.class(), Class::Universal);
        assert_eq!(Tag::GeneralizedTime.class(), Class::Universal);
        assert_eq!(Tag::Sequence.class(), Class::Universal);

        for num in 0..=30 {
            for &constructed in &[false, true] {
                let number = TagNumber::new(num);

                assert_eq!(
                    Tag::Application {
                        constructed,
                        number
                    }
                    .class(),
                    Class::Application
                );

                assert_eq!(
                    Tag::ContextSpecific {
                        constructed,
                        number
                    }
                    .class(),
                    Class::ContextSpecific
                );

                assert_eq!(
                    Tag::Private {
                        constructed,
                        number
                    }
                    .class(),
                    Class::Private
                );
            }
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn peek() {
        let reader = SliceReader::new(&[0x02]).unwrap();
        assert_eq!(reader.position(), Length::ZERO);
        assert_eq!(Tag::peek(&reader).unwrap(), Tag::Integer);
        assert_eq!(reader.position(), Length::ZERO); // Position unchanged
    }

    #[test]
    fn decode_application() {
        const TAG_APPLICATION: [u8; 2] = [0x7F, 0x21];
        let mut reader = SliceReader::new(&TAG_APPLICATION).unwrap();
        let tag = Tag::decode(&mut reader).unwrap();

        assert_eq!(
            tag,
            Tag::Application {
                constructed: true,
                number: TagNumber(33)
            }
        );

        let mut buf = [0u8; 8];
        let encoded = tag.encode_to_slice(&mut buf).unwrap();

        assert_eq!(TAG_APPLICATION, encoded);
    }

    #[test]
    fn decode_private_out_of_range() {
        const TAG_PRIVATE: [u8; 4] = [0xFF, 0xFF, 0xFF, 0x7f];
        let mut reader = SliceReader::new(&TAG_PRIVATE).unwrap();
        let result = Tag::decode(&mut reader);
        assert!(result.is_err());
    }
    #[test]
    fn decode_private() {
        const TAG_PRIVATE: [u8; 4] = [0xFF, 0x83, 0xFF, 0x70];
        let mut reader = SliceReader::new(&TAG_PRIVATE).unwrap();
        let tag = Tag::decode(&mut reader).unwrap();

        assert_eq!(
            tag,
            Tag::Private {
                constructed: true,
                number: TagNumber(0xfff0)
            }
        );

        let mut buf = [0u8; 8];
        let encoded = tag.encode_to_slice(&mut buf).unwrap();

        assert_eq!(TAG_PRIVATE, encoded);
    }
}

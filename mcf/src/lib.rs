#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    unused_qualifications
)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod base64;
mod error;
mod fields;

pub use base64::Base64;
pub use error::{Error, Result};
pub use fields::{Field, Fields};

#[cfg(feature = "alloc")]
use {
    alloc::string::String,
    core::{fmt, str},
};

/// Debug message used in panics when invariants aren't properly held.
const INVARIANT_MSG: &str = "should be ensured valid by constructor";

/// Zero-copy decoder for hashes in the Modular Crypt Format (MCF).
///
/// For more information, see [`McfHash`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct McfHashRef<'a>(&'a str);

impl<'a> McfHashRef<'a> {
    /// Parse the given input string, returning an [`McfHashRef`] if valid.
    pub fn new(s: &'a str) -> Result<Self> {
        validate(s)?;
        Ok(Self(s))
    }

    /// Get the contained string as a `str`.
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Get the algorithm identifier for this MCF hash.
    pub fn id(self) -> &'a str {
        Fields::new(self.as_str())
            .next()
            .expect(INVARIANT_MSG)
            .as_str()
    }

    /// Get an iterator over the parts of the password hash as delimited by `$`, excluding the
    /// initial identifier.
    pub fn fields(self) -> Fields<'a> {
        let mut fields = Fields::new(self.as_str());

        // Remove the leading identifier
        let id = fields.next().expect(INVARIANT_MSG);
        debug_assert_eq!(self.id(), id.as_str());

        fields
    }
}

/// Modular Crypt Format (MCF) serialized password hash.
///
/// Password hashes in this format take the form `${id}$...`, where `{id}` is a short numeric or
/// alphanumeric algorithm identifier optionally containing a `-`, followed by `$` as a delimiter,
/// further followed by an algorithm-specific serialization of a password hash, typically
/// using a variant (often an algorithm-specific variant) of Base64. This algorithm-specific
/// serialization contains one or more fields `${first}[${second}]...`, where each field only uses
/// characters in the regexp range `[A-Za-z0-9./+=,\-]`.
///
/// Example (SHA-crypt w\ SHA-512):
///
/// ```text
/// $6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0
/// ```
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct McfHash(String);

#[cfg(feature = "alloc")]
impl McfHash {
    /// Parse the given input string, returning an [`McfHash`] if valid.
    pub fn new(s: impl Into<String>) -> Result<McfHash> {
        let s = s.into();
        validate(&s)?;
        Ok(Self(s))
    }

    /// Create an [`McfHash`] from an identifier.
    ///
    /// # Returns
    ///
    /// Error if the identifier is invalid.
    ///
    /// Allowed characters match the regex: `[a-z0-9\-]`, where the first and last characters do NOT
    /// contain a `-`.
    pub fn from_id(id: &str) -> Result<McfHash> {
        validate_id(id)?;

        let mut hash = String::with_capacity(1 + id.len());
        hash.push(fields::DELIMITER);
        hash.push_str(id);
        Ok(Self(hash))
    }

    /// Get the contained string as a `str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get an [`McfHashRef`] which corresponds to this owned [`McfHash`].
    pub fn as_mcf_hash_ref(&self) -> McfHashRef {
        McfHashRef(self.as_str())
    }

    /// Get the algorithm identifier for this MCF hash.
    pub fn id(&self) -> &str {
        self.as_mcf_hash_ref().id()
    }

    /// Get an iterator over the parts of the password hash as delimited by `$`, excluding the
    /// initial identifier.
    pub fn fields(&self) -> Fields {
        self.as_mcf_hash_ref().fields()
    }

    /// Push an additional field onto the password hash string.
    pub fn push_field(&mut self, field: Field<'_>) {
        self.0.push(fields::DELIMITER);
        self.0.push_str(field.as_str());
    }

    /// Push an additional field onto the password hash string, encoding it first as Base64.
    pub fn push_field_base64(&mut self, field: &[u8], base64_encoding: Base64) {
        self.0.push(fields::DELIMITER);
        self.0.push_str(&base64_encoding.encode_string(field));
    }
}

impl<'a> AsRef<str> for McfHashRef<'a> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(feature = "alloc")]
impl AsRef<str> for McfHash {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for McfHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "alloc")]
impl str::FromStr for McfHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// Perform validations that the given string is well-formed MCF.
fn validate(s: &str) -> Result<()> {
    // Require leading `$`
    if !s.starts_with(fields::DELIMITER) {
        return Err(Error {});
    }

    // Disallow trailing `$`
    if s.ends_with(fields::DELIMITER) {
        return Err(Error {});
    }

    // Validates the hash begins with a leading `$`
    let mut fields = Fields::new(s);

    // Validate characters in the identifier field
    let id = fields.next().ok_or(Error {})?;
    validate_id(id.as_str())?;

    // Validate the remaining fields have an appropriate format
    for field in fields {
        field.validate()?;
    }

    Ok(())
}

/// Validate the password hash identifier is well-formed.
///
/// Allowed characters match the regex: `[a-z0-9\-]`, where the first and last characters do NOT
/// contain a `-`.
fn validate_id(id: &str) -> Result<()> {
    let first = id.chars().next().ok_or(Error {})?;
    let last = id.chars().last().ok_or(Error {})?;

    for c in [first, last] {
        match c {
            'a'..='z' | '0'..='9' => (),
            _ => return Err(Error {}),
        }
    }

    for c in id.chars() {
        match c {
            'a'..='z' | '0'..='9' | '-' => (),
            _ => return Err(Error {}),
        }
    }

    Ok(())
}

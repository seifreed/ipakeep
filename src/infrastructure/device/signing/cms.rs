//! Minimal BER reader for CMS `SignedData` envelopes such as `.mobileprovision`.
//!
//! Like `security cms -D`, this only unwraps `encapContentInfo.eContent`: it does
//! not verify the signer certificates or the signature, so the returned payload
//! is not authenticated. Both DER and Apple's indefinite-length BER (with
//! constructed, chunked OCTET STRINGs) are accepted.

use thiserror::Error;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OCTET_STRING_CONSTRUCTED: u8 = 0x24;
const TAG_EXPLICIT_0: u8 = 0xA0;
const CONSTRUCTED_BIT: u8 = 0x20;
const HIGH_TAG_NUMBER: u8 = 0x1F;
const LONG_LENGTH_BIT: u8 = 0x80;
const INDEFINITE_LENGTH: u8 = 0x80;
const END_OF_CONTENTS: [u8; 2] = [0x00, 0x00];
const MAX_LENGTH_OCTETS: usize = size_of::<usize>();
const MAX_DEPTH: usize = 32;
/// `1.2.840.113549.1.7.2` (pkcs7-signedData).
const SIGNED_DATA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

/// Reasons a blob cannot be unwrapped as CMS `SignedData`.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum CmsError {
    /// The input ends inside an element.
    #[error("truncated BER data")]
    Truncated,
    /// The element uses an encoding this reader does not accept.
    #[error("unsupported BER encoding")]
    Unsupported,
    /// An element has a different tag than the CMS structure requires.
    #[error("expected BER tag {expected:#04x}, found {found:#04x}")]
    UnexpectedTag {
        /// Tag required at this position.
        expected: u8,
        /// Tag present in the input.
        found: u8,
    },
    /// The outer `ContentInfo` does not carry `SignedData`.
    #[error("not a CMS SignedData envelope")]
    NotSignedData,
    /// `encapContentInfo` has no `eContent` (detached signature).
    #[error("CMS SignedData has no encapsulated content")]
    MissingContent,
    /// Nesting exceeds the reader's recursion limit.
    #[error("BER nesting exceeds {MAX_DEPTH} levels")]
    TooDeep,
}

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Return the encapsulated content of a CMS `SignedData` blob without verifying its signature.
pub(crate) fn signed_data_content(input: &[u8]) -> Result<Vec<u8>, CmsError> {
    let content_info = expect(input, TAG_SEQUENCE)?.0;
    let (content_type, rest) = expect(content_info.content, TAG_OID)?;
    if content_type.content != SIGNED_DATA_OID {
        return Err(CmsError::NotSignedData);
    }
    let explicit = expect(rest, TAG_EXPLICIT_0)?.0;
    let signed_data = expect(explicit.content, TAG_SEQUENCE)?.0;
    let after_version = parse(signed_data.content, 0)?.1;
    let after_digests = parse(after_version, 0)?.1;
    let encapsulated = expect(after_digests, TAG_SEQUENCE)?.0;
    let after_type = expect(encapsulated.content, TAG_OID)?.1;
    if after_type.is_empty() {
        return Err(CmsError::MissingContent);
    }
    let explicit = expect(after_type, TAG_EXPLICIT_0)?.0;
    let octets = parse(explicit.content, 0)?.0;
    let mut content = Vec::new();
    collect_octets(&octets, &mut content, 0)?;
    Ok(content)
}

fn expect(input: &[u8], expected: u8) -> Result<(Tlv<'_>, &[u8]), CmsError> {
    let found = *input.first().ok_or(CmsError::Truncated)?;
    if found != expected {
        return Err(CmsError::UnexpectedTag { expected, found });
    }
    parse(input, 0)
}

fn parse(input: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8]), CmsError> {
    if depth > MAX_DEPTH {
        return Err(CmsError::TooDeep);
    }
    let (&tag, rest) = input.split_first().ok_or(CmsError::Truncated)?;
    if tag & HIGH_TAG_NUMBER == HIGH_TAG_NUMBER {
        return Err(CmsError::Unsupported);
    }
    let (&first, rest) = rest.split_first().ok_or(CmsError::Truncated)?;
    if first != INDEFINITE_LENGTH {
        let (length, rest) = definite_length(first, rest)?;
        let (content, rest) = rest.split_at_checked(length).ok_or(CmsError::Truncated)?;
        return Ok((Tlv { tag, content }, rest));
    }
    if tag & CONSTRUCTED_BIT == 0 {
        return Err(CmsError::Unsupported);
    }
    let length = indefinite_content_length(rest, depth)?;
    let (content, rest) = rest.split_at_checked(length).ok_or(CmsError::Truncated)?;
    let rest = rest
        .strip_prefix(&END_OF_CONTENTS)
        .ok_or(CmsError::Truncated)?;
    Ok((Tlv { tag, content }, rest))
}

fn definite_length(first: u8, rest: &[u8]) -> Result<(usize, &[u8]), CmsError> {
    if first & LONG_LENGTH_BIT == 0 {
        return Ok((usize::from(first), rest));
    }
    let count = usize::from(first & !LONG_LENGTH_BIT);
    if count > MAX_LENGTH_OCTETS {
        return Err(CmsError::Unsupported);
    }
    let (octets, rest) = rest.split_at_checked(count).ok_or(CmsError::Truncated)?;
    let length = octets
        .iter()
        .fold(0usize, |length, &octet| (length << 8) | usize::from(octet));
    Ok((length, rest))
}

fn indefinite_content_length(input: &[u8], depth: usize) -> Result<usize, CmsError> {
    let mut remaining = input;
    while !remaining.starts_with(&END_OF_CONTENTS) {
        remaining = parse(remaining, depth + 1)?.1;
    }
    Ok(input.len() - remaining.len())
}

fn collect_octets(tlv: &Tlv<'_>, output: &mut Vec<u8>, depth: usize) -> Result<(), CmsError> {
    match tlv.tag {
        TAG_OCTET_STRING => output.extend_from_slice(tlv.content),
        TAG_OCTET_STRING_CONSTRUCTED => {
            let mut remaining = tlv.content;
            while !remaining.is_empty() {
                let (chunk, rest) = parse(remaining, depth + 1)?;
                collect_octets(&chunk, output, depth + 1)?;
                remaining = rest;
            }
        }
        found => {
            return Err(CmsError::UnexpectedTag {
                expected: TAG_OCTET_STRING,
                found,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod fixtures {
    //! Builders for synthetic CMS envelopes used in tests.

    const ID_DATA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];

    /// Encode a definite-length element (short or long length form).
    pub(crate) fn definite(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let bytes = content.len().to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = &bytes[skip..];
        match u8::try_from(content.len()) {
            Ok(short) if short < 0x80 => out.push(short),
            _ => {
                let count = u8::try_from(significant.len()).expect("length octet count");
                out.push(0x80 | count);
                out.extend_from_slice(significant);
            }
        }
        out.extend_from_slice(content);
        out
    }

    /// Encode an indefinite-length constructed element.
    pub(crate) fn indefinite(tag: u8, children: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![tag, 0x80];
        for child in children {
            out.extend_from_slice(child);
        }
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// DER `SignedData` wrapping `payload` in a primitive OCTET STRING.
    pub(crate) fn der_signed_data(payload: &[u8]) -> Vec<u8> {
        let econtent = definite(0xA0, &definite(0x04, payload));
        let encap = definite(0x30, &[definite(0x06, ID_DATA_OID), econtent].concat());
        let signed = [
            definite(0x02, &[1]),
            definite(0x31, &[]),
            encap,
            definite(0x31, &[]),
        ]
        .concat();
        let explicit = definite(0xA0, &definite(0x30, &signed));
        definite(
            0x30,
            &[definite(0x06, super::SIGNED_DATA_OID), explicit].concat(),
        )
    }

    /// Apple-style BER `SignedData`: indefinite lengths and a chunked, nested OCTET STRING.
    pub(crate) fn ber_signed_data(payload: &[u8], chunk: usize) -> Vec<u8> {
        let chunks: Vec<Vec<u8>> = payload
            .chunks(chunk)
            .map(|part| definite(0x04, part))
            .collect();
        let (first, second) = chunks.split_at(chunks.len() / 2);
        let octets = indefinite(
            0x24,
            &[indefinite(0x24, first), definite(0x24, &second.concat())],
        );
        let econtent = indefinite(0xA0, &[octets]);
        let encap = indefinite(0x30, &[definite(0x06, ID_DATA_OID), econtent]);
        let signed = indefinite(
            0x30,
            &[
                definite(0x02, &[1]),
                indefinite(0x31, &[]),
                encap,
                definite(0x31, &[]),
            ],
        );
        indefinite(
            0x30,
            &[
                definite(0x06, super::SIGNED_DATA_OID),
                indefinite(0xA0, &[signed]),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{ber_signed_data, definite, der_signed_data};
    use super::*;

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
    }

    #[test]
    fn extracts_content_from_der_short_and_long_lengths() {
        for len in [0, 5, 0x7F, 0x80, 0x1234, 70_000] {
            let data = payload(len);
            assert_eq!(signed_data_content(&der_signed_data(&data)), Ok(data));
        }
    }

    #[test]
    fn extracts_content_from_indefinite_length_constructed_octets() {
        for (len, chunk) in [(1, 1), (100, 7), (5000, 1000), (70_000, 4096)] {
            let data = payload(len);
            assert_eq!(
                signed_data_content(&ber_signed_data(&data, chunk)),
                Ok(data)
            );
        }
    }

    #[test]
    fn rejects_non_signed_data_and_detached_content() {
        let data_oid = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
        let wrong = definite(0x30, &definite(0x06, data_oid));
        assert_eq!(signed_data_content(&wrong), Err(CmsError::NotSignedData));

        let encap = definite(0x30, &definite(0x06, data_oid));
        let signed = [definite(0x02, &[1]), definite(0x31, &[]), encap].concat();
        let explicit = definite(0xA0, &definite(0x30, &signed));
        let detached = definite(0x30, &[definite(0x06, SIGNED_DATA_OID), explicit].concat());
        assert_eq!(
            signed_data_content(&detached),
            Err(CmsError::MissingContent)
        );
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        let valid = der_signed_data(b"payload");
        for end in 0..valid.len() {
            assert!(signed_data_content(&valid[..end]).is_err(), "prefix {end}");
        }
        let ber = ber_signed_data(b"payload", 3);
        for end in 0..ber.len() {
            assert!(signed_data_content(&ber[..end]).is_err(), "prefix {end}");
        }
        assert_eq!(
            signed_data_content(b"not a provisioning profile"),
            Err(CmsError::UnexpectedTag {
                expected: TAG_SEQUENCE,
                found: b'n'
            })
        );
        assert_eq!(
            signed_data_content(&[0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Err(CmsError::Unsupported)
        );
        assert_eq!(
            signed_data_content(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(CmsError::Truncated)
        );
        assert!(matches!(
            parse(&[0x04, 0x80, 0, 0], 0),
            Err(CmsError::Unsupported)
        ));
        assert!(matches!(
            parse(&[0x1F, 0x01, 0x00], 0),
            Err(CmsError::Unsupported)
        ));
    }

    #[test]
    fn deep_indefinite_nesting_is_bounded() {
        let levels = 100_000;
        let bomb = [[0x30, 0x80].repeat(levels), [0, 0].repeat(levels)].concat();
        assert_eq!(signed_data_content(&bomb), Err(CmsError::TooDeep));
    }
}

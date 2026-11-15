//! DMAP (DAAP tagged binary) encoding and parsing.
//!
//! Ported from the DMAP helpers in ipatool `pkg/appstore/appstore_owned_apps.go`.
//! A DMAP element is a 4-byte ASCII tag, a big-endian `u32` payload length
//! and the payload; container tags nest further elements.

use thiserror::Error;

const TAG_LEN: usize = 4;
const HEADER_LEN: usize = 8;
const MAX_DEPTH: usize = 16;
const PRINTABLE_FIRST: u8 = 0x20;
const PRINTABLE_LAST: u8 = 0x7e;
const CONTAINER_TAGS: [&[u8; TAG_LEN]; 13] = [
    b"adbs", b"adsr", b"aply", b"avdb", b"mbcl", b"mccr", b"mcty", b"mdcl", b"mlcl", b"mlit",
    b"mlog", b"msrv", b"mupd",
];

/// A malformed DMAP document.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DmapError {
    /// Containers nest deeper than upstream's limit of 16.
    #[error("DMAP nesting is too deep")]
    TooDeep,
    /// Fewer than 8 bytes remain for a tag header.
    #[error("truncated DMAP tag header at byte {0}")]
    TruncatedHeader(usize),
    /// The tag contains non-printable bytes.
    #[error("invalid DMAP tag at byte {0}")]
    InvalidTag(usize),
    /// The declared payload is longer than the remaining data.
    #[error("DMAP tag {tag} length {length} exceeds remaining response length {remaining}")]
    Overflow {
        /// Offending tag.
        tag: String,
        /// Declared payload length.
        length: usize,
        /// Bytes left after the header.
        remaining: usize,
    },
    /// An integer payload has an unsupported width.
    #[error("tag {tag} has invalid integer length {length}")]
    IntegerLength {
        /// Offending tag.
        tag: String,
        /// Payload length.
        length: usize,
    },
    /// A visitor rejected an element.
    #[error("{0}")]
    Invalid(String),
}

/// Encode one element; a payload over 4 GiB saturates the length at `u32::MAX`.
#[must_use]
pub fn tag(name: &[u8; TAG_LEN], payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut element = Vec::with_capacity(HEADER_LEN + payload.len());
    element.extend_from_slice(name);
    element.extend_from_slice(&length.to_be_bytes());
    element.extend_from_slice(payload);
    element
}

/// Encode a one-byte integer element.
#[must_use]
pub fn uint8(name: &[u8; TAG_LEN], value: u8) -> Vec<u8> {
    tag(name, &[value])
}

/// Encode a big-endian `u32` element.
#[must_use]
pub fn uint32(name: &[u8; TAG_LEN], value: u32) -> Vec<u8> {
    tag(name, &value.to_be_bytes())
}

/// Encode a UTF-8 string element.
#[must_use]
pub fn string(name: &[u8; TAG_LEN], value: &str) -> Vec<u8> {
    tag(name, value.as_bytes())
}

/// Visit every element depth-first, descending into container tags.
///
/// # Errors
///
/// Malformed structure, or the first error returned by `visit`.
pub fn walk<F>(data: &[u8], visit: &mut F) -> Result<(), DmapError>
where
    F: FnMut(&str, &[u8]) -> Result<(), DmapError>,
{
    walk_at(data, 0, visit)
}

fn walk_at<F>(data: &[u8], depth: usize, visit: &mut F) -> Result<(), DmapError>
where
    F: FnMut(&str, &[u8]) -> Result<(), DmapError>,
{
    if depth > MAX_DEPTH {
        return Err(DmapError::TooDeep);
    }
    let mut offset = 0;
    while offset < data.len() {
        let (name, payload) = element_at(data, offset)?;
        visit(name, payload)?;
        if is_container(name) {
            walk_at(payload, depth + 1, visit)?;
        }
        offset += HEADER_LEN + payload.len();
    }
    Ok(())
}

fn element_at(data: &[u8], offset: usize) -> Result<(&str, &[u8]), DmapError> {
    let header = data
        .get(offset..offset + HEADER_LEN)
        .ok_or(DmapError::TruncatedHeader(offset))?;
    let name = &header[..TAG_LEN];
    if !name
        .iter()
        .all(|byte| (PRINTABLE_FIRST..=PRINTABLE_LAST).contains(byte))
    {
        return Err(DmapError::InvalidTag(offset));
    }
    let name = std::str::from_utf8(name).map_err(|_| DmapError::InvalidTag(offset))?;
    let length = be_uint(&header[TAG_LEN..]).unwrap_or_default();
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    let remaining = data.len() - offset - HEADER_LEN;
    if length > remaining {
        return Err(DmapError::Overflow {
            tag: name.to_string(),
            length,
            remaining,
        });
    }
    let start = offset + HEADER_LEN;
    Ok((name, &data[start..start + length]))
}

fn is_container(name: &str) -> bool {
    CONTAINER_TAGS
        .iter()
        .any(|tag| tag.as_slice() == name.as_bytes())
}

/// Big-endian unsigned integer of 1, 2, 4 or 8 bytes.
#[must_use]
pub fn be_uint(payload: &[u8]) -> Option<u64> {
    match payload.len() {
        1 | 2 | 4 | 8 => Some(
            payload
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
        ),
        _ => None,
    }
}

/// The first `target` element anywhere in `data`, read as a 4- or 8-byte integer.
///
/// # Errors
///
/// Malformed structure or a first match with another integer width.
pub fn first_uint(data: &[u8], target: &str) -> Result<Option<u64>, DmapError> {
    let mut found = None;
    walk(data, &mut |name, payload| {
        if found.is_some() || name != target {
            return Ok(());
        }
        if !matches!(payload.len(), 4 | 8) {
            return Err(DmapError::IntegerLength {
                tag: target.to_string(),
                length: payload.len(),
            });
        }
        found = be_uint(payload);
        Ok(())
    })?;
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_elements_byte_for_byte() {
        assert_eq!(uint32(b"mlid", 42), b"mlid\0\0\0\x04\0\0\0\x2a");
        assert_eq!(uint8(b"mikd", 2), b"mikd\0\0\0\x01\x02");
        assert_eq!(string(b"mque", "ab"), b"mque\0\0\0\x02ab");
        assert_eq!(tag(b"aetl", &[]), b"aetl\0\0\0\0");
    }

    #[test]
    fn round_trips_nested_containers() {
        let item = [uint32(b"aeSI", 7), string(b"aeBI", "com.x")].concat();
        let document = tag(b"adbs", &tag(b"mlcl", &tag(b"mlit", &item)));
        let mut seen = Vec::new();
        walk(&document, &mut |name, payload| {
            seen.push((name.to_string(), payload.len()));
            Ok(())
        })
        .expect("walk");
        let names: Vec<_> = seen.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["adbs", "mlcl", "mlit", "aeSI", "aeBI"]);
        assert_eq!(first_uint(&document, "aeSI"), Ok(Some(7)));
        assert_eq!(first_uint(&document, "none"), Ok(None));
    }

    #[test]
    fn reads_eight_byte_integers_and_rejects_other_widths() {
        let document = tag(b"mupd", &tag(b"musr", &9_u64.to_be_bytes()));
        assert_eq!(first_uint(&document, "musr"), Ok(Some(9)));
        let bad = tag(b"mlog", &tag(b"mlid", &[1, 2, 3]));
        assert!(matches!(
            first_uint(&bad, "mlid"),
            Err(DmapError::IntegerLength { length: 3, .. })
        ));
    }

    #[test]
    fn rejects_truncated_invalid_and_deep_documents() {
        let overflow = walk(b"adbs\x00\x00\x00\x10short", &mut |_, _| Ok(()));
        assert!(
            overflow
                .expect_err("overflow")
                .to_string()
                .contains("exceeds remaining response length")
        );
        assert_eq!(
            walk(b"adbs\0\0", &mut |_, _| Ok(())),
            Err(DmapError::TruncatedHeader(0))
        );
        assert_eq!(
            walk(b"\x01bcd\0\0\0\0", &mut |_, _| Ok(())),
            Err(DmapError::InvalidTag(0))
        );
        let deep = (0..=MAX_DEPTH + 1).fold(Vec::new(), |inner, _| tag(b"mlit", &inner));
        assert_eq!(walk(&deep, &mut |_, _| Ok(())), Err(DmapError::TooDeep));
        assert_eq!(walk(&[], &mut |_, _| Ok(())), Ok(()));
    }
}

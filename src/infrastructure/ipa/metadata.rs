//! `iTunesMetadata.plist` serialization helpers.

use crate::domain::entity::DownloadMetadata;
use crate::infrastructure::http::plist_codec::encode_plist;

/// Build an `iTunesMetadata.plist` XML blob from metadata.
pub(super) fn build_itunes_metadata_plist(
    metadata: &DownloadMetadata,
) -> Result<Vec<u8>, plist::Error> {
    encode_plist(&serde_json::Value::Object(metadata.clone()))
}

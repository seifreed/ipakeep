//! HTTP infrastructure — Apple API client and plist codec.

pub mod client;
pub mod plist_codec;

pub use client::AppleHttpClient;
pub use plist_codec::{build_plist_dict, decode_plist, encode_plist};

//! Model Context Protocol server transport.
//!
//! A minimal, hand-rolled JSON-RPC 2.0 server spoken over stdio. It depends
//! only on `serde_json` and `tokio`, both already in the dependency tree, and
//! exposes a [`ToolInvoker`] port so the presentation layer can wire concrete
//! tools without the transport knowing anything about the App Store.

pub mod protocol;
pub mod server;

pub use protocol::{CallToolResult, Implementation, ListToolsResult, ToolContent, ToolDefinition};
pub use server::{ToolInvoker, serve};

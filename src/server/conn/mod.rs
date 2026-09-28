//! Connection utilities.

#[cfg(any(feature = "http1", feature = "http2"))]
pub mod auto;

#[cfg(feature = "http3")]
pub mod http3;

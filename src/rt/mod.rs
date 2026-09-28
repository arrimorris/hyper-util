//! Runtime utilities

#[cfg(feature = "tracing")]
pub mod tracing;
#[cfg(feature = "tracing")]
pub use self::tracing::{CurrentSpanExecutor, MkSpanExecutor, WithSpanExecutor};

#[cfg(feature = "client-legacy")]
mod io;
#[cfg(feature = "client-legacy")]
pub(crate) use self::io::{read, write_all};

#[cfg(feature = "http3")]
pub mod quic;

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "tokio")]
pub use self::tokio::{TokioExecutor, TokioIo, TokioTimer};

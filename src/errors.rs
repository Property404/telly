#![warn(missing_docs)]
//! Error and result types for Telly.
use std::io;
use thiserror::Error;

/// Error type used in this crate.
#[derive(Error, Debug)]
pub enum TellyError {
    /// IO error wrapper.
    #[error("IoError")]
    IoError(#[from] io::Error),
    /// Not all bytes were written in a call to [write()](std::io::Write::write).
    #[error("Failed to write all bytes")]
    DidNotWriteAllBytes,
}

/// Result type used in this crate.
pub type TellyResult<T = ()> = Result<T, TellyError>;

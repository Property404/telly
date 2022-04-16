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
    /// Decoded bad Telnet Data.
    #[error("Bad telnet data: {0}")]
    DecodeError(String),
    /// Invalid conversion.
    #[error("Invalid variant: {0}")]
    ConversionError(String),
}

/// Result type used in this crate.
pub type TellyResult<T = ()> = Result<T, TellyError>;

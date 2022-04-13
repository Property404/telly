//! A Telnet parsing library.
#![warn(missing_docs)]
pub mod errors;
pub mod utils;

mod stream;
mod telnet;

pub use stream::TelnetStream;
pub use telnet::{
    TelnetCommand, TelnetEvent, TelnetOption, TelnetParser, TelnetSubnegotiation,
    UnparsedTelnetSubnegotiation,
};

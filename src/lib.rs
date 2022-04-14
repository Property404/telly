//! A Telnet parsing library.
#![warn(missing_docs)]
pub mod errors;
pub mod utils;

mod commands;
mod constants;
mod stream;
mod telnet;

pub use commands::TelnetCommand;
pub use stream::TelnetStream;
pub use telnet::{
    TelnetAction, TelnetEvent, TelnetOption, TelnetParser, TelnetSubnegotiation,
    UnparsedTelnetSubnegotiation,
};

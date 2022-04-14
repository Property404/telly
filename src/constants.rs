/// Used in some response subnegotiations
pub const IS: u8 = 0x00;
/// Used in some request subnegotiations
pub const SEND: u8 = 0x01;
/// End of subnegotiation parameters
pub const SE: u8 = 0xf0;
/// Indicates that what follows is subnegotiation of the indicated option.
pub const SB: u8 = 0xfa;
/// Indicates the want to begin performing, or confirmation that you are now performing, the indicated option.
pub const WILL: u8 = 0xfb;
/// Indicates the refusal to perform, or continue performing, the indicated option.
pub const WONT: u8 = 0xfc;
/// Indicates the request that the other party perform, or confirmation that you are expecting the other party to perform, the indicated option.
pub const DO: u8 = 0xfd;
/// Indicates the demand that the other party stop performing, or confirmation that you are no longer expecting the other party to perform, the indicated option.
pub const DONT: u8 = 0xfe;
/// Interpret As Command - precedes all Telnet commands. Is sent twice to signify a literal
/// 0xff.
pub const IAC: u8 = 0xff;

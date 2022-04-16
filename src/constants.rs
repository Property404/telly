/// Used in some response subnegotiations
pub const IS: u8 = 0x00;
/// Used in some request subnegotiations
pub const SEND: u8 = 0x01;
/// End of subnegotiation parameters
pub const SE: u8 = 0xf0;
/// Indicates that what follows is subnegotiation of the indicated option.
pub const SB: u8 = 0xfa;
/// Interpret As Command - precedes all Telnet commands. Is sent twice to signify a literal
/// 0xff.
pub const IAC: u8 = 0xff;

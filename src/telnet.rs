use crate::{
    constants,
    errors::{TellyError, TellyResult},
    utils::TellyIterTraits,
    TelnetCommand,
};
use bytes::{Buf, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[derive(FromPrimitive, PartialEq, Debug, Clone, Copy)]
/// Options that follow WILL, DO, DONT, WONT, and SB. These are defined across multiple RFCs.
pub enum TelnetOption {
    /// [RFC856](https://www.rfc-editor.org/rfc/rfc856.html)
    BinaryTransmission = 0,
    /// [RFC857](https://www.rfc-editor.org/rfc/rfc857.html)
    Echo = 1,
    /// NIC15391 of 1973
    Reconnection = 2,
    /// [RFC858](https://www.rfc-editor.org/rfc/rfc858.html)
    SuppressGoAhead = 3,
    /// NIC15393 of 1973
    ApproxMessageSizeNegotiation = 4,
    /// [RFC859](https://www.rfc-editor.org/rfc/rfc859.html)
    Status = 5,
    /// [RFC860](https://www.rfc-editor.org/rfc/rfc860.html)
    TimingMark = 6,
    /// [RFC727](https://www.rfc-editor.org/rfc/rfc727.html)
    Logout = 18,
    /// [RFC1091](https://www.rfc-editor.org/rfc/rfc1091.html)
    TerminalType = 24,
    /// [RFC1073](https://www.rfc-editor.org/rfc/rfc1073.html)
    NegotiateAboutWindowSize = 31,
    /// [RFC1184](https://www.rfc-editor.org/rfc/rfc1184.html)
    LineMode = 34,
    /// Unknown Telnet option.
    Unknown = 0xfe,
}

impl From<TelnetOption> for u8 {
    fn from(option: TelnetOption) -> u8 {
        option as u8
    }
}
impl From<u8> for TelnetOption {
    fn from(byte: u8) -> Self {
        match Self::from_u8(byte) {
            Some(val) => val,
            None => Self::Unknown,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
/// Represents an event sent over, or to be sent over, Telnet.
pub enum TelnetEvent {
    /// A Telnet command.
    Command(TelnetCommand),
    /// A Telnet request/demand/ack/nack like WILL <option>, DONT <option>, WONT <option>, or DO
    /// <option>
    Negotiation(TelnetNegotiation),
    /// A subnegotiation, defined by one of many RFC's. This contains arbitrary data.
    Subnegotiation(UnparsedTelnetSubnegotiation),
    /// ASCII(generally). This is not NVT encoded.
    Data(Vec<u8>),
}

impl TelnetEvent {
    /// Construct a "do" negotiation from an option.
    pub const fn r#do(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation(TelnetNegotiation::Do(option))
    }

    /// Construct a "dont" negotiation from an option.
    pub const fn dont(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation(TelnetNegotiation::Dont(option))
    }

    /// Construct a "will" negotiation from an option.
    pub const fn will(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation(TelnetNegotiation::Will(option))
    }

    /// Construct a "wont" negotiation from an option.
    pub const fn wont(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation(TelnetNegotiation::Wont(option))
    }

    /// Transform into bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            TelnetEvent::Data(data) => data.into_iter().unix_to_nvt().collect(),
            TelnetEvent::Command(command) => {
                vec![constants::IAC, command.into()]
            }
            TelnetEvent::Negotiation(negotiation) => {
                // Does option need to be escaped if 0xFF??
                // RFC seems not so clear about that
                vec![
                    constants::IAC,
                    negotiation.command(),
                    negotiation.option().into(),
                ]
            }
            TelnetEvent::Subnegotiation(subnegotiation) => subnegotiation.into_bytes(),
        }
    }
}

impl From<TelnetSubnegotiation> for TelnetEvent {
    fn from(other: TelnetSubnegotiation) -> Self {
        Self::Subnegotiation(other.into())
    }
}
impl From<TelnetNegotiation> for TelnetEvent {
    fn from(other: TelnetNegotiation) -> Self {
        Self::Negotiation(other)
    }
}

impl From<TelnetCommand> for TelnetEvent {
    fn from(other: TelnetCommand) -> Self {
        Self::Command(other)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TelnetNegotiation {
    Will(TelnetOption),
    Wont(TelnetOption),
    Do(TelnetOption),
    Dont(TelnetOption),
}

impl TelnetNegotiation {
    const fn option(&self) -> TelnetOption {
        match self {
            Self::Will(option) | Self::Wont(option) | Self::Do(option) | Self::Dont(option) => {
                *option
            }
        }
    }

    const fn command(&self) -> u8 {
        match self {
            Self::Will(_) => constants::WILL,
            Self::Wont(_) => constants::WONT,
            Self::Dont(_) => constants::DONT,
            Self::Do(_) => constants::DO,
        }
    }
}

/// A yet-to-be-parsed Telnet subnegotiation.
///
/// # Example
/// ```
/// use telly::{UnparsedTelnetSubnegotiation, TelnetSubnegotiation};
///
/// let parsed = TelnetSubnegotiation::NegotiateAboutWindowSize {
///     width: 55,
///     height: 20
/// };
/// let deparsed = UnparsedTelnetSubnegotiation::from(parsed.clone());
///
/// assert_eq!(parsed, deparsed.try_into().unwrap());
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct UnparsedTelnetSubnegotiation {
    /// The [TelnetOption] this subnegotiation is associated with.
    pub option: TelnetOption,
    /// The unparsed inner bytes of the subnegotiation.
    pub bytes: Vec<u8>,
}
impl From<TelnetSubnegotiation> for UnparsedTelnetSubnegotiation {
    fn from(other: TelnetSubnegotiation) -> Self {
        let (option, bytes) = other.option_bytes();
        Self { option, bytes }
    }
}

impl UnparsedTelnetSubnegotiation {
    const fn new(option: TelnetOption, bytes: Vec<u8>) -> Self {
        Self { option, bytes }
    }
    fn into_bytes(self) -> Vec<u8> {
        [constants::IAC, constants::SB, self.option.into()]
            .into_iter()
            .chain(self.bytes.into_iter().escape_iacs())
            .chain([constants::IAC, constants::SE])
            .collect()
    }
}

/// A parsed subnegotiation event.
#[derive(PartialEq, Debug, Clone)]
pub enum TelnetSubnegotiation {
    /// Parsed NAWS subnegotiation. See [RFC1073](https://datatracker.ietf.org/doc/html/rfc1073)
    /// for details.
    NegotiateAboutWindowSize {
        /// The width of the window in characters.
        width: u16,
        /// The height of the window in characters.
        height: u16,
    },
    /// Parsed terminal-type request subnegotiation. The other end should send a
    /// [TelnetSubnegotiation::TerminalTypeResponse] in response. See
    /// [RFC1091](https://www.rfc-editor.org/rfc/rfc1091.html) for details.
    TerminalTypeRequest,
    /// Parsed terminal-type response subnegotiation. Contains the name of the terminal as a string. E.g.
    /// "XTERM-256COLOR". See [RFC1091](https://www.rfc-editor.org/rfc/rfc1091.html) for details.
    TerminalTypeResponse(String),
    /// A subnegotiation for which Telly has not implemented parsing. But fear not, for you can
    /// parse it yourself!
    Other {
        /// The [TelnetOption] this subnegotiation is associated with.
        option: TelnetOption,
        /// The unparsed inner bytes of the subnegotiation.
        bytes: Vec<u8>,
    },
}

impl TryFrom<UnparsedTelnetSubnegotiation> for TelnetSubnegotiation {
    type Error = TellyError;
    fn try_from(other: UnparsedTelnetSubnegotiation) -> TellyResult<Self> {
        let bytes = other.bytes;
        let option = other.option;
        match option {
            TelnetOption::NegotiateAboutWindowSize => {
                if bytes.len() != 4 {
                    return Err(TellyError::DecodeError(
                        "Incorrect number of bytes for NAWS subnegotiation".into(),
                    ));
                }

                let width: u16 = ((bytes[0] as u16) << 8) + (bytes[1] as u16);
                let height: u16 = ((bytes[2] as u16) << 8) + (bytes[3] as u16);

                Ok(Self::NegotiateAboutWindowSize { width, height })
            }
            TelnetOption::TerminalType => {
                if !bytes.is_empty() && bytes[0] == constants::SEND {
                    return Ok(TelnetSubnegotiation::TerminalTypeRequest);
                } else if bytes.is_empty() || bytes[0] != constants::IS {
                    return Err(TellyError::DecodeError(
                        "Expected IS or SEND in terminal-type subnegotiation".into(),
                    ));
                };

                let term_name = String::from_utf8_lossy(&bytes[1..]).to_string();

                Ok(Self::TerminalTypeResponse(term_name))
            }
            _ => Ok(Self::Other { option, bytes }),
        }
    }
}

impl TelnetSubnegotiation {
    fn option_bytes(self) -> (TelnetOption, Vec<u8>) {
        let (option, bytes) = match self {
            Self::Other { option, bytes } => (option, bytes),
            Self::NegotiateAboutWindowSize { width, height } => (
                TelnetOption::NegotiateAboutWindowSize,
                vec![
                    (width >> 8) as u8,
                    (width & 0xFF) as u8,
                    (height >> 8) as u8,
                    (height & 0xFF) as u8,
                ],
            ),
            Self::TerminalTypeRequest => (TelnetOption::TerminalType, vec![constants::SEND]),
            Self::TerminalTypeResponse(term_name) => (TelnetOption::TerminalType, {
                let mut vec = vec![constants::IS];
                vec.extend(term_name.as_bytes());
                vec
            }),
        };

        (option, bytes)
    }
}

/// Stateless Telnet parser.
pub struct TelnetParser {
    // Translate from NVT?
    translate: bool,
}

impl Default for TelnetParser {
    fn default() -> Self {
        Self { translate: true }
    }
}
impl TelnetParser {
    /// Pull next event out of a BytesMut, if available.
    pub fn next_event(&self, rx_buffer: &mut BytesMut) -> Option<TelnetEvent> {
        let mut event_type = EventType::Null;
        let mut data_buffer = Vec::new();
        let mut command = None;
        let mut option = None;
        let mut advancement = 0;
        let mut result = None;
        let mut iac = false;

        #[derive(PartialEq)]
        enum EventType {
            Null,
            Data,
            Negotiation,
            Subnegotiation,
        }

        for byte in rx_buffer.iter() {
            advancement += 1;

            let byte = *byte;
            if byte == constants::IAC {
                if iac {
                    iac = false;
                } else {
                    iac = true;
                    continue;
                }
            }

            match event_type {
                EventType::Null => {
                    if iac {
                        command = Some(byte);
                        let command = command.expect("Bug: No Command");
                        if [
                            constants::WILL,
                            constants::WONT,
                            constants::DO,
                            constants::DONT,
                        ]
                        .contains(&command)
                        {
                            event_type = EventType::Negotiation;
                        } else if command == constants::SB {
                            event_type = EventType::Subnegotiation;
                        } else {
                            result = Some(TelnetEvent::Command(TelnetCommand::from(command as u8)));
                            break;
                        }
                    } else {
                        event_type = EventType::Data;
                        data_buffer.push(byte);
                        if advancement == rx_buffer.len() {
                            result = Some(TelnetEvent::Data(data_buffer));
                            break;
                        }
                    }
                }
                EventType::Negotiation => {
                    let option = TelnetOption::from(byte);
                    let command = command.expect("Bug: telnet command is None");
                    result = Some(
                        match command {
                            constants::WILL => TelnetNegotiation::Will(option),
                            constants::WONT => TelnetNegotiation::Wont(option),
                            constants::DONT => TelnetNegotiation::Dont(option),
                            constants::DO => TelnetNegotiation::Do(option),
                            _ => unreachable!("Command isn't Will/Do/Won't/Don't!"),
                        }
                        .into(),
                    );
                    break;
                }
                EventType::Subnegotiation => {
                    if let Some(option) = option {
                        if iac && byte == constants::SE {
                            result = Some(TelnetEvent::Subnegotiation(
                                UnparsedTelnetSubnegotiation::new(option, data_buffer),
                            ));
                            break;
                        } else {
                            data_buffer.push(byte);
                        }
                    } else {
                        option = Some(TelnetOption::from(byte));
                    }
                }
                EventType::Data => {
                    // Don't push commands
                    if !iac {
                        // Escape NVT nonsense
                        if !(byte == 0 && self.translate) {
                            data_buffer.push(byte);
                        }
                    } else {
                        advancement -= 2;
                    }

                    if iac || advancement == rx_buffer.len() {
                        result = Some(TelnetEvent::Data(data_buffer));
                        break;
                    }
                }
            }

            iac = false
        }

        if result.is_some() {
            rx_buffer.advance(advancement);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let test_vectors = vec![
            (
                vec![0xDE, 0xAD, 0xBE, 0xEF, 8],
                vec![TelnetEvent::Data(vec![0xDE, 0xAD, 0xBE, 0xEF, 8])],
            ),
            (
                vec![
                    constants::IAC,
                    constants::WILL,
                    TelnetOption::LineMode.into(),
                    0x42,
                ],
                vec![
                    TelnetEvent::Negotiation(TelnetNegotiation::Will(TelnetOption::LineMode)),
                    TelnetEvent::Data(vec![0x42]),
                ],
            ),
            (vec![constants::IAC, constants::WILL], vec![]),
            (vec![], vec![]),
            (vec![constants::IAC], vec![]),
            (
                vec![constants::IAC, constants::IAC],
                vec![TelnetEvent::Data(vec![0xff])],
            ),
            (
                vec![
                    constants::IAC,
                    constants::SB,
                    TelnetOption::NegotiateAboutWindowSize.into(),
                    0x00,
                    0xCA,
                    0x00,
                    0xFE,
                    constants::IAC,
                    constants::SE,
                ],
                vec![TelnetEvent::Subnegotiation(
                    TelnetSubnegotiation::NegotiateAboutWindowSize {
                        width: 0xCA,
                        height: 0xFE,
                    }
                    .into(),
                )],
            ),
        ];

        let parser = TelnetParser::default();
        for tv in test_vectors {
            let mut bytes = BytesMut::from(&tv.0[0..tv.0.len()]);
            for expected_event in tv.1 {
                let actual_event = parser.next_event(&mut bytes);
                assert_eq!(actual_event, Some(expected_event));
            }
            assert_eq!(parser.next_event(&mut bytes), None);
        }
    }
}

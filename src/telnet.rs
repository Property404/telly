use crate::{
    errors::{TellyError, TellyResult},
    utils::TellyIterTraits,
};
use bytes::{Buf, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

// Constants used in some Telnet subnegotiations.
const IS: u8 = 0x00;
const SEND: u8 = 0x01;

#[derive(FromPrimitive, PartialEq, Debug, Clone, Copy)]
/// Telnet commands listed in [RFC854](https://www.rfc-editor.org/rfc/rfc854).
pub enum TelnetCommand {
    /// End of subnegotiation parameters
    SE = 0xf0,
    /// No operation.
    NOP = 0xf1,
    /// The data stream portion of a Synch. This should always be accompanied by a TCP Urgent
    /// notification.
    DataMark = 0xf2,
    /// NVT character BRK.
    Break = 0xf3,
    /// Suspend, interrupt, abort or terminate the process to which the NVT is connected. Also,
    /// part of the out-of-band signal for other protocols which use Telnet
    InterruptProcess = 0xf4,
    /// Allow the current process to (appear to) run to completion, but do not send its output to
    /// the user. Also, send a Synch to the user.
    AbortOutput = 0xf5,
    /// It's me, Margaret. Tell the receive to send back to the NVT some visible (i.e., printable)
    /// evidence that the AYT was received. This function may be invoked by the user when the
    /// system is unexpectedly "silent" for a long time, because of the unanticipated (by the user)
    /// length of a computation, an unusually heavy system load, etc. AYT is the standard
    /// representation for invoking this function.
    AreYouThere = 0xf6,
    /// Inform the recipient that they should delete the last preceding undeleted character or
    /// "print position" from the data stream.
    EraseCharacter = 0xf7,
    /// Inform the recipient that they should delete characters from the data stream back to, but
    /// not including, the last "CR LF" sequence sent over the Telnet connection.
    EraseLine = 0xf8,
    /// The GA signal.
    GoAhead = 0xf9,
    /// Indicates that what follows is subnegotiation of the indicated option.
    SB = 0xfa,
    /// Indicates the want to begin performing, or confirmation that you are now performing, the indicated option.
    Will = 0xfb,
    /// Indicates the refusal to perform, or continue performing, the indicated option.
    Wont = 0xfc,
    /// Indicates the request that the other party perform, or confirmation that you are expecting the other party to perform, the indicated option.
    Do = 0xfd,
    /// Indicates the demand that the other party stop performing, or confirmation that you are no longer expecting the other party to perform, the indicated option.
    Dont = 0xfe,
    /// Interpret As Command - precedes all Telnet commands. Is sent twice to signify a literal
    /// 0xff.
    IAC = 0xff,

    /// Unknown Telnet command.
    Unknown = 0x00,
}

impl From<TelnetCommand> for u8 {
    fn from(command: TelnetCommand) -> u8 {
        command as u8
    }
}

impl From<u8> for TelnetCommand {
    fn from(byte: u8) -> Self {
        match Self::from_u8(byte) {
            Some(val) => val,
            None => Self::Unknown,
        }
    }
}

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
    Negotiation {
        /// The command.
        command: TelnetCommand,
        /// The option to request/demand/acknowledge/negative-acknowledge
        option: TelnetOption,
    },
    /// A subnegotiation, defined by one of many RFC's. This contains arbitrary data.
    Subnegotiation(UnparsedTelnetSubnegotiation),
    /// ASCII(generally). This is not NVT encoded.
    Data(Vec<u8>),
}

impl TelnetEvent {
    /// Construct a "do" negotiation from an option.
    pub const fn r#do(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::Do,
            option,
        }
    }

    /// Construct a "dont" negotiation from an option.
    pub const fn dont(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::Dont,
            option,
        }
    }

    /// Construct a "will" negotiation from an option.
    pub const fn will(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::Will,
            option,
        }
    }

    /// Construct a "wont" negotiation from an option.
    pub const fn wont(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::Wont,
            option,
        }
    }

    /// Transform into bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            TelnetEvent::Data(data) => data.into_iter().unix_to_nvt().collect(),
            TelnetEvent::Command(command) => {
                vec![TelnetCommand::IAC.into(), command.into()]
            }
            TelnetEvent::Negotiation { command, option } => {
                // Does option need to be escaped if 0xFF??
                // RFC seems not so clear about that
                vec![TelnetCommand::IAC.into(), command.into(), option.into()]
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
        [
            TelnetCommand::IAC.into(),
            TelnetCommand::SB.into(),
            self.option.into(),
        ]
        .into_iter()
        .chain(self.bytes.into_iter().escape_iacs())
        .chain([TelnetCommand::IAC.into(), TelnetCommand::SE.into()])
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
                if !bytes.is_empty() && bytes[0] == SEND {
                    return Ok(TelnetSubnegotiation::TerminalTypeRequest);
                } else if bytes.is_empty() || bytes[0] != IS {
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
            Self::TerminalTypeRequest => (TelnetOption::TerminalType, vec![SEND]),
            Self::TerminalTypeResponse(term_name) => (TelnetOption::TerminalType, {
                let mut vec = vec![IS];
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
            if byte == TelnetCommand::IAC.into() {
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
                        command = Some(TelnetCommand::from(byte));
                        let command = command.expect("Bug: No Command");
                        if [
                            TelnetCommand::Will,
                            TelnetCommand::Wont,
                            TelnetCommand::Do,
                            TelnetCommand::Dont,
                        ]
                        .contains(&command)
                        {
                            event_type = EventType::Negotiation;
                        } else if command == TelnetCommand::SB {
                            event_type = EventType::Subnegotiation;
                        } else {
                            result = Some(TelnetEvent::Command(command));
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
                    result = Some(TelnetEvent::Negotiation {
                        command: command.expect("Bug: telnet command None"),
                        option: TelnetOption::from(byte),
                    });
                    break;
                }
                EventType::Subnegotiation => {
                    if let Some(option) = option {
                        if iac && byte == TelnetCommand::SE.into() {
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
                    TelnetCommand::IAC.into(),
                    TelnetCommand::Will.into(),
                    TelnetOption::LineMode.into(),
                    0x42,
                ],
                vec![
                    TelnetEvent::Negotiation {
                        command: TelnetCommand::Will,
                        option: TelnetOption::LineMode,
                    },
                    TelnetEvent::Data(vec![0x42]),
                ],
            ),
            (
                vec![TelnetCommand::IAC.into(), TelnetCommand::Will.into()],
                vec![],
            ),
            (vec![], vec![]),
            (vec![TelnetCommand::IAC.into()], vec![]),
            (
                vec![TelnetCommand::IAC.into(), TelnetCommand::IAC.into()],
                vec![TelnetEvent::Data(vec![0xff])],
            ),
            (
                vec![
                    TelnetCommand::IAC.into(),
                    TelnetCommand::SB.into(),
                    TelnetOption::NegotiateAboutWindowSize.into(),
                    0x00,
                    0xCA,
                    0x00,
                    0xFE,
                    TelnetCommand::IAC.into(),
                    TelnetCommand::SE.into(),
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

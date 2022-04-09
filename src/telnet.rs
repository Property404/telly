use crate::utils::TellyIterTraits;
use bytes::{Buf, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[derive(FromPrimitive, PartialEq, Debug, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum TelnetCommand {
    /// End of subnegotiation parameters
    SE = 0xf0,
    /// No operation.
    NOP = 0xf1,
    /// The data stream portion of a Synch. This should always be accompanied by a TCP Urgent notification.
    DataMark = 0xf2,
    /// NVT character BRK.
    Break = 0xf3,
    /// The function IP.
    InterruptProcess = 0xf4,
    /// The function AO.
    AbortOutput = 0xf5,
    /// It's me, Margaret.
    AreYouThere = 0xf6,
    /// The function EC.
    EraseCharacter = 0xf7,
    /// The function EL.
    EraseLine = 0xf8,
    /// The GA signal.
    GoAhead = 0xf9,
    /// Indicates that what follows is subnegotiation of the indicated option.
    SB = 0xfa,
    /// Indicates the want to begin performing, or confirmation that you are now performing, the indicated option.
    WILL = 0xfb,
    /// Indicates the refusal to perform, or continue performing, the indicated option.
    WONT = 0xfc,
    /// Indicates the request that the other party perform, or confirmation that you are expecting the other party to perform, the indicated option.
    DO = 0xfd,
    /// Indicates the demand that the other party stop performing, or confirmation that you are no longer expecting the other party to perform, the indicated option.
    DONT = 0xfe,
    /// Interpret As Command - precedes Telnet commands. Is sent twice to signify a literal 0xff.
    IAC = 0xff,

    /// Unknown Telnet command.
    UNKNOWN = 0x00,
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
            None => Self::UNKNOWN,
        }
    }
}

#[derive(FromPrimitive, PartialEq, Debug, Clone, Copy)]
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
    /// [RFC1091](https://www.rfc-editor.org/rfc/rfc1091.html)
    TerminalType = 24,
    /// [RFC1073](https://www.rfc-editor.org/rfc/rfc1073.html)
    NegotiateAboutWindowSize = 31,
    /// [RFC1184](https://www.rfc-editor.org/rfc/rfc1184.html)
    LineMode = 34,
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
pub enum TelnetEvent {
    Command(TelnetCommand),

    Negotiation {
        command: TelnetCommand,
        option: TelnetOption,
    },

    SubNegotiation {
        option: TelnetOption,
        bytes: Vec<u8>,
    },

    Data(Vec<u8>),
}

impl TelnetEvent {
    /// Construct a "do" negotiation from an option.
    pub const fn r#do(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::DO,
            option,
        }
    }

    /// Construct a "dont" negotiation from an option.
    pub const fn dont(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::DONT,
            option,
        }
    }

    /// Construct a "will" negotiation from an option.
    pub const fn will(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::WILL,
            option,
        }
    }

    /// Construct a "wont" negotiation from an option.
    pub const fn wont(option: TelnetOption) -> Self {
        TelnetEvent::Negotiation {
            command: TelnetCommand::WONT,
            option,
        }
    }

    /// Transform into bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            TelnetEvent::Data(data) => data.into_iter().escape_iacs().collect(),
            TelnetEvent::Command(command) => {
                vec![TelnetCommand::IAC.into(), command.into()]
            }
            TelnetEvent::Negotiation { command, option } => {
                // Does option need to be escaped if 0xFF??
                // RFC seems not so clear about that
                vec![TelnetCommand::IAC.into(), command.into(), option.into()]
            }
            TelnetEvent::SubNegotiation { option, bytes } => {
                let mut vec = vec![
                    TelnetCommand::IAC.into(),
                    TelnetCommand::SB.into(),
                    option.into(),
                ];
                vec.extend(bytes.into_iter().escape_iacs().collect::<Vec<_>>());
                vec.extend(&[TelnetCommand::IAC.into(), TelnetCommand::SE.into()]);
                vec
            }
        }
    }
}

/// Stateless telnet parser.
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
    /// Get next event from a BytesMut.
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
            SubNegotiation,
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
                            TelnetCommand::WILL,
                            TelnetCommand::WONT,
                            TelnetCommand::DO,
                            TelnetCommand::DONT,
                        ]
                        .contains(&command)
                        {
                            event_type = EventType::Negotiation;
                        } else if command == TelnetCommand::SB {
                            event_type = EventType::SubNegotiation;
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
                EventType::SubNegotiation => {
                    if let Some(option) = option {
                        if iac && byte == TelnetCommand::SE.into() {
                            result = Some(TelnetEvent::SubNegotiation {
                                option,
                                bytes: data_buffer,
                            });
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
                    TelnetCommand::WILL.into(),
                    TelnetOption::LineMode.into(),
                    0x42,
                ],
                vec![
                    TelnetEvent::Negotiation {
                        command: TelnetCommand::WILL,
                        option: TelnetOption::LineMode,
                    },
                    TelnetEvent::Data(vec![0x42]),
                ],
            ),
            (
                vec![TelnetCommand::IAC.into(), TelnetCommand::WILL.into()],
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
                    0xCA,
                    0xFE,
                    TelnetCommand::IAC.into(),
                    TelnetCommand::SE.into(),
                ],
                vec![TelnetEvent::SubNegotiation {
                    option: TelnetOption::NegotiateAboutWindowSize,
                    bytes: vec![0xCA, 0xFE],
                }],
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

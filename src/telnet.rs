use crate::errors::{TellyError, TellyResult};
use bytes::{Buf, BufMut, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::{
    io::{Read, Write},
    iter::Iterator,
};

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

pub struct TelnetStream<StreamType>
where
    StreamType: Write + Read,
{
    // Underlying stream
    stream: StreamType,
    // Bytes read from stream, waiting to be processed
    rx_buffer: BytesMut,

    // OPTIONS:
    // Translate from NVT?
    translate: bool,
}

impl<StreamType: Write + Read> TelnetStream<StreamType> {
    /// Construct a TelnetStream from, e.g., a TcpStream
    pub fn from_stream(stream: StreamType) -> Self {
        const CAPACITY: usize = 32;
        Self {
            stream,
            rx_buffer: BytesMut::with_capacity(CAPACITY),
            translate: true,
        }
    }

    /// Send a TelnetEvent to remote
    pub fn send_event(&mut self, event: TelnetEvent) -> TellyResult {
        match event {
            TelnetEvent::Data(data) => {
                self.send_bytes(&data)?;
            }
            TelnetEvent::Command(command) => {
                self.send_raw_bytes(&[TelnetCommand::IAC.into(), command.into()])?;
            }
            TelnetEvent::Negotiation { command, option } => {
                // Does option need to be escaped if 0xFF??
                // RFC seems not so clear about that
                self.send_raw_bytes(&[TelnetCommand::IAC.into(), command.into(), option.into()])?;
            }
            TelnetEvent::SubNegotiation { option, bytes } => {
                self.send_raw_bytes(&[
                    TelnetCommand::IAC.into(),
                    TelnetCommand::SB.into(),
                    option.into(),
                ])?;
                self.send_bytes(&bytes)?;
                self.send_raw_bytes(&[TelnetCommand::IAC.into(), TelnetCommand::SE.into()])?;
            }
        }
        self.stream.flush()?;
        Ok(())
    }

    /// Convenience function to send a WILL negotiation event
    pub fn send_will(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::Negotiation {
            command: TelnetCommand::WILL,
            option,
        })
    }

    /// Convenience function to send a DO negotiation event
    pub fn send_do(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::Negotiation {
            command: TelnetCommand::DO,
            option,
        })
    }

    /// Convenience function to send a WONT negotiation event
    pub fn send_wont(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::Negotiation {
            command: TelnetCommand::WONT,
            option,
        })
    }

    /// Convenience function to send a DONT negotiation event
    pub fn send_dont(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::Negotiation {
            command: TelnetCommand::DONT,
            option,
        })
    }

    /// Convenience function to send ASCII data to remote.
    pub fn send_data(&mut self, data: &[u8]) -> TellyResult {
        self.send_bytes(data)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Convenience function to send ASCII data to remote.
    pub fn send_str(&mut self, data: &str) -> TellyResult {
        self.send_bytes(data.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> TellyResult {
        for byte in bytes.iter().copied() {
            if byte == TelnetCommand::IAC.into() {
                self.send_raw_bytes(&[TelnetCommand::IAC.into()])?;
            }

            self.send_raw_bytes(bytes)?;
        }

        Ok(())
    }

    fn send_raw_bytes(&mut self, bytes: &[u8]) -> TellyResult {
        if self.stream.write(bytes)? != bytes.len() {
            return Err(TellyError::DidNotWriteAllBytes);
        }
        Ok(())
    }

    fn next_event(&mut self) -> Option<TelnetEvent> {
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

        for byte in &self.rx_buffer {
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
                        if advancement == self.rx_buffer.len() {
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
                        if !(self.translate && byte == 0) {
                            data_buffer.push(byte);
                        }
                    } else {
                        advancement -= 2;
                    }

                    if iac || advancement == self.rx_buffer.len() {
                        result = Some(TelnetEvent::Data(data_buffer));
                        break;
                    }
                }
            }

            iac = false
        }

        if result.is_some() {
            self.rx_buffer.advance(advancement);
        }

        result
    }
}

impl<T: Write + Read> Iterator for TelnetStream<T> {
    type Item = TelnetEvent;

    fn next(&mut self) -> Option<Self::Item> {
        const BUFFER_SIZE: usize = 16;
        let mut vec: Vec<u8> = vec![0; BUFFER_SIZE];

        if let Some(event) = self.next_event() {
            return Some(event);
        }

        loop {
            let bytes_read = self.stream.read(&mut vec).expect("fuck");
            self.rx_buffer.put(&vec[0..bytes_read]);

            if let Some(event) = self.next_event() {
                return Some(event);
            } else if bytes_read == 0 {
                println!("next> End of stream!");
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, io::Result};

    #[derive(Default)]
    struct MockStream {
        buffer: VecDeque<u8>,
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if buf.len() == 0 {
                panic!("Cannot read into empty buffer");
            }
            for i in 0..buf.len() {
                if self.buffer.is_empty() {
                    return Ok(i);
                }
                buf[i] = self.buffer.pop_front().unwrap();
            }
            Ok(buf.len())
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            for byte in buf {
                self.buffer.push_back(*byte);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

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

        for tv in test_vectors {
            let mut stream = MockStream::default();
            assert!(tv.0.len() == stream.write(&tv.0).unwrap());
            let mut stream = TelnetStream::from_stream(stream);
            for expected_event in tv.1 {
                assert_eq!(stream.next(), Some(expected_event));
            }
            assert_eq!(stream.next(), None);
        }
    }
}

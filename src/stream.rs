use crate::{
    errors::{TellyError, TellyResult},
    TelnetCommand, TelnetEvent, TelnetOption, TelnetParser,
};
use bytes::{BufMut, BytesMut};
use std::{
    io::{Read, Write},
    iter::Iterator,
};

pub struct TelnetStream<StreamType>
where
    StreamType: Write + Read,
{
    // Underlying stream
    stream: StreamType,
    // Bytes read from stream, waiting to be processed
    rx_buffer: BytesMut,

    parser: TelnetParser,
}

impl<StreamType: Write + Read> TelnetStream<StreamType> {
    /// Construct a TelnetStream from, e.g., a TcpStream
    pub fn from_stream(stream: StreamType) -> Self {
        const CAPACITY: usize = 32;
        Self {
            stream,
            rx_buffer: BytesMut::with_capacity(CAPACITY),
            parser: TelnetParser::default(),
        }
    }

    /// Send a TelnetEvent to remote
    pub fn send_event(&mut self, event: TelnetEvent) -> TellyResult {
        let bytes = event.into_bytes();
        self.send_bytes(&bytes)
    }

    /// Convenience function to send a WILL negotiation event
    pub fn send_will(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::will(option))
    }

    /// Convenience function to send a DO negotiation event
    pub fn send_do(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::r#do(option))
    }

    /// Convenience function to send a WONT negotiation event
    pub fn send_wont(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::wont(option))
    }

    /// Convenience function to send a DONT negotiation event
    pub fn send_dont(&mut self, option: TelnetOption) -> TellyResult {
        self.send_event(TelnetEvent::dont(option))
    }

    /// Convenience function to send ASCII data to remote.
    pub fn send_str(&mut self, data: &str) -> TellyResult {
        self.send_bytes(data.as_bytes())
    }

    /// Send ASCII data to remote.
    pub fn send_bytes(&mut self, bytes: &[u8]) -> TellyResult {
        for byte in bytes.iter().copied() {
            if byte == TelnetCommand::IAC.into() {
                self.send_raw_bytes(&[TelnetCommand::IAC.into()])?;
            }

            self.send_raw_bytes(bytes)?;
        }

        self.stream.flush()?;
        Ok(())
    }

    fn send_raw_bytes(&mut self, bytes: &[u8]) -> TellyResult {
        if self.stream.write(bytes)? != bytes.len() {
            return Err(TellyError::DidNotWriteAllBytes);
        }
        Ok(())
    }

    fn next_event(&mut self) -> Option<TelnetEvent> {
        self.parser.next_event(&mut self.rx_buffer)
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

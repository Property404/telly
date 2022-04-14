use crate::{
    errors::{TellyError, TellyResult},
    utils::TellyIterTraits,
    TelnetEvent, TelnetOption, TelnetParser,
};
use bytes::{BufMut, BytesMut};
use std::{
    io::{Read, Write},
    iter::Iterator,
};

/// Abstraction representing a Telnet server or client. This is a stateful wrapper around
/// TelnetParser.
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
        self.send_raw_bytes(&bytes)
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
        let bytes: Vec<u8> = data.as_bytes().iter().copied().escape_iacs().collect();
        self.send_raw_bytes(&bytes)
    }

    /// Convenience function to send ASCII data to remote.
    pub fn send_data(&mut self, data: &[u8]) -> TellyResult {
        self.send_event(TelnetEvent::Data(Vec::from(data)))
    }

    /// Send raw telnet data to remote. This does NOT escape ASCII data.
    fn send_raw_bytes(&mut self, bytes: &[u8]) -> TellyResult {
        if self.stream.write(bytes)? != bytes.len() {
            return Err(TellyError::DidNotWriteAllBytes);
        }
        self.stream.flush()?;
        Ok(())
    }
}

impl<T: Write + Read> Iterator for TelnetStream<T> {
    type Item = TelnetEvent;

    fn next(&mut self) -> Option<Self::Item> {
        const BUFFER_SIZE: usize = 16;
        let mut vec: Vec<u8> = vec![0; BUFFER_SIZE];

        if let Some(event) = self.parser.next_event(&mut self.rx_buffer) {
            return Some(event);
        }

        loop {
            let bytes_read = self.stream.read(&mut vec).expect("fuck");
            self.rx_buffer.put(&vec[0..bytes_read]);

            if let Some(event) = self.parser.next_event(&mut self.rx_buffer) {
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
    use crate::{TelnetCommand, TelnetSubnegotiation, UnparsedTelnetSubnegotiation};
    use std::{collections::VecDeque, io::Result};

    // A loopback stream: `write()`'s feed its own read buffer.
    #[derive(Default)]
    struct MockStream {
        buffer: VecDeque<u8>,
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if buf.is_empty() {
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
    fn send_string() {
        let stream = MockStream::default();
        let mut stream = TelnetStream::from_stream(stream);
        let test_string = "Hello World!";
        stream.send_str(&test_string).unwrap();

        match stream.next().unwrap() {
            TelnetEvent::Data(data) => {
                assert_eq!(String::from_utf8_lossy(&data).to_string(), test_string);
            }
            _ => {
                panic!("Received telnet command but should have received data");
            }
        }
    }

    #[test]
    fn send_events() {
        let stream = MockStream::default();
        let mut stream = TelnetStream::from_stream(stream);

        let events = [
            TelnetEvent::Data(vec![0x42]),
            TelnetEvent::Data(vec![0x42, 0xFF, 0x41]),
            TelnetEvent::Data(vec![0x42, 0xFF]),
            TelnetEvent::Data(vec![0xFF]),
            TelnetEvent::Data(vec![0xFF, 0xFF]),
            TelnetEvent::Command(TelnetCommand::Nop),
            TelnetEvent::will(TelnetOption::SuppressGoAhead),
            TelnetEvent::dont(TelnetOption::TimingMark),
            TelnetEvent::wont(TelnetOption::BinaryTransmission),
            TelnetEvent::Subnegotiation(UnparsedTelnetSubnegotiation {
                option: TelnetOption::BinaryTransmission,
                bytes: vec![0xde, 0xad, 0xbe, 0xef],
            }),
            TelnetSubnegotiation::TerminalTypeResponse("xterm-turbo-edition".into()).into(),
        ];

        for event in events {
            stream.send_event(event.clone()).unwrap();
            assert_eq!(stream.next(), Some(event));
        }
        assert_eq!(stream.next(), None);
    }
}

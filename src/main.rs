use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};
use telly::{TelnetEvent, TelnetOption, TelnetStream};

struct TelnetServer {
    listener: TcpListener,
}

impl TelnetServer {
    pub fn new(host: &str) -> Self {
        Self {
            listener: TcpListener::bind(host).unwrap(),
        }
    }

    pub fn listen(&self, cb: fn(TcpStream)) {
        for connection in self.listener.incoming() {
            match connection {
                Ok(connection) => {
                    thread::spawn(move || {
                        cb(connection);
                    });
                }
                Err(err) => {
                    panic!("Error: {err}");
                }
            }
        }
    }
}

fn handle_client(stream: impl Write + Read) {
    let mut stream = TelnetStream::from_stream(stream);

    // Enable character mode
    stream.send_will(TelnetOption::Echo).unwrap();
    stream.send_will(TelnetOption::SuppressGoAhead).unwrap();

    // Get terminal size
    // Returns as:
    // IAC SB NAWS <16-bit value> <16-bit value> IAC SE
    // See https://www.rfc-editor.org/rfc/rfc1073.html
    stream
        .send_do(TelnetOption::NegotiateAboutWindowSize)
        .unwrap();

    loop {
        let event = stream.next().unwrap();
        match event {
            TelnetEvent::Data(data) => {
                for data in data {
                    if data == b'\r' {
                        println!();
                    } else {
                        if (0x20..0x7f).contains(&data) {
                            print!("{}", data as char);
                            stream.send_bytes(&[data]).unwrap();
                        } else {
                            print!("[0x{data:x}]");
                        }
                        std::io::stdout().flush().expect("Oh jeez");
                    }
                }
            }
            TelnetEvent::SubNegotiation { option, bytes } => match option {
                TelnetOption::NegotiateAboutWindowSize => {
                    if bytes.len() != 4 {
                        eprintln!("Failed to parse NegotiateAboutWindowSize");
                        continue;
                    }

                    let bytes: Vec<_> = bytes.into_iter().map(|x| x as u16).collect();
                    let width = (bytes[0] << 8) + bytes[1];
                    let height = (bytes[2] << 8) + bytes[3];
                    println!("Width: {width}\nHeight: {height}");
                }
                _ => {
                    println!("Ignoring unknown subnegotiation");
                }
            },
            other => {
                println!("Received Telnet stuff: {other:?}!");
            }
        }
    }
}

fn main() {
    let server = TelnetServer::new("127.0.0.1:8000");
    server.listen(handle_client);
}

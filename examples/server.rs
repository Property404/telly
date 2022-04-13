use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};
use telly::{TelnetEvent, TelnetOption, TelnetStream, TelnetSubnegotiation};

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
    stream.send_do(TelnetOption::TerminalType).unwrap();
    stream
        .send_event(TelnetSubnegotiation::TerminalTypeRequest.into())
        .unwrap();

    // Get terminal size
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
                            stream.send_data(&[data]).unwrap();
                        } else {
                            print!("[0x{data:x}]");
                        }
                        std::io::stdout().flush().expect("Oh jeez");
                    }
                }
            }
            TelnetEvent::Subnegotiation(subnegotiation) => {
                match subnegotiation.try_into().unwrap() {
                    TelnetSubnegotiation::NegotiateAboutWindowSize { width, height } => {
                        println!("Width: {width}\nHeight: {height}");
                    }
                    TelnetSubnegotiation::TerminalTypeResponse(terminal) => {
                        println!("Terminal type: {terminal}");
                    }
                    _ => {
                        println!("Ignoring unknown subnegotiation");
                    }
                }
            }
            other => {
                println!("Received Telnet stuff: {other:?}!");
            }
        }
    }
}

fn main() {
    let host = "127.0.0.1:8000";
    let server = TelnetServer::new(host);
    println!("Listening on {host}");
    server.listen(handle_client);
}

use std::{env, io::Write, net::TcpStream};
use telly::{TelnetEvent, TelnetStream};

fn start_client(host: &str) {
    let stream = TcpStream::connect(host).unwrap();
    let mut stream = TelnetStream::from_stream(stream);

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
                        } else {
                            print!("[0x{data:x}]");
                        }
                        std::io::stdout().flush().expect("Oh jeez");
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
    let mut args = env::args();
    args.next().unwrap();
    let host = args.next().unwrap();
    println!("Host: {host}");
    start_client(&host);
}

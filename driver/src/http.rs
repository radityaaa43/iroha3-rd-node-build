//! Minimal HTTP/1.0 over std TCP for the coordinator <-> bi-auditor hop inside the
//! cluster (one request per connection, JSON bodies). Not exposed outside namespace iroha3.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use eyre::{Result, WrapErr, eyre};

const MAX_BODY: usize = 1 << 20;

/// Send one request; returns (status, body).
pub fn request(addr: &str, method: &str, path: &str, body: &str) -> Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr).wrap_err_with(|| format!("connect {addr}"))?;
    // Approval fetches capsules from 3 of 4 nodes and submits a quorum: allow minutes.
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| eyre!("bad status line: {status_line:?}"))?;
    Ok((status, read_message(&mut reader)?))
}

/// Serve requests one at a time (serialising approvals is intended).
pub fn serve(addr: &str, handler: impl Fn(&str, &str, &str) -> (u16, String)) -> Result<()> {
    let listener = TcpListener::bind(addr).wrap_err_with(|| format!("bind {addr}"))?;
    eprintln!("listening on {addr}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if let Err(error) = serve_one(stream, &handler) {
            eprintln!("request failed: {error}");
        }
    }
    Ok(())
}

fn serve_one(
    mut stream: TcpStream,
    handler: &impl Fn(&str, &str, &str) -> (u16, String),
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let body = read_message(&mut reader)?;
    let (status, response) = handler(method, path, &body);
    write!(
        stream,
        "HTTP/1.0 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{response}",
        response.len()
    )?;
    Ok(())
}

/// Headers, then a Content-Length body (or up to EOF without one).
fn read_message(reader: &mut impl BufRead) -> Result<String> {
    let mut length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse::<usize>()?);
            }
        }
    }
    let mut body = Vec::new();
    match length {
        Some(n) if n > MAX_BODY => return Err(eyre!("body too large: {n}")),
        Some(n) => {
            body.resize(n, 0);
            reader.read_exact(&mut body)?;
        }
        None => {
            reader.take(MAX_BODY as u64).read_to_end(&mut body)?;
        }
    }
    Ok(String::from_utf8(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_one(stream, &|method, path, body| {
                (201, format!("{method} {path} {body}"))
            })
            .unwrap();
        });
        let (status, body) = request(&addr, "POST", "/approve", "{\"a\":1}").unwrap();
        server.join().unwrap();
        assert_eq!(status, 201);
        assert_eq!(body, "POST /approve {\"a\":1}");
    }
}

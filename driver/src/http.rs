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
    // Approval fetches capsules from 3 of 4 nodes and submits a quorum: allow minutes.
    request_with(addr, method, path, body, None, Duration::from_secs(600))
}

/// One request to an auditor/gateway target: `https://gateway...` goes over mutual TLS (needs `[tls]`), a plain `host:port` over
/// the in-namespace HTTP/1.0 path (iroha3 S13: plain HTTP stays inside ONE namespace).
pub fn send(tls: Option<&crate::config::TlsConfig>, target: &str, method: &str, path: &str, body: &str, connect: Option<Duration>, read: Duration) -> Result<(u16, String)> {
    if target.starts_with("https://") {
        let tls = tls.ok_or_else(|| eyre!("{target} needs a [tls] section in the config (client cert, key, server CA dir)"))?;
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        return crate::tls_http::request(tls, &url, method, body, connect.unwrap_or(Duration::from_secs(10)), read);
    }
    request_with(target, method, path, body, connect, read)
}

/// `request` with an optional connect timeout and an explicit read (response) timeout.
pub fn request_with(addr: &str, method: &str, path: &str, body: &str, connect: Option<Duration>, read: Duration) -> Result<(u16, String)> {
    let mut stream = match connect {
        None => TcpStream::connect(addr),
        Some(limit) => {
            use std::net::ToSocketAddrs;
            let target = addr.to_socket_addrs().wrap_err_with(|| format!("resolve {addr}"))?.next().ok_or_else(|| eyre!("no address for {addr}"))?;
            TcpStream::connect_timeout(&target, limit)
        }
    }
    .wrap_err_with(|| format!("connect {addr}"))?;
    stream.set_read_timeout(Some(read))?;
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
    Ok((status, read_message(&mut reader, true)?))
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
    // A request without Content-Length has no body (RFC 9112 6.3); reading to EOF would hang a
    // client such as fetch() that keeps the connection open for the response.
    let body = read_message(&mut reader, false)?;
    let (status, response) = handler(method, path, &body);
    write!(
        stream,
        "HTTP/1.0 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{response}",
        response.len()
    )?;
    Ok(())
}

/// Headers, then a Content-Length body; without one, up to EOF (`until_eof`) or empty.
fn read_message(reader: &mut impl BufRead, until_eof: bool) -> Result<String> {
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
        None if !until_eof => {}
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

    #[test]
    fn get_without_content_length_is_answered_while_the_client_keeps_the_connection_open() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_one(stream, &|method, path, body| (200, format!("{method} {path} [{body}]"))).unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.write_all(b"GET /records/ab HTTP/1.1\r\nHost: x\r\n\r\n").unwrap(); // no shutdown: like fetch()
        let mut response = String::new();
        BufReader::new(&client).read_to_string(&mut response).unwrap();
        server.join().unwrap();
        assert!(response.ends_with("GET /records/ab []"), "{response}");
    }

    /// Live 2026-11-13: the kubelet tcpSocket readiness probe connects and closes every 10 s; each one reached the
    /// handler as method "" path "" and logged " : not found" (about 2580 lines per auditor in 7 h).
    #[test]
    fn a_connection_closed_without_a_request_is_not_handled() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        drop(TcpStream::connect(listener.local_addr().unwrap()).unwrap());
        let (stream, _) = listener.accept().unwrap();
        let called = std::cell::Cell::new(false);
        serve_one(stream, &|_, _, _| {
            called.set(true);
            (404, String::new())
        })
        .unwrap();
        assert!(!called.get(), "an empty connection must not reach the handler");
    }

    #[test]
    fn an_https_target_without_a_tls_section_is_refused_and_a_plain_target_does_not_need_one() {
        let err = send(None, "https://gateway.rd-iroha3-bi.svc.cluster.local:8443", "GET", "/keys", "", None, Duration::from_secs(1)).unwrap_err();
        assert!(format!("{err:#}").contains("[tls]"), "{err:#}");
        // a plain host:port still takes the old path (nothing listens: connection refused, not a TLS error)
        let err = send(None, "127.0.0.1:1", "GET", "/healthz", "", Some(Duration::from_millis(300)), Duration::from_secs(1)).unwrap_err();
        assert!(!format!("{err:#}").contains("[tls]"));
    }
}

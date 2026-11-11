//! Mutual-TLS HTTP client for the driver's calls to ANOTHER party's gateway (iroha3 PLAN S13 transport A; ANALYST Q4(c): no plain
//! HTTP across namespaces or clusters, principle 6: a party reaches another party only through its gateway).
//!
//! The driver presents its own client certificate (`iroha3-client-cert`, signed by the org's role CA) and trusts ONLY the target
//! party's own server root (`<server_ca_dir>/<party>-server-ca.pem`, party taken from the gateway host
//! `gateway.rd-iroha3-<party>.svc[.cluster.local]`): the system roots are switched off, so there is no fallback and a gateway
//! signed by any other root is refused. A URL whose host is not a gateway host is refused, so a CA file name cannot be forged.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use eyre::{Result, WrapErr, ensure, eyre};

use crate::config::TlsConfig;

/// `https://gateway.rd-iroha3-<party>.svc[.cluster.local][:port][/path]` -> `<party>`.
pub fn party_of_url(url: &str) -> Result<String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| eyre!("not an https URL: {url:?}"))?;
    let host = rest.split(['/', ':']).next().unwrap_or("");
    let inner = host.strip_prefix("gateway.rd-iroha3-").ok_or_else(|| eyre!("{url:?} is not a gateway host (gateway.rd-iroha3-<party>.svc)"))?;
    let party = inner
        .strip_suffix(".svc.cluster.local")
        .or_else(|| inner.strip_suffix(".svc"))
        .ok_or_else(|| eyre!("{url:?} is not a gateway host (gateway.rd-iroha3-<party>.svc)"))?;
    ensure!(
        !party.is_empty() && !party.starts_with('-') && party.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "{url:?}: bad party name {party:?}"
    );
    Ok(party.to_owned())
}

/// The pinned server root of `party`.
pub fn ca_path(tls: &TlsConfig, party: &str) -> PathBuf {
    tls.server_ca_dir.join(format!("{party}-server-ca.pem"))
}

/// One request over mutual TLS; `url` is the full https URL. Returns (status, body).
pub fn request(tls: &TlsConfig, url: &str, method: &str, body: &str, connect: Duration, read: Duration) -> Result<(u16, String)> {
    let party = party_of_url(url)?;
    let ca_file = ca_path(tls, &party);
    let ca = reqwest::Certificate::from_pem(&std::fs::read(&ca_file).wrap_err_with(|| format!("read pinned server CA {}", ca_file.display()))?)
        .wrap_err("pinned server CA")?;
    let mut pem = std::fs::read(&tls.client_cert).wrap_err_with(|| format!("read client cert {}", tls.client_cert.display()))?;
    pem.push(b'\n');
    pem.extend(std::fs::read(&tls.client_key).wrap_err_with(|| format!("read client key {}", tls.client_key.display()))?);
    let identity = reqwest::Identity::from_pem(&pem).wrap_err("client identity (cert + key)")?;
    let mut builder = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        .connect_timeout(connect)
        .timeout(read);
    for (host, address) in &tls.resolve {
        let address: SocketAddr = address.parse().wrap_err_with(|| format!("[tls.resolve] {host} = {address:?} is not ip:port"))?;
        builder = builder.resolve(host, address);
    }
    let client = builder.build().wrap_err("build TLS client")?;
    let method = reqwest::Method::from_bytes(method.as_bytes()).wrap_err("HTTP method")?;
    let mut request = client.request(method, url).header("Content-Type", "application/json");
    if !body.is_empty() {
        request = request.body(body.to_owned());
    }
    let response = request.send().wrap_err_with(|| format!("TLS request to {url}"))?;
    let status = response.status().as_u16();
    Ok((status, response.text().wrap_err("read response body")?))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{TcpListener, TcpStream},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::Duration,
    };

    use super::*;
    use crate::config::TlsConfig;

    fn tls(dir: &str) -> TlsConfig {
        TlsConfig {
            client_cert: PathBuf::from(format!("{dir}/client.crt")),
            client_key: PathBuf::from(format!("{dir}/client.key")),
            server_ca_dir: PathBuf::from(dir),
            resolve: Default::default(),
        }
    }

    #[test]
    fn the_party_comes_from_the_gateway_host_of_the_url() {
        assert_eq!(party_of_url("https://gateway.rd-iroha3-bank-a.svc.cluster.local:8443").unwrap(), "bank-a");
        assert_eq!(party_of_url("https://gateway.rd-iroha3-bi.svc:8443/keys").unwrap(), "bi");
        assert_eq!(party_of_url("https://gateway.rd-iroha3-bank-c.svc.cluster.local/approve").unwrap(), "bank-c");
    }

    #[test]
    fn any_other_url_is_refused_so_a_ca_file_name_cannot_be_forged() {
        for bad in [
            "http://gateway.rd-iroha3-bi.svc:8443",
            "https://evil.example.com:8443",
            "https://gateway.rd-iroha3-.svc:8443",
            "https://gateway.rd-iroha3-../x.svc:8443",
            "https://gateway.rd-iroha3-bi.evil.com:8443",
            "https://gateway.rd-iroha3-a/b.svc:8443",
            "bi-auditor:8090",
            "",
        ] {
            assert!(party_of_url(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_pinned_ca_of_a_party_is_its_own_server_root_file() {
        assert_eq!(ca_path(&tls("/tls/cas"), "bank-b"), PathBuf::from("/tls/cas/bank-b-server-ca.pem"));
    }

    #[test]
    fn a_missing_pinned_ca_or_client_cert_is_an_error_not_a_fallback_to_system_roots() {
        let err = request(&tls("/nonexistent"), "https://gateway.rd-iroha3-bi.svc.cluster.local:8443/keys", "GET", "", Duration::from_secs(1), Duration::from_secs(1))
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("bi-server-ca.pem") || text.contains("client.crt"), "{text}");
    }

    // ---- real mutual TLS against `openssl s_server -Verify` (skipped when the openssl binary is absent) ----

    fn have_openssl() -> bool {
        Command::new("openssl").arg("version").output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn openssl(args: &[&str]) {
        let out = Command::new("openssl").args(args).output().expect("run openssl");
        assert!(out.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    fn ca(dir: &Path, name: &str) {
        let (key, crt) = (dir.join(format!("{name}.key")), dir.join(format!("{name}.crt")));
        openssl(&["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key.to_str().unwrap(), "-out", crt.to_str().unwrap(), "-days", "2", "-subj", &format!("/CN={name}"), "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"]);
    }

    fn leaf(dir: &Path, name: &str, cn: &str, ext: &str, ca_name: &str) {
        let p = |suffix: &str| dir.join(format!("{name}{suffix}")).to_str().unwrap().to_owned();
        openssl(&["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", &p(".key"), "-out", &p(".csr"), "-subj", &format!("/CN={cn}")]);
        std::fs::write(p(".ext"), ext).unwrap();
        openssl(&["x509", "-req", "-in", &p(".csr"), "-CA", dir.join(format!("{ca_name}.crt")).to_str().unwrap(), "-CAkey", dir.join(format!("{ca_name}.key")).to_str().unwrap(), "-CAcreateserial", "-out", &p(".crt"), "-days", "2", "-extfile", &p(".ext")]);
    }

    struct Server(Child);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    const HOST: &str = "gateway.rd-iroha3-bi.svc.cluster.local";

    /// PKI in `dir`: server-ca + server cert (SAN = HOST), client-ca + client cert, an unrelated other-ca + its client cert.
    fn pki(dir: &Path) {
        ca(dir, "server-ca");
        leaf(dir, "server", HOST, &format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{HOST}\n"), "server-ca");
        ca(dir, "client-ca");
        leaf(dir, "client", "bi", "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n", "client-ca");
        ca(dir, "other-ca");
        leaf(dir, "intruder", "bi", "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n", "other-ca");
        // the pinned file name the client derives from the URL
        std::fs::copy(dir.join("server-ca.crt"), dir.join("bi-server-ca.pem")).unwrap();
        std::fs::copy(dir.join("other-ca.crt"), dir.join("other-server-ca.pem")).unwrap();
    }

    fn serve(dir: &Path) -> (Server, u16) {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let child = Command::new("openssl")
            .args(["s_server", "-accept", &port.to_string(), "-cert", dir.join("server.crt").to_str().unwrap(), "-key", dir.join("server.key").to_str().unwrap(), "-CAfile", dir.join("client-ca.crt").to_str().unwrap(), "-Verify", "1", "-www", "-quiet"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start s_server");
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        (Server(child), port)
    }

    fn config(dir: &Path, client: &str, port: u16) -> TlsConfig {
        let mut cfg = tls(dir.to_str().unwrap());
        cfg.client_cert = dir.join(format!("{client}.crt"));
        cfg.client_key = dir.join(format!("{client}.key"));
        cfg.resolve.insert(HOST.to_owned(), format!("127.0.0.1:{port}"));
        cfg
    }

    #[test]
    fn mutual_tls_with_the_pinned_server_root_and_an_accepted_client_cert_succeeds() {
        if !have_openssl() {
            eprintln!("SKIP: no openssl binary");
            return;
        }
        let dir = tempdir("mtls-ok");
        pki(&dir);
        let (_server, port) = serve(&dir);
        let url = format!("https://{HOST}:{port}/keys");
        let (status, body) = request(&config(&dir, "client", port), &url, "GET", "", Duration::from_secs(3), Duration::from_secs(10)).unwrap();
        assert_eq!(status, 200);
        assert!(!body.is_empty());
    }

    #[test]
    fn a_client_cert_from_another_ca_is_refused_by_the_server() {
        if !have_openssl() {
            eprintln!("SKIP: no openssl binary");
            return;
        }
        let dir = tempdir("mtls-intruder");
        pki(&dir);
        let (_server, port) = serve(&dir);
        let url = format!("https://{HOST}:{port}/keys");
        assert!(request(&config(&dir, "intruder", port), &url, "GET", "", Duration::from_secs(3), Duration::from_secs(10)).is_err());
    }

    #[test]
    fn a_server_signed_by_a_root_that_is_not_the_pinned_one_is_refused() {
        if !have_openssl() {
            eprintln!("SKIP: no openssl binary");
            return;
        }
        let dir = tempdir("mtls-pin");
        pki(&dir);
        // pin the OTHER root under the file name the client derives from the URL
        std::fs::copy(dir.join("other-ca.crt"), dir.join("bi-server-ca.pem")).unwrap();
        let (_server, port) = serve(&dir);
        let url = format!("https://{HOST}:{port}/keys");
        assert!(request(&config(&dir, "client", port), &url, "GET", "", Duration::from_secs(3), Duration::from_secs(10)).is_err());
    }

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rd-dfabi-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

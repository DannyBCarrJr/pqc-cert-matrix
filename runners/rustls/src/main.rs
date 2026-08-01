// Test client for the rustls runner. One test per invocation; exit 0 ok / 1 fail.
// Default build: rustls with the aws-lc-rs provider as shipped (no unstable
// feature flags). ML-DSA support behind `aws-lc-rs-unstable` is a separate cell
// question; this column measures what `cargo add rustls` gives you today.
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};

fn load(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut rd = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?,
    );
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut rd).collect();
    let certs = certs.map_err(|e| format!("pem parse: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificates in {path}"));
    }
    Ok(certs)
}

fn parse(leaf: &str) -> Result<String, String> {
    let certs = load(leaf)?;
    // webpki's EndEntityCert is rustls's actual parse path for a peer cert.
    match webpki::EndEntityCert::try_from(&certs[0]) {
        Ok(_) => Ok(format!("parsed: {} bytes DER, webpki accepted", certs[0].len())),
        Err(e) => Err(format!("webpki parse: {e:?}")),
    }
}

fn roots(root: &str) -> Result<RootCertStore, String> {
    let mut store = RootCertStore::empty();
    for c in load(root)? {
        store.add(c).map_err(|e| format!("add root: {e}"))?;
    }
    Ok(store)
}

fn verify(root: &str, inter: &str, leaf: &str) -> Result<String, String> {
    let store = roots(root)?;
    let leaf_der = load(leaf)?.remove(0);
    let inters = if inter == "-" { vec![] } else { load(inter)? };
    let ee = webpki::EndEntityCert::try_from(&leaf_der).map_err(|e| format!("parse: {e:?}"))?;

    let anchors: Vec<_> = store.roots.iter().cloned().collect();
    let now = UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap(),
    );
    let algs = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
    ee.verify_for_usage(
        algs.all,
        &anchors,
        &inters,
        now,
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map(|_| "verify: OK".to_string())
    .map_err(|e| format!("verify: {e:?}"))
}

fn handshake(root: &str, host: &str, port: &str) -> Result<String, String> {
    let store = roots(root)?;
    let config = ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).map_err(|e| format!("servername: {e}"))?;
    let mut conn = ClientConnection::new(Arc::new(config), name)
        .map_err(|e| format!("client: {e}"))?;
    let mut sock =
        TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| format!("connect: {e}"))?;
    let mut tls = Stream::new(&mut conn, &mut sock);
    // Force the handshake to run to completion.
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n")
        .map_err(|e| format!("handshake: {e}"))?;
    tls.flush().ok();
    let proto = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());
    Ok(format!("handshake: OK {proto}"))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let r = match a.get(1).map(String::as_str) {
        Some("parse") => parse(&a[2]),
        Some("verify") => verify(&a[2], &a[3], &a[4]),
        Some("handshake") => handshake(&a[2], &a[3], &a[4]),
        _ => Err("usage: parse|verify|handshake".into()),
    };
    match r {
        Ok(m) => println!("{m}"),
        Err(e) => {
            println!("{e}");
            std::process::exit(1);
        }
    }
}

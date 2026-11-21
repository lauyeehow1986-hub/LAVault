use std::net::UdpSocket;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use ed25519_dalek::VerifyingKey;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vault_core::identity::{DataEncryptionKey, DerivedIdentityKeys};
use vault_core::transport::{
    build_unlock_challenge_for_vlt, encode_8word_verifier, fulfill_unlock_challenge,
    verify_and_extract_unlock_dek, verify_and_extract_unlock_dek_optional_vk,
    EphemeralResponseSecret, UnlockChallenge, UnlockResponse, MDNS_SERVICE_TYPE, MDNS_TCP_PORT,
};

use crate::qr::{render_terminal_qr, write_unlock_qr_html};

#[derive(Debug, Clone)]
pub struct PinnedTlsPeer {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub expected_remote_cert_der: Vec<u8>,
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected_cert: Vec<u8>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_cert.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "pinned server certificate mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
struct PinnedClientVerifier {
    expected_cert: Vec<u8>,
    hints: Vec<DistinguishedName>,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_cert.as_slice() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "pinned client certificate mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

pub fn advertise_mdns_service(instance_name: &str, host_name: &str) -> Result<ServiceDaemon> {
    let mdns = ServiceDaemon::new()?;
    let service_info = ServiceInfo::new(
        MDNS_SERVICE_TYPE,
        instance_name,
        host_name,
        "127.0.0.1",
        MDNS_TCP_PORT,
        &[("proto", "lavault1")][..],
    )?;
    mdns.register(service_info)?;
    Ok(mdns)
}

async fn write_framed_cbor<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

async fn read_framed_cbor<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(anyhow!("CBOR frame exceeds 1 MiB limit"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn run_pinned_tls13_unlock_roundtrip(
    vlt_bytes: &[u8],
    slot_id: &str,
    requester_name: &str,
    pc_peer: PinnedTlsPeer,
    phone_peer: PinnedTlsPeer,
    phone_keys: &DerivedIdentityKeys,
) -> Result<DataEncryptionKey> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let server_verifier = Arc::new(PinnedClientVerifier {
        expected_cert: phone_peer.expected_remote_cert_der.clone(),
        hints: vec![],
    });
    let server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(server_verifier)
        .with_single_cert(
            vec![CertificateDer::from(phone_peer.cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(phone_peer.key_der)),
        )?;

    let client_verifier = Arc::new(PinnedServerVerifier {
        expected_cert: pc_peer.expected_remote_cert_der.clone(),
    });
    let client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(client_verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(pc_peer.cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pc_peer.key_der)),
        )?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let phone_x = phone_keys.x25519_secret().to_bytes();
    let phone_ed = phone_keys.ed25519_signing().to_bytes();
    let phone_db = phone_keys.vault_db_key().clone();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut tls = acceptor.accept(tcp).await?;
        let req_bytes = read_framed_cbor(&mut tls).await?;
        let challenge = UnlockChallenge::from_cbor(&req_bytes)?;
        let task_keys = DerivedIdentityKeys::from_raw_parts(phone_x, phone_ed, phone_db);
        let resp = fulfill_unlock_challenge(&challenge, &challenge.slot_id, &task_keys)?;
        let resp_bytes = resp.to_cbor()?;
        write_framed_cbor(&mut tls, &resp_bytes).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (challenge, pc_ephem) = build_unlock_challenge_for_vlt(vlt_bytes, slot_id, requester_name)?;
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let stream = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost")?;
    let mut tls = match connector.connect(server_name, stream).await {
        Ok(s) => s,
        Err(client_err) => {
            let srv_res = server_task.await;
            return Err(anyhow!(
                "client TLS connect error: {client_err}; server_task={srv_res:?}"
            ));
        }
    };

    write_framed_cbor(&mut tls, &challenge.to_cbor()?).await?;
    let resp_bytes = read_framed_cbor(&mut tls).await?;
    let resp = UnlockResponse::from_cbor(&resp_bytes)?;
    server_task.await??;

    let dek = verify_and_extract_unlock_dek(&resp, &pc_ephem, &phone_keys.ed25519_verifying())?;
    Ok(dek)
}

pub struct LanUnlockOutcome {
    pub dek: DataEncryptionKey,
    pub responder_id: String,
}

pub fn detect_lan_ipv4() -> String {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn send_http_json(stream: &mut TcpStream, status: &str, json_body: &str) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_http_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("unexpected EOF while reading HTTP headers"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("HTTP headers too large"));
        }
    };

    let head_str = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| anyhow!("invalid UTF-8 in HTTP headers"))?;
    let mut lines = head_str.lines();
    let req_line = lines.next().ok_or_else(|| anyhow!("missing HTTP request line"))?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let raw_path = parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or("/").to_string();

    let mut content_len: Option<usize> = None;
    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().ok();
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    let body_start = header_end + 4;
    if is_chunked {
        let mut cursor = body_start;
        let mut decoded = Vec::new();
        loop {
            let line_rel = loop {
                if let Some(pos) = buf[cursor..].windows(2).position(|w| w == b"\r\n") {
                    break pos;
                }
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(anyhow!("unexpected EOF reading chunked size line"));
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 2 * 1024 * 1024 {
                    return Err(anyhow!("chunked HTTP body exceeds limit"));
                }
            };
            let size_line = std::str::from_utf8(&buf[cursor..cursor + line_rel])
                .map_err(|_| anyhow!("invalid UTF-8 in chunk size"))?;
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let chunk_size = usize::from_str_radix(size_hex, 16)
                .map_err(|_| anyhow!("invalid chunk size '{size_hex}'"))?;
            cursor += line_rel + 2;
            if chunk_size == 0 {
                break;
            }
            if decoded.len().saturating_add(chunk_size) > 1024 * 1024 {
                return Err(anyhow!("HTTP request body exceeds 1 MiB"));
            }
            while buf.len() < cursor + chunk_size + 2 {
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(anyhow!("unexpected EOF reading chunked payload"));
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            decoded.extend_from_slice(&buf[cursor..cursor + chunk_size]);
            cursor += chunk_size + 2;
        }
        return Ok((method, path, decoded));
    }

    if let Some(len) = content_len {
        if len > 1024 * 1024 {
            return Err(anyhow!("HTTP request body exceeds 1 MiB"));
        }
        let mut body = buf[body_start..].to_vec();
        while body.len() < len {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(len);
        return Ok((method, path, body));
    }

    Ok((method, path, buf[body_start..].to_vec()))
}

fn extract_ur_res_from_body(raw_body: &str) -> Result<String> {
    let trimmed = raw_body.trim();
    if trimmed.to_ascii_lowercase().starts_with("ur:lavault-res/") {
        return Ok(trimmed.to_string());
    }
    if let Some(idx) = trimmed.to_ascii_lowercase().find("ur:lavault-res/") {
        let slice = &trimmed[idx..];
        let end = slice
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '}')
            .unwrap_or(slice.len());
        return Ok(slice[..end].to_string());
    }
    Err(anyhow!("request body does not contain ur:lavault-res/..."))
}

pub async fn serve_lan_unlock_once(
    listener: TcpListener,
    challenge: UnlockChallenge,
    pc_ephem: EphemeralResponseSecret,
    target_file: String,
    expected_responder_vk: Option<VerifyingKey>,
) -> Result<LanUnlockOutcome> {
    let ur_req = challenge.to_bcur()?;
    let pending_json = format!(
        r#"{{"req_id":"{}","requester_name":"{}","target_file":"{}","slot_id":"{}","ur_req":"{}"}}"#,
        json_escape(&challenge.req_id),
        json_escape(&challenge.requester_name),
        json_escape(&target_file),
        json_escape(&challenge.slot_id),
        json_escape(&ur_req),
    );

    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        let (method, path, body) = match read_http_request(&mut stream).await {
            Ok(v) => v,
            Err(_) => continue,
        };

        match (method.as_str(), path.as_str()) {
            ("GET", "/pending") => {
                println!("[Wi-Fi LAN] Phone connected from {peer_addr} -> sent challenge for '{target_file}'");
                let _ = send_http_json(&mut stream, "200 OK", &pending_json).await;
            }
            ("POST", "/respond") => {
                let body_str = String::from_utf8_lossy(&body);
                match extract_ur_res_from_body(&body_str)
                    .and_then(|ur| Ok(UnlockResponse::from_bcur(&ur)?))
                    .and_then(|resp| {
                        let dek = verify_and_extract_unlock_dek_optional_vk(
                            &resp,
                            &pc_ephem,
                            expected_responder_vk.as_ref(),
                        )?;
                        Ok((dek, resp.responder_id))
                    }) {
                    Ok((dek, responder_id)) => {
                        let _ = send_http_json(&mut stream, "200 OK", r#"{"status":"unlocked"}"#).await;
                        return Ok(LanUnlockOutcome { dek, responder_id });
                    }
                    Err(e) => {
                        eprintln!("[Wi-Fi LAN] Rejected response from {peer_addr}: {e}");
                        let err_json = format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string()));
                        let _ = send_http_json(&mut stream, "400 Bad Request", &err_json).await;
                    }
                }
            }
            ("POST", "/deny") => {
                let _ = send_http_json(&mut stream, "200 OK", r#"{"status":"denied"}"#).await;
                return Err(anyhow!("Unlock request denied by phone ({peer_addr})"));
            }
            _ => {
                let _ = send_http_json(&mut stream, "404 Not Found", r#"{"error":"not found"}"#).await;
            }
        }
    }
}

pub fn run_lan_unlock_blocking(
    port: u16,
    challenge: UnlockChallenge,
    pc_ephem: EphemeralResponseSecret,
    target_file: String,
    html_out: &Path,
) -> Result<LanUnlockOutcome> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let listener = TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| {
            anyhow!("failed to bind Wi-Fi unlock listener on 0.0.0.0:{port}: {e}")
        })?;
        let local_port = listener.local_addr()?.port();
        let lan_ip = detect_lan_ipv4();
        let wifi_url = format!("http://{lan_ip}:{local_port}");
        let ur_req = challenge.to_bcur()?;
        let verifier = encode_8word_verifier(&challenge.challenge_nonce);

        write_unlock_qr_html(&ur_req, &verifier, &target_file, Some(&wifi_url), html_out)?;

        println!("=== LaVault 1-Tap Local Wi-Fi Unlocker ===");
        println!("Target file      : {target_file}");
        println!("PC Wi-Fi Address : {lan_ip}:{local_port}");
        println!("Helper QR page   : {}", html_out.display());
        println!("(On Phone -> Unlocker tab: tap 'Scan Wi-Fi / QR' below OR enter {lan_ip}:{local_port} and tap 'Check PC' -> 'Approve Unlock')");
        let wifi_qr = format!("lavault-wifi://{wifi_url}");
        if let Ok(term) = render_terminal_qr(&wifi_qr) {
            println!("{term}");
        }
        println!("Waiting for phone approval on http://{lan_ip}:{local_port} ...");

        serve_lan_unlock_once(listener, challenge, pc_ephem, target_file, None).await
    })
}

use std::sync::Arc;

use anyhow::{anyhow, Result};
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
    build_unlock_challenge_for_vlt, fulfill_unlock_challenge, verify_and_extract_unlock_dek,
    UnlockChallenge, UnlockResponse, MDNS_SERVICE_TYPE, MDNS_TCP_PORT,
};

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

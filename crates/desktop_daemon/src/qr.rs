use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use ed25519_dalek::VerifyingKey;
use qrcode::render::svg;
use qrcode::QrCode;
use vault_core::identity::{DerivedIdentityKeys, MasterIdentitySeed};
use vault_core::transport::{
    build_unlock_challenge_for_vlt, encode_8word_verifier, encode_bcur_multipart,
    verify_and_extract_unlock_dek_optional_vk, EphemeralResponseSecret, UnlockChallenge,
    UnlockResponse,
};
use vault_core::vlt::{
    decrypt_bytes_with_dek, encrypt_bytes_to_vlt, DirectWrapMethod, PayloadCipher, VltOptions,
};

pub fn render_terminal_qr(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes()).map_err(|e| anyhow!("QR encode failed: {e}"))?;
    let mut rendered = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

pub fn render_qr_svg(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes()).map_err(|e| anyhow!("QR SVG encode failed: {e}"))?;
    Ok(code
        .render()
        .min_dimensions(280, 280)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn run_qr_challenge_prompt(challenge: &UnlockChallenge, verifier_8words: &str) -> Result<()> {
    let cbor = challenge.to_cbor()?;
    if cbor.len() <= 220 {
        let ur = challenge.to_bcur()?;
        println!("=== Air-Gapped QR Request (ur:lavault-req) ===");
        if let Ok(term) = render_terminal_qr(&ur) {
            println!("{term}");
        }
        println!("{ur}");
    } else {
        println!("=== Air-Gapped Multipart QR Request ===");
        for frame in encode_bcur_multipart("lavault-req", &cbor, 128)? {
            println!("{frame}");
        }
    }
    println!("8-Word One-Time Verifier (no-webcam fallback): {verifier_8words}");
    Ok(())
}

pub fn decode_qr_response(ur_res: &str) -> Result<UnlockResponse> {
    Ok(UnlockResponse::from_bcur(ur_res)?)
}

pub struct PhoneTestSession {
    pub vlt_path: PathBuf,
    pub html_path: PathBuf,
    pub vlt_bytes: Vec<u8>,
    pub ur_request: String,
    pub verifier_8words: String,
    phone_verifying_key: Option<VerifyingKey>,
    ephem_secret: EphemeralResponseSecret,
}

impl PhoneTestSession {
    pub fn complete_with_ur_response(&self, ur_res: &str) -> Result<Vec<u8>> {
        let trimmed = ur_res.trim();
        let response = decode_qr_response(trimmed)?;
        let dek = verify_and_extract_unlock_dek_optional_vk(
            &response,
            &self.ephem_secret,
            self.phone_verifying_key.as_ref(),
        )?;
        Ok(decrypt_bytes_with_dek(&self.vlt_bytes, &dek)?)
    }
}

pub fn prepare_phone_test_session(
    phone_x25519_hex: &str,
    phone_ed25519_hex: Option<&str>,
    pc_owner_keys: Option<&DerivedIdentityKeys>,
    payload: &[u8],
    vlt_out: &Path,
    html_out: &Path,
) -> Result<PhoneTestSession> {
    let x_arr: [u8; 32] = hex::decode(phone_x25519_hex.trim())?
        .try_into()
        .map_err(|_| anyhow!("phone X25519 public key must be 32 bytes (64 hex chars)"))?;
    let phone_verifying_key = if let Some(ed_hex) = phone_ed25519_hex {
        let e_arr: [u8; 32] = hex::decode(ed_hex.trim())?
            .try_into()
            .map_err(|_| anyhow!("phone Ed25519 verifying key must be 32 bytes (64 hex chars)"))?;
        Some(
            VerifyingKey::from_bytes(&e_arr)
                .map_err(|e| anyhow!("invalid phone Ed25519 public key: {e}"))?,
        )
    } else {
        None
    };

    let generated_owner;
    let owner = match pc_owner_keys {
        Some(k) => k,
        None => {
            generated_owner = DerivedIdentityKeys::from_seed(&MasterIdentitySeed::generate()?)?;
            &generated_owner
        }
    };

    let vlt_bytes = encrypt_bytes_to_vlt(
        payload,
        owner,
        &VltOptions {
            cipher: PayloadCipher::ChaCha20Poly1305,
            wrap_method: DirectWrapMethod::XChaCha20Poly1305,
            direct_recipients: vec![("phone".into(), x_arr)],
            quorum_members: vec![],
            quorum_threshold_k: 0,
        },
    )?;

    if let Some(parent) = vlt_out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(vlt_out, &vlt_bytes)?;

    let (challenge, ephem_secret) =
        build_unlock_challenge_for_vlt(&vlt_bytes, "phone", "LaVault-PhoneTest")?;
    let ur_request = challenge.to_bcur()?;
    let verifier_8words = encode_8word_verifier(&challenge.challenge_nonce);
    let svg_qr = render_qr_svg(&ur_request)?;

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LaVault Phone Unlocker QR Test</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 24px; }}
  .card {{ max-width: 680px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 24px; border: 1px solid #334155; }}
  .qr-box {{ background: #ffffff; padding: 18px; border-radius: 12px; display: inline-block; margin: 16px 0; }}
  code, pre {{ background: #0f172a; color: #38bdf8; padding: 10px; border-radius: 8px; display: block; word-break: break-all; white-space: pre-wrap; font-size: 12px; }}
  .verifier {{ font-size: 16px; font-weight: 700; color: #4ade80; margin: 10px 0; }}
</style>
</head>
<body>
<div class="card">
  <h1>LaVault Phone Unlocker Test</h1>
  <p>Open <strong>LaVault</strong> on your Android/iOS phone &rarr; <strong>Unlocker</strong> tab &rarr; tap <strong>Scan PC Unlock QR</strong> and scan this code:</p>
  <div class="qr-box">{svg_qr}</div>
  <div class="verifier">8-Word Verifier: {verifier_esc}</div>
  <p>After authenticating with biometrics on your phone, paste the generated <code>ur:lavault-res/...</code> string back into the PC terminal.</p>
  <h3>Copyable Request String (fallback if camera is busy):</h3>
  <pre>{ur_esc}</pre>
  <p>Encrypted container written to: <code>{vlt_esc}</code></p>
</div>
</body>
</html>
"#,
        svg_qr = svg_qr,
        verifier_esc = html_escape(&verifier_8words),
        ur_esc = html_escape(&ur_request),
        vlt_esc = html_escape(&vlt_out.display().to_string()),
    );

    if let Some(parent) = html_out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(html_out, html)?;

    Ok(PhoneTestSession {
        vlt_path: vlt_out.to_path_buf(),
        html_path: html_out.to_path_buf(),
        vlt_bytes,
        ur_request,
        verifier_8words,
        phone_verifying_key,
        ephem_secret,
    })
}

pub fn save_stress_qr_html(
    totp_secret_b32: &str,
    sample_ur_req: &str,
    html_out: &Path,
) -> Result<()> {
    let otpauth_uri = format!(
        "otpauth://totp/LaVault:StressTest?secret={}&issuer=LaVault&algorithm=SHA1&digits=6&period=30",
        totp_secret_b32.trim()
    );
    let totp_svg = render_qr_svg(&otpauth_uri)?;
    let req_svg = render_qr_svg(sample_ur_req)?;

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LaVault Stress &amp; TOTP Parity Sheet</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; max-width: 1000px; margin: 0 auto; }}
  .card {{ background: #1e293b; border-radius: 16px; padding: 20px; border: 1px solid #334155; }}
  .qr-box {{ background: #ffffff; padding: 14px; border-radius: 12px; display: inline-block; margin: 12px 0; }}
  code {{ background: #0f172a; color: #38bdf8; padding: 6px 10px; border-radius: 6px; word-break: break-all; display: inline-block; }}
</style>
</head>
<body>
<div class="grid">
  <div class="card">
    <h2>1. TOTP 6-Digit Parity Test</h2>
    <p>In the Android app <strong>Vault + TOTP</strong> tab, tap <strong>+</strong> and paste this Base32 Secret (or scan with any standard authenticator to cross-verify):</p>
    <p>Secret: <code>{secret_esc}</code></p>
    <div class="qr-box">{totp_svg}</div>
    <p>Both your phone and <code>lavault stress --live-totp-secs 90</code> will display identical 6-digit codes every 30 seconds.</p>
  </div>
  <div class="card">
    <h2>2. Sample Unlocker Camera QR</h2>
    <p>In the Android app <strong>Unlocker</strong> tab, tap <strong>Scan PC Unlock QR</strong> to test camera decoding of a live <code>ur:lavault-req/...</code> challenge:</p>
    <div class="qr-box">{req_svg}</div>
    <p>For full PC file decryption with your phone's real key, run <code>lavault phone-test --phone-x25519 &lt;HEX&gt; --phone-ed25519 &lt;HEX&gt;</code>.</p>
  </div>
</div>
</body>
</html>
"#,
        secret_esc = html_escape(totp_secret_b32.trim()),
        totp_svg = totp_svg,
        req_svg = req_svg,
    );

    if let Some(parent) = html_out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(html_out, html)?;
    Ok(())
}

pub fn write_unlock_qr_html(
    ur_request: &str,
    verifier_8words: &str,
    target_label: &str,
    wifi_url: Option<&str>,
    html_out: &Path,
) -> Result<()> {
    let wifi_card = if let Some(url) = wifi_url {
        let wifi_payload = format!("lavault-wifi://{url}");
        let wifi_svg = render_qr_svg(&wifi_payload)?;
        let host_display = url.strip_prefix("http://").unwrap_or(url);
        format!(
            r#"  <div class="card">
    <h2>1. Seamless 1-Tap Local Wi-Fi Unlock</h2>
    <p>On your Android phone, open <strong>LaVault &rarr; Unlocker</strong>:</p>
    <ul>
      <li>Tap <strong>Scan Wi-Fi / QR</strong> and scan this tiny Wi-Fi code, OR</li>
      <li>Type <code>{host_esc}</code> into <strong>PC Wi-Fi Address</strong> and tap <strong>Check PC</strong> &rarr; <strong>Approve Unlock</strong>.</li>
    </ul>
    <div class="qr-box">{wifi_svg}</div>
    <p>Target: <code>{target_esc}</code></p>
  </div>"#,
            host_esc = html_escape(host_display),
            wifi_svg = wifi_svg,
            target_esc = html_escape(target_label),
        )
    } else {
        String::new()
    };

    let req_svg = render_qr_svg(ur_request)?;
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LaVault Unlock Request</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; max-width: 1040px; margin: 0 auto; }}
  .card {{ background: #1e293b; border-radius: 16px; padding: 24px; border: 1px solid #334155; }}
  .qr-box {{ background: #ffffff; padding: 16px; border-radius: 12px; display: inline-block; margin: 14px 0; }}
  code, pre {{ background: #0f172a; color: #38bdf8; padding: 8px 10px; border-radius: 8px; word-break: break-all; white-space: pre-wrap; font-size: 12px; display: block; }}
  .verifier {{ font-size: 15px; font-weight: 700; color: #4ade80; margin: 10px 0; }}
</style>
</head>
<body>
<div class="grid">
{wifi_card}
  <div class="card">
    <h2>Air-Gapped Optical QR Challenge</h2>
    <p>Unlock target: <strong>{target_esc}</strong></p>
    <div class="qr-box">{req_svg}</div>
    <div class="verifier">8-Word Verifier: {verifier_esc}</div>
    <pre>{ur_esc}</pre>
  </div>
</div>
</body>
</html>
"#,
        wifi_card = wifi_card,
        target_esc = html_escape(target_label),
        req_svg = req_svg,
        verifier_esc = html_escape(verifier_8words),
        ur_esc = html_escape(ur_request),
    );

    if let Some(parent) = html_out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(html_out, html)?;
    Ok(())
}

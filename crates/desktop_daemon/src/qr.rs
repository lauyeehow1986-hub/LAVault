use anyhow::Result;
use vault_core::transport::{encode_bcur_multipart, UnlockChallenge, UnlockResponse};

pub fn run_qr_challenge_prompt(challenge: &UnlockChallenge, verifier_8words: &str) -> Result<()> {
    let cbor = challenge.to_cbor()?;
    if cbor.len() <= 220 {
        println!("=== Air-Gapped QR Request (ur:lavault-req) ===");
        println!("{}", challenge.to_bcur()?);
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

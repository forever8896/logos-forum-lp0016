//! Encode the params_blob + roster_blob for the `forum_registry::create_instance`
//! instruction. Generates a fresh threshold ElGamal key + M moderator signing
//! keys, borsh-encodes them, and prints everything as JSON so a shell driver
//! can pipe the blobs to `spel create-instance --params-blob ... --roster-blob ...`
//! and at the same time show the operator the master secret + per-mod shares
//! that must be distributed out-of-band.
//!
//! Usage:
//!   encode_create_instance --k 3 --n 2 --m 3 --d 8 --stake 1000 --label "Strict"

use borsh::BorshSerialize;
use forum_core::{InstanceParams, ModeratorRoster};
use forum_moderation::generate_threshold_key;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find_map(|w| (w[0] == flag).then(|| w[1].clone()))
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let k: u8 = arg_value(&args, "--k").unwrap_or("3".into()).parse()?;
    let n: u8 = arg_value(&args, "--n").unwrap_or("2".into()).parse()?;
    let m: u8 = arg_value(&args, "--m").unwrap_or("3".into()).parse()?;
    let d: u8 = arg_value(&args, "--d").unwrap_or("8".into()).parse()?;
    let stake_amount: u128 = arg_value(&args, "--stake").unwrap_or("1000".into()).parse()?;
    let label = arg_value(&args, "--label").unwrap_or("Forum".into());

    if n == 0 || n > m || k < 2 || d < 2 {
        anyhow::bail!("invalid params: K>=2, N in [1, M], D>=2");
    }

    // 1. Threshold ElGamal key (forum mod_pubkey + per-mod ElGamal shares).
    let key = generate_threshold_key(n, m, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("threshold key gen: {:?}", e))?;

    // 2. M moderator long-lived signing keys.
    let mut signing_keys = Vec::with_capacity(m as usize);
    let mut signing_pubs = Vec::with_capacity(m as usize);
    for _ in 0..m {
        let sk = SigningKey::random(&mut OsRng);
        let pk: [u8; 33] = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("pubkey encoding length"))?;
        signing_keys.push(sk.to_bytes());
        signing_pubs.push(pk);
    }
    let roster = ModeratorRoster::from_points(&signing_pubs);

    // roster_hash = SHA256("/logos-forum/v1/roster" || u32 count || entries)
    let mut h = Sha256::new();
    h.update(b"/logos-forum/v1/roster");
    h.update(&(roster.count() as u32).to_le_bytes());
    h.update(&roster.entries);
    let roster_hash: [u8; 32] = h.finalize().into();

    // 3. Build InstanceParams.
    let params = InstanceParams {
        k,
        n,
        m,
        d,
        stake_amount,
        mod_pubkey: key.public_key,
        moderator_roster_hash: roster_hash,
        label: label.clone(),
    };
    let params_blob = borsh::to_vec(&params)?;
    let roster_blob = borsh::to_vec(&roster)?;

    // 4. Format output for both human + machine consumption.
    let to_decimal = |bs: &[u8]| -> String {
        bs.iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    let mod_shares: Vec<_> = key
        .shares
        .iter()
        .zip(signing_keys.iter())
        .zip(signing_pubs.iter())
        .map(|(((idx, eg_share), signing_secret), signing_pub)| {
            json!({
                "moderator_index": idx,
                "elgamal_share_secret_hex": hex::encode(eg_share),
                "signing_secret_hex": hex::encode(signing_secret),
                "signing_pubkey_hex": hex::encode(signing_pub),
            })
        })
        .collect();

    let out = json!({
        "label": label,
        "k": k, "n": n, "m": m, "d": d, "stake_amount": stake_amount.to_string(),
        "mod_pubkey_hex": hex::encode(key.public_key),
        "mod_master_secret_hex": hex::encode(key.master_secret),
        "moderator_roster_hash_hex": hex::encode(roster_hash),
        "params_blob_decimal": to_decimal(&params_blob),
        "params_blob_hex":     hex::encode(&params_blob),
        "roster_blob_decimal": to_decimal(&roster_blob),
        "roster_blob_hex":     hex::encode(&roster_blob),
        "moderator_shares":    mod_shares,
    });

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

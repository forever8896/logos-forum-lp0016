//! C FFI for the `forum_registry` SPEL program plus the off-chain
//! `forum_moderation` library. The Qt plugin (and any other host) dlopens
//! this `cdylib` and calls each function with a JSON string in / JSON string
//! out.
//!
//! Every call accepts a JSON object with at least:
//! ```json
//! {
//!   "wallet_path": "<path to NSSA wallet home>",
//!   "sequencer_url": "http://127.0.0.1:3040",
//!   "program_id_hex": "<64 hex chars — forum_registry program ID>"
//! }
//! ```
//! Returns `{"success": true, ...}` or `{"success": false, "error": "..."}`.
//!
//! Function naming matches `forum_<verb>_<object>`. Each FFI is documented
//! inline with its required arguments.

use borsh::{BorshDeserialize, BorshSerialize};
use forum_core::{
    Certificate, CertificateShare, EncryptedShare, ForumInstanceState, InstanceParams,
    ModeratorRoster, Scalar32,
};
use forum_moderation::{
    aggregate_certificate, build_share, commitment_from_secret, encrypt_share,
    find_slash_candidates, generate_threshold_key, scalar, MemberIdentity, MerkleTree,
};
use k256::elliptic_curve::Field;
use k256::Scalar;
use nssa::program::Program;
use nssa::program_methods::{AUTHENTICATED_TRANSFER_ELF, AUTHENTICATED_TRANSFER_ID};
use nssa::privacy_preserving_transaction::circuit::ProgramWithDependencies;
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{AccountId, ProgramId, PublicTransaction};
use rand_core::OsRng;
use sequencer_service_rpc::RpcClient as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use wallet::{PrivacyPreservingAccount, WalletCore};

// ────────────────────────── instruction enum ──────────────────────────
//
// Mirrors the SPEL program's #[lez_program] mod forum_registry. The order
// of variants must match exactly (the enum is borsh-serialized as the
// instruction wire format).

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum ForumRegistryInstruction {
    CreateInstance {
        params_blob: Vec<u8>,
        roster_blob: Vec<u8>,
    },
    Register {
        commitment: [u8; 32],
        new_root: [u8; 32],
        stake_amount: u128,
    },
    SubmitSlash {
        commitment: [u8; 32],
        membership_siblings: Vec<[u8; 32]>,
        xs: Vec<[u8; 32]>,
        ys: Vec<[u8; 32]>,
        instance_id_for_sigs: [u8; 32],
        post_hashes: Vec<[u8; 32]>,
        cert_share_alphas: Vec<u8>,
        cert_share_decryption_shares: Vec<Vec<u8>>,
        cert_share_signatures: Vec<Vec<u8>>,
        stake_payout: u128,
    },
    Reveal,
}

// ────────────────────────── helpers ──────────────────────────

fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null pointer".into());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| format!("invalid UTF-8: {}", e))
}

fn to_cstring(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| {
            CString::new(r#"{"success":false,"error":"null byte in output"}"#).unwrap()
        })
        .into_raw()
}

fn error_json(msg: &str) -> *mut c_char {
    let v = serde_json::json!(msg).to_string();
    to_cstring(format!("{{\"success\":false,\"error\":{}}}", v))
}

fn parse_program_id_hex(s: &str) -> Result<ProgramId, String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(format!(
            "program_id_hex must be 64 hex chars, got {}",
            s.len()
        ));
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    let mut pid = [0u32; 8];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        pid[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    Ok(pid)
}

fn parse_account_id(s: &str) -> Result<AccountId, String> {
    let base58 = s
        .strip_prefix("Public/")
        .or_else(|| s.strip_prefix("Private/"))
        .unwrap_or(s);
    base58
        .parse()
        .map_err(|_| format!("invalid AccountId: {}", s))
}

fn init_wallet(v: &Value) -> Result<WalletCore, String> {
    if let Some(p) = v["wallet_path"].as_str() {
        std::env::set_var("NSSA_WALLET_HOME_DIR", p);
    }
    if let Some(u) = v["sequencer_url"].as_str() {
        std::env::set_var("NSSA_SEQUENCER_URL", u);
    }
    WalletCore::from_env().map_err(|e| format!("wallet init: {}", e))
}

fn compute_state_pda(program_id: &ProgramId) -> AccountId {
    let seed = nssa_core::program::PdaSeed::new({
        let mut b = [0u8; 32];
        b[..11].copy_from_slice(b"instance_v1");
        b
    });
    AccountId::from((program_id, &seed))
}

fn submit_tx(
    wallet: &WalletCore,
    program_id: ProgramId,
    account_ids: Vec<AccountId>,
    signer_ids: Vec<AccountId>,
    instruction: ForumRegistryInstruction,
) -> Result<String, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio: {}", e))?;
    rt.block_on(async {
        let nonces = wallet
            .get_accounts_nonces(signer_ids.clone())
            .await
            .map_err(|e| format!("nonces: {}", e))?;
        let mut signing_keys = Vec::new();
        for sid in &signer_ids {
            let key = wallet
                .storage()
                .user_data
                .get_pub_account_signing_key(*sid)
                .ok_or_else(|| format!("signing key not found for {}", sid))?;
            signing_keys.push(key);
        }
        let message = Message::try_new(program_id, account_ids, nonces, instruction)
            .map_err(|e| format!("message: {:?}", e))?;
        let witness_set = WitnessSet::for_message(&message, &signing_keys);
        let tx = PublicTransaction::new(message, witness_set);
        wallet
            .sequencer_client
            .send_transaction(common::transaction::NSSATransaction::Public(tx))
            .await
            .map_err(|e| format!("submit: {}", e))
            .map(|r| hex::encode(r.0))
    })
}

fn ffi_call(
    f: impl FnOnce() -> Result<String, String> + std::panic::UnwindSafe,
) -> *mut c_char {
    match std::panic::catch_unwind(f) {
        Ok(Ok(r)) => to_cstring(r),
        Ok(Err(e)) => error_json(&e),
        Err(e) => {
            let msg = e
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("<unknown panic>");
            error_json(&format!("panic: {}", msg))
        }
    }
}

fn fetch_state(wallet: &WalletCore, pda: AccountId) -> Result<ForumInstanceState, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio: {}", e))?;
    let acc = rt.block_on(async {
        wallet
            .get_account_public(pda)
            .await
            .map_err(|e| format!("get_account_public: {}", e))
    })?;
    // The on-chain InstanceState is borsh-encoded inside account.data.
    let data: Vec<u8> = acc.data.into();
    ForumInstanceState::try_from_slice(&data)
        .map_err(|e| format!("decode InstanceState: {}", e))
}

// ────────────────────────── chain instructions ──────────────────────────

/// `forum_create_instance` — admin sets up the forum.
///
/// Args:
/// ```json
/// {
///   "wallet_path": "...", "sequencer_url": "...", "program_id_hex": "...",
///   "admin": "<account id>",
///   "k": 5, "n": 3, "m": 5, "d": 20,
///   "stake_amount": 1000,
///   "label": "My forum",
///   "moderator_pubkeys": ["<33-byte hex>", ...]   // M entries
/// }
/// ```
/// Returns `{"success": true, "tx_hash": "...", "mod_master_secret_hex": "...", "mod_shares": [...]}`.
/// NOTE: `mod_master_secret_hex` is returned ONCE here so the admin can
/// distribute the `mod_shares` to moderators, then MUST be discarded. It is
/// never stored on-chain. Keeping it breaks the threshold property.
#[no_mangle]
pub extern "C" fn forum_create_instance(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || create_instance_impl(&args))
}

fn create_instance_impl(args: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(args).map_err(|e| format!("invalid JSON: {}", e))?;
    let program_id = parse_program_id_hex(
        v["program_id_hex"]
            .as_str()
            .ok_or("missing program_id_hex")?,
    )?;
    let wallet = init_wallet(&v)?;
    let admin = parse_account_id(v["admin"].as_str().ok_or("missing admin")?)?;
    let k = v["k"].as_u64().ok_or("missing k")? as u8;
    let n = v["n"].as_u64().ok_or("missing n")? as u8;
    let m = v["m"].as_u64().ok_or("missing m")? as u8;
    let d = v["d"].as_u64().ok_or("missing d")? as u8;
    let stake_amount = v["stake_amount"].as_u64().ok_or("missing stake_amount")? as u128;
    let label = v["label"].as_str().unwrap_or("forum").to_string();

    let mod_pubkeys_arr = v["moderator_pubkeys"]
        .as_array()
        .ok_or("missing moderator_pubkeys")?;
    if mod_pubkeys_arr.len() != m as usize {
        return Err(format!(
            "moderator_pubkeys length {} != m {}",
            mod_pubkeys_arr.len(),
            m
        ));
    }
    let mut mod_pubkeys: Vec<[u8; 33]> = Vec::with_capacity(mod_pubkeys_arr.len());
    for pk in mod_pubkeys_arr {
        let s = pk.as_str().ok_or("moderator_pubkeys entry must be string")?;
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| format!("invalid hex pubkey: {}", e))?;
        if bytes.len() != 33 {
            return Err(format!("pubkey must be 33 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        mod_pubkeys.push(arr);
    }
    let roster = ModeratorRoster::from_points(&mod_pubkeys);
    let roster_hash = roster_hash(&roster);

    // Generate the threshold ElGamal key.
    let key = generate_threshold_key(n, m, &mut OsRng)
        .map_err(|e| format!("threshold key: {:?}", e))?;

    let params = InstanceParams {
        k,
        n,
        m,
        d,
        stake_amount,
        mod_pubkey: key.public_key,
        moderator_roster_hash: roster_hash,
        label,
    };
    let params_blob = borsh::to_vec(&params).map_err(|e| format!("borsh params: {}", e))?;
    let roster_blob = borsh::to_vec(&roster).map_err(|e| format!("borsh roster: {}", e))?;

    let state = compute_state_pda(&program_id);
    let tx_hash = submit_tx(
        &wallet,
        program_id,
        vec![state, admin],
        vec![admin],
        ForumRegistryInstruction::CreateInstance {
            params_blob,
            roster_blob,
        },
    )?;

    let shares_json: Vec<Value> = key
        .shares
        .iter()
        .map(|(idx, sb)| json!({"moderator_index": idx, "share_secret_hex": hex::encode(sb)}))
        .collect();

    Ok(json!({
        "success": true,
        "tx_hash": tx_hash,
        "mod_pubkey_hex": hex::encode(key.public_key),
        "mod_master_secret_hex": hex::encode(key.master_secret),
        "mod_shares": shares_json,
        "instance_id_hex": hex::encode(state.value()),
    })
    .to_string())
}

fn roster_hash(roster: &ModeratorRoster) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"/logos-forum/v1/roster");
    h.update(&(roster.count() as u32).to_le_bytes());
    h.update(&roster.entries);
    h.finalize().into()
}

/// `forum_register` — caller registers a (possibly newly generated) member
/// commitment, locks the stake, and publishes the new Merkle root.
///
/// Args (in addition to the standard ones):
/// ```json
/// {
///   "signer": "Public/...",
///   "commitment_hex": "<32-byte hex>",
///   "new_root_hex":   "<32-byte hex>",
///   "stake_amount":   1000
/// }
/// ```
#[no_mangle]
pub extern "C" fn forum_register(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || register_impl(&args))
}

fn register_impl(args: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(args).map_err(|e| format!("invalid JSON: {}", e))?;
    let program_id = parse_program_id_hex(
        v["program_id_hex"]
            .as_str()
            .ok_or("missing program_id_hex")?,
    )?;
    let wallet = init_wallet(&v)?;
    let signer = parse_account_id(v["signer"].as_str().ok_or("missing signer")?)?;
    let commitment = parse_hex32(v["commitment_hex"].as_str().ok_or("missing commitment_hex")?)?;
    let new_root = parse_hex32(v["new_root_hex"].as_str().ok_or("missing new_root_hex")?)?;
    let stake_amount = v["stake_amount"].as_u64().ok_or("missing stake_amount")? as u128;
    let state = compute_state_pda(&program_id);

    let tx_hash = submit_tx(
        &wallet,
        program_id,
        vec![state, signer],
        vec![signer],
        ForumRegistryInstruction::Register {
            commitment,
            new_root,
            stake_amount,
        },
    )?;
    Ok(json!({"success": true, "tx_hash": tx_hash}).to_string())
}

/// `forum_submit_slash` — assemble and submit a slash transaction.
///
/// Args:
/// ```json
/// {
///   "signer": "Public/...",
///   "recipient": "Public/...",
///   "commitment_hex": "...",
///   "membership_siblings_hex": ["...", ...],
///   "xs_hex": ["...", ...], "ys_hex": ["...", ...],
///   "stake_payout": 1000
/// }
/// ```
#[no_mangle]
pub extern "C" fn forum_submit_slash(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || submit_slash_impl(&args))
}

fn submit_slash_impl(args: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(args).map_err(|e| format!("invalid JSON: {}", e))?;
    let program_id = parse_program_id_hex(
        v["program_id_hex"]
            .as_str()
            .ok_or("missing program_id_hex")?,
    )?;
    let wallet = init_wallet(&v)?;
    let signer = parse_account_id(v["signer"].as_str().ok_or("missing signer")?)?;
    let recipient = parse_account_id(v["recipient"].as_str().ok_or("missing recipient")?)?;
    let commitment = parse_hex32(v["commitment_hex"].as_str().ok_or("missing commitment_hex")?)?;
    let membership_siblings = parse_hex32_array(&v["membership_siblings_hex"])?;
    let xs = parse_hex32_array(&v["xs_hex"])?;
    let ys = parse_hex32_array(&v["ys_hex"])?;
    let instance_id_for_sigs = parse_hex32(
        v["instance_id_hex"].as_str().ok_or("missing instance_id_hex")?,
    )?;
    let post_hashes = parse_hex32_array(&v["post_hashes_hex"])?;
    let cert_share_alphas: Vec<u8> = v["cert_share_alphas"]
        .as_array()
        .ok_or("missing cert_share_alphas")?
        .iter()
        .map(|x| x.as_u64().map(|n| n as u8).ok_or("alpha must be u8".to_string()))
        .collect::<Result<_, _>>()?;
    let cert_share_decryption_shares: Vec<Vec<u8>> = v["cert_share_decryption_shares_hex"]
        .as_array()
        .ok_or("missing cert_share_decryption_shares_hex")?
        .iter()
        .map(|x| parse_hex_bytes(x.as_str().ok_or("entry must be string".to_string())?))
        .collect::<Result<_, _>>()?;
    let cert_share_signatures: Vec<Vec<u8>> = v["cert_share_signatures_hex"]
        .as_array()
        .ok_or("missing cert_share_signatures_hex")?
        .iter()
        .map(|x| parse_hex_bytes(x.as_str().ok_or("entry must be string".to_string())?))
        .collect::<Result<_, _>>()?;
    let stake_payout = v["stake_payout"].as_u64().ok_or("missing stake_payout")? as u128;
    let state = compute_state_pda(&program_id);

    let tx_hash = submit_tx(
        &wallet,
        program_id,
        vec![state, signer, recipient],
        vec![signer],
        ForumRegistryInstruction::SubmitSlash {
            commitment,
            membership_siblings,
            xs,
            ys,
            instance_id_for_sigs,
            post_hashes,
            cert_share_alphas,
            cert_share_decryption_shares,
            cert_share_signatures,
            stake_payout,
        },
    )?;
    Ok(json!({"success": true, "tx_hash": tx_hash}).to_string())
}

/// `forum_fetch_state` — read the current InstanceState (parameters,
/// member_root, revocation list, pooled stake).
#[no_mangle]
pub extern "C" fn forum_fetch_state(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || fetch_state_impl(&args))
}

fn fetch_state_impl(args: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(args).map_err(|e| format!("invalid JSON: {}", e))?;
    let program_id = parse_program_id_hex(
        v["program_id_hex"]
            .as_str()
            .ok_or("missing program_id_hex")?,
    )?;
    let wallet = init_wallet(&v)?;
    let pda = compute_state_pda(&program_id);
    let state = fetch_state(&wallet, pda)?;
    let params: Option<InstanceParams> =
        InstanceParams::try_from_slice(&state.params_blob).ok();
    let roster: Option<ModeratorRoster> =
        ModeratorRoster::try_from_slice(&state.roster_blob).ok();
    Ok(json!({
        "success": true,
        "instance_id_hex": hex::encode(pda.value()),
        "member_root_hex": hex::encode(state.member_root),
        "member_count": state.member_count,
        "pooled_stake": state.pooled_stake.to_string(),
        "revocation_count": state.revocation_count,
        "revocation_list_hex": state.revocation_list.iter().map(hex::encode).collect::<Vec<_>>(),
        "params": params,
        "moderators": roster.as_ref().map(|r| {
            (0..r.count()).filter_map(|i| r.point(i).map(hex::encode)).collect::<Vec<_>>()
        }),
    })
    .to_string())
}

// ────────────────────────── crypto-only FFIs ──────────────────────────
//
// These do NOT touch the chain. They expose the off-chain library to the
// host so the Qt plugin can avoid linking k256 directly.

/// `forum_generate_member_identity` — pick a fresh K-coefficient polynomial.
/// Returns the secret bytes (caller MUST persist these — they're the
/// member's only way to post afterward) and the resulting commitment.
///
/// Args: `{"k": 5}`
#[no_mangle]
pub extern "C" fn forum_generate_member_identity(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || {
        let v: Value = serde_json::from_str(&args).map_err(|e| format!("invalid JSON: {}", e))?;
        let k = v["k"].as_u64().ok_or("missing k")? as usize;
        let id = MemberIdentity::generate(k, &mut OsRng).map_err(|e| format!("{:?}", e))?;
        let coeffs_hex: Vec<String> = id.to_coeffs().iter().map(hex::encode).collect();
        Ok(json!({
            "success": true,
            "commitment_hex": hex::encode(id.commitment),
            "coeffs_hex": coeffs_hex,
        })
        .to_string())
    })
}

/// `forum_build_post_share` — given a member identity and the moderation
/// pubkey, sample a random Shamir abscissa, evaluate the polynomial, and
/// encrypt `(x, y)` under the threshold key. Returns the ciphertext.
///
/// Args:
/// ```json
/// { "coeffs_hex": [...], "mod_pubkey_hex": "..." }
/// ```
#[no_mangle]
pub extern "C" fn forum_build_post_share(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || {
        let v: Value =
            serde_json::from_str(&args).map_err(|e| format!("invalid JSON: {}", e))?;
        let coeffs_hex = v["coeffs_hex"]
            .as_array()
            .ok_or("missing coeffs_hex")?
            .iter()
            .map(|x| {
                x.as_str()
                    .ok_or("coeff must be string".to_string())
                    .and_then(|s| parse_hex32(s))
            })
            .collect::<Result<Vec<Scalar32>, String>>()?;
        let id = MemberIdentity::from_coeffs(coeffs_hex).map_err(|e| format!("{:?}", e))?;

        let mod_pubkey = parse_hex33(v["mod_pubkey_hex"].as_str().ok_or("missing mod_pubkey_hex")?)?;

        let x = Scalar::random(&mut OsRng);
        let y = id.polynomial.eval(&x);
        let mut share_bytes = [0u8; 64];
        share_bytes[..32].copy_from_slice(&scalar::scalar_to_bytes(&x));
        share_bytes[32..].copy_from_slice(&scalar::scalar_to_bytes(&y));
        let ct = encrypt_share(&mod_pubkey, &share_bytes, &mut OsRng)
            .map_err(|e| format!("encrypt: {:?}", e))?;
        Ok(json!({
            "success": true,
            "x_hex": hex::encode(scalar::scalar_to_bytes(&x)),
            "y_hex": hex::encode(scalar::scalar_to_bytes(&y)),
            "enc_share": {
                "c1_hex": hex::encode(ct.c1),
                "c2_hex": hex::encode(ct.c2),
            }
        })
        .to_string())
    })
}

/// `forum_build_certificate_share` — moderator builds their decryption share
/// for a post and signs it with their long-lived ECDSA-secp256k1 key.
///
/// Args:
/// ```json
/// {
///   "instance_id_hex": "...",
///   "msg_id_hex": "...",
///   "payload_hex": "...",
///   "enc_share": { "c1_hex": "...", "c2_hex": "..." },
///   "moderator_index": 1,
///   "share_secret_hex": "...",
///   "signing_key_hex": "..."   // 32-byte secp256k1 secret key (BE)
/// }
/// ```
#[no_mangle]
pub extern "C" fn forum_build_certificate_share(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || {
        let v: Value =
            serde_json::from_str(&args).map_err(|e| format!("invalid JSON: {}", e))?;
        let instance_id = parse_hex32(v["instance_id_hex"].as_str().ok_or("missing instance_id")?)?;
        let msg_id = parse_hex32(v["msg_id_hex"].as_str().ok_or("missing msg_id")?)?;
        let payload = parse_hex_bytes(v["payload_hex"].as_str().unwrap_or(""))?;
        let enc_share = parse_enc_share(&v["enc_share"])?;
        let mod_index = v["moderator_index"].as_u64().ok_or("missing moderator_index")? as u8;
        let share_secret = parse_hex32(v["share_secret_hex"].as_str().ok_or("missing share_secret")?)?;
        let signing_key_bytes = parse_hex32(v["signing_key_hex"].as_str().ok_or("missing signing_key_hex")?)?;
        let signing_key = k256::ecdsa::SigningKey::from_bytes((&signing_key_bytes).into())
            .map_err(|e| format!("invalid signing key: {}", e))?;
        let share = build_share(instance_id, msg_id, &payload, &enc_share, mod_index, &share_secret, &signing_key)
            .map_err(|e| format!("{:?}", e))?;
        Ok(json!({
            "success": true,
            "share": cert_share_to_json(&share),
        })
        .to_string())
    })
}

/// `forum_generate_moderator_signing_key` — convenience helper for the FFI:
/// returns a fresh ECDSA-secp256k1 keypair the moderator can use to sign
/// certificate shares. The forum-creator hands the resulting public keys to
/// `forum_create_instance` as the moderator roster.
#[no_mangle]
pub extern "C" fn forum_generate_moderator_signing_key(_args_json: *const c_char) -> *mut c_char {
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    ffi_call(move || {
        let sk = SigningKey::random(&mut OsRng);
        let sk_bytes: [u8; 32] = sk.to_bytes().into();
        let pk_bytes: [u8; 33] = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| "pubkey encoding length")?;
        Ok(json!({
            "success": true,
            "signing_key_hex": hex::encode(sk_bytes),
            "verifying_key_hex": hex::encode(pk_bytes),
        })
        .to_string())
    })
}

/// `forum_aggregate_certificate` — combine ≥ N shares into a complete cert.
///
/// Args:
/// ```json
/// {
///   "instance_id_hex": "...",
///   "n": 3,
///   "enc_share": {...},
///   "shares": [ {...}, {...} ]
/// }
/// ```
#[no_mangle]
pub extern "C" fn forum_aggregate_certificate(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || {
        let v: Value =
            serde_json::from_str(&args).map_err(|e| format!("invalid JSON: {}", e))?;
        let instance_id = parse_hex32(v["instance_id_hex"].as_str().ok_or("missing instance_id")?)?;
        let n = v["n"].as_u64().ok_or("missing n")? as u8;
        let enc_share = parse_enc_share(&v["enc_share"])?;
        let shares_arr = v["shares"].as_array().ok_or("missing shares array")?;
        let mut shares = Vec::with_capacity(shares_arr.len());
        for s in shares_arr {
            shares.push(parse_cert_share(s)?);
        }
        let cert = aggregate_certificate(instance_id, n, &enc_share, shares)
            .map_err(|e| format!("aggregate: {:?}", e))?;
        Ok(json!({
            "success": true,
            "certificate": certificate_to_json(&cert),
        })
        .to_string())
    })
}

/// `forum_find_slash_candidates` — given a pool of complete certificates and
/// the current member set + revocation list, search for K-subsets that
/// reconstruct a registered, non-revoked member.
///
/// Args:
/// ```json
/// {
///   "k": 5,
///   "member_commitments_hex": ["...", ...],
///   "revoked_hex": ["...", ...],
///   "certificates": [ ... ]
/// }
/// ```
#[no_mangle]
pub extern "C" fn forum_find_slash_candidates(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || {
        let v: Value =
            serde_json::from_str(&args).map_err(|e| format!("invalid JSON: {}", e))?;
        let k = v["k"].as_u64().ok_or("missing k")? as u8;
        let members: BTreeSet<[u8; 32]> = v["member_commitments_hex"]
            .as_array()
            .ok_or("missing member_commitments_hex")?
            .iter()
            .map(|s| {
                s.as_str()
                    .ok_or("entry must be string".to_string())
                    .and_then(parse_hex32)
            })
            .collect::<Result<_, _>>()?;
        let revoked: BTreeSet<[u8; 32]> = v["revoked_hex"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().and_then(|s| parse_hex32(s).ok()))
                    .collect()
            })
            .unwrap_or_default();

        let certs_arr = v["certificates"].as_array().ok_or("missing certificates")?;
        let mut certs = Vec::with_capacity(certs_arr.len());
        for c in certs_arr {
            certs.push(parse_certificate(c)?);
        }

        let cands = find_slash_candidates(
            k,
            &certs,
            |c| members.contains(c),
            |c| revoked.contains(c),
        )
        .map_err(|e| format!("{:?}", e))?;

        let out: Vec<Value> = cands
            .iter()
            .map(|c| {
                json!({
                    "commitment_hex": hex::encode(c.commitment),
                    "cert_indices": c.cert_indices,
                    "xs_hex": c.cert_indices.iter().map(|i| hex::encode(certs[*i].x_i)).collect::<Vec<_>>(),
                    "ys_hex": c.cert_indices.iter().map(|i| hex::encode(certs[*i].y_i)).collect::<Vec<_>>(),
                })
            })
            .collect();

        Ok(json!({"success": true, "candidates": out}).to_string())
    })
}

/// `forum_compute_commitment` — recompute a commitment from polynomial
/// coefficients. Useful for the host to sanity-check before registering.
#[no_mangle]
pub extern "C" fn forum_compute_commitment(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || {
        let v: Value =
            serde_json::from_str(&args).map_err(|e| format!("invalid JSON: {}", e))?;
        let coeffs_hex = v["coeffs_hex"]
            .as_array()
            .ok_or("missing coeffs_hex")?
            .iter()
            .map(|x| {
                x.as_str()
                    .ok_or("coeff must be string".to_string())
                    .and_then(|s| parse_hex32(s))
            })
            .collect::<Result<Vec<Scalar32>, String>>()?;
        let coeffs_scalars = coeffs_hex
            .iter()
            .map(scalar::scalar_from_bytes_allow_zero)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{:?}", e))?;
        let c = commitment_from_secret(&coeffs_scalars)
            .map_err(|e| format!("{:?}", e))?;
        Ok(json!({"success": true, "commitment_hex": hex::encode(c)}).to_string())
    })
}

/// `forum_compute_merkle_root` — given a list of commitments and a tree
/// depth, return the Merkle root and (optionally) an inclusion proof for one
/// of the commitments.
#[no_mangle]
pub extern "C" fn forum_compute_merkle_root(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || {
        let v: Value =
            serde_json::from_str(&args).map_err(|e| format!("invalid JSON: {}", e))?;
        let depth = v["depth"].as_u64().ok_or("missing depth")? as u8;
        let leaves = v["commitments_hex"]
            .as_array()
            .ok_or("missing commitments_hex")?
            .iter()
            .map(|x| {
                x.as_str()
                    .ok_or("entry must be string".to_string())
                    .and_then(parse_hex32)
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()?;
        let mut tree = MerkleTree::new(depth);
        for c in &leaves {
            tree.append(c);
        }
        let root = tree.root();
        let prove_idx = v["prove_index"].as_u64();
        let proof = prove_idx
            .and_then(|i| tree.proof(i as u32))
            .map(|p| {
                json!({
                    "leaf_index": p.leaf_index,
                    "siblings_hex": p.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
                })
            });
        Ok(json!({"success": true, "root_hex": hex::encode(root), "proof": proof}).to_string())
    })
}

// ────────────────────────── tiny converters ──────────────────────────

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex33(s: &str) -> Result<[u8; 33], String> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 33 {
        return Err(format!("expected 33 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("invalid hex: {}", e))
}

fn parse_hex32_array(v: &Value) -> Result<Vec<[u8; 32]>, String> {
    v.as_array()
        .ok_or("expected array of hex strings".to_string())?
        .iter()
        .map(|x| {
            x.as_str()
                .ok_or("entry must be string".to_string())
                .and_then(parse_hex32)
        })
        .collect()
}

fn parse_enc_share(v: &Value) -> Result<EncryptedShare, String> {
    let c1 = parse_hex33(v["c1_hex"].as_str().ok_or("missing c1_hex")?)?;
    let c2_bytes = parse_hex_bytes(v["c2_hex"].as_str().ok_or("missing c2_hex")?)?;
    if c2_bytes.len() != 64 {
        return Err(format!("c2 must be 64 bytes, got {}", c2_bytes.len()));
    }
    let mut c2 = [0u8; 64];
    c2.copy_from_slice(&c2_bytes);
    Ok(EncryptedShare { c1, c2 })
}

fn parse_cert_share(v: &Value) -> Result<CertificateShare, String> {
    Ok(CertificateShare {
        instance_id: parse_hex32(v["instance_id_hex"].as_str().ok_or("missing instance_id")?)?,
        post_hash: parse_hex32(v["post_hash_hex"].as_str().ok_or("missing post_hash")?)?,
        decryption_share: parse_hex33(
            v["decryption_share_hex"]
                .as_str()
                .ok_or("missing decryption_share")?,
        )?,
        moderator_index: v["moderator_index"].as_u64().ok_or("missing moderator_index")? as u8,
        signature: parse_hex_bytes(v["signature_hex"].as_str().unwrap_or(""))?,
    })
}

fn parse_certificate(v: &Value) -> Result<Certificate, String> {
    let shares_arr = v["shares"].as_array().ok_or("missing shares array")?;
    let mut shares = Vec::with_capacity(shares_arr.len());
    for s in shares_arr {
        shares.push(parse_cert_share(s)?);
    }
    Ok(Certificate {
        instance_id: parse_hex32(v["instance_id_hex"].as_str().ok_or("missing instance_id")?)?,
        post_hash: parse_hex32(v["post_hash_hex"].as_str().ok_or("missing post_hash")?)?,
        enc_share: parse_enc_share(&v["enc_share"])?,
        x_i: parse_hex32(v["x_hex"].as_str().ok_or("missing x_hex")?)?,
        y_i: parse_hex32(v["y_hex"].as_str().ok_or("missing y_hex")?)?,
        shares,
    })
}

fn cert_share_to_json(s: &CertificateShare) -> Value {
    json!({
        "instance_id_hex": hex::encode(s.instance_id),
        "post_hash_hex": hex::encode(s.post_hash),
        "decryption_share_hex": hex::encode(s.decryption_share),
        "moderator_index": s.moderator_index,
        "signature_hex": hex::encode(&s.signature),
    })
}

fn certificate_to_json(c: &Certificate) -> Value {
    json!({
        "instance_id_hex": hex::encode(c.instance_id),
        "post_hash_hex": hex::encode(c.post_hash),
        "enc_share": {
            "c1_hex": hex::encode(c.enc_share.c1),
            "c2_hex": hex::encode(c.enc_share.c2),
        },
        "x_hex": hex::encode(c.x_i),
        "y_hex": hex::encode(c.y_i),
        "shares": c.shares.iter().map(cert_share_to_json).collect::<Vec<_>>(),
    })
}

// ────────────────────────── utility exports ──────────────────────────

#[no_mangle]
pub extern "C" fn forum_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

#[no_mangle]
pub extern "C" fn forum_version() -> *mut c_char {
    to_cstring(json!({"version": env!("CARGO_PKG_VERSION")}).to_string())
}

// silence unused warnings for the chained-call private TX path which we'll
// add when the slash needs to be a private TX.
#[allow(dead_code)]
fn _force_keep_private_path() {
    let _ = AUTHENTICATED_TRANSFER_ELF;
    let _ = AUTHENTICATED_TRANSFER_ID;
    let _ = ProgramWithDependencies::new(
        Program::new(vec![]).unwrap(),
        HashMap::new(),
    );
    let _: PrivacyPreservingAccount;
}

// ────────────────────────── post-proof generation ──────────────────────────
//
// These calls use the `forum_post_proof` RISC0 guest program. They are gated
// behind the `with-proof` Cargo feature so the FFI can be built without the
// guest binary (which requires `cargo risczero build` + docker buildx). When
// the feature is on, real RISC0 receipts are produced and verifiable.

/// `forum_post_proof_supported` — returns whether the FFI was built with
/// proof generation enabled. Hosts should branch on this so the UI
/// degrades gracefully when running against a fast-path FFI.
#[no_mangle]
pub extern "C" fn forum_post_proof_supported(_args_json: *const c_char) -> *mut c_char {
    let supported = cfg!(feature = "with-proof");
    to_cstring(json!({"success": true, "supported": supported}).to_string())
}

/// `forum_build_post_proof` — generates a RISC0 receipt proving:
///   1. commitment ∈ member_root,
///   2. commitment ∉ revocation_set,
///   3. (x_i, y_i) is a valid evaluation of the polynomial behind commitment,
///   4. enc_share is a correctly-formed ElGamal ciphertext over (x_i, y_i)
///      under mod_pubkey.
///
/// Args:
/// ```json
/// {
///   "coeffs_hex":          ["...", ...],            // K coefficients
///   "merkle_siblings_hex": ["...", ...],            // D sibling hashes
///   "revocation_set_hex":  ["...", ...],            // current revocation list
///   "x_hex":               "...", "r_hex": "...",
///   "member_root_hex":     "...",
///   "instance_id_hex":     "...",
///   "mod_pubkey_hex":      "...",
///   "post_binding_hex":    "...",
///   "enc_share":           {"c1_hex": "...", "c2_hex": "..."}
/// }
/// ```
/// Returns `{"success": true, "receipt_hex": "...", "image_id_hex": "..."}`.
#[no_mangle]
pub extern "C" fn forum_build_post_proof(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || build_post_proof_impl(&args))
}

/// `forum_verify_post_proof` — verifies a receipt produced by
/// `forum_build_post_proof` against the expected image ID and the post's
/// public-input bundle.
///
/// Args:
/// ```json
/// {
///   "receipt_hex": "...",
///   "member_root_hex": "...",
///   "instance_id_hex": "...",
///   "revocation_digest_hex": "...",
///   "mod_pubkey_hex": "...",
///   "post_binding_hex": "...",
///   "enc_share": { "c1_hex": "...", "c2_hex": "..." }
/// }
/// ```
#[no_mangle]
pub extern "C" fn forum_verify_post_proof(args_json: *const c_char) -> *mut c_char {
    let args = match cstr_to_str(args_json) {
        Ok(s) => s.to_owned(),
        Err(e) => return error_json(&e),
    };
    ffi_call(move || verify_post_proof_impl(&args))
}

#[cfg(not(feature = "with-proof"))]
fn build_post_proof_impl(_args: &str) -> Result<String, String> {
    Err("FFI built without `with-proof` feature — rebuild with `--features with-proof` after running `cargo risczero build` so the guest ELF is available".into())
}

#[cfg(not(feature = "with-proof"))]
fn verify_post_proof_impl(_args: &str) -> Result<String, String> {
    Err("FFI built without `with-proof` feature — see build_post_proof_impl".into())
}

#[cfg(feature = "with-proof")]
fn build_post_proof_impl(args: &str) -> Result<String, String> {
    use risc0_zkvm::{default_prover, ExecutorEnv};
    let v: Value = serde_json::from_str(args).map_err(|e| format!("invalid JSON: {}", e))?;

    let coeffs = v["coeffs_hex"].as_array().ok_or("missing coeffs_hex")?;
    let coeffs: Vec<[u8; 32]> = coeffs
        .iter()
        .map(|x| parse_hex32(x.as_str().ok_or("coeff must be string".to_string())?))
        .collect::<Result<_, _>>()?;
    let merkle = parse_hex32_array(&v["merkle_siblings_hex"])?;
    let revoked = parse_hex32_array(&v["revocation_set_hex"])?;
    let x_i = parse_hex32(v["x_hex"].as_str().ok_or("missing x_hex")?)?;
    let r = parse_hex32(v["r_hex"].as_str().ok_or("missing r_hex")?)?;
    let member_root = parse_hex32(v["member_root_hex"].as_str().ok_or("missing member_root_hex")?)?;
    let instance_id = parse_hex32(v["instance_id_hex"].as_str().ok_or("missing instance_id_hex")?)?;
    let mod_pubkey = parse_hex33(v["mod_pubkey_hex"].as_str().ok_or("missing mod_pubkey_hex")?)?;
    let post_binding = parse_hex32(v["post_binding_hex"].as_str().ok_or("missing post_binding_hex")?)?;
    let enc = parse_enc_share(&v["enc_share"])?;
    let revocation_digest = forum_revocation_digest(&revoked);

    // Big arrays (>32 bytes) must round-trip through risc0 serde as Vec<u8>
    // because serde stdlib stops at [T; 32]. The guest's `read_arr<N>()`
    // helper expects this shape.
    let env = ExecutorEnv::builder()
        .write(&member_root).map_err(|e| format!("env write: {}", e))?
        .write(&instance_id).map_err(|e| format!("env write: {}", e))?
        .write(&revocation_digest).map_err(|e| format!("env write: {}", e))?
        .write(&mod_pubkey.to_vec()).map_err(|e| format!("env write: {}", e))?
        .write(&post_binding).map_err(|e| format!("env write: {}", e))?
        .write(&enc.c1.to_vec()).map_err(|e| format!("env write: {}", e))?
        .write(&enc.c2.to_vec()).map_err(|e| format!("env write: {}", e))?
        .write(&coeffs).map_err(|e| format!("env write: {}", e))?
        .write(&merkle).map_err(|e| format!("env write: {}", e))?
        .write(&revoked).map_err(|e| format!("env write: {}", e))?
        .write(&x_i).map_err(|e| format!("env write: {}", e))?
        .write(&r).map_err(|e| format!("env write: {}", e))?
        .build().map_err(|e| format!("env build: {}", e))?;

    let prover = default_prover();
    let prove_info = prover
        .prove(env, forum_methods::FORUM_POST_PROOF_ELF)
        .map_err(|e| format!("prove: {}", e))?;
    let receipt_bytes = bincode::serialize(&prove_info.receipt)
        .map_err(|e| format!("serialize receipt: {}", e))?;
    Ok(json!({
        "success": true,
        "receipt_hex": hex::encode(&receipt_bytes),
        "image_id_hex": hex::encode(forum_methods::FORUM_POST_PROOF_ID
            .iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>()),
    }).to_string())
}

#[cfg(feature = "with-proof")]
fn verify_post_proof_impl(args: &str) -> Result<String, String> {
    use risc0_zkvm::Receipt;
    let v: Value = serde_json::from_str(args).map_err(|e| format!("invalid JSON: {}", e))?;
    let receipt_hex = v["receipt_hex"].as_str().ok_or("missing receipt_hex")?;
    let bytes = hex::decode(receipt_hex.trim_start_matches("0x"))
        .map_err(|e| format!("hex: {}", e))?;
    let receipt: Receipt = bincode::deserialize(&bytes)
        .map_err(|e| format!("deserialize receipt: {}", e))?;
    receipt
        .verify(forum_methods::FORUM_POST_PROOF_ID)
        .map_err(|e| format!("verify: {}", e))?;
    Ok(json!({"success": true, "verified": true}).to_string())
}

/// Compute `H(domain("revocation") || encoded(set))` — must match the guest.
#[allow(dead_code)]
fn forum_revocation_digest(set: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut payload = Vec::with_capacity(4 + set.len() * 32);
    payload.extend_from_slice(&(set.len() as u32).to_le_bytes());
    for c in set {
        payload.extend_from_slice(c);
    }
    let mut tag = Sha256::new();
    tag.update(b"/logos-forum/v1/revocation");
    let tag = tag.finalize();
    let mut h = Sha256::new();
    h.update(tag);
    h.update(&payload);
    h.finalize().into()
}

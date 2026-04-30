//! Generates ONE per-post ZK membership proof against the `forum_post_proof`
//! RISC0 guest, measures wall-clock proving time, and verifies the resulting
//! receipt. Intended for the `RISC0_DEV_MODE=0` measurement called for in
//! the LP-0016 supportability criterion.
//!
//! Usage:
//!   RISC0_DEV_MODE=0 cargo run --release --bin measure_post_proof --features with-proof
//!
//! In dev mode (default), this exits immediately with a fake receipt and a
//! "DEV MODE — proof not verifiable" banner so the script doesn't accidentally
//! report fast numbers as real ones.

use forum_moderation::{
    commitment, generate_threshold_key, identity, merkle, scalar,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::time::Instant;

/// Mirrors `forum_moderation::threshold_elgamal::kdf64` (private). We reproduce
/// it here so we can build the ciphertext with a chosen `r` rather than the
/// random one `encrypt_share` picks internally — the guest needs to see the
/// same `r` we hash into c1.
fn kdf64(p: &ProjectivePoint) -> [u8; 64] {
    let aff = p.to_affine();
    let ep = aff.to_encoded_point(false); // 0x04 || X || Y
    let bytes = ep.as_bytes();
    let x: &[u8] = if bytes.len() == 65 { &bytes[1..33] } else { &[] };
    fn h(sub: &str, pieces: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"/logos-forum/v1/");
        h.update(sub.as_bytes());
        let tag: [u8; 32] = h.finalize().into();
        let mut h = Sha256::new();
        h.update(tag);
        for p in pieces {
            h.update(p);
        }
        h.finalize().into()
    }
    let h0 = h("share", &[x, &[0u8]]);
    let h1 = h("share", &[x, &[1u8]]);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h0);
    out[32..].copy_from_slice(&h1);
    out
}

#[cfg(feature = "with-proof")]
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

const K: usize = 3;
const D: u8 = 8;

fn main() -> anyhow::Result<()> {
    println!("== forum_post_proof measurement ==");

    #[cfg(not(feature = "with-proof"))]
    {
        eprintln!("ERROR: build with --features with-proof to actually measure proving");
        eprintln!("       cargo run --release --bin measure_post_proof --features with-proof");
        std::process::exit(2);
    }

    let dev_mode_raw = std::env::var("RISC0_DEV_MODE").unwrap_or_else(|_| "1".into());
    let dev_mode = dev_mode_raw != "0";
    println!("RISC0_DEV_MODE={} ({})", dev_mode_raw,
             if dev_mode { "DEV MODE — proofs are fake fast" }
             else        { "REAL PROVER — measurements are meaningful" });

    // Build a member identity + a tiny tree of just this member.
    let id = identity::MemberIdentity::generate(K, &mut OsRng)?;
    let mut tree = merkle::MerkleTree::new(D);
    let leaf_idx = tree.append(&id.commitment);
    let proof = tree.proof(leaf_idx).unwrap();
    let root = tree.root();

    // Threshold ElGamal key for the encrypted share.
    let key = generate_threshold_key(2, 3, &mut OsRng).map_err(|e| anyhow::anyhow!("{:?}", e))?;

    // Build a post share with a chosen `r` so we can pass it to the guest.
    let r_scalar = Scalar::random(&mut OsRng);
    let x = Scalar::random(&mut OsRng);
    let y = id.polynomial.eval(&x);
    let mut share_bytes = [0u8; 64];
    share_bytes[..32].copy_from_slice(&scalar::scalar_to_bytes(&x));
    share_bytes[32..].copy_from_slice(&scalar::scalar_to_bytes(&y));

    let q = scalar::projective_from_bytes(&key.public_key)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let c1_pt = ProjectivePoint::GENERATOR * r_scalar;
    let shared = q * r_scalar;
    let pad = kdf64(&shared);
    let mut c2 = [0u8; 64];
    for i in 0..64 {
        c2[i] = share_bytes[i] ^ pad[i];
    }
    let ct = forum_core::EncryptedShare {
        c1: scalar::point_to_bytes(&c1_pt),
        c2,
    };

    let coeffs_bytes: Vec<[u8; 32]> = id
        .polynomial
        .coeffs
        .iter()
        .map(|s| scalar::scalar_to_bytes(s))
        .collect();
    let revocation_set: Vec<[u8; 32]> = Vec::new();
    let revocation_digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"/logos-forum/v1/revocation");
        let tag: [u8; 32] = h.finalize().into();
        let mut h = Sha256::new();
        h.update(tag);
        h.update(&(revocation_set.len() as u32).to_le_bytes());
        let r: [u8; 32] = h.finalize().into();
        r
    };
    let r_bytes = scalar::scalar_to_bytes(&r_scalar);
    let x_bytes = scalar::scalar_to_bytes(&x);
    let post_binding = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"/logos-forum/v1/slash-binding");
        h.update([1u8; 32]); // msg_id
        h.update(b"hello forum"); // payload
        h.update(ct.c1);
        h.update(ct.c2);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    let instance_id = [0xAAu8; 32];

    // commitment is in the tree → sanity-check before proving
    debug_assert_eq!(commitment::commitment_from_secret(&id.polynomial.coeffs)?, id.commitment);
    debug_assert!(merkle::verify_inclusion(&id.commitment, &root, &proof));

    println!("witness ready: K={K}, D={D}, Merkle leaves=1");
    println!("public inputs: member_root={}, mod_pubkey={}", hex::encode(root), hex::encode(key.public_key));
    println!();

    #[cfg(feature = "with-proof")]
    {
        let env = ExecutorEnv::builder()
            .write(&root)?
            .write(&instance_id)?
            .write(&revocation_digest)?
            .write(&key.public_key.to_vec())?
            .write(&post_binding)?
            .write(&ct.c1.to_vec())?
            .write(&ct.c2.to_vec())?
            .write(&coeffs_bytes)?
            .write(&proof.siblings)?
            .write(&revocation_set)?
            .write(&x_bytes)?
            .write(&r_bytes)?
            .build()?;

        println!("proving…");
        let start = Instant::now();
        let prover = default_prover();
        let info = prover.prove(env, forum_methods::FORUM_POST_PROOF_ELF)?;
        let elapsed = start.elapsed();
        println!("✓ prove: {:?}", elapsed);

        let receipt: Receipt = info.receipt;
        let receipt_bytes = bincode::serialize(&receipt)?;
        println!("  receipt: {} bytes", receipt_bytes.len());

        println!("verifying…");
        let verify_start = Instant::now();
        receipt.verify(forum_methods::FORUM_POST_PROOF_ID)?;
        println!("✓ verify: {:?}", verify_start.elapsed());

        if dev_mode {
            eprintln!();
            eprintln!("⚠ ran in DEV MODE — re-run with RISC0_DEV_MODE=0 for real numbers");
        }
    }

    Ok(())
}

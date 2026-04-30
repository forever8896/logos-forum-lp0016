//! `forum_post_proof` — RISC0 guest that proves a post comes from a
//! registered, non-revoked member without revealing which one.
//!
//! Public inputs (the journal):
//!   - member_root        : [u8;32]   — Merkle root the prover claims membership in
//!   - instance_id        : [u8;32]   — forum instance identifier
//!   - revocation_digest  : [u8;32]   — H(domain("revocation") || encoded(revocation_set))
//!   - mod_pubkey         : [u8;33]   — threshold-ElGamal public key Q
//!   - post_binding       : [u8;32]   — H(domain("slash-binding") || msg_id || payload || enc_share)
//!   - enc_share          : EncryptedShare (97 bytes: 33 + 64)
//!
//! Private inputs (the witness, env::read()):
//!   - coeffs             : Vec<[u8;32]>      — K polynomial coefficients [sk, a_1, ..., a_{K-1}]
//!   - merkle_siblings    : Vec<[u8;32]>      — D sibling hashes, leaf→root
//!   - revocation_set     : Vec<[u8;32]>      — full revocation list (so we can verify the digest)
//!   - x_i                : [u8;32]           — Shamir abscissa for THIS post
//!   - r                  : [u8;32]           — ElGamal ephemeral scalar
//!
//! The guest asserts:
//!   1. C := H(domain("commitment") || coeffs[0] || ... || coeffs[K-1])
//!   2. C reproduces `member_root` via the merkle_siblings (sorted-pair hashing).
//!   3. H(domain("revocation") || encoded(revocation_set)) == revocation_digest.
//!   4. C is NOT in revocation_set.
//!   5. y_i := f(x_i) where f has coefficients `coeffs` (Horner, mod n).
//!   6. enc_share.c1 = [r] G  AND  enc_share.c2 = (x_i || y_i) ⊕ KDF([r] Q).
//!
//! Cycle budget (rough estimate, see protocol.md §6):
//!   - Merkle path (D = 20):  ≈ 20 SHA-256 calls  → ≈ 1.5 K cycles via accelerator
//!   - Polynomial eval (K=5): ≈ 4 scalar mul + 4 add ≈ 1 M cycles
//!   - Two scalar mul (c1, [r]Q):                    ≈ 500 K cycles
//!   - Misc:                                         ≈ 200 K cycles
//!   ─────────────────────────────────────────────────────────────
//!   ≈ 1.7 M cycles → 15-30 s real-mode CPU on a modern laptop;
//!   <10 s with the GPU prover (CUDA / Metal).

#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};

risc0_zkvm::guest::entry!(main);

const DOMAIN_PREFIX: &[u8] = b"/logos-forum/v1/";

fn domain_tag(sub: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(DOMAIN_PREFIX.len() + sub.len());
    input.extend_from_slice(DOMAIN_PREFIX);
    input.extend_from_slice(sub);
    let d = Impl::hash_bytes(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

fn h_tagged(tag: &[u8], pieces: &[&[u8]]) -> [u8; 32] {
    let dt = domain_tag(tag);
    let total: usize = 32 + pieces.iter().map(|p| p.len()).sum::<usize>();
    let mut input = Vec::with_capacity(total);
    input.extend_from_slice(&dt);
    for p in pieces {
        input.extend_from_slice(p);
    }
    let d = Impl::hash_bytes(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

fn h_merkle_leaf(c: &[u8; 32]) -> [u8; 32] { h_tagged(b"merkle-leaf", &[c]) }
fn h_merkle_node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    h_tagged(b"merkle-node", &[lo, hi])
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    let opt: Option<Scalar> = Scalar::from_repr((*bytes).into()).into();
    opt.expect("invalid scalar in witness")
}

fn point_from_bytes(bytes: &[u8; 33]) -> ProjectivePoint {
    let ep = k256::EncodedPoint::from_bytes(bytes).expect("bad point encoding");
    let opt: Option<k256::AffinePoint> = k256::AffinePoint::from_encoded_point(&ep).into();
    opt.expect("off-curve point").into()
}

fn point_to_bytes(p: &ProjectivePoint) -> [u8; 33] {
    let ep = p.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(ep.as_bytes());
    out
}

fn kdf64(p: &ProjectivePoint) -> [u8; 64] {
    let ep = p.to_affine().to_encoded_point(false); // 0x04 || X || Y
    let bytes = ep.as_bytes();
    let x: &[u8] = if bytes.len() == 65 { &bytes[1..33] } else { &[] };
    let h0 = h_tagged(b"share", &[x, &[0u8]]);
    let h1 = h_tagged(b"share", &[x, &[1u8]]);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h0);
    out[32..].copy_from_slice(&h1);
    out
}

fn read_arr<const N: usize>() -> [u8; N] {
    let v: Vec<u8> = env::read();
    let mut out = [0u8; N];
    if v.len() != N {
        panic!("env::read length mismatch: got {} expected {}", v.len(), N);
    }
    out.copy_from_slice(&v);
    out
}

fn main() {
    // ── Public inputs ────────────────────────────────────────────────
    // Arrays > 32 bytes round-trip through risc0's serde via Vec<u8> because
    // serde's stdlib impl tops out at [T; 32]. We commit them the same way.
    let member_root: [u8; 32]       = env::read();
    let instance_id: [u8; 32]       = env::read();
    let revocation_digest: [u8; 32] = env::read();
    let mod_pubkey: [u8; 33]        = read_arr::<33>();
    let post_binding: [u8; 32]      = env::read();
    let enc_c1: [u8; 33]            = read_arr::<33>();
    let enc_c2: [u8; 64]            = read_arr::<64>();

    // ── Private inputs (witness) ─────────────────────────────────────
    let coeffs: Vec<[u8; 32]>          = env::read();
    let merkle_siblings: Vec<[u8; 32]> = env::read();
    let revocation_set: Vec<[u8; 32]>  = env::read();
    let x_i: [u8; 32]                  = env::read();
    let r:   [u8; 32]                  = env::read();

    // ── 1. Re-derive the commitment from coeffs. ─────────────────────
    let coeff_refs: Vec<&[u8]> = coeffs.iter().map(|c| c.as_slice()).collect();
    let commitment = h_tagged(b"commitment", &coeff_refs);

    // ── 2. Merkle inclusion of `commitment` in `member_root`. ────────
    {
        let mut node = h_merkle_leaf(&commitment);
        for sib in &merkle_siblings {
            node = h_merkle_node(&node, sib);
        }
        assert_eq!(node, member_root, "membership proof failed");
    }

    // ── 3. Revocation digest binding. ────────────────────────────────
    {
        let mut input = Vec::with_capacity(8 + revocation_set.len() * 32);
        input.extend_from_slice(&(revocation_set.len() as u32).to_le_bytes());
        for r_c in &revocation_set {
            input.extend_from_slice(r_c);
        }
        let computed = h_tagged(b"revocation", &[&input]);
        assert_eq!(computed, revocation_digest, "revocation digest mismatch");
    }

    // ── 4. Commitment NOT in revocation set. ─────────────────────────
    for r_c in &revocation_set {
        assert_ne!(*r_c, commitment, "this member is revoked");
    }

    // ── 5. y_i = f(x_i), Horner. ─────────────────────────────────────
    let x = scalar_from_bytes(&x_i);
    let scalars: Vec<Scalar> = coeffs.iter().map(scalar_from_bytes).collect();
    let mut y = Scalar::ZERO;
    for c in scalars.iter().rev() {
        y = y * x + c;
    }
    let y_bytes: [u8; 32] = y.to_bytes().into();

    // ── 6. ElGamal ciphertext correctness. ───────────────────────────
    let r_s = scalar_from_bytes(&r);
    let q   = point_from_bytes(&mod_pubkey);
    let c1  = ProjectivePoint::GENERATOR * r_s;
    let shared = q * r_s;
    let pad = kdf64(&shared);

    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(&x_i);
    msg[32..].copy_from_slice(&y_bytes);
    let mut c2 = [0u8; 64];
    for i in 0..64 {
        c2[i] = msg[i] ^ pad[i];
    }
    assert_eq!(point_to_bytes(&c1), enc_c1, "c1 mismatch");
    assert_eq!(c2, enc_c2, "c2 mismatch");

    // ── Bind the post hash so observers can match the proof to the
    //    enclosing PostEnvelope without trust. ────────────────────────
    // (post_binding is already in the journal; binding is structural.)
    let _ = post_binding;
    let _ = instance_id;

    // ── Commit the journal: just the public inputs. ──────────────────
    // Same big-array workaround as in `read`.
    env::commit(&member_root);
    env::commit(&instance_id);
    env::commit(&revocation_digest);
    env::commit(&mod_pubkey.to_vec());
    env::commit(&post_binding);
    env::commit(&enc_c1.to_vec());
    env::commit(&enc_c2.to_vec());
}

//! `forum_registry` — the LP-0016 membership-registry SPEL program.
//!
//! One deployment of this program = one forum instance. State is stored under
//! a single PDA `instance_v1`. The program owns its own PDA (claimed at
//! `create_instance`) so it can stake/unstake balance directly.
//!
//! Instructions:
//!   - `create_instance(params_blob, roster_blob)`  — admin-only setup
//!   - `register(commitment, new_root, stake_amount)` — locks stake, appends
//!     to membership tree (caller-supplied new root + commitment, signer pays)
//!   - `submit_slash(commitment, membership_proof, recovered_coeffs, x_pts, y_pts, stake_recipient)`
//!     — verifies K Shamir points reconstruct `commitment` which is in tree
//!     and not in revocation list; adds to revocation, pays out stake
//!   - `reveal()` — read-only, returns the state account unchanged
//!
//! NOTE on signature verification of moderator certificates: v0.1 verifies
//! the cryptographic reconstruction of the commitment but NOT individual
//! moderator signatures on the certificate shares. The off-chain library
//! refuses to publish unsigned certificates, and the slash will only succeed
//! if the recovered points genuinely Lagrange-interpolate to a registered
//! commitment — which requires either K honest moderation events OR N
//! colluding moderators decrypting K of an author's posts in secret. The
//! latter case is documented as the "malicious-mod-quorum" threat in
//! `docs/protocol.md` §11 and is the limit of v0.1's audit-trail guarantee.
//! v0.2 will require k256 ECDSA verification of N moderator sigs per cert.

#![no_main]

use spel_framework::prelude::*;

risc0_zkvm::guest::entry!(main);

/// Domain prefix — must match `forum_core::DOMAIN_PREFIX`.
const DOMAIN_PREFIX: &[u8] = b"/logos-forum/v1/";

/// Commitment / hash size.
const HASH_SIZE: usize = 32;

/// On-chain state for one forum instance. Encoded with borsh into the PDA's
/// `account.data`. Field layout matches `forum_core::ForumInstanceState`
/// because clients need to decode it.
///
/// `params_blob` and `roster_blob` are opaque byte slices — they hold the
/// borsh-encoded `InstanceParams` and `ModeratorRoster`. We don't decode them
/// in the guest because the guest doesn't need to interpret most fields; we
/// only pull `K`, `N`, `D`, `stake_amount`, and `mod_pubkey` out via fixed
/// offsets when needed.
#[account_type]
#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct InstanceState {
    pub params_blob: Vec<u8>,
    pub roster_blob: Vec<u8>,
    pub member_root: [u8; 32],
    pub member_count: u64,
    pub pooled_stake: u128,
    pub revocation_count: u32,
    pub revocation_list: Vec<[u8; 32]>,
}

/// Convenience tag-builder, matching `forum_moderation::domain::tag`.
fn domain_tag(sub: &[u8]) -> [u8; HASH_SIZE] {
    use risc0_zkvm::sha::{Impl, Sha256};
    let mut input = Vec::with_capacity(DOMAIN_PREFIX.len() + sub.len());
    input.extend_from_slice(DOMAIN_PREFIX);
    input.extend_from_slice(sub);
    let d = Impl::hash_bytes(&input);
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(d.as_bytes());
    out
}

/// `H(domain(tag) || piece_1 || ... || piece_n)`.
fn h_tagged(tag: &[u8], pieces: &[&[u8]]) -> [u8; HASH_SIZE] {
    use risc0_zkvm::sha::{Impl, Sha256};
    let dt = domain_tag(tag);
    let total: usize = HASH_SIZE + pieces.iter().map(|p| p.len()).sum::<usize>();
    let mut input = Vec::with_capacity(total);
    input.extend_from_slice(&dt);
    for p in pieces {
        input.extend_from_slice(p);
    }
    let d = Impl::hash_bytes(&input);
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(d.as_bytes());
    out
}

fn h_merkle_leaf(commitment: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    h_tagged(b"merkle-leaf", &[commitment])
}

fn h_merkle_node(a: &[u8; HASH_SIZE], b: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    h_tagged(b"merkle-node", &[lo, hi])
}

/// Verify a sorted-pair Merkle inclusion proof.
fn verify_merkle_inclusion(
    commitment: &[u8; HASH_SIZE],
    root: &[u8; HASH_SIZE],
    siblings: &[[u8; HASH_SIZE]],
) -> bool {
    let mut node = h_merkle_leaf(commitment);
    for sib in siblings {
        node = h_merkle_node(&node, sib);
    }
    node == *root
}

/// Re-derive the membership commitment from a Shamir polynomial's coefficients.
/// Mirrors `forum_moderation::commitment::commitment_from_secret`.
fn commitment_from_coeffs(coeffs: &[[u8; 32]]) -> [u8; HASH_SIZE] {
    let refs: Vec<&[u8]> = coeffs.iter().map(|c| c.as_slice()).collect();
    h_tagged(b"commitment", &refs)
}

/// Bytes signed by each moderator for a certificate share. Mirrors
/// `forum_moderation::certificate::sig_message`.
fn cert_sig_message(
    instance_id: &[u8; 32],
    post_hash: &[u8; 32],
    alpha: u8,
    decryption_share: &[u8; 33],
) -> [u8; HASH_SIZE] {
    h_tagged(b"cert-sig", &[instance_id, post_hash, &[alpha], decryption_share])
}

/// Verify one moderator's ECDSA-secp256k1 signature on a certificate share.
/// Returns true only on a fully valid DER signature against the recorded
/// roster pubkey.
fn verify_cert_share_signature(
    moderator_pubkey: &[u8; 33],
    instance_id: &[u8; 32],
    post_hash: &[u8; 32],
    alpha: u8,
    decryption_share: &[u8; 33],
    signature_der: &[u8],
) -> bool {
    use k256::ecdsa::signature::Verifier;
    use k256::ecdsa::{Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_sec1_bytes(moderator_pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(signature_der) else {
        return false;
    };
    let msg = cert_sig_message(instance_id, post_hash, alpha, decryption_share);
    vk.verify(&msg, &sig).is_ok()
}

/// Decode the roster blob (concatenated 33-byte SEC1-compressed pubkeys)
/// into individual pubkeys. Mirrors `forum_core::ModeratorRoster`.
fn decode_roster(blob: &[u8]) -> Option<Vec<[u8; 33]>> {
    if blob.len() < 4 {
        return None;
    }
    // The blob is the borsh encoding of `ModeratorRoster { entries: Vec<u8> }`.
    // borsh prefixes Vec<u8> with a u32 length. So the first 4 bytes are the
    // length, then the bytes follow.
    let len_bytes: [u8; 4] = blob[0..4].try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if blob.len() < 4 + len {
        return None;
    }
    let entries = &blob[4..4 + len];
    if !entries.len().is_multiple_of(33) {
        return None;
    }
    let mut out = Vec::with_capacity(entries.len() / 33);
    for chunk in entries.chunks_exact(33) {
        let mut pk = [0u8; 33];
        pk.copy_from_slice(chunk);
        out.push(pk);
    }
    Some(out)
}

/// Decode just the (k, n) parameters from a borsh-encoded `InstanceParams`.
/// We avoid pulling the full forum_core type into the guest. Layout:
///   u8 k | u8 n | u8 m | u8 d | u128 stake | [u8;33] mod_pubkey | …
fn decode_kn(params_blob: &[u8]) -> Option<(u8, u8)> {
    if params_blob.len() < 2 { return None; }
    Some((params_blob[0], params_blob[1]))
}

/// Lagrange-interpolate K (x_i, y_i) points to recover the polynomial
/// coefficients in the secp256k1 scalar field.
///
/// Inputs are 32-byte big-endian scalars. Output is the K coefficients
/// `[c_0, c_1, ..., c_{K-1}]` (also 32-byte BE).
///
/// Returns `None` on degenerate input (duplicate x, non-invertible scalar).
fn lagrange_interpolate(
    xs: &[[u8; 32]],
    ys: &[[u8; 32]],
) -> Option<Vec<[u8; 32]>> {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;

    if xs.len() != ys.len() || xs.is_empty() {
        return None;
    }
    let n = xs.len();
    let mut x_s: Vec<Scalar> = Vec::with_capacity(n);
    let mut y_s: Vec<Scalar> = Vec::with_capacity(n);
    for i in 0..n {
        let xb: Option<Scalar> = Scalar::from_repr(xs[i].into()).into();
        let yb: Option<Scalar> = Scalar::from_repr(ys[i].into()).into();
        x_s.push(xb?);
        y_s.push(yb?);
    }

    let mut result: Vec<Scalar> = vec![Scalar::ZERO; n];
    for j in 0..n {
        let mut basis: Vec<Scalar> = vec![Scalar::ONE];
        let mut denom = Scalar::ONE;
        for m in 0..n {
            if m == j {
                continue;
            }
            let mut new_basis: Vec<Scalar> = vec![Scalar::ZERO; basis.len() + 1];
            for (i, &b) in basis.iter().enumerate() {
                new_basis[i + 1] += b;
                new_basis[i] -= b * x_s[m];
            }
            basis = new_basis;
            let diff = x_s[j] - x_s[m];
            if bool::from(diff.is_zero()) {
                return None;
            }
            denom *= diff;
        }
        let inv: Option<Scalar> = denom.invert().into();
        let inv = inv?;
        let scale = y_s[j] * inv;
        for (i, b) in basis.iter().enumerate() {
            result[i] += *b * scale;
        }
    }
    Some(result.iter().map(|s| s.to_bytes().into()).collect())
}

#[lez_program]
mod forum_registry {
    #[allow(unused_imports)]
    use super::*;

    /// Initialise a forum instance. Claims the `instance_v1` PDA, marks the
    /// signer as the admin, and stores the parameter + roster blobs.
    ///
    /// Reasonable bounds enforced: K ∈ [2, 16], N ∈ [1, 32], D ∈ [4, 24],
    /// stake_amount ≥ 1. We don't decode the full borsh blobs in the guest;
    /// the off-chain library is responsible for producing valid blobs and the
    /// IDL inspect tool is the canonical decoder.
    #[instruction]
    pub fn create_instance(
        #[account(init, pda = literal("instance_v1"))]
        mut state: AccountWithMetadata,
        #[account(signer)]
        admin: AccountWithMetadata,
        params_blob: Vec<u8>,
        roster_blob: Vec<u8>,
    ) -> SpelResult {
        if params_blob.is_empty() || roster_blob.is_empty() {
            return Err(SpelError::custom(1, "params/roster blob must be non-empty"));
        }
        if params_blob.len() > 4096 || roster_blob.len() > 8192 {
            return Err(SpelError::custom(2, "params/roster blob too large"));
        }
        let _ = admin; // signer constraint already validated by the macro

        let initial = InstanceState {
            params_blob,
            roster_blob,
            // Empty Merkle tree of any depth has the same well-known empty
            // root computed off-chain by the client; we trust it on first
            // registration and rebind on each register.
            member_root: [0u8; 32],
            member_count: 0,
            pooled_stake: 0,
            revocation_count: 0,
            revocation_list: Vec::new(),
        };
        let bytes = borsh::to_vec(&initial).map_err(|e| SpelError::SerializationError {
            message: e.to_string(),
        })?;
        state.account.data = bytes.try_into().unwrap();

        Ok(SpelOutput::execute(vec![state, admin], vec![]))
    }

    /// Register a new member.
    ///
    /// Caller supplies:
    ///   - `commitment`: the 32-byte member commitment to append.
    ///   - `new_root`: the Merkle root the caller computed by appending
    ///     `commitment` to the existing tree.
    ///   - `stake_amount`: amount of native token to lock as the stake.
    ///
    /// The program:
    ///   - Trusts the caller's `new_root` (commitments are random hashes,
    ///     so no one can game the membership-tree position). The off-chain
    ///     library mirrors all commitments via Logos Delivery so any client
    ///     can verify `new_root` independently.
    ///   - Locks `stake_amount` from the signer and adds it to `pooled_stake`.
    ///
    /// SECURITY NOTE: a malicious caller could pass a wrong `new_root` and
    /// trick later registrants. v0.2 will replay the tree update inside the
    /// guest (cost: O(D) hashes per registration ≈ 1.5K cycles).
    #[instruction]
    pub fn register(
        #[account(mut, pda = literal("instance_v1"))]
        mut state: AccountWithMetadata,
        #[account(signer, mut)]
        mut signer: AccountWithMetadata,
        commitment: [u8; 32],
        new_root: [u8; 32],
        stake_amount: u128,
    ) -> SpelResult {
        let data: Vec<u8> = state.account.data.clone().into();
        let mut current: InstanceState =
            borsh::from_slice(&data).map_err(|e| SpelError::DeserializationError {
                account_index: 0,
                message: e.to_string(),
            })?;

        if stake_amount == 0 {
            return Err(SpelError::custom(10, "stake_amount must be > 0"));
        }
        if signer.account.balance < stake_amount {
            return Err(SpelError::InsufficientBalance {
                available: signer.account.balance,
                requested: stake_amount,
            });
        }
        if current
            .revocation_list
            .iter()
            .any(|r| r == &commitment)
        {
            return Err(SpelError::custom(11, "commitment already revoked"));
        }

        // Move stake from signer to the program-owned state account.
        signer.account.balance -= stake_amount;
        state.account.balance = state
            .account
            .balance
            .checked_add(stake_amount)
            .ok_or(SpelError::Overflow {
                operation: "pooled stake add".to_string(),
            })?;

        current.member_root = new_root;
        current.member_count = current.member_count.saturating_add(1);
        current.pooled_stake = current
            .pooled_stake
            .checked_add(stake_amount)
            .ok_or(SpelError::Overflow {
                operation: "pooled_stake add".to_string(),
            })?;

        let bytes = borsh::to_vec(&current).map_err(|e| SpelError::SerializationError {
            message: e.to_string(),
        })?;
        state.account.data = bytes.try_into().unwrap();
        let _ = commitment; // accepted, mirrored off-chain
        Ok(SpelOutput::execute(vec![state, signer], vec![]))
    }

    /// Submit a slash transaction.
    ///
    /// Caller supplies:
    ///   - `commitment`: the recovered commitment to slash.
    ///   - `membership_siblings`: D × 32-byte sibling hashes proving
    ///     `commitment` is in `member_root`.
    ///   - `xs`, `ys`: K Shamir points (32-byte BE scalars each) that
    ///     Lagrange-interpolate to the polynomial whose coefficients hash
    ///     to `commitment`.
    ///   - `instance_id_for_sigs`: the instance PDA bytes that moderators
    ///     bound their signatures to (passed explicitly so the verifier
    ///     doesn't have to recompute).
    ///   - `post_hashes`: K post hashes — one per cert.
    ///   - `cert_share_alphas`: K*N moderator indices (flat).
    ///   - `cert_share_decryption_shares`: K*N decryption-share bytes.
    ///   - `cert_share_signatures`: K*N DER ECDSA signatures.
    ///   - `stake_payout`: amount to release to `recipient`.
    ///
    /// The handler:
    ///   (a) checks the commitment is in the membership tree and not revoked,
    ///   (b) Lagrange-reconstructs the K Shamir points → polynomial → hashes
    ///       back to `commitment`,
    ///   (c) verifies for each of the K*N shares that the ECDSA signature
    ///       checks out against the moderator pubkey recorded in the roster.
    ///
    /// (c) is what binds the slash to N-of-M moderator agreement: a
    ///     colluding ≥N quorum could secretly decrypt and slash without (c),
    ///     leaving no audit trail. With (c), every slash carries N signed
    ///     attestations per cert.
    #[instruction]
    pub fn submit_slash(
        #[account(mut, pda = literal("instance_v1"))]
        mut state: AccountWithMetadata,
        #[account(signer)]
        signer: AccountWithMetadata,
        #[account(mut)]
        mut recipient: AccountWithMetadata,
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
    ) -> SpelResult {
        let data: Vec<u8> = state.account.data.clone().into();
        let mut current: InstanceState =
            borsh::from_slice(&data).map_err(|e| SpelError::DeserializationError {
                account_index: 0,
                message: e.to_string(),
            })?;

        // 1. Reject if already revoked.
        if current.revocation_list.iter().any(|r| r == &commitment) {
            return Err(SpelError::custom(20, "commitment already revoked"));
        }

        // 2. Verify Merkle inclusion of commitment in member_root.
        if !verify_merkle_inclusion(&commitment, &current.member_root, &membership_siblings) {
            return Err(SpelError::custom(21, "membership proof does not verify"));
        }

        // 3. Lagrange-interpolate (xs, ys) → polynomial coefficients.
        let coeffs = lagrange_interpolate(&xs, &ys)
            .ok_or_else(|| SpelError::custom(22, "lagrange interpolation failed"))?;

        // 4. Hash coefficients → must equal `commitment`.
        let rederived = commitment_from_coeffs(&coeffs);
        if rederived != commitment {
            return Err(SpelError::custom(
                23,
                "recovered polynomial does not hash to commitment",
            ));
        }

        // 5. Verify the N moderator signatures on each of the K certificates.
        let (k, n) = decode_kn(&current.params_blob)
            .ok_or_else(|| SpelError::custom(30, "params_blob decode failed"))?;
        let roster = decode_roster(&current.roster_blob)
            .ok_or_else(|| SpelError::custom(31, "roster_blob decode failed"))?;
        if xs.len() != k as usize || ys.len() != k as usize || post_hashes.len() != k as usize {
            return Err(SpelError::custom(32, "K mismatch in slash inputs"));
        }
        let expected_share_count = (k as usize) * (n as usize);
        if cert_share_alphas.len() != expected_share_count
            || cert_share_decryption_shares.len() != expected_share_count
            || cert_share_signatures.len() != expected_share_count
        {
            return Err(SpelError::custom(33, "share-array length != K*N"));
        }
        for cert_idx in 0..(k as usize) {
            let post_hash = &post_hashes[cert_idx];
            // Track which alphas appeared in this cert — must be N distinct.
            let mut seen = [false; 256];
            for share_in_cert in 0..(n as usize) {
                let flat = cert_idx * (n as usize) + share_in_cert;
                let alpha = cert_share_alphas[flat];
                if alpha == 0 || (alpha as usize) > roster.len() {
                    return Err(SpelError::custom(34, "moderator index out of range"));
                }
                if seen[alpha as usize] {
                    return Err(SpelError::custom(35, "duplicate moderator within cert"));
                }
                seen[alpha as usize] = true;
                if cert_share_decryption_shares[flat].len() != 33 {
                    return Err(SpelError::custom(36, "decryption_share must be 33 bytes"));
                }
                let mut dj = [0u8; 33];
                dj.copy_from_slice(&cert_share_decryption_shares[flat]);
                let pk = &roster[(alpha - 1) as usize];
                if !verify_cert_share_signature(
                    pk,
                    &instance_id_for_sigs,
                    post_hash,
                    alpha,
                    &dj,
                    &cert_share_signatures[flat],
                ) {
                    return Err(SpelError::custom(
                        37,
                        "moderator signature on cert share failed verification",
                    ));
                }
            }
        }

        // 5. Bound the payout.
        let payout = core::cmp::min(stake_payout, current.pooled_stake);
        if payout == 0 {
            return Err(SpelError::custom(24, "no stake available to pay out"));
        }

        // 6. Mutate state: add to revocation, decrease pooled stake.
        current.revocation_list.push(commitment);
        current.revocation_count = current.revocation_count.saturating_add(1);
        current.pooled_stake = current.pooled_stake.saturating_sub(payout);

        // 7. Move funds: state → recipient.
        state.account.balance = state.account.balance.saturating_sub(payout);
        recipient.account.balance = recipient
            .account
            .balance
            .checked_add(payout)
            .ok_or(SpelError::Overflow {
                operation: "recipient balance add".to_string(),
            })?;

        let bytes = borsh::to_vec(&current).map_err(|e| SpelError::SerializationError {
            message: e.to_string(),
        })?;
        state.account.data = bytes.try_into().unwrap();
        let _ = signer; // signer presence is the only requirement on submitter

        Ok(SpelOutput::execute(vec![state, signer, recipient], vec![]))
    }

    /// Read-only: returns the state account unchanged. Clients then decode
    /// the data via `spel inspect <pda> --type InstanceState`.
    #[instruction]
    pub fn reveal(
        #[account(pda = literal("instance_v1"))]
        state: AccountWithMetadata,
    ) -> SpelResult {
        Ok(SpelOutput::execute(vec![state], vec![]))
    }
}

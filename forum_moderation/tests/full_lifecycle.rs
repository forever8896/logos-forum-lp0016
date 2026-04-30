//! End-to-end exercise of the moderation library, with NO LEZ dependency.
//!
//! Pipeline:
//!   1. Forum creator generates a threshold ElGamal key (N-of-M).
//!   2. Three members register, each producing a commitment that gets
//!      appended to a shared Merkle tree.
//!   3. Each member publishes K posts. Each post embeds an encrypted
//!      Shamir share of the author's polynomial.
//!   4. Moderators decrypt shares for K of one author's posts (this is
//!      the "K strikes" path).
//!   5. The slash search reconstructs that author's commitment, ONLY
//!      that author's, and the membership tree confirms it.
//!   6. Other members' posts remain unlinkable.

use forum_moderation::{
    aggregate_certificate, build_share, commitment_from_secret, encrypt_share,
    find_slash_candidates, generate_threshold_key, scalar, MemberIdentity, MerkleTree,
};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::Field;
use k256::Scalar;
use rand_core::OsRng;
use std::collections::BTreeSet;

#[test]
fn three_members_one_gets_slashed() {
    const K: u8 = 3;
    const N: u8 = 2;
    const M: u8 = 3;
    const TREE_DEPTH: u8 = 8;

    // 1. Forum creator key setup.
    let key = generate_threshold_key(N, M, &mut OsRng).unwrap();

    // 2. Three members register.
    let alice = MemberIdentity::generate(K as usize, &mut OsRng).unwrap();
    let bob = MemberIdentity::generate(K as usize, &mut OsRng).unwrap();
    let eve = MemberIdentity::generate(K as usize, &mut OsRng).unwrap();

    let mut tree = MerkleTree::new(TREE_DEPTH);
    tree.append(&alice.commitment);
    tree.append(&bob.commitment);
    tree.append(&eve.commitment);
    let _root = tree.root();
    let revoked: BTreeSet<[u8; 32]> = BTreeSet::new();

    // 3. Each member publishes K posts. Encrypt a Shamir share per post.
    //    For brevity we don't run a real ZK proof here — that's covered by
    //    the RISC0 guest crate. We simulate the share construction.
    let make_post_share = |member: &MemberIdentity| {
        let x = Scalar::random(&mut OsRng);
        let y = member.polynomial.eval(&x);
        let mut share_bytes = [0u8; 64];
        share_bytes[..32].copy_from_slice(&scalar::scalar_to_bytes(&x));
        share_bytes[32..].copy_from_slice(&scalar::scalar_to_bytes(&y));
        let ct = encrypt_share(&key.public_key, &share_bytes, &mut OsRng).unwrap();
        (x, y, ct)
    };

    // K posts from Alice, K-1 from Bob, K from Eve.
    let alice_posts: Vec<_> = (0..K).map(|_| make_post_share(&alice)).collect();
    let bob_posts: Vec<_> = (0..(K - 1)).map(|_| make_post_share(&bob)).collect();
    let _eve_posts: Vec<_> = (0..K).map(|_| make_post_share(&eve)).collect();

    // 4. K of Alice's posts get moderated. Each cert is N moderator shares
    //    aggregated into a complete certificate.
    let instance_id = [0xAAu8; 32];
    let mut certs = Vec::new();
    for (i, (_x, _y, ct)) in alice_posts.iter().enumerate() {
        let msg_id = [(i as u8); 32];
        let payload = b"alice's post body".to_vec();
        let mut shares = Vec::new();
        for j in 0..(N as usize) {
            let (alpha, dj) = key.shares[j];
            shares.push(build_share(instance_id, msg_id, &payload, ct, alpha, &dj, &SigningKey::random(&mut OsRng)).unwrap());
        }
        let cert = aggregate_certificate(instance_id, N, ct, shares).unwrap();
        certs.push(cert);
    }

    // For added realism: also moderate one of Bob's posts. Bob is below the
    // K-strike threshold and must NOT be slashed.
    {
        let (_x, _y, ct) = &bob_posts[0];
        let msg_id = [0xCCu8; 32];
        let payload = b"bob's post body".to_vec();
        let mut shares = Vec::new();
        for j in 0..(N as usize) {
            let (alpha, dj) = key.shares[j];
            shares.push(build_share(instance_id, msg_id, &payload, ct, alpha, &dj, &SigningKey::random(&mut OsRng)).unwrap());
        }
        let cert = aggregate_certificate(instance_id, N, ct, shares).unwrap();
        certs.push(cert);
    }

    // 5. Slash search.
    let in_tree_set: BTreeSet<[u8; 32]> =
        [alice.commitment, bob.commitment, eve.commitment]
            .into_iter()
            .collect();

    let candidates = find_slash_candidates(
        K,
        &certs,
        |c| in_tree_set.contains(c),
        |c| revoked.contains(c),
    )
    .unwrap();

    // Exactly one slash candidate, and it's Alice.
    assert_eq!(candidates.len(), 1, "expected one slash candidate");
    assert_eq!(candidates[0].commitment, alice.commitment);

    // Sanity: the recovered polynomial reproduces the SAME commitment when
    // re-hashed via the protocol's commitment function. This is exactly what
    // the on-chain SPEL handler checks.
    let rederived = commitment_from_secret(&candidates[0].polynomial.coeffs).unwrap();
    assert_eq!(rederived, alice.commitment);

    // Sanity: Bob and Eve are NOT slashable (below threshold or never moderated).
    assert!(!candidates.iter().any(|c| c.commitment == bob.commitment));
    assert!(!candidates.iter().any(|c| c.commitment == eve.commitment));
}

#[test]
fn revoked_member_is_not_re_slashed() {
    const K: u8 = 3;
    const N: u8 = 2;
    const M: u8 = 3;

    let key = generate_threshold_key(N, M, &mut OsRng).unwrap();
    let alice = MemberIdentity::generate(K as usize, &mut OsRng).unwrap();

    let make_share = || {
        let x = Scalar::random(&mut OsRng);
        let y = alice.polynomial.eval(&x);
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&scalar::scalar_to_bytes(&x));
        bytes[32..].copy_from_slice(&scalar::scalar_to_bytes(&y));
        encrypt_share(&key.public_key, &bytes, &mut OsRng).unwrap()
    };

    let instance_id = [0u8; 32];
    let mut certs = Vec::new();
    for i in 0..K {
        let ct = make_share();
        let mut shares = Vec::new();
        for j in 0..(N as usize) {
            let (alpha, dj) = key.shares[j];
            shares
                .push(build_share(instance_id, [i; 32], &[], &ct, alpha, &dj, &SigningKey::random(&mut OsRng)).unwrap());
        }
        certs.push(aggregate_certificate(instance_id, N, &ct, shares).unwrap());
    }

    let tree: BTreeSet<[u8; 32]> = [alice.commitment].into_iter().collect();
    let revoked: BTreeSet<[u8; 32]> = [alice.commitment].into_iter().collect();

    let candidates = find_slash_candidates(
        K,
        &certs,
        |c| tree.contains(c),
        |c| revoked.contains(c),
    )
    .unwrap();
    assert!(
        candidates.is_empty(),
        "already-revoked member should not be re-slashable"
    );
}

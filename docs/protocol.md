# Logos Forum — Protocol Specification

**Status:** v0.1 — implementation reference for the LP-0016 prize submission.
**Last updated:** 2026-04-29.

This document is the source of truth for the cryptographic protocol implemented by the `forum_moderation` library and the `forum_registry` LEZ program. The goal is *anonymous moderated posting with cryptographic K-strike revocation*.

The intended audience is a reviewer who needs to convince themselves the unlinkability and revocation properties hold, and a developer who needs to know what bytes to put on the wire. Section numbering matches `forum_moderation` module names.

## 0. Notation

- `H(x₁,…,xₙ)` — SHA-256 of the domain-separated, length-prefixed concatenation of inputs. We use SHA-256 because the LEZ RISC0 guest provides it as an accelerated precompile (`risc0_zkvm::sha::Impl`); Poseidon would be smaller in an arithmetic circuit but is irrelevant here.
- `𝔽` — the scalar field of secp256k1 (order `n ≈ 2²⁵⁶`). All polynomial arithmetic is done modulo `n`.
- `G` — the secp256k1 base point.
- `[k]P` — scalar multiplication of point `P` by scalar `k`.
- `‖` — byte concatenation.
- `domain(s)` — fixed 32-byte tag `H("/logos-forum/v1/" ‖ s)`. Tags used: `commitment`, `merkle-leaf`, `merkle-node`, `nullifier`, `share`, `cert`, `slash-binding`.

## 1. Roles and parameters

A **forum instance** is parameterised at creation by:
- `K` — number of moderation strikes that revoke a member. (Recommended 3–7.)
- `N`, `M` — moderation threshold: `N` of `M` moderators must agree to issue one strike.
- `(Q, sk_shares)` — a threshold ElGamal key over secp256k1. `Q = [d]G` is the public moderation key. `d ∈ 𝔽` is split via Shamir into `M` shares such that any `N` reconstruct `d`. The `M` shares are handed to the `M` moderators out-of-band at instance creation.
- `S` — required stake amount (in LEZ native token), locked at registration and forfeited on slash.

Roles:
- **Member** — anyone holding a private identity `sk ∈ 𝔽` whose commitment has been registered and is not in the revocation list.
- **Moderator** — one of the `M` parties holding an ElGamal key share. Each moderator also has a long-lived public signing key `mk_i` used to sign certificate shares.
- **Anyone** — may submit a slash transaction once `K` valid certificates have accumulated against a single (recoverable) commitment.

There is **no admin** with unilateral power once the instance is created. The instance creator is trusted only at instance creation: they choose moderators and run the threshold-key distribution. After that they have no special role.

## 2. Membership commitment

A member secret consists of `K` field elements:
- `sk ∈ 𝔽` — the identity scalar (drives revocation linkability).
- `a₁, …, a_{K-1} ∈ 𝔽` — random Shamir polynomial coefficients.
- `salt ∈ 𝔽` — random hiding salt.

Define the polynomial
```
f(x) = sk + a₁·x + a₂·x² + … + a_{K-1}·x^{K-1}    (mod n)
```
so that `f(0) = sk` and `f` has degree `K-1`. Recovering `f` from `K` distinct evaluation points yields `sk` by Lagrange interpolation.

The on-chain **commitment** is
```
C = H(domain("commitment") ‖ sk ‖ a₁ ‖ … ‖ a_{K-1} ‖ salt)
```
written as a 32-byte SHA-256 digest. Inputs are 32-byte big-endian scalar encodings.

Properties:
- `C` hides `(sk, a_i, salt)` under the random-oracle assumption on SHA-256.
- Two members produce the same `C` only with negligible probability.
- The whole secret tuple `(sk, a₁, …, a_{K-1}, salt)` is required to *open* `C`. A slash can therefore only succeed if the slasher recovers the full tuple — recovering only `sk` is insufficient because `salt` and the `a_i` are also hashed in.

## 3. Membership tree and revocation list

Per forum, the on-chain registry maintains:
- `member_root` — the root of an append-only binary Merkle tree over registered commitments.
- `revocation_set` — the set of commitments that have been slashed.

The Merkle tree is computed with sorted-pair hashing:
- Leaves: `H(domain("merkle-leaf") ‖ C)` for each commitment `C`.
- Internal nodes: `H(domain("merkle-node") ‖ min(L,R) ‖ max(L,R))`.
- Empty siblings at a level are filled with the level's *zero hash*: `Z₀ = H(domain("merkle-leaf") ‖ 0³²)`, `Z_{i+1} = H(domain("merkle-node") ‖ Z_i ‖ Z_i)`.

The tree depth `D` is fixed at instance creation (default `D = 20`, capacity `2²⁰ ≈ 1M members`).

Sorted-pair hashing means an inclusion proof is a list of `D` sibling hashes — no left/right bits required. A leaf belongs to the tree iff folding from leaf to root using `min/max` reproduces `member_root`.

The `revocation_set` is stored on-chain as a small set (until it grows large; for v0.1 we store it as a flat list — at most a few hundred entries before slashing rate is dominated by membership churn). A future version can switch to a sparse Merkle tree of revocations; the protocol surface is unchanged.

> **On-chain storage budget.** LEZ accounts cap `account.data` at ≈64 KiB. The `member_root` and the `revocation_set` are tiny. The actual list of commitments needed to compute the tree off-chain is mirrored over Logos Delivery so any client can reconstruct the tree. Each registration tx publishes both the new root *and* the new commitment; clients append the commitment, recompute the root locally, and verify it matches the on-chain value before trusting the new root.

## 4. Off-chain post format

A **post** is a tuple
```
Post = (
    msg_id,         // 32-byte random — also used as a domain tag below
    payload,        // arbitrary application bytes (interpreted by the forum app, opaque to us)
    root_seen,      // member_root the author saw at post time
    enc_share,      // threshold-ElGamal ciphertext over (xᵢ, yᵢ) — see §5
    proof,          // RISC0 receipt — see §6
)
```
A post is broadcast over Logos Delivery on the topic `/logos-forum/1/<instance_id>/posts/v1`. Recipients verify the proof; if valid, the post is shown.

Two important non-properties:
- A post does NOT contain any author identifier. Two posts from the same author are indistinguishable from posts by two different authors.
- A post does NOT contain a nullifier in the Semaphore sense. We deliberately do *not* link posts within an epoch — that would defeat the prize's unlinkability requirement.

## 5. Threshold-ElGamal share encryption

For each post the author produces an evaluation point `(xᵢ, yᵢ)` of their polynomial `f`:

1. Sample `xᵢ ∈ 𝔽 \ {0}` uniformly at random. This is the *abscissa*; we never reuse abscissas across posts (a duplicate is only a soundness risk to the author, not to others).
2. Compute `yᵢ = f(xᵢ) mod n`.
3. Encode the pair as `mᵢ = (xᵢ ‖ yᵢ)` — 64 bytes.
4. Encrypt `mᵢ` to the moderation public key `Q`:
   - Sample `r ∈ 𝔽` uniformly.
   - `c₁ = [r]G`
   - `c₂ = mᵢ ⊕ KDF([r]Q)` where `KDF` is `H(domain("share") ‖ x_coord)` taking the x-coordinate of `[r]Q` and expanding to 64 bytes via `SHA-256(KDF_seed ‖ 0x00) ‖ SHA-256(KDF_seed ‖ 0x01)`.
5. The ciphertext is `enc_share = (c₁, c₂)`.

To decrypt with `t ≥ N` cooperating moderators:
- Each moderator with share `(α_j, d_j)` computes their **decryption share** `D_j = [d_j] c₁` and signs `D_j` with `mk_j`.
- Once `N` valid `D_j` are gathered, compute `[d] c₁ = Σ_{j∈T} λ_j(0) · D_j` where `λ_j(0)` are the standard Lagrange coefficients evaluated at 0 over the chosen index set `T`.
- Recover `mᵢ = c₂ ⊕ KDF([d] c₁)` and parse `(xᵢ, yᵢ)`.

Single-share confidentiality follows from the IND-CPA security of ElGamal under the DDH assumption on secp256k1, modelling KDF as a random oracle.

## 6. ZK membership proof (RISC0 guest `forum_post_proof`)

**Public inputs (the journal):**
```
member_root  : [u8; 32]   — root the author claims membership in
instance_id  : [u8; 32]   — forum instance identifier
revocation   : Hash32     — H(domain("revocation") || revocation_set_serialized)
mod_pubkey   : SerializedPoint — Q (compressed secp256k1 point)
post_binding : [u8; 32]   — H(domain("slash-binding") || msg_id || payload || enc_share)
enc_share    : (c1, c2)   — the ciphertext from §5
```

**Private inputs (witness):**
```
sk, a_1, ..., a_{K-1}, salt   : K+1 scalars in 𝔽
merkle_path                   : [Hash32; D]  — sibling hashes from leaf to root
x_i, r                        : 2 scalars in 𝔽
```

**Asserts inside the guest:**
1. `C := H(domain("commitment") || sk || a_1 || ... || a_{K-1} || salt)` matches the leaf computed from `merkle_path` against `member_root`.
2. `C ∉ revocation_set` (the revocation set is short — passed as private input together with `revocation` so the guest can verify the hash binding).
3. `y_i := sk + a_1*x_i + ... + a_{K-1}*x_i^{K-1} mod n`.
4. `enc_share == (c1 = [r]G, c2 = (x_i || y_i) ⊕ KDF([r]Q))`.
5. `post_binding` matches the SHA-256 in the journal — implicitly verified by the journal binding.

If all asserts pass, the guest writes the journal and exits. The receipt is what an observer verifies as `proof` in §4.

**Performance budget.** The guest does:
- ≈D + 1 ≈ 21 SHA-256 invocations (Merkle path + commitment) — each ≈70 cycles with the SHA accelerator → ≈1.5K cycles.
- 2 × secp256k1 scalar multiplications (one for `c1`, one for `[r]Q`) — ≈250K cycles each with the k256 accelerator → ≈500K cycles.
- One polynomial evaluation modulo `n` of degree `K-1` — for `K=5` this is 4 secp256k1 scalar mults and 4 adds → ≈1M cycles.
- KDF + ChaCha-style XOR — negligible.

Total: order-of-magnitude **1.5M cycles**. RISC0 v3.0.5 in real proving mode delivers 50K–100K cycles/s on a modern laptop CPU, **15–30 seconds** for one proof. With the GPU prover (CUDA or Metal): 1–3 seconds.

The prize requires <10s on a "standard laptop". This is achievable on any laptop with discrete GPU; on a CPU-only laptop we will need to either (a) cut `K` to 3 or fewer in the demo configuration, (b) reduce `D` from 20 to 16, or (c) document the actual measured number and note that it exceeds the criterion on CPU-only hardware. The library exposes `K` and `D` as parameters so a forum operator can choose.

## 7. Moderation certificate

When a post is judged to violate the rules, `N` moderators jointly produce a certificate.

A **certificate share** by moderator `j` for post `Post` is the tuple
```
CertShare_j = (
    instance_id,
    post_hash := H(domain("cert") || msg_id || payload || enc_share),
    decryption_share := D_j = [d_j] c1,
    moderator_index := α_j,
    signature := Sign_{mk_j}(post_hash || α_j || D_j)
)
```
Shares are broadcast over `/logos-forum/1/<instance_id>/certs/v1`.

A **complete certificate** is `N` valid shares with distinct `α_j`. The aggregator combines them:
```
[d]c1 = Σ_{j∈T} λ_j(0) · D_j
m_i   = c2 ⊕ KDF([d]c1)
(x_i, y_i) = parse(m_i)
```
The aggregated certificate is published as
```
Certificate = (
    post_hash,
    enc_share,
    (x_i, y_i),         // the recovered Shamir share
    [(α_j, D_j, σ_j) for j in T]   // the underlying shares for auditability
)
```
Validity: all `σ_j` verify against the published moderator pubkeys, the `D_j` correctly Lagrange-combine to a value whose KDF XORed with `c2` parses back as the same `(x_i, y_i)`, and `(x_i, y_i)` lies on a polynomial that — *together with K-1 other certificates against the same author* — reconstructs an `sk` whose commitment is in the tree. The last clause is what gates slashing.

A `< N` partial cert is structurally invalid and the library refuses to submit one to chain.

## 8. Slash reconstruction

Given a pool of complete certificates `{Cert_1, …, Cert_t}` against this forum, a slasher does:

1. For each `K`-subset `S ⊆ {1,…,t}` (in increasing order of `min(S)` for determinism):
   - Take the `K` Shamir points `{(x_i, y_i) : i ∈ S}`.
   - Lagrange-interpolate to find a candidate polynomial `f̃` of degree at most `K-1`.
   - Read off `s̃k = f̃(0)`.
   - For each `(a_1, …, a_{K-1}, salt)` candidate that the polynomial implies (the polynomial fully determines `a_i`), compute `C̃ = H(domain("commitment") || s̃k || a_1 || … || a_{K-1} || salt)`.
   - Wait — the salt is NOT in the polynomial. We need a way to recover `salt`.

This is the protocol's most subtle point. We have two options:

**Option A — drop `salt`:** the commitment is `C = H(domain("commitment") || sk || a_1 || … || a_{K-1})`. The polynomial fully determines this. Simpler, but the commitment is no longer hiding under the assumption that an attacker can't enumerate `sk`-space — and `sk` IS the secret, so this is fine in practice (the commitment hides `sk` because `sk` is a uniform 256-bit scalar).

**Option B — embed `salt` in the abscissa:** force `x_i = H(domain("nullifier") || salt || i)` for the `i`-th post. Then on slash the recovered abscissas leak `salt` (once the slasher tries each commitment in the tree). More complex; gives nothing extra over Option A.

We adopt **Option A**. The commitment becomes
```
C = H(domain("commitment") || sk || a_1 || … || a_{K-1})
```
and the polynomial fully determines `C` once interpolated.

The slasher then:
2. Looks up `C̃` in the on-chain `member_root` (off-chain Merkle membership check) AND verifies `C̃ ∉ revocation_set`.
3. If found, this `K`-subset reconstructed a real member. Submit the slash tx (§9).
4. If not found, this `K`-subset is a coincidence (different authors' shares interpolating by chance). Discard and try the next subset.

**Search cost.** With `t` outstanding certs and threshold `K`, the search is `C(t, K) = O(t^K / K!)` polynomial interpolations and Merkle-membership lookups. For typical instance configurations `K ∈ {3, 5, 7}` and `t ≤ 200`, this is ≤ 1.5M interpolations — well within seconds on modern hardware. The library exposes incremental aggregation: as each new certificate arrives, only the `C(t-1, K-1)` new subsets containing it need to be tried.

False positives (random `K`-subset coincidentally Lagrange-interpolating to a registered commitment) require collision in 32-byte SHA-256 → cryptographically negligible.

## 9. On-chain slash transaction

The slash instruction (`forum_registry::submit_slash`) takes:
```
instance_pda        : the forum instance state
member_root_account : holds member_root and the membership tree off-chain mirror hash
revocation_account  : holds revocation_set
commitment          : C̃ — the recovered commitment
membership_proof    : sibling path proving C̃ is in member_root (D hashes)
certificates        : K certificates, each containing (post_hash, x_i, y_i, [shares])
```

The on-chain SPEL handler verifies:

1. The instance PDA is initialised and its parameters match the certs (same `K`, `N`, same `mod_pubkey`).
2. `C̃ ∉ revocation_set`.
3. `membership_proof` reproduces `member_root` from `C̃`.
4. The `K` certificates pairwise distinct: distinct `post_hash` values.
5. For each certificate:
   - At least `N` valid `(α_j, D_j, σ_j)` shares.
   - `Σ_{j∈T} λ_j(0) · D_j` correctly XORed with `KDF` of `c1` parses to `(x_i, y_i)`.
6. The `K` Shamir points `{(x_i, y_i)}` Lagrange-interpolate to a polynomial whose coefficients hash (with the SHA-256 domain tag from §2) to exactly `C̃`.

If all checks pass:
- Add `C̃` to `revocation_set`.
- Transfer the locked stake `S` from `member_root_account` (which holds the pooled stakes) to a configured destination (slash beneficiary — typically the slasher).
- Emit a `MemberSlashed` event.

> The slash tx is the only on-chain interaction in the common path. Registration is also on-chain (rare, infrequent). Posts and certificate broadcast are entirely off-chain via Logos Delivery.

## 10. Unlinkability argument

**Claim.** As long as a member has accumulated strictly fewer than `K` certificates, their posts are unlinkable to one another and to their commitment, even to the moderators.

**Proof sketch.**
- Each post broadcasts `(msg_id, payload, root_seen, enc_share, proof)`. By §6 the `proof` reveals nothing beyond its public inputs.
- `enc_share` is an IND-CPA ElGamal ciphertext of a random Shamir point. Without `≥ N` decryption shares, the ciphertext is computationally indistinguishable from random under DDH on secp256k1.
- Even with all decryption shares, a single recovered `(x_i, y_i)` is a single point on a degree-`K-1` polynomial. Any `K-1` such points are *information-theoretically* uniformly distributed: for any candidate `sk* ∈ 𝔽`, there exists a unique polynomial of degree `K-1` passing through the `K-1` revealed points and through `(0, sk*)`. Therefore the revealed shares contain zero information about `sk` (Shamir secret-sharing's perfect-secrecy property for `< K` shares).
- Since neither `proof` nor `enc_share` carries any author tag, two posts from the same author look the same as posts from any two members.

**Claim.** Once `K` certificates are published against a member, their commitment is recoverable; their pre-slash post history becomes retroactively linkable to that commitment by anyone who collects the certificates.

**Proof.** Direct from §8 — `K` shares Lagrange-interpolate to the polynomial which hashes to the commitment. With the commitment known, an observer who has been logging all `enc_share`s can decrypt each (by matching against the polynomial: `y = f(x)` for the recovered `f`) and identify which historical posts came from the slashed author.

This retroactive deanonymization on slash is **explicit and intentional**: it is the deterrent that makes the moderation scheme effective, and it is restricted to the slashed member only — every other member's polynomial is independent.

## 11. Threat model

| Adversary | Capability | Defence |
|---|---|---|
| Passive observer (off-chain) | Reads all posts, all certificates, all on-chain state | Cannot link posts of any non-slashed member; learns the membership tree but not which member is which |
| Active observer | Posts garbage to fill the membership tree | Pays stake `S` per identity; gains no posting capability beyond what the stake buys |
| `< N` moderators colluding | Read all decryption shares they emit | Cannot decrypt any single share (threshold confidentiality) |
| `≥ N` moderators colluding | Decrypt every post's share at will | Can deanonymize members who have posted ≥ K times. **This is the moderation power** — must be granted only to a trusted committee |
| Malicious member | Reuses abscissa `x_i` across posts | Two different posts with the same `x_i` from the same author both Lagrange-fit the same polynomial, so the slasher sees `(x_i, y_i)` and `(x_i, y_i')` and detects `y_i = y_i'` (always true) — no extra info leaks. Reusing `x_i` across DIFFERENT authors gives no info either. Self-harm only. |
| Malicious member 2 | Refuses to lock stake at registration | Registration tx fails; commitment never enters tree |
| Malicious slasher | Submits slash with fake K-subset that doesn't reconstruct a real member | On-chain handler rejects: step 6 of §9 checks the recovered commitment is in the tree |
| Malicious moderator | Signs a fake decryption share | Detected: aggregated decryption fails to parse, or yields a `(x_i, y_i)` not lying on any polynomial that hashes to a tree commitment |
| Network adversary | Drops post or cert messages | Logos Delivery has no delivery guarantees; a censored post is simply unseen. A censored certificate prevents that specific strike. Members and moderators can re-broadcast |
| Forum creator (after instance creation) | Has no special key material | No power |
| Forum creator (at instance creation) | Generates and distributes the threshold ElGamal shares; could keep a copy of `d` | **Trust assumption.** Mitigated long-term by switching to a DKG (Pedersen / FROST) — out of scope for v0.1 |

## 12. Parameter recommendations

| Parameter | v0.1 default | Notes |
|---|---|---|
| `K` (strikes-to-revoke) | 5 | Higher K = more friction to deanonymize, slower slashing. K=3 for sensitive forums; K=7 for tolerant ones. |
| `N` (mods to issue strike) | 3 | Lower N = faster moderation, less collusion-resistant. |
| `M` (total moderators) | 5 | Larger M dilutes individual mod power; pick `N ≤ M/2 + 1` for security against minority forks. |
| `D` (Merkle tree depth) | 20 | Capacity 1M members. Reduce to 16 (65K capacity) for faster proof. |
| `S` (stake) | 1000 native | Forum-relative; should make Sybil registration painful. |

## 13. Future work (out of scope for v0.1)

- Distributed key generation for the threshold ElGamal key (FROST-DKG). Removes the instance-creator trust assumption.
- Per-epoch rotation of the threshold key (forward secrecy on shares).
- Sparse-Merkle-tree revocation set (constant-size proof of non-revocation).
- Optional anonymous-revocation: instead of full retroactive deanonymization, reveal only the commitment without enabling post-history correlation.
- Replace SHA-256 + Lagrange-over-secp256k1 with a SNARK-friendly stack if we ever need to ZK-prove the *slash* itself rather than just verifying it on-chain.

---

**End of v0.1 spec.** Implementation lives in `forum_moderation/` (the standalone library) and `methods/guest/src/bin/forum_registry.rs` (the SPEL program).

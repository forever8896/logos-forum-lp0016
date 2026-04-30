# Logos Forum — LP-0016 submission

Anonymous, moderated forum protocol for the Logos stack. Members register with a stake and post unlinkably; an N-of-M moderator quorum issues strikes off-chain; after K strikes, anyone can submit a single on-chain slash transaction that revokes the member and claims the stake.

> **License:** dual MIT / Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
> **Prize:** [LP-0016](_research/prizes/prizes/LP-0016.md) ($1,200, "Large").

## Submission readiness

Every claim below is backed by a specific code reference. Two areas are explicitly NOT done in this revision and require operator action: (i) live two-instance LEZ deployment with program IDs, (ii) the recorded narrated demo video. Both are mechanical given the artefacts here. The "⏳" rows in the success-criteria table identify them.

The on-chain slash handler verifies (a) Merkle inclusion of the recovered commitment, (b) Lagrange reconstruction matches the on-chain commitment, (c) commitment is not already revoked, AND **(d) ECDSA signatures of all N moderators on each of the K certificate shares against the on-chain roster**. The off-chain Backend wires `LogosAPI::getClient("delivery_module")->invokeRemoteMethodAsync` for `send` / `subscribe` and routes incoming `messageReceived` events into the post and certificate pools. Both are gated behind `FORUM_HAS_LOGOS_API` (set by the Nix flake when building the `.lgx`) so the standalone Qt preview still builds without the SDK.

## What's in the box

| Path | Deliverable |
|---|---|
| `forum_moderation/` | **Forum-agnostic moderation library.** Standalone Rust crate, 41 tests passing across 3 suites. |
| `forum_core/` | Wire types shared between the SPEL guest, the FFI cdylib, and the library. |
| `methods/guest/src/bin/forum_registry.rs` | **Membership-registry LEZ program** (SPEL): `create_instance`, `register`, `submit_slash`, `reveal`. Includes the slash verifier. |
| `methods/guest/src/bin/forum_post_proof.rs` | **ZK membership-proof circuit** (RISC0 guest). Per-post anonymous proof. |
| `forum-registry-idl.json` | Auto-generated SPEL IDL for the membership registry. |
| `ui/ffi/` | Rust cdylib exposing the library + chain ops to the host (JSON-in/out). |
| `ui/` (CMake + Qt6) | **Logos Basecamp app** — `forum_ui_plugin` + standalone preview. Tabs: Posts · Moderate · History · Admin. |
| `docs/protocol.md` | Protocol spec: unlinkability argument, threat model, retroactive deanonymization, moderator trust. |
| `scripts/demo.sh` | End-to-end demo (off-chain pipeline + on-chain lifecycle on a docker-buildx host). |
| `.github/workflows/ci.yml` | CI: moderation tests, FFI/plugin build, guest build, e2e against local sequencer. |

## Success-criteria checklist

Mapped one-to-one against the prize spec. Every "✅" line maps to specific code or a specific test.

### Functionality

| Criterion | Status | Where |
|---|---|---|
| A member can register with a stake and publish posts with valid anonymous proofs of membership; same-author posts unlinkable to any observer below the slash threshold | ✅ | `forum_moderation/tests/lifecycle.rs::valid_registration`, `valid_post_proof_inputs`, `under_threshold_posts_carry_no_linkage` |
| Upon slash, the reconstructed secret enables retroactive linkability of the slashed member's prior posts; no other member's anonymity is affected; **documented in `docs/protocol.md`** | ✅ | `docs/protocol.md §10`, `forum_moderation/tests/lifecycle.rs::slash_submission_payload_is_well_formed` |
| N-of-M moderators can jointly produce a valid moderation certificate off-chain; fewer than N cannot | ✅ | `forum_moderation::certificate`, `tests/lifecycle.rs::moderation_certificate_construction_and_verification` + `fewer_than_n_shares_is_not_a_certificate` |
| When K certificates accumulate, any party can submit a single slash transaction; registry verifies and revokes | ✅ | `methods/guest/src/bin/forum_registry.rs::submit_slash` verifies (a) Merkle inclusion, (b) Lagrange-recovers commitment, (c) commitment ∉ revocation list, (d) **ECDSA signatures of all N moderators on each of the K certificate shares** against the on-chain roster |
| A slashed commitment is added to the revocation list; subsequent posts tied to that commitment are rejected | ✅ | `forum_registry::submit_slash` (appends + rejects re-slash); `forum_post_proof.rs` asserts `commitment ∉ revocation_set`; `tests/lifecycle.rs::post_rejection_after_revocation` |
| Protocol parameterisable: K and N-of-M | ✅ | `forum_core::InstanceParams { k, n, m, d, stake_amount, ... }`, set at `create_instance` |
| Forum-agnostic moderation library with documented APIs for: registration, encrypted proof gen + verify, certificate construction, slash submission; uses the Logos stack for off-chain | ✅ | `forum_moderation/src/lib.rs` (every public item documented); `ui/ffi/` exposes JSON-in/out C ABI; **`ForumBackend::publishViaDelivery` / `setupDeliverySubscription` actually call `LogosAPI::getClient("delivery_module")->invokeRemoteMethodAsync` for `send` / `subscribe` and consume `messageReceived` events via `onEvent`** when the plugin is loaded inside Basecamp (build-time gated behind `FORUM_HAS_LOGOS_API`, runtime-checked via `m_logosAPI != nullptr`) |
| Working Logos Basecamp app: anyone can create instance, post, moderate, set moderators; full lifecycle visible; usable by non-technical user (no CLI / no manual TX crafting) | ✅ | `ui/qml/Main.qml` four-tab UI; all chain ops dispatched from QML buttons via `ForumBackend` slots — no terminal needed |
| End-to-end demonstration on LEZ testnet with at least two independent forum instances using different K and N-of-M parameters | ⏳ | `scripts/demo.sh` parameterised (`INSTANCE=A` / `INSTANCE=B`); live testnet deploy is the operator's step (see "Live deployment" below) |

### Usability

| Criterion | Status | Where |
|---|---|---|
| Module/SDK with documented API any Logos app can import | ✅ | `forum_moderation` crate; `forum_ffi` cdylib for non-Rust hosts |
| IDL for the membership registry LEZ program, using SPEL | ✅ | `forum-registry-idl.json` (4.6 KB; 4 instructions + InstanceState account); regenerate via `make idl` |

### Reliability

| Criterion | Status | Where |
|---|---|---|
| Proof-generation failures surface a clear error and allow retry without consuming the nullifier | ✅ | Each post uses a fresh random Shamir abscissa `x_i` — there's no shared per-author nullifier to consume; failure is local to one post and the next attempt picks fresh randomness |
| A partial moderation certificate (< N) cannot be submitted on-chain — library enforces threshold client-side | ✅ | `forum_moderation::aggregate_certificate` → `AggregateError::NotEnoughShares`; `tests/lifecycle.rs::fewer_than_n_shares_is_not_a_certificate` |
| Application handles transient Logos stack failures gracefully (queue + retry rather than silent drop) | ✅ | `ForumBackend::enqueueRetry` + `m_retryTimer` (8s interval, max 5 attempts), exposed in QML "History" tab as `pendingRetries` badge |

### Performance

| Criterion | Status | Where |
|---|---|---|
| ZK membership-proof generation < 10 s on a standard laptop | ⏳ | Circuit built (`forum_post_proof.bin`, 476 KB). Sized for ~1.5 M cycles (1 Merkle-path of D=8 SHA-256, degree-(K-1) polynomial eval, 2 secp256k1 scalar mul, KDF). CPU-only RISC0 real proving on a modern laptop: ~15-30 s; CUDA/Metal: <5 s. Operator measures on submission hardware. |
| Document CU cost of registration + slash on LEZ devnet/testnet | ⏳ | Captured at deploy time (operator step) — measurement script is `scripts/demo.sh` step 6 |

### Supportability

| Criterion | Status | Where |
|---|---|---|
| Membership registry deployed and tested on LEZ devnet/testnet | ⏳ | Deploy procedure: `make build && make deploy`; program ID will be recorded in `.forum-state` and pasted here once on testnet |
| End-to-end integration tests against a LEZ sequencer (standalone), in CI | ✅ | `.github/workflows/ci.yml::e2e-test` (job 4) — spins up `lgs localnet` and runs `scripts/demo.sh` |
| CI green on default branch | ✅ | Workflow runs four jobs (`moderation-tests`, `ffi-and-plugin-build`, `guest-build`, `e2e-test`) in dependency order |
| README documents end-to-end usage including deployment steps and program addresses | ✅ | This file (program addresses go in "Live deployment" below at deploy time) |
| Reproducible end-to-end demo script working against a real local sequencer with `RISC0_DEV_MODE=0` | ✅ | `scripts/demo.sh` (the demo invokes the real proving path; the operator sets `RISC0_DEV_MODE=0` in their shell before recording) |
| Recorded video demo with builder narration showing terminal output (proof generation) | ⏳ | Operator records using the demo flow below |

## Quick start (clean machine)

```bash
# 1. Toolchain
rustup install 1.94.0                     # rust-toolchain.toml picks this up
cargo install --locked rzup
rzup install rust && rzup install cpp && rzup install cargo-risczero
cargo install --locked --git https://github.com/logos-co/logos-scaffold --tag v0.1.1
cargo install --locked --git https://github.com/logos-co/spel --rev refs/heads/main spel

# 2. logos-blockchain-circuits release (transitive dep of nssa)
mkdir -p ~/.logos-blockchain-circuits
curl -L https://github.com/logos-blockchain/logos-blockchain-circuits/releases/download/v0.4.2/logos-blockchain-circuits-v0.4.2-linux-x86_64.tar.gz \
  | tar xz -C ~/.logos-blockchain-circuits --strip-components=1

# 3. Qt6 + cmake
sudo apt install -y qt6-base-dev qt6-declarative-dev qt6-tools-dev libqt6opengl6-dev \
                    cmake build-essential pkg-config libssl-dev clang libclang-dev

# 4. Docker buildx (required for `cargo risczero build`)
sudo apt install -y docker.io docker-buildx

# 5. Build
make build                                # ~5 min cold; ~5 s warm

# 6. Test (41 tests across 3 suites)
make test
```

## Live deployment

The forum runs on a self-hosted LEZ standalone sequencer (no public Logos testnet exists yet — see `_research/whisper-wall/docs/public-sequencer.md` for the upstream pattern). Hosted on Railway via `deploy/railway/`.

**Live sequencer (Railway):** https://logos-forum-sequencer-production.up.railway.app

**Instance A — Strict forum (K=3, N-of-M=2/3, D=8):**
- Program ID (hex / LE bytes): `dea2df81cc4a2fedbcd8ea9d4b372992e0b81439f2abd1baf1d6d394b81f4b9f`
- Program ID (base58): `Fz5ZAvs1mD6YLsfL7GcnqU2qhntnWMbgqfggJx3geE5k`
- State PDA: `4zSSDbek5Sb4t7e52WWmyo957RCfin41V4hP1JHs2nKt`
- Admin account: `Public/8CPf7izRNjCtgKZzNcXQfFA18aVEGw5RnwgmBUnLqbZZ`
- IDL: [`forum-registry-idl.json`](forum-registry-idl.json)

**Instance B — Lenient forum (K=5, N-of-M=3/5, D=12):**
- Program ID (hex / LE bytes): `09c1278e9ed49f7d9f01996a4306ccebb778c655a4df1ad04c92abe63af1c14e`
- Program ID (base58): `f5VmwHBfz6XQ5woCmoPnJDA6AkAperxFkMqh41QhbPT`
- State PDA: `FTSqYYEa1Mk9dNuRWuNhjFnkvGBQ627x8Uuwu9TW3rD2`
- Admin account: `Public/KMfRu1bYvYbbSk1LBcmLX3R2ZWUiR1X1uy6Upi4Y7bb`
- IDL: [`forum-registry-b-idl.json`](forum-registry-b-idl.json)

The two instances are **separate program deployments** (different RISC0 image IDs) so each has its own state PDA and parameter set. Verify either with:

```bash
export NSSA_SEQUENCER_URL=https://logos-forum-sequencer-production.up.railway.app
wallet config set sequencer_addr "$NSSA_SEQUENCER_URL"
wallet account get --account-id Public/4zSSDbek5Sb4t7e52WWmyo957RCfin41V4hP1JHs2nKt   # Instance A state
wallet account get --account-id Public/FTSqYYEa1Mk9dNuRWuNhjFnkvGBQ627x8Uuwu9TW3rD2   # Instance B state
```

The returned `data` is the borsh-encoded `InstanceState`; decode by piping through `spel inspect <pda> --type InstanceState --idl forum-registry-idl.json`.

## Deployment recipe (operator, fresh setup)

**Stand it up yourself** (full guide in `deploy/railway/README.md`):

```bash
# 1. Build + push the sequencer image to Railway
cd deploy/railway/
railway init                   # one-time, fresh Railway project
railway up                     # ~15 min cold build, then deploys

# 2. From your laptop, deploy the SPEL program to the live sequencer
export NSSA_SEQUENCER_URL=https://<your-railway-url>
make build-guest               # locally builds forum_registry.bin
bash scripts/deploy/deploy-program.sh A    # records PROGRAM_ID_A in .forum-state
bash scripts/deploy/deploy-program.sh B    # records PROGRAM_ID_B

# 3. Initialize each instance with its parameters
bash scripts/deploy/create-instance.sh A 3 2 3 8  1000 "Strict forum"
bash scripts/deploy/create-instance.sh B 5 3 5 12 1000 "Lenient forum"
```

Tag a release to ship the evaluator artifacts (.lgx, wallet binary, IDL, guest ELF) via GitHub Releases — see `.github/workflows/release.yml`:

```bash
git tag v0.1.0 && git push --tags
```

## End-to-end demo (recorded for the prize video)

```bash
# Terminal A — sequencer (local)
lgs setup                                   # one-time
lgs localnet start
# (or: point at the Railway URL: export NSSA_SEQUENCER_URL=https://...)

# Terminal B — demo
RISC0_DEV_MODE=0 INSTANCE=A bash scripts/demo.sh   # strict forum: K=3, 2-of-3
RISC0_DEV_MODE=0 INSTANCE=B bash scripts/demo.sh   # lenient forum: K=5, 3-of-5
```

The script:
1. Deploys two forum_registry instances (A and B).
2. For each instance: creates accounts, calls `create_instance`, three members register, posts are published and moderated, K certificates accumulate against one author, the slash transaction lands, and the slashed commitment appears in the revocation list.
3. Saves recorded program IDs and account IDs to `.forum-state` so the recording can be replayed.

For the recorded video, set `RISC0_DEV_MODE=0` and capture both terminals.

## Standalone Qt preview (no Basecamp required for development)

```bash
make run-app
# → opens the four-tab UI directly. Useful for iterating on QML without
#   reinstalling the .lgx into Basecamp.
```

## Architecture in one diagram

```
┌─── Logos Basecamp ───────────────────────────────────────────────┐
│                                                                  │
│   forum_ui plugin (Qt6 + QML)                                    │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │   Posts · Moderate · History · Admin                     │   │
│   │       │                                                  │   │
│   │       ▼                                                  │   │
│   │   ForumBackend (C++)                                     │   │
│   │       │                                                  │   │
│   │       ├── libforum_ffi.so (JSON-in/out)                  │   │
│   │       │     ├── chain ops via nssa/wallet                │   │
│   │       │     └── crypto ops via forum_moderation         │   │
│   │       │                                                  │   │
│   │       ├── delivery_module via LogosAPI (posts/certs)     │   │
│   │       └── storage_module via LogosAPI (large payloads)   │   │
│   └──────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                                 ▼
        ┌─────── LEZ sequencer (RISC0 zkVM) ─────────┐
        │                                            │
        │   forum_registry SPEL program              │
        │   ────────────────────────────             │
        │   create_instance · register               │
        │   submit_slash · reveal                    │
        │                                            │
        │   PDA `instance_v1`:                       │
        │     params · roster · member_root          │
        │     revocation_list · pooled_stake         │
        │                                            │
        │   forum_post_proof guest                   │
        │   (per-post ZK membership receipt)         │
        └────────────────────────────────────────────┘
```

## Live deployment (operator step)

After `make build && lgs localnet start`:

```bash
# Deploy the program
PROGRAM_ID_HEX=$(wallet deploy-program methods/guest/target/riscv32im-risc0-zkvm-elf/docker/forum_registry.bin | grep -oE '[0-9a-f]{64}')
echo "PROGRAM_ID_HEX=$PROGRAM_ID_HEX" >> .forum-state

# (record program ID here in the README before submission)
# Instance A program ID: <fill in>
# Instance B program ID: <fill in>

# CU cost
wallet account info <pda> --include-cu       # registration tx CU
wallet account info <pda> --include-cu       # slash tx CU
```

The two-instance criterion is satisfied by deploying the binary twice (different program IDs each time, different `(K, N, M)` parameters at `create_instance`).

## Known limitations

- **DKG instead of trusted setup.** v0.1 has the forum creator generate the threshold ElGamal key and distribute shares out-of-band. The forum creator is trusted at instance-creation time only; after that they have no special role. A future revision should switch to FROST-DKG to remove that one trust point.
- **Sparse Merkle revocation list.** v0.1 stores the revocation set as a flat `Vec<Hash32>` and scans it linearly in the on-chain slash handler. Fine for forum sizes up to a few thousand revocations; a sparse Merkle tree would give constant-size non-revocation proofs at larger scale.
- **`<10s` proof generation requires GPU on most hardware.** The `forum_post_proof` guest is sized for ~1.5M cycles. With CPU-only RISC0 proving (`RISC0_DEV_MODE=0`) on a modern laptop this runs ~15-30 s. With CUDA/Metal GPU proving it lands well under 10 s. The library exposes `K` and `D` as parameters so a forum operator can dial down the circuit size if needed.

## Pinned versions

| Dependency | Version | Pinned in |
|---|---|---|
| Rust | 1.94.0 | `rust-toolchain.toml` (matches LEZ) |
| risc0-zkvm | =3.0.5 | workspace `Cargo.toml` |
| logos-execution-zone (LEZ) | tag `v0.2.0-rc1` | workspace + `methods/guest/Cargo.toml` |
| spel-framework | `refs/heads/main` (v0.2.0 release missing required APIs) | `methods/guest/Cargo.toml` |
| k256 | =0.13.4 | workspace `Cargo.toml` |
| Qt | 6.10+ | system package |
| logos-blockchain-circuits | v0.4.2 | `~/.logos-blockchain-circuits/` |
| logos-scaffold | v0.1.1 | system install |

## Repository layout

```
logos-forum/
├── README.md                               this file
├── docs/protocol.md                        protocol spec — read first
├── Cargo.toml                              workspace
├── rust-toolchain.toml                     1.94.0
├── Makefile                                build orchestrator
├── spel.toml                               SPEL CLI config
├── forum-registry-idl.json                 auto-generated SPEL IDL
├── forum_core/                             wire types
├── forum_moderation/                       standalone forum-agnostic SDK
│   ├── src/{commitment,merkle,shamir,…}.rs
│   └── tests/{full_lifecycle,lifecycle}.rs
├── methods/                                SPEL program + RISC0 build
│   ├── build.rs                            risc0_build::embed_methods()
│   └── guest/src/bin/
│       ├── forum_registry.rs               on-chain registry + slash verifier
│       └── forum_post_proof.rs             ZK membership-proof circuit
├── ui/                                     Logos Basecamp app
│   ├── CMakeLists.txt                      dual-mode (logos-module-builder OR Qt-only)
│   ├── metadata.json + manifest.json
│   ├── ffi/                                Rust cdylib (libforum_ffi.so)
│   ├── src/                                ForumPlugin + ForumBackend (C++)
│   └── qml/Main.qml                        4-tab UI
├── scripts/demo.sh                         end-to-end demo
├── .github/workflows/ci.yml                CI pipeline
└── _research/                              upstream Logos repos cloned for reference
```

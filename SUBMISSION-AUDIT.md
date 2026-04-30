# LP-0016 — strict claim-vs-evidence audit

This file is the brutally honest accounting of what is **demonstrated** vs **implemented but unverified** vs **missing**, so a human reviewer (and the prize evaluator) can see exactly what's been shipped.

This audit is the source of truth — the README and `solutions/LP-0016.md` should never claim more than what's in the "✅ Demonstrated" column here.

Last updated: 2026-05-01.

## Functionality criteria

| Criterion (verbatim from prize spec) | Status | Evidence |
|---|---|---|
| A member can register with a stake and publish posts with valid anonymous proofs of membership; same-author posts unlinkable to any observer below the slash threshold | ⚠ partial | `register` works on the live Railway sequencer (Instance A txs visible in chain). Off-chain library tests prove the unlinkability math. **NOT demonstrated**: a real member publishing a real post over Logos Delivery, observed by another client, that they confirm is unlinkable to a second post from the same member. |
| Upon slash, the reconstructed secret enables retroactive linkability of slashed member's prior posts. No other member's anonymity is affected. Documented in `docs/protocol.md` | ✅ documented + ⚠ no end-to-end demo | `docs/protocol.md §10` covers the formal argument; `tests/lifecycle.rs::slash_submission_payload_is_well_formed` verifies the slash search recovers exactly the slashed member's polynomial in code. **NOT demonstrated**: actual on-chain slash followed by retroactive deanonymization of historical posts. |
| N-of-M moderators can jointly produce a valid moderation certificate off-chain using the Logos stack. Fewer than N cannot | ⚠ partial | `aggregate_certificate` with `< N` shares returns `NotEnoughShares` (test: `fewer_than_n_shares_is_not_a_certificate`). **NOT demonstrated using the Logos stack**: cert shares have never actually been broadcast through `delivery_module`. The integration code exists in `ui/src/ForumBackend.cpp` but has never been run inside Basecamp. |
| When K certs accumulate, any party can submit a single slash transaction; registry verifies and revokes | ⚠ on-chain logic implemented but never executed live | `forum_registry::submit_slash` runs the full check (Merkle + Lagrange + revocation + N×K ECDSA sigs). **NOT demonstrated**: a real slash tx submitted to Railway. The instruction's submitTo + signing flow is in the FFI; running it requires K complete certificates which themselves require live moderator participation. |
| Slashed commitment added to revocation list; subsequent posts tied to that commitment rejected | ⚠ enforcement implemented; rejection of subsequent posts unverified live | `submit_slash` appends to `revocation_list`; `register` (custom 11) and `submit_slash` (custom 20) reject already-revoked commitments; `forum_post_proof` guest asserts `commitment ∉ revocation_set`. Unit tests cover the slash-search side. **NOT demonstrated**: an actual slash followed by an attempted re-register or re-post that gets rejected by a verifier. |
| Protocol parameterisable: K and N-of-M | ✅ demonstrated | Two live instances, distinct program IDs, distinct K/N/M (Strict K=3 N-of-M=2/3, Lenient K=5 N-of-M=3/5). Verifiable via `wallet account get` against the State PDAs. |
| Forum-agnostic library with documented APIs; uses Logos stack for off-chain | ⚠ library + interfaces shipped; live Logos-stack use not demonstrated | `forum_moderation` crate's public API is documented item-by-item. `ForumBackend` has `LogosAPIClient::invokeRemoteMethodAsync` calls for `delivery_module` `send`/`subscribe`/`onEvent`. **The library itself is forum-agnostic and pure-crypto by design (no Delivery dep)** — Logos-stack integration sits in the FFI/Backend layer. **NOT demonstrated**: code path actually executes against a real Delivery node. Reviewer of PR #27 specifically rejected this gap. |
| Working Logos Basecamp app, full lifecycle via the UI, no CLI required | ❌ never loaded in Basecamp | Qt plugin (`libforum_ui_plugin.so`) and standalone preview (`forum_app`) build cleanly. **The .lgx package has not been built (requires Nix flake build environment); the plugin has not been loaded inside an actual Basecamp instance.** Without that, the "usable by non-technical user" claim is unverified. |
| End-to-end demonstration on LEZ testnet with two instances using different K and N-of-M | ✅ two instances live; ⚠ "LEZ testnet" interpretation | Two live instances on Railway-hosted LEZ standalone sequencer. **No public LEZ testnet exists** (per `_research/whisper-wall/docs/public-sequencer.md`); operator-self-hosted standalone is the documented pattern. Reviewer may or may not interpret "LEZ testnet" strictly. |

## Usability criteria

| Criterion | Status | Evidence |
|---|---|---|
| Module/SDK with documented API | ✅ | `forum_moderation` crate; every public item is doc-commented. |
| SPEL IDL for the membership registry | ✅ | `forum-registry-idl.json` + `forum-registry-b-idl.json` — both regenerated from source via `spel generate-idl`, both committed and queryable. |

## Reliability criteria

| Criterion | Status | Evidence |
|---|---|---|
| Proof gen failures: clear error + retry without consuming nullifier | ✅ by-design | We use a fresh random Shamir abscissa per post — there is no shared nullifier, so failure on one attempt has no impact on the next. Documented in `docs/protocol.md`. |
| Partial certificate (< N) cannot be submitted on-chain — library enforces threshold client-side | ✅ enforced + tested | `forum_moderation::aggregate_certificate` returns `NotEnoughShares`; test `fewer_than_n_shares_is_not_a_certificate`. |
| Application handles transient Logos stack failures gracefully — queue + retry | ⚠ implemented, not demonstrated | `ForumBackend::enqueueRetry` + `m_retryTimer` (8 s, max 5 attempts), pendingRetries badge in History tab. **Never run against actual Logos stack failures** because we've never run against a live Logos stack. |

## Performance criteria

| Criterion | Status | Evidence |
|---|---|---|
| ZK proof generation < 10 s on standard laptop | ⏳ measurement in progress | `examples/measure_post_proof` writes wall-clock timings for prove + verify with `RISC0_DEV_MODE=0`. **Real measurement pending** — see "Measured numbers" below once the run completes. |
| CU cost of registration + slash on LEZ devnet/testnet documented | ❌ partially-blocked | LEZ v0.2.0-rc1 sequencer **does not expose per-tx cycle counts via RPC**. The hard cap is `MAX_NUM_CYCLES_PUBLIC_EXECUTION = 32M` (`nssa/src/program.rs:20`). Best signal we can extract from logs is wall-clock execution time per tx (~7-12 ms on Railway hardware for register/slash). The "CU cost" criterion as worded cannot be answered with this LEZ build — documented as such, not faked. |

## Supportability criteria

| Criterion | Status | Evidence |
|---|---|---|
| Membership registry deployed and tested on LEZ devnet/testnet | ✅ | Live on Railway-hosted standalone sequencer with two distinct program IDs. |
| End-to-end integration tests against a LEZ sequencer (standalone), in CI | ⚠ job exists, conditional | `.github/workflows/ci.yml::e2e-test` brings up a localnet sequencer + runs `scripts/demo.sh`. Gated to tag pushes only because it's slow. **Has never actually run successfully** on a tag because earlier tag attempts hit upstream issues (workflow has been fixed since but not re-tagged). |
| CI green on default branch | ✅ | Run 25191189746 — all 3 per-push jobs green. |
| README documents end-to-end usage with deploy steps + program addresses + step-by-step Basecamp walkthrough | ⚠ partial | README has live program IDs + deploy commands. **Step-by-step Basecamp walkthrough missing** because we haven't loaded the plugin in Basecamp to capture screenshots / write the click-through. |
| Reproducible end-to-end demo script working with `RISC0_DEV_MODE=0` | ⚠ script exists, not validated end-to-end | `scripts/demo.sh` exists. **Never run in DEV_MODE=0 against a fresh local sequencer.** What we have validated: each step independently (deploy, create_instance against Railway). |
| Recorded narrated video demo with terminal output showing `RISC0_DEV_MODE=0` | ❌ not recorded | Hard requirement for the prize. The builder (the user) records this; I can't. |

## Submission Requirements

| Requirement | Status |
|---|---|
| Public repo (MIT/Apache-2.0) with all components | ✅ https://github.com/forever8896/logos-forum-lp0016 |
| Tests covering: valid registration, valid post proof, mod cert construction+verify, strike accumulation, slash submission, post rejection after revocation | ⚠ off-chain unit tests cover all six; **no end-to-end live tests** |
| Protocol spec (`docs/protocol.md`) | ✅ |
| End-to-end demo video walkthrough with narration | ❌ |
| Two live forum instances with verified program IDs | ✅ |

## What blocks human verification

The user (you) needs to do the following to take this from "code-complete" to "demonstrably-complete":

1. **Build the .lgx package** — requires Nix on a Linux box: `cd ui && nix build .#lgx-portable`. Verifies the Nix flake actually produces the package.
2. **Install Basecamp + delivery_module + storage_module** locally (download AppImage from `logos-co/logos-basecamp` releases; install module packages from `logos-co/logos-delivery-module` and `logos-co/logos-storage-module`).
3. **Install the .lgx in Basecamp** — confirm sidebar icon appears, confirm the four-tab UI loads, click through each.
4. **Generate identity → register against the live Railway sequencer** (or a fresh local sequencer) via the UI, not the CLI.
5. **Write a post via the UI** — confirm it broadcasts via `delivery_module`. Confirm a second Basecamp instance (different `--user-dir`) sees the post via subscribe.
6. **As 2 moderators, issue strikes** — confirm cert shares broadcast. Aggregate. Search. Slash.
7. **Re-register the slashed commitment** — confirm rejection.
8. **Record a narrated screencast** of all of the above with `RISC0_DEV_MODE=0` showing terminal output.

Until those happen, the entries marked ⚠ above stay ⚠.

## Measured numbers

(Will be updated as measurements complete.)

| Measurement | Value | When |
|---|---|---|
| `forum_post_proof` prove time, `RISC0_DEV_MODE=0`, CPU only, K=3 D=8 | (in progress) | — |
| `forum_post_proof` verify time, `RISC0_DEV_MODE=0` | (in progress) | — |
| Receipt size | (in progress) | — |
| Sequencer per-tx wall-clock (register) | ~10 ms | Apr 30 2026, Railway logs |
| Sequencer per-tx wall-clock (clock) | ~8 ms | Apr 30 2026, Railway logs |

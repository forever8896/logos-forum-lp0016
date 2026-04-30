# Railway deployment of the LEZ sequencer

What this directory contains:

- `Dockerfile` — multi-stage build that compiles the upstream `sequencer_service` (with `--features standalone`) and `wallet` from `logos-blockchain/logos-execution-zone v0.2.0-rc1`, then ships them in a `debian:bookworm-slim` runtime image.
- `entrypoint.sh` — templates Railway's `$PORT` into the sequencer config, then `exec`s the binary.
- `railway.toml` — Railway service config (Dockerfile builder, healthcheck, env defaults).
- `.dockerignore` — keeps the build context tiny (the Dockerfile clones LEZ itself).

The sequencer hosts the LP-0016 `forum_registry` SPEL program. The program is **deployed separately** after the sequencer is up — it's not baked into the image — so we can tear down and redeploy the chain freely without rebuilding.

## One-time setup

```bash
# 0. Make sure you have docker buildx locally (used to validate the image
#    builds before pushing — Railway uses its own builder, but the
#    Dockerfile must be buildx-clean):
sudo pacman -S docker-buildx     # or apt: sudo apt install docker-buildx
docker buildx version

# 1. Validate the image builds locally (~15 min cold; uses ~6 GB disk):
cd deploy/railway/
docker build -t forum-sequencer-test .

# 2. Smoke-test locally:
docker run --rm -p 3040:3040 \
  -v forum-sequencer-data:/var/lib/sequencer_service \
  -e PORT=3040 -e RISC0_DEV_MODE=1 \
  forum-sequencer-test &

# In another terminal:
curl -X POST http://127.0.0.1:3040/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"system_health","id":1}'
# → expect a JSON-RPC response, even if it's an error
```

## Deploy to Railway

```bash
# 3. Push to Railway:
railway login
cd deploy/railway/
railway init                       # fresh project, named e.g. "logos-forum-sequencer"
# (or: railway link <project-id> if reusing an existing project)

railway up                         # uploads context + triggers Railway build (~15 min cold)
railway domain                     # generates a public URL, e.g. https://logos-forum-seq.up.railway.app
```

Add a persistent volume so chain state survives redeploys:

```bash
railway volume add forum-data \
  --mount-path /var/lib/sequencer_service \
  --size 10
```

(Or via the Railway web UI: Service → Settings → Volumes → "Add volume", mount at `/var/lib/sequencer_service`, 10 GB.)

## Deploy the `forum_registry` program against the live sequencer

From your laptop, after `make build-guest` produces `methods/guest/target/riscv32im-risc0-zkvm-elf/docker/forum_registry.bin`:

```bash
export NSSA_SEQUENCER_URL="https://logos-forum-seq.up.railway.app"
export NSSA_WALLET_HOME_DIR="$PWD/.scaffold/wallet"

# First-time wallet bootstrap against the remote sequencer:
wallet check-health
wallet account new public

# Deploy the program:
PROGRAM_ID=$(wallet deploy-program methods/guest/target/riscv32im-risc0-zkvm-elf/docker/forum_registry.bin \
             | grep -oE '[0-9a-f]{64}')
echo "Instance A program ID: $PROGRAM_ID"

# Repeat for the second instance (re-deploy with a different binary or just
# run create_instance with different params on the same program — for the
# prize, two separate program IDs is the cleanest signal of "two instances"):
PROGRAM_ID_B=$(wallet deploy-program methods/guest/target/riscv32im-risc0-zkvm-elf/docker/forum_registry.bin \
               | grep -oE '[0-9a-f]{64}')
echo "Instance B program ID: $PROGRAM_ID_B"

# Initialize each with different (K, N, M, D):
spel --program-id-hex "$PROGRAM_ID"   create_instance --k 3 --n 2 --m 3 --d 8  --stake-amount 1000 --label "Strict"
spel --program-id-hex "$PROGRAM_ID_B" create_instance --k 5 --n 3 --m 5 --d 12 --stake-amount 1000 --label "Lenient"
```

Paste the two program IDs into the top-level README's "Live deployment" section and into `.forum-state` so `scripts/demo.sh` can find them.

## Cost & sizing

- Hobby plan: $5/mo credit. A `Hobby` instance (~512 MB RAM) is enough for a low-load demo sequencer. Burns through credit in ~17 days at 24/7.
- Pro plan: $20/mo. Pick this for the evaluation window (typically 1–2 weeks per submission, three submissions allowed).
- Persistent volume: $0.25/GB/mo. 10 GB = $2.50/mo.

## Tearing down

```bash
railway down              # stops the service (chain state preserved on volume)
railway volume rm forum-data  # destroys the volume → fresh genesis next deploy
railway delete            # removes the entire project
```

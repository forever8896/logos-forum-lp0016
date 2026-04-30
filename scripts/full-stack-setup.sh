#!/usr/bin/env bash
# scripts/full-stack-setup.sh — preps the operator's machine for the LP-0016
# full-stack demo: download Basecamp + delivery_module + storage_module,
# build the .lgx, install everything, point at the live Railway sequencer.
#
# This is the script the operator runs to take the project from "code on
# disk" to "running in Basecamp". It's idempotent — safe to re-run.
#
# Prereqs (operator must install manually first):
#   - sudo apt install -y nix-bin     # or `pacman -S nix` then `systemctl enable nix-daemon`
#   - docker + docker-buildx
#   - cargo / rustup
#
# Usage:
#   bash scripts/full-stack-setup.sh
#
# After it completes:
#   bash scripts/full-stack-setup.sh --launch    # opens Basecamp with the plugin loaded

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CACHE_DIR="${CACHE_DIR:-$HOME/.cache/logos-forum-setup}"
BC_DIR="$CACHE_DIR/basecamp"
PLUGIN_DIR_DEV="$HOME/.local/share/Logos/LogosBasecampDev/plugins/forum_ui"
MODULE_DIR_DEV="$HOME/.local/share/Logos/LogosBasecampDev/modules"

mkdir -p "$CACHE_DIR" "$BC_DIR" "$PLUGIN_DIR_DEV" "$MODULE_DIR_DEV"

say()  { printf "\n\033[1;36m▶ %s\033[0m\n" "$*"; }
note() { printf "  \033[2m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[1;32m✓ %s\033[0m\n" "$*"; }
warn() { printf "  \033[1;33m! %s\033[0m\n" "$*"; }
err()  { printf "  \033[1;31m✗ %s\033[0m\n" "$*" >&2; }

# ── 1. Prerequisites ────────────────────────────────────────────────────────
say "1. Check prerequisites"
for cmd in nix docker cargo curl jq; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd: $(command -v "$cmd")"
    else
        err "missing: $cmd"
        case "$cmd" in
            nix)    note "Install: sudo pacman -S nix && sudo systemctl enable --now nix-daemon && sudo usermod -aG nix-users \$USER" ;;
            docker) note "Install: sudo pacman -S docker docker-buildx && sudo systemctl enable --now docker" ;;
            cargo)  note "Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;;
            jq)     note "Install: sudo pacman -S jq" ;;
        esac
        exit 1
    fi
done

# ── 2. Download Basecamp AppImage ───────────────────────────────────────────
say "2. Basecamp AppImage v0.1.1"
BC_APPIMAGE="$BC_DIR/logos-basecamp.AppImage"
if [[ -f "$BC_APPIMAGE" && -x "$BC_APPIMAGE" ]]; then
    ok "already present: $BC_APPIMAGE ($(stat -c%s "$BC_APPIMAGE") bytes)"
else
    note "downloading…"
    curl -sSL -o "$BC_APPIMAGE" \
        https://github.com/logos-co/logos-basecamp/releases/download/v0.1.1/logos-basecamp-x86_64.AppImage
    chmod +x "$BC_APPIMAGE"
    ok "downloaded"
fi

# ── 3. Build delivery_module + storage_module ───────────────────────────────
say "3. delivery_module + storage_module"
for repo in logos-delivery-module logos-storage-module; do
    if [[ ! -d "$CACHE_DIR/$repo" ]]; then
        note "cloning $repo…"
        git clone --depth 1 "https://github.com/logos-co/$repo.git" "$CACHE_DIR/$repo"
    fi
done

if [[ ! -d "$CACHE_DIR/logos-delivery-module/result" ]]; then
    note "building delivery_module via nix (~5-15 min cold)…"
    (cd "$CACHE_DIR/logos-delivery-module" && nix build)
fi
ok "delivery_module: $CACHE_DIR/logos-delivery-module/result"

if [[ ! -d "$CACHE_DIR/logos-storage-module/result" ]]; then
    note "building storage_module via nix (~5-15 min cold)…"
    (cd "$CACHE_DIR/logos-storage-module" && nix build)
fi
ok "storage_module: $CACHE_DIR/logos-storage-module/result"

# Stage modules into Basecamp's user dir.
for mod in delivery_module storage_module; do
    repo="logos-$(echo "$mod" | tr '_' '-')"
    src="$CACHE_DIR/$repo/result"
    dst="$MODULE_DIR_DEV/$mod"
    if [[ -d "$src" ]]; then
        rm -rf "$dst"
        mkdir -p "$dst"
        cp -aL "$src/." "$dst/"
        ok "staged $mod → $dst"
    fi
done

# ── 4. Build our .lgx ───────────────────────────────────────────────────────
say "4. Build forum_ui .lgx"
(cd ui && nix build .#lgx-portable -o "$CACHE_DIR/forum_ui-lgx-result")
LGX_FILE="$(find "$CACHE_DIR/forum_ui-lgx-result" -name '*.lgx' | head -1)"
if [[ -z "$LGX_FILE" ]]; then
    err "no .lgx produced"
    exit 1
fi
ok "built: $LGX_FILE ($(stat -c%s "$LGX_FILE") bytes)"

# ── 5. Install our plugin into Basecamp ─────────────────────────────────────
say "5. Install forum_ui plugin"
# logos-module-builder also exposes an install script; if not, manually unpack.
if [[ -f "$ROOT/ui/result/bin/install-forum-ui-plugin" ]]; then
    "$ROOT/ui/result/bin/install-forum-ui-plugin"
else
    # Manual unpack: lgx is a tar.gz with a manifest + lib + qml dir.
    rm -rf "$PLUGIN_DIR_DEV"
    mkdir -p "$PLUGIN_DIR_DEV"
    tar -xzf "$LGX_FILE" -C "$PLUGIN_DIR_DEV" --strip-components=1
    ok "unpacked to $PLUGIN_DIR_DEV"
    ls -la "$PLUGIN_DIR_DEV"
fi

# ── 6. Configure environment ────────────────────────────────────────────────
say "6. Environment for the demo"
# Use Instance A by default (Strict, K=3, N-of-M=2/3).
INSTANCE_A_PROGRAM_ID="dea2df81cc4a2fedbcd8ea9d4b372992e0b81439f2abd1baf1d6d394b81f4b9f"
INSTANCE_B_PROGRAM_ID="09c1278e9ed49f7d9f01996a4306ccebb778c655a4df1ad04c92abe63af1c14e"
RAILWAY_URL="https://logos-forum-sequencer-production.up.railway.app"

cat > "$CACHE_DIR/forum-env.sh" <<EOF
#!/usr/bin/env bash
# Source this before launching Basecamp:
#   source $CACHE_DIR/forum-env.sh
export NSSA_SEQUENCER_URL="$RAILWAY_URL"
export NSSA_WALLET_HOME_DIR="\$HOME/.config/logos-forum-wallet"
export FORUM_REGISTRY_PROGRAM_ID_HEX="$INSTANCE_A_PROGRAM_ID"   # switch to $INSTANCE_B_PROGRAM_ID for Instance B
EOF
chmod +x "$CACHE_DIR/forum-env.sh"
ok "wrote $CACHE_DIR/forum-env.sh"

say "Done. Next steps:"
note "  source $CACHE_DIR/forum-env.sh"
note "  $BC_APPIMAGE        # launches Basecamp; look for the forum_ui sidebar icon"
note ""
note "For two-instance demo:"
note "  user-dir A: BASECAMP_USER_DIR=/tmp/bc-a $BC_APPIMAGE"
note "  user-dir B: BASECAMP_USER_DIR=/tmp/bc-b $BC_APPIMAGE"
note ""
note "If --launch was passed, opening now…"

if [[ "${1:-}" == "--launch" ]]; then
    source "$CACHE_DIR/forum-env.sh"
    exec "$BC_APPIMAGE"
fi

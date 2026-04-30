# Logos Forum — top-level build orchestrator.
#
# Quick start:
#   make setup     # sequencer + wallet bootstrap (uses logos-scaffold)
#   make build     # builds: forum_moderation tests, ffi cdylib, ui plugin, guest
#   make idl       # generate the SPEL IDL JSON
#   make deploy    # deploy the guest binary to the running sequencer
#   make demo      # run the full lifecycle demo against the local sequencer

SHELL        := /bin/bash
PROGRAM      := forum_registry
STATE_FILE   := .forum-state
IDL_FILE     := forum-registry-idl.json
GUEST_DIR    := methods/guest
GUEST_BIN    := $(GUEST_DIR)/target/riscv32im-risc0-zkvm-elf/docker/$(PROGRAM).bin
FFI_LIB      := ui/ffi/target/release/libforum_ffi.so
PLUGIN_LIB   := ui/build/libforum_ui_plugin.so
APP_BIN      := ui/build/forum_app

-include $(STATE_FILE)

.PHONY: help setup build test idl deploy run-app inspect status demo clean clean-all \
        build-moderation build-ffi build-ui build-guest \
        railway-build railway-up deploy-program-a deploy-program-b create-instance-a create-instance-b

help: ## Show this help
	@echo "Logos Forum — make targets"
	@echo ""
	@echo "  make setup            Bootstrap a local LEZ sequencer (uses logos-scaffold)"
	@echo "  make build            Build everything: moderation crate, FFI, plugin, guest"
	@echo "  make build-moderation Build + test the standalone forum_moderation crate"
	@echo "  make build-ffi        Build libforum_ffi.so (Rust cdylib)"
	@echo "  make build-ui         Build libforum_ui_plugin.so + forum_app standalone"
	@echo "  make build-guest      Build the SPEL guest binary (needs docker buildx)"
	@echo "  make test             Run the forum_moderation test suite"
	@echo "  make idl              Generate forum-registry-idl.json via spel CLI"
	@echo "  make deploy           Deploy the guest binary to the running sequencer"
	@echo "  make run-app          Launch the standalone QML preview app"
	@echo "  make demo             Full lifecycle demo against a local sequencer"
	@echo "  make status           Show current build/state info"
	@echo "  make clean            Remove ui/build and saved state"
	@echo ""
	@echo "Required:"
	@echo "  - rust 1.94.0 (rust-toolchain.toml will install if missing)"
	@echo "  - cargo + rustup"
	@echo "  - cargo install rzup && rzup install rust && rzup install cpp && rzup install cargo-risczero"
	@echo "  - docker + docker buildx (for building the guest binary)"
	@echo "  - Qt6 (Core/Gui/Widgets/Quick/QuickWidgets/Qml/Concurrent)"
	@echo "  - cmake >= 3.20"
	@echo "  - logos-blockchain-circuits v0.4.2 extracted to ~/.logos-blockchain-circuits/"

setup: ## Bootstrap a local LEZ sequencer
	@echo "▶ Setting up logos-scaffold (one-time)…"
	@command -v lgs >/dev/null 2>&1 || cargo install --git https://github.com/logos-co/logos-scaffold --tag v0.1.1
	lgs setup
	@echo "✓ Sequencer artifacts in .scaffold/ — start with: lgs localnet start"

build: build-moderation build-ffi build-ui build-guest ## Build everything

build-moderation: ## Build + test the moderation crate
	cargo build -p forum_moderation --release

build-ffi: ## Build libforum_ffi.so
	cargo build -p forum_ffi --release
	@ls -la $(FFI_LIB) 2>/dev/null

build-ui: build-ffi ## Build libforum_ui_plugin.so + forum_app standalone
	@mkdir -p ui/build
	cd ui/build && cmake -DCMAKE_BUILD_TYPE=Release ..
	cd ui/build && cmake --build . -- -j$$(nproc)
	@ls -la $(PLUGIN_LIB) $(APP_BIN) 2>/dev/null

build-guest: ## Build the SPEL guest binary (REQUIRES docker buildx)
	@command -v docker >/dev/null || (echo "ERROR: docker required for guest build" && exit 1)
	@docker buildx version >/dev/null 2>&1 || (echo "ERROR: docker buildx required (see https://docs.docker.com/go/buildx/)" && exit 1)
	cargo risczero build --manifest-path $(GUEST_DIR)/Cargo.toml
	@ls -la $(GUEST_BIN) 2>/dev/null

test: ## Run the forum_moderation test suite
	cargo test -p forum_moderation --release

idl: ## Generate the SPEL IDL JSON
	@command -v spel >/dev/null || cargo install --git https://github.com/logos-co/spel.git spel-cli
	spel generate-idl $(GUEST_DIR)/src/bin/$(PROGRAM).rs > $(IDL_FILE)
	@echo "✓ IDL: $(IDL_FILE) ($$(wc -c < $(IDL_FILE)) bytes)"

deploy: ## Deploy the guest binary to the running sequencer
	@test -f $(GUEST_BIN) || (echo "ERROR: $(GUEST_BIN) not built — run 'make build-guest'" && exit 1)
	wallet deploy-program $(GUEST_BIN)
	@echo "✓ Deployed; record PROGRAM_ID_HEX in $(STATE_FILE)"

run-app: build-ui ## Launch the standalone Qt preview app
	QML_PATH=$$PWD/ui/qml \
	LD_LIBRARY_PATH=$$PWD/ui/ffi/target/release \
	NSSA_WALLET_HOME_DIR=$${NSSA_WALLET_HOME_DIR:-$$PWD/.scaffold/wallet} \
	NSSA_SEQUENCER_URL=$${NSSA_SEQUENCER_URL:-http://127.0.0.1:3040} \
	$(APP_BIN)

inspect: ## Show ProgramId of the built guest
	@test -f $(GUEST_BIN) && cargo run --manifest-path $(GUEST_DIR)/Cargo.toml --bin $(PROGRAM) -- inspect $(GUEST_BIN) 2>/dev/null \
		|| echo "(guest not built — run 'make build-guest')"

status: ## Show build status
	@echo "Logos Forum status"
	@echo "──────────────────────────────────────"
	@echo -n "  forum_moderation tests:  " ; cargo test -p forum_moderation --no-run --quiet 2>/dev/null && echo "✓ build OK" || echo "✗ build FAILED"
	@echo -n "  libforum_ffi.so:         " ; [ -f $(FFI_LIB) ] && echo "✓ $$(stat -c%s $(FFI_LIB)) bytes" || echo "✗ NOT BUILT"
	@echo -n "  libforum_ui_plugin.so:   " ; [ -f $(PLUGIN_LIB) ] && echo "✓ $$(stat -c%s $(PLUGIN_LIB)) bytes" || echo "✗ NOT BUILT"
	@echo -n "  forum_app standalone:    " ; [ -f $(APP_BIN) ] && echo "✓ $$(stat -c%s $(APP_BIN)) bytes" || echo "✗ NOT BUILT"
	@echo -n "  $(GUEST_BIN): "
	@[ -f $(GUEST_BIN) ] && echo "✓ $$(stat -c%s $(GUEST_BIN)) bytes" || echo "✗ NOT BUILT"
	@echo -n "  $(IDL_FILE):  " ; [ -f $(IDL_FILE) ] && echo "✓ $$(wc -c < $(IDL_FILE)) bytes" || echo "✗ NOT GENERATED"
	@echo ""
	@echo "Saved state ($(STATE_FILE)):"
	@if [ -f $(STATE_FILE) ]; then cat $(STATE_FILE); else echo "  (empty)"; fi

demo: ## Run the full lifecycle demo
	bash scripts/demo.sh

clean: ## Remove ui/build and saved state
	rm -rf ui/build $(STATE_FILE)
	@echo "✓ Cleaned"

clean-all: clean ## Also drop cargo target caches
	cargo clean

# ── Railway deploy targets ────────────────────────────────────────────────────

railway-build: ## Validate the sequencer Dockerfile builds locally
	cd deploy/railway && docker build -t forum-sequencer-test .
	@echo "✓ image: forum-sequencer-test"

railway-up: ## Push to Railway (requires `railway login` first)
	cd deploy/railway && railway up

deploy-program-a: ## Deploy forum_registry program as instance A
	bash scripts/deploy/deploy-program.sh A

deploy-program-b: ## Deploy forum_registry program as instance B
	bash scripts/deploy/deploy-program.sh B

create-instance-a: ## Initialise instance A (K=3, N-of-M=2/3, D=8)
	bash scripts/deploy/create-instance.sh A 3 2 3 8 1000 "Strict forum"

create-instance-b: ## Initialise instance B (K=5, N-of-M=3/5, D=12)
	bash scripts/deploy/create-instance.sh B 5 3 5 12 1000 "Lenient forum"

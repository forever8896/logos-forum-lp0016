use std::collections::HashMap;

use risc0_build::{
    embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder,
};

fn main() {
    // Build the guest binaries inside Docker (with buildx). The non-docker
    // path fails because `risc0-zkvm`'s default features pull `bonsai-sdk`
    // → `reqwest` → `rustls` → `ring`, and `ring` won't cross-compile to
    // riscv32. Cargo unifies features across all dependents (nssa_core
    // re-pulls risc0-zkvm with defaults), so disabling defaults on our
    // guest's risc0-zkvm dep alone doesn't help. Docker isolates the build
    // tree and avoids the unified-feature issue.
    //
    // Operator must have `docker` + `docker-buildx` installed.
    let docker = DockerOptionsBuilder::default()
        .root_dir(std::env::current_dir().unwrap().parent().unwrap())
        .build()
        .expect("DockerOptions");

    let opts = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .expect("GuestOptions");

    let mut map = HashMap::new();
    map.insert("forum-methods-guest", opts);
    embed_methods_with_options(map);
}

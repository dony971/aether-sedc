//! OBSERVABILITY-ONLY build script (logging milestone n°4).
//! Exposes the git commit hash to the binary for boot banners. No
//! consensus/DAG/ledger/economic/genesis impact. Never fails the build:
//! without git metadata the hash is "unknown".

fn main() {
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.iter().all(|b| b.is_ascii_whitespace()))
        .unwrap_or(false);
    let hash = if dirty { format!("{hash}-dirty") } else { hash };
    println!("cargo:rustc-env=GIT_COMMIT_HASH={hash}");
    println!("cargo:rerun-if-changed=.git/HEAD");
}

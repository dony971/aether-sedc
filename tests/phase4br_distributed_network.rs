//! Mission BR — two independent processes, unavailability and recovery.
//!
//! The two nodes are separate operating-system processes
//! (`CARGO_BIN_EXE_bq_peer`): distinct directories, distinct Ed25519 keys,
//! distinct sled stores, a real TCP link on loopback.
//!
//! What is **not** here, deliberately: latency, jitter and message loss. A
//! byte-level proxy was attempted and removed: the node's handshake is a single
//! Hello/HelloAck exchange, and an intermediate that forwards frames without
//! being a protocol participant stalls it. Adding a perturbation hook would be a
//! new feature in the transport, which this mission forbids. Latency and loss are
//! therefore exercised by the project's own simulator (`phase4bj_network_sim_tests`),
//! in-process and labelled as such.
//!
//! | Test | Scenario |
//! |---|---|
//! | `br_01` | the server is killed before any request: nothing is installed |
//! | `br_02` | the same directory is served again by a new process: B catches up |
//! | `br_03` | the client keeps its state across the unavailability window |
//! | `br_04` | a serving process is killed hard: the store reopens without a half install |

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_bq_peer")
}

fn store_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aether-br-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn fields(stdout: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn run(args: &[&str]) -> BTreeMap<String, String> {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("child process");
    assert!(
        output.status.success(),
        "child {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fields(&output.stdout)
}

struct Peer {
    child: Child,
    stop: PathBuf,
    addr: String,
}

impl Peer {
    fn serve(dir: &Path, tag: &str) -> Self {
        let stop = dir.join(format!("stop-{tag}"));
        let ready = PathBuf::from(format!("{}.ready", stop.display()));
        let _ = std::fs::remove_file(&ready);
        let child = Command::new(binary())
            .args([
                "serve",
                dir.to_str().expect("path"),
                "127.0.0.1:0",
                stop.to_str().expect("stop"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("serve child");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut addr = None;
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&ready) {
                if let Some(value) = text.lines().find_map(|l| l.strip_prefix("ADDR=")) {
                    addr = Some(value.trim().to_string());
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Self {
            child,
            stop,
            addr: addr.expect("published address"),
        }
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn wait(mut self) -> BTreeMap<String, String> {
        std::fs::write(&self.stop, b"stop").expect("stop file");
        let output = self.child.wait_with_output().expect("finished");
        assert!(
            output.status.success(),
            "serve failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fields(&output.stdout)
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn produced(dir: &Path) -> String {
    let out = run(&["produce", dir.to_str().expect("path")]);
    out["CANONICAL"].clone()
}

#[test]
fn br_01_a_killed_server_leaves_the_client_with_nothing() {
    let a = store_root("br01-a");
    let b = store_root("br01-b");
    produced(&a);

    let server = Peer::serve(&a, "srv");
    let dead = server.addr().to_string();
    server.kill();

    let output = Command::new(binary())
        .args(["fetch", b.to_str().expect("path"), &dead])
        .env("BQ_READ_TIMEOUT_MS", "300")
        .output()
        .expect("child");
    let offline = fields(&output.stdout);
    if output.status.success() {
        assert_eq!(offline["INSTALLED_LINKS"], "0", "{offline:?}");
        assert_eq!(offline["LEDGER_ACTIVE"], "none", "nothing was written");
    }

    // The client's own store is untouched by the failure.
    let resumed = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(resumed["DECISIONS"], "0");
    assert_eq!(resumed["MAY_SIGN"], "0");
}

#[test]
fn br_02_a_second_process_serves_the_same_history_and_the_client_catches_up() {
    let a = store_root("br02-a");
    let b = store_root("br02-b");
    let canonical = produced(&a);

    let first = Peer::serve(&a, "one");
    let dead = first.addr().to_string();
    first.kill();
    // Nothing answered the first attempt.
    let _ = Command::new(binary())
        .args(["fetch", b.to_str().expect("path"), &dead])
        .env("BQ_READ_TIMEOUT_MS", "300")
        .output()
        .expect("child");

    let second = Peer::serve(&a, "two");
    let recovered = run(&["fetch", b.to_str().expect("path"), second.addr()]);
    let served = second.wait();

    assert_eq!(served["SERVED_REQUESTS"], "1", "one history served");
    assert_eq!(recovered["INSTALLED_LINKS"], "1", "{recovered:?}");
    assert_eq!(recovered["LEDGER_ACTIVE"], canonical);
    assert_eq!(recovered["LEDGER_CLOSURES"], "1");
}

#[test]
fn br_03_the_client_state_survives_the_unavailability_window() {
    let a = store_root("br03-a");
    let b = store_root("br03-b");
    let canonical = produced(&a);

    let first = Peer::serve(&a, "one");
    let dead = first.addr().to_string();
    first.kill();
    let _ = Command::new(binary())
        .args(["fetch", b.to_str().expect("path"), &dead])
        .env("BQ_READ_TIMEOUT_MS", "300")
        .output()
        .expect("child");

    // A restart of B before the server comes back: no obligation, no signing.
    let blocked = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(blocked["MAY_SIGN"], "0");

    let second = Peer::serve(&a, "two");
    let _ = run(&["fetch", b.to_str().expect("path"), second.addr()]);
    let _ = second.wait();

    let resumed = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(resumed["GENERATION"], canonical);
    assert_eq!(resumed["MAY_SIGN"], "1");
    assert_eq!(resumed["SIGN_TIP"], "ok");
}

#[test]
fn br_04_a_hard_killed_process_leaves_a_store_that_reopens_cleanly() {
    let a = store_root("br04-a");
    let b = store_root("br04-b");
    let canonical = produced(&a);

    let server = Peer::serve(&a, "srv");
    let addr = server.addr().to_string();
    let installed = run(&["fetch", b.to_str().expect("path"), &addr]);
    assert_eq!(installed["INSTALLED_LINKS"], "1", "{installed:?}");

    // Terminate, not shutdown: no flush on exit, no stop file, no destructor.
    server.kill();

    // The store that the killed process held is reopened by a new process and
    // must show one closure, no pending install and no residue.
    let reopened = run(&["resume", a.to_str().expect("path")]);
    assert_eq!(reopened["GENERATION"], canonical, "{reopened:?}");
    assert_eq!(
        reopened["STALE_MAY_SIGN"], "0",
        "only the canonical generation"
    );
    assert_eq!(reopened["MAY_SIGN"], "1");

    let client = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(client["GENERATION"], canonical);
    assert_eq!(
        client["STALE_MAY_SIGN"], "0",
        "the superseded registry stays out"
    );
    assert_eq!(client["DECISIONS"], "1");
    assert_eq!(
        client["MAY_SIGN"], "1",
        "the restored client can still sign"
    );
    assert_eq!(client["SIGN_TIP"], "ok");

    // The same directory still serves a fresh process.
    let again = Peer::serve(&a, "again");
    let refetched = run(&["fetch", b.to_str().expect("path"), again.addr()]);
    let _ = again.wait();
    assert_eq!(
        refetched["LEDGER_CLOSURES"], "1",
        "a replay installs nothing new"
    );
}

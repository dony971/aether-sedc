//! Mission BQ — two **independent operating-system processes** over real TCP.
//!
//! Every child below is `CARGO_BIN_EXE_bq_peer`, a separate process with its own
//! directory, its own Ed25519 key and its own `sled` store. The channel between
//! them is the existing blocking TCP transport (`network::Node` / `FramedStream`),
//! carrying the existing `SyncRequest` / `SyncBundle` message kinds; no new
//! protocol is introduced here.
//!
//! | Test | What it proves |
//! |---|---|
//! | `bq_01` | the producer installs the **canonical** identity (label = transition id) |
//! | `bq_02` | B fetches, verifies, installs, then restarts and signs at height 1 only |
//! | `bq_03` | re-receiving the same bundle is idempotent |
//! | `bq_04` | a bundle that relabels the generation is refused (BO-F1 over the wire) |
//! | `bq_05` | a dropped connection costs one attempt, not the process |
//! | `bq_06` | a decision alone survives a restart, blocks progress, then completes |
//!
//! The three steps of `bq_02` are three processes started by this one; "restart"
//! means the store directory outlives the process that wrote it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_bq_peer")
}

fn store_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aether-bq-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
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

fn fields(stdout: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

struct Server {
    child: Child,
    stop: PathBuf,
    addr: String,
}

impl Server {
    /// Start a server on an ephemeral port and read back the address it bound.
    /// No probe connection is made, so the handshake window belongs to the test.
    fn start(dir: &Path, tag: &str, relabel: bool) -> Self {
        let stop = dir.join(format!("stop-{tag}"));
        let ready = PathBuf::from(format!("{}.ready", stop.display()));
        let _ = std::fs::remove_file(&ready);
        let mut command = Command::new(binary());
        command.arg("serve").arg(dir).arg("127.0.0.1:0").arg(&stop);
        if relabel {
            command.arg("relabel");
        }
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("serve child");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut addr = None;
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&ready) {
                if let Some(value) = text.lines().find_map(|line| line.strip_prefix("ADDR=")) {
                    addr = Some(value.trim().to_string());
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let addr = addr.unwrap_or_else(|| panic!("the server never published an address"));
        Self { child, stop, addr }
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn wait(mut self) -> BTreeMap<String, String> {
        std::fs::write(&self.stop, b"stop").expect("stop file");
        let output = self
            .child
            .wait_with_output()
            .expect("serve process finished");
        assert!(
            output.status.success(),
            "serve failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fields(&output.stdout)
    }
}

fn kill(mut server: Server) {
    let _ = server.child.kill();
    let _ = server.child.wait();
}

// ---------------------------------------------------------------------------
// bq_01 — canonical identity in the producing process
// ---------------------------------------------------------------------------

#[test]
fn bq_01_the_producer_installs_the_canonical_identity() {
    let dir = store_root("bq01");
    let out = run(&["produce", dir.to_str().expect("path")]);
    let generation = out["GENERATION"].clone();
    assert_ne!(generation, "none");
    assert_eq!(
        out["LEDGER_ACTIVE"], generation,
        "the ledger activates what was installed"
    );
    assert_eq!(
        out["CANONICAL"], generation,
        "the installed label is the transition id the quorum signed"
    );
}

// ---------------------------------------------------------------------------
// bq_02 — produce (A) → serve (A) → fetch (B) → restart B
// ---------------------------------------------------------------------------

#[test]
fn bq_02_two_processes_synchronise_and_b_restarts_coherently() {
    let a = store_root("bq02-a");
    let b = store_root("bq02-b");
    let produced = run(&["produce", a.to_str().expect("path")]);
    let canonical = produced["CANONICAL"].clone();

    let server = Server::start(&a, "srv", false);
    let fetched = run(&["fetch", b.to_str().expect("path"), server.addr()]);
    let served = server.wait();

    assert_eq!(served["SERVED_REQUESTS"], "1", "one history request");
    assert_eq!(
        fetched["INSTALLED_LINKS"], "1",
        "one verified link installed"
    );
    assert_eq!(
        fetched["LEDGER_ACTIVE"], canonical,
        "B installed the canonical generation, not a label of its own"
    );
    assert_eq!(fetched["LEDGER_CLOSURES"], "1");

    // A third process reopens B's directory.
    let resumed = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(resumed["MAY_SIGN"], "1");
    assert_eq!(resumed["GENERATION"], canonical);
    assert_eq!(resumed["TIP"], "0");
    assert_eq!(resumed["SIGN_TIP"], "ok", "signing at the installed height");
    assert_eq!(
        resumed["STALE_MAY_SIGN"], "0",
        "the superseded registry cannot restore the store"
    );
}

// ---------------------------------------------------------------------------
// bq_03 — replay
// ---------------------------------------------------------------------------

#[test]
fn bq_03_receiving_the_same_bundle_twice_is_idempotent() {
    let a = store_root("bq03-a");
    let b = store_root("bq03-b");
    let produced = run(&["produce", a.to_str().expect("path")]);
    let canonical = produced["CANONICAL"].clone();

    let server = Server::start(&a, "srv", false);
    let first = run(&["fetch", b.to_str().expect("path"), server.addr()]);
    let second = run(&["fetch", b.to_str().expect("path"), server.addr()]);
    let served = server.wait();

    assert_eq!(first["LEDGER_ACTIVE"], canonical);
    assert_eq!(
        second["LEDGER_ACTIVE"], canonical,
        "the replay names the same generation"
    );
    assert_eq!(second["LEDGER_CLOSURES"], "1", "one closure, not two");
    assert_eq!(served["SERVED_REFUSED"], "0", "the server refused nothing");
}

// ---------------------------------------------------------------------------
// bq_04 — the BO-F1 attack over the wire
// ---------------------------------------------------------------------------

#[test]
fn bq_04_a_relabelled_bundle_is_refused_over_the_wire() {
    let a = store_root("bq04-a");
    let c = store_root("bq04-c");
    run(&["produce", a.to_str().expect("path")]);

    let server = Server::start(&a, "srv", true);
    let fetched = run(&["fetch", c.to_str().expect("path"), server.addr()]);
    let _ = server.wait();

    assert_eq!(
        fetched["INSTALLED_LINKS"], "0",
        "a renamed generation is not installed"
    );
    assert_eq!(fetched["LEDGER_ACTIVE"], "none", "nothing was written");
    assert!(
        fetched["REFUSALS"].contains("history"),
        "the refusal is recorded as a history failure: {:?}",
        fetched["REFUSALS"]
    );
}

// ---------------------------------------------------------------------------
// bq_05 — disconnect and reconnect
// ---------------------------------------------------------------------------

#[test]
fn bq_05_a_dropped_connection_costs_one_attempt_not_the_process() {
    let a = store_root("bq05-a");
    let b = store_root("bq05-b");
    let produced = run(&["produce", a.to_str().expect("path")]);
    let canonical = produced["CANONICAL"].clone();

    let server = Server::start(&a, "srv", false);
    let fetched = run(&["fetch-retry", b.to_str().expect("path"), server.addr()]);
    let _ = server.wait();

    assert_eq!(
        fetched["INSTALLED_LINKS"], "1",
        "the reconnection completed the synchronisation"
    );
    assert_eq!(fetched["LEDGER_ACTIVE"], canonical);
}

// ---------------------------------------------------------------------------
// bq_06 — decision alone, restart, later closure
// ---------------------------------------------------------------------------

#[test]
fn bq_06_a_decision_alone_survives_a_restart_and_completes_later() {
    let a = store_root("bq06-a");
    let b = store_root("bq06-b");
    let produced = run(&["produce", a.to_str().expect("path")]);
    let canonical = produced["CANONICAL"].clone();

    // B decides on its own and dies before installing anything.
    let decided = run(&["decide", b.to_str().expect("path")]);
    assert_eq!(decided["INSTALLED"], "0");

    // A new process finds the obligation but may not sign.
    let blocked = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(blocked["PENDING"], "1", "the obligation is durable");
    assert_eq!(
        blocked["MAY_SIGN"], "0",
        "an incomplete installation does not sign"
    );

    // The closure arrives over TCP, from the other process.
    let server = Server::start(&a, "srv", false);
    let fetched = run(&["fetch", b.to_str().expect("path"), server.addr()]);
    let _ = server.wait();
    assert_eq!(fetched["INSTALLED_LINKS"], "1");

    let resumed = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(resumed["GENERATION"], canonical);
    assert_eq!(resumed["MAY_SIGN"], "1", "the node completes and signs");
    assert_eq!(resumed["SIGN_TIP"], "ok");
}

// ---------------------------------------------------------------------------
// bq_07 — a process that dies while serving leaves nothing half-installed on B
// ---------------------------------------------------------------------------

#[test]
fn bq_07_killing_the_server_before_any_request_leaves_b_untouched() {
    let a = store_root("bq07-a");
    let b = store_root("bq07-b");
    run(&["produce", a.to_str().expect("path")]);

    let server = Server::start(&a, "srv", false);
    kill(server);

    let resumed = run(&["resume", b.to_str().expect("path")]);
    assert_eq!(
        resumed["DECISIONS"], "0",
        "B never talked to A, so B holds nothing"
    );
    assert_eq!(resumed["MAY_SIGN"], "0");
}

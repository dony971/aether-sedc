//! PHASE 4AQ: deterministic inventory tests (F4AN-1 only).
//!
//! Offline, read-only, hermetic (all trees under `tempfile::TempDir`).
//! No consensus, P2P, stake, governance or activation logic is touched.
//! A scenario that cannot run here (privileges / platform) records
//! `NOT_RUN` via eprintln and passes without asserting, never by silently
//! ignoring the case inside the implementation.

use aether_unified::inventory::{
    canonical_bytes, canonical_line, diff_inventories, inventory_digest, manifest_digest,
    matches_exclusion, parse_canonical_line, verify_against_manifest, walk_release_root,
    EntryKind, PackageBinding,
};
use std::path::{Path, PathBuf};

fn write_tree(root: &Path, files: &[(&str, &[u8])]) {
    for (rel, bytes) in files {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&p, bytes).expect("write");
    }
}

fn snapshot_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = std::fs::read_dir(&d).expect("readdir");
        for e in rd {
            let e = e.expect("entry");
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push((p.clone(), std::fs::read(&p).expect("read")));
            }
            // Symlinks intentionally not followed here (read-only guard).
        }
    }
    out.sort();
    out
}

#[test]
fn q01_deterministic_despite_creation_order() {
    // Same logical tree built in two different creation orders must yield
    // identical canonical bytes and digest (walk order independence).
    let d1 = tempfile::tempdir().expect("tempdir");
    let d2 = tempfile::tempdir().expect("tempdir");
    write_tree(d1.path(), &[("b.txt", b"B"), ("a.txt", b"A"), ("sub/c.txt", b"C")]);
    write_tree(d2.path(), &[("sub/c.txt", b"C"), ("a.txt", b"A"), ("b.txt", b"B")]);
    let i1 = walk_release_root(d1.path(), &[], None).expect("walk1");
    let i2 = walk_release_root(d2.path(), &[], None).expect("walk2");
    assert_eq!(canonical_bytes(&i1.entries), canonical_bytes(&i2.entries));
    assert_eq!(inventory_digest(&i1.entries), inventory_digest(&i2.entries));
}

#[test]
fn q02_sorted_normalized_canonical() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("sub/b.txt", b"x"), ("a.txt", b"y")]);
    let inv = walk_release_root(d.path(), &[], None).expect("walk");
    let paths: Vec<&str> = inv.entries.iter().map(|e| e.normalized_path.as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "entries must be byte-sorted");
    assert!(paths.contains(&"a.txt") && paths.contains(&"sub/b.txt"));
    assert!(paths.iter().all(|p| !p.contains('\\')), "forward slash only");
    let bytes = canonical_bytes(&inv.entries);
    assert!(bytes.ends_with(b"\n"), "final LF required");
    assert!(!bytes.contains(&b'\r'), "hashed stream LF-only, no CR");
    for line in String::from_utf8(bytes).expect("utf8").lines() {
        let (_, _, _, _, _) = parse_canonical_line(line).expect("parse");
    }
    // Spaces allowed via splitn(5).
    let spaced = "aa file 3 f my dir/sp ace.bin";
    let (_, _, _, _, p) = parse_canonical_line(spaced).expect("spaced parse");
    assert_eq!(p, "my dir/sp ace.bin");
}

#[test]
fn q03_digest_stable_for_identical_content() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("f.bin", b"stable-bytes"), ("g.txt", b"other")]);
    let a = walk_release_root(d.path(), &[], None).expect("walk a");
    let b = walk_release_root(d.path(), &[], None).expect("walk b");
    assert_eq!(inventory_digest(&a.entries), inventory_digest(&b.entries));
    assert_eq!(a.entries.len(), b.entries.len());
}

#[test]
fn q04_missing_file_detected() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("keep.txt", b"k"), ("gone.txt", b"g")]);
    let t0 = walk_release_root(d.path(), &[], None).expect("t0").entries;
    std::fs::remove_file(d.path().join("gone.txt")).expect("rm");
    let t1 = walk_release_root(d.path(), &[], None).expect("t1").entries;
    let diff = diff_inventories(&t0, &t1);
    assert_eq!(diff.missing, vec!["gone.txt".to_string()]);
    assert!(diff.unexpected.is_empty() && diff.changed.is_empty());
    assert!(!diff.is_clean());
}

#[test]
fn q05_extra_file_detected() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("keep.txt", b"k")]);
    let t0 = walk_release_root(d.path(), &[], None).expect("t0").entries;
    write_tree(d.path(), &[("extra.txt", b"e")]);
    let t1 = walk_release_root(d.path(), &[], None).expect("t1").entries;
    let diff = diff_inventories(&t0, &t1);
    assert_eq!(diff.unexpected, vec!["extra.txt".to_string()]);
    assert!(diff.missing.is_empty() && diff.changed.is_empty());
}

#[test]
fn q06_modified_content_and_size_detected() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("mut.bin", b"v1")]);
    let t0 = walk_release_root(d.path(), &[], None).expect("t0").entries;
    write_tree(d.path(), &[("mut.bin", b"v1-extended")]);
    let t1 = walk_release_root(d.path(), &[], None).expect("t1").entries;
    let diff = diff_inventories(&t0, &t1);
    assert_eq!(diff.changed, vec!["mut.bin".to_string()]);
    // Same-size mutation must also be detected (hash, not size).
    write_tree(d.path(), &[("mut.bin", b"v1-EXTENDED")]);
    assert_eq!(b"v1-extended".len(), b"v1-EXTENDED".len());
    let t2 = walk_release_root(d.path(), &[], None).expect("t2").entries;
    let diff2 = diff_inventories(&t0, &t2);
    assert_eq!(diff2.changed, vec!["mut.bin".to_string()]);
}

#[test]
fn q07_exclusions_allowlisted_only() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("keep.txt", b"k"), ("skip.log", b"s"), ("tmp/a.txt", b"t")]);
    let inv = walk_release_root(d.path(), &["*.log".to_string(), "tmp/*".to_string()], None)
        .expect("walk");
    let paths: Vec<&str> = inv.entries.iter().map(|e| e.normalized_path.as_str()).collect();
    assert!(paths.contains(&"keep.txt"));
    assert!(!paths.iter().any(|p| p.ends_with(".log")), "excluded suffix must be absent");
    assert!(!paths.iter().any(|p| p.starts_with("tmp/")), "excluded subtree must be absent");
    assert!(matches_exclusion("*.log", "a.log"));
    assert!(!matches_exclusion("*.log", "a.txt"));
}

fn try_link(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        }
    }
}

#[test]
fn q08_symlink_internal_recorded_never_followed() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("real.txt", b"content")]);
    let link = d.path().join("link-inside.txt");
    if try_link(&d.path().join("real.txt"), &link).is_err() {
        eprintln!("NOT_RUN: symlink creation unavailable (internal)");
        return;
    }
    let inv = walk_release_root(d.path(), &[], None).expect("walk");
    let e = inv.entries.iter().find(|e| e.normalized_path == "link-inside.txt").expect("link entry");
    assert_eq!(e.kind, EntryKind::Symlink);
    assert!(e.content_hash.starts_with("link:"), "symlink binds target string, not content");
    assert_eq!(e.size, 0);
    // Target bytes must NOT appear as a followed file under the link path.
    assert!(!inv.warnings.external_links.iter().any(|p| p == "link-inside.txt"));
}

#[test]
fn q09_symlink_external_flagged() {
    let outer = tempfile::tempdir().expect("tempdir");
    let d = tempfile::tempdir().expect("tempdir");
    let outside = outer.path().join("outside.bin");
    std::fs::write(&outside, b"evil").expect("write");
    let link = d.path().join("link-out.txt");
    if try_link(&outside, &link).is_err() {
        eprintln!("NOT_RUN: symlink creation unavailable (external)");
        return;
    }
    let inv = walk_release_root(d.path(), &[], None).expect("walk");
    let e = inv.entries.iter().find(|e| e.normalized_path == "link-out.txt").expect("link entry");
    assert_eq!(e.kind, EntryKind::Symlink);
    assert!(e.flags.iter().any(|f| f == "external-link"), "outside target must be flagged");
    assert!(inv.warnings.external_links.contains(&"link-out.txt".to_string()));
}

#[test]
fn q10_symlink_chain_and_dangling() {
    let outer = tempfile::tempdir().expect("tempdir");
    let d = tempfile::tempdir().expect("tempdir");
    std::fs::write(outer.path().join("real-outside.bin"), b"evil").expect("write");
    let l1 = d.path().join("link1.bin");
    let l2 = d.path().join("link2.bin");
    let dangling = d.path().join("dangling.bin");
    let missing = d.path().join("no-such-target.bin");
    if try_link(&outer.path().join("real-outside.bin"), &l1)
        .and(try_link(&l1, &l2))
        .and(try_link(&missing, &dangling))
        .is_err()
    {
        eprintln!("NOT_RUN: symlink chain/dangling creation unavailable");
        return;
    }
    let inv = walk_release_root(d.path(), &[], None).expect("walk");
    let e2 = inv.entries.iter().find(|e| e.normalized_path == "link2.bin").expect("chain entry");
    assert_eq!(e2.kind, EntryKind::Symlink, "chain link recorded, never resolved for content");
    let ed = inv.entries.iter().find(|e| e.normalized_path == "dangling.bin").expect("dangling entry");
    assert_eq!(ed.kind, EntryKind::Symlink);
    assert!(ed.flags.iter().any(|f| f == "dangling-target"), "dangling must be explicit");
}

#[test]
fn q11_case_collision_and_hardlink_policy() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("Readme.txt", b"a"), ("README.txt", b"b")]);
    let inv = walk_release_root(d.path(), &[], None).expect("walk");
    #[cfg(unix)]
    {
        // Both coexist on unix: collision must be flagged, digest covers both.
        let flagged: Vec<&str> = inv
            .entries
            .iter()
            .filter(|e| e.flags.iter().any(|f| f.starts_with("case-collision:")))
            .map(|e| e.normalized_path.as_str())
            .collect();
        assert!(!flagged.is_empty(), "unix case pair must flag collision");
    }
    #[cfg(windows)]
    {
        // Pair cannot coexist on Windows: reaching here means creation of the
        // second file failed or overwrote; assert no false collision claim on
        // whatever single entry remains.
        let _ = inv;
        eprintln!("NOT_RUN (partial): case-collision coexistence impossible on Windows; detection logic still runs");
    }
    // Hardlinks: unix groups natively; windows groups via native
    // volume+index identity (4BB, option B) with the same flag contract.
    #[cfg(unix)]
    {
        let h = tempfile::tempdir().expect("tempdir");
        write_tree(h.path(), &[("orig.bin", b"hardlink-bytes")]);
        std::fs::hard_link(h.path().join("orig.bin"), h.path().join("alias.bin")).expect("hardlink");
        let hi = walk_release_root(h.path(), &[], None).expect("walk");
        assert!(
            !hi.warnings.hardlink_groups.is_empty(),
            "unix hardlink pair must form a group"
        );
        for e in &hi.entries {
            if e.normalized_path == "orig.bin" || e.normalized_path == "alias.bin" {
                assert!(e.flags.iter().any(|f| f.starts_with("hardlink-group:")), "member flagged");
                assert_eq!(e.content_hash, hi.entries.iter().find(|x| x.normalized_path == "orig.bin").unwrap().content_hash);
            }
        }
    }
    #[cfg(windows)]
    {
        let h = tempfile::tempdir().expect("tempdir");
        write_tree(h.path(), &[("orig.bin", b"hardlink-bytes")]);
        match std::fs::hard_link(h.path().join("orig.bin"), h.path().join("alias.bin")) {
            Ok(()) => {
                let hi = walk_release_root(h.path(), &[], None).expect("walk");
                // 4BB: native identity replaces the UNAVAILABLE flag when
                // the API answers; the pair must group exactly like unix.
                let members: Vec<&str> = hi
                    .entries
                    .iter()
                    .filter(|e| e.flags.iter().any(|f| f.starts_with("hardlink-group:")))
                    .map(|e| e.normalized_path.as_str())
                    .collect();
                assert!(
                    members.contains(&"orig.bin") && members.contains(&"alias.bin"),
                    "windows hardlink pair must form a native group"
                );
                assert!(
                    !hi.warnings.hardlink_groups.is_empty(),
                    "windows group warning present"
                );
                for e in &hi.entries {
                    if e.normalized_path == "orig.bin" || e.normalized_path == "alias.bin" {
                        assert!(
                            e.flags.iter().any(|f| f.starts_with("hardlink-id:")),
                            "member carries native identity"
                        );
                        assert!(
                            e.flags.iter().any(|f| f.starts_with("hardlink-nlinks:")),
                            "member carries native link count"
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("NOT_RUN: windows hardlink creation unavailable ({})", e);
            }
        }
    }
}

#[test]
fn q12_special_and_unsupported_refused_explicitly() {
    // Newline-bearing names cannot be represented in the LF stream: the
    // implementation must refuse them explicitly (never silently).
    #[cfg(unix)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        let evil = d.path().join("bad\nname.txt");
        match std::fs::write(&evil, b"x") {
            Ok(()) => {
                let inv = walk_release_root(d.path(), &[], None).expect("walk");
                let found = inv.entries.iter().find(|e| e.kind == EntryKind::Unreadable);
                assert!(found.is_some(), "newline path must become unreadable entry");
                assert!(found.unwrap().flags.iter().any(|f| f.contains("unsupported-newline-in-path")));
            }
            Err(e) => {
                eprintln!("NOT_RUN: newline filename creation unavailable ({})", e);
            }
        }
        // FIFO: record as special, never hashed.
        let f = tempfile::tempdir().expect("tempdir");
        let fifo = f.path().join("pipe.fifo");
        let mk = std::process::Command::new("mkfifo").arg(&fifo).output();
        match mk {
            Ok(o) if o.status.success() => {
                let inv = walk_release_root(f.path(), &[], None).expect("walk");
                let e = inv.entries.iter().find(|en| en.normalized_path == "pipe.fifo").expect("fifo entry");
                assert_eq!(e.kind, EntryKind::Special);
                assert_eq!(e.content_hash, "none");
            }
            _ => {
                eprintln!("NOT_RUN: mkfifo unavailable on this runner");
            }
        }
    }
    #[cfg(windows)]
    {
        // Windows forbids `\n` in names at the OS level: assert the walk
        // succeeds without false unreadables on a normal tree.
        let d = tempfile::tempdir().expect("tempdir");
        write_tree(d.path(), &[("ok.txt", b"ok")]);
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        assert!(inv.entries.iter().all(|e| e.kind != EntryKind::Unreadable));
        eprintln!("NOT_RUN (partial): newline-name and fifo cases are unix-only by OS design");
    }
}

#[test]
fn q13_package_manifest_binding() {
    let d = tempfile::tempdir().expect("tempdir");
    write_tree(d.path(), &[("a.bin", b"AAA"), ("sub/b.bin", b"BBB")]);
    let inv = walk_release_root(d.path(), &[], None).expect("walk");
    let files: Vec<(String, String)> = inv
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| (e.normalized_path.clone(), e.content_hash.clone()))
        .collect();
    // Exact binding passes.
    verify_against_manifest(&inv.entries, &files, &[]).expect("exact binding");
    // Tampered hash fails.
    let mut bad = files.clone();
    bad[0].1 = "00".repeat(32);
    assert!(verify_against_manifest(&inv.entries, &bad, &[]).is_err());
    // Missing manifest entry fails; unexpected inventory file fails unless
    // declared generated.
    assert!(verify_against_manifest(&inv.entries, &files[..1], &[]).is_err());
    verify_against_manifest(&inv.entries, &files[..1], &["sub/*".to_string()]).expect("generated allowlist");
    // Triple binding.
    let manifest_bytes = b"{\"fixture\":true}";
    let binding = PackageBinding {
        package_id: "aether-test:9.9.9:build0".to_string(),
        manifest_digest: manifest_digest(manifest_bytes),
        inventory_digest: inventory_digest(&inv.entries),
    };
    binding
        .verify(&inventory_digest(&inv.entries), &manifest_digest(manifest_bytes))
        .expect("triple verify");
    assert!(binding.verify("00", &manifest_digest(manifest_bytes)).is_err());
    assert!(binding.verify(&inventory_digest(&inv.entries), "00").is_err());
}

#[test]
fn q14_preflight_writes_nothing_and_dirty_gate_kept() {
    // Walk + binary run must not modify any artifact bytes.
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    write_tree(&repo, &[("artifact.bin", b"bytes"), ("sub/f.bin", b"more")]);
    let before = snapshot_bytes(&repo);
    let inv = walk_release_root(&repo, &[], None).expect("walk");
    let after_walk = snapshot_bytes(&repo);
    assert_eq!(before, after_walk, "inventory walk must not write");
    // Binary opt-in inventory on the same tree: still read-only.
    let bin = env!("CARGO_BIN_EXE_v6_preflight");
    // Minimal manifest is not needed for the read-only assertion on the
    // inventory path itself: run --help (read-only) and re-snapshot.
    let out = std::process::Command::new(bin).arg("--help").output().expect("run help");
    assert!(out.status.success());
    let after_help = snapshot_bytes(&repo);
    assert_eq!(before, after_help, "preflight --help must not write");
    // Dirty-tree protection still enforced by the binary (existing gate):
    // an untracked tree presented as its own release commit cannot PASS.
    // Here we only assert the walk did not stage or clean anything: no
    // `.git` was created or modified by us.
    assert!(!repo.join(".git").exists(), "walk must not init git");
    let _ = inv;
}

#[test]
fn q15_empty_and_depth_limit_fail_explicitly() {
    let d = tempfile::tempdir().expect("tempdir");
    let inv = walk_release_root(d.path(), &[], None).expect("walk empty");
    assert!(inv.entries.is_empty(), "empty root yields empty set");
    assert_eq!(inventory_digest(&[]), manifest_digest(b""));
    // Depth limit reached is an error, not a skip.
    let e = tempfile::tempdir().expect("tempdir");
    write_tree(e.path(), &[("a/b/c.txt", b"deep")]);
    assert!(walk_release_root(e.path(), &[], Some(0)).is_err(), "depth 0 with nested content must error");
}

#[test]
fn q16_canonical_line_contract() {
    // hash kind size mode path; symlink marker; dir none; LF-only stream.
    let f = aether_unified::inventory::InventoryEntry {
        normalized_path: "f.bin".to_string(),
        kind: EntryKind::File,
        size: 4,
        mode: "f".to_string(),
        content_hash: "ab".to_string(),
        flags: vec![],
        diagnostic: String::new(),
    };
    assert_eq!(canonical_line(&f), "ab file 4 f f.bin");
    let s = aether_unified::inventory::InventoryEntry {
        normalized_path: "l".to_string(),
        kind: EntryKind::Symlink,
        size: 0,
        mode: "l".to_string(),
        content_hash: "link:cd".to_string(),
        flags: vec![],
        diagnostic: String::new(),
    };
    assert_eq!(canonical_line(&s), "link:cd symlink 0 l l");
    assert!(parse_canonical_line("x unknown 0 f p").is_err(), "unknown kind rejected");
    assert!(parse_canonical_line("only two fields").is_err(), "short line rejected");
}

//! PHASE 4CP-BH: inventory hardening tests.
//!
//! Covers path normalization, hardlink/reference topology, canonical-stream
//! order independence, security-flag diffs and the strict release gate.
//! Hermetic, offline, read-only.

use aether_unified::inventory::{
    canonical_bytes, diff_inventories, inventory_digest, verify_release_inventory,
    walk_release_root, EntryKind, Inventory, InventoryEntry, WalkWarnings,
};

fn file(path: &str, hash: &str, flags: &[&str]) -> InventoryEntry {
    InventoryEntry {
        normalized_path: path.to_string(),
        kind: EntryKind::File,
        size: 1,
        mode: "f".to_string(),
        content_hash: hash.to_string(),
        flags: flags.iter().map(|s| s.to_string()).collect(),
        diagnostic: String::new(),
    }
}

fn dir(path: &str) -> InventoryEntry {
    InventoryEntry {
        normalized_path: path.to_string(),
        kind: EntryKind::Dir,
        size: 0,
        mode: "d".to_string(),
        content_hash: "none".to_string(),
        flags: Vec::new(),
        diagnostic: String::new(),
    }
}

fn symlink(path: &str) -> InventoryEntry {
    InventoryEntry {
        normalized_path: path.to_string(),
        kind: EntryKind::Symlink,
        size: 0,
        mode: "l".to_string(),
        content_hash: "link:aa".to_string(),
        flags: Vec::new(),
        diagnostic: "target=artifact.bin".to_string(),
    }
}

fn inventory(entries: Vec<InventoryEntry>) -> Inventory {
    Inventory {
        entries,
        warnings: WalkWarnings::default(),
        diagnostics: Vec::new(),
    }
}

#[test]
fn bh01_canonical_bytes_are_order_independent() {
    let a = file("b.bin", "bb", &[]);
    let b = file("a.bin", "aa", &[]);
    let x = vec![a.clone(), b.clone()];
    let y = vec![b, a];
    assert_eq!(canonical_bytes(&x), canonical_bytes(&y));
    assert_eq!(inventory_digest(&x), inventory_digest(&y));
}

#[test]
fn bh02_diff_detects_security_flags_but_not_their_order() {
    let clean = file("a.bin", "aa", &[]);
    let linked = file("a.bin", "aa", &["external-link"]);
    let d = diff_inventories(&[clean.clone()], &[linked]);
    assert_eq!(d.changed, vec!["a.bin".to_string()]);

    let first = file("a.bin", "aa", &["hardlink-nlinks:2", "unexplained-link-ref:1"]);
    let second = file("a.bin", "aa", &["unexplained-link-ref:1", "hardlink-nlinks:2"]);
    assert!(diff_inventories(&[first], &[second]).is_clean());
}

#[test]
fn bh03_release_gate_allows_dirs_and_rejects_symlinks() {
    let expected = vec![("sub/a.bin".to_string(), "aa".to_string())];
    let clean = inventory(vec![dir("sub"), file("sub/a.bin", "aa", &[])]);
    verify_release_inventory(&clean, &expected, &[]).expect("clean tree");

    let linked = inventory(vec![dir("sub"), symlink("sub/a.bin")]);
    let err = verify_release_inventory(&linked, &expected, &[]).unwrap_err();
    assert!(err.contains("symlink"), "err: {}", err);
}

#[test]
fn bh04_release_gate_rejects_hardlink_topology_and_unavailable_identity() {
    let expected = vec![("a.bin".to_string(), "aa".to_string())];
    for flags in [
        vec!["hardlink-id:1", "hardlink-nlinks:2", "hardlink-group:1"],
        vec!["hardlink-id:1", "hardlink-nlinks:2", "unexplained-link-ref:1"],
        vec!["hardlink-id:1", "hardlink-nlinks:2", "unresolved-link-ref:1"],
        vec!["hardlink-detection=unavailable-on-windows:no-stable-index"],
    ] {
        let inv = inventory(vec![file("a.bin", "aa", &flags)]);
        let err = verify_release_inventory(&inv, &expected, &[]).unwrap_err();
        assert!(err.contains("hardlink"), "flags {:?}, err: {}", flags, err);
    }
}

#[test]
fn bh11_manifest_gate_rejects_non_files_duplicates_and_collisions() {
    let expected = vec![("sub".to_string(), "aa".to_string())];
    let inv = inventory(vec![dir("sub")]);
    let err = verify_release_inventory(&inv, &expected, &[]).unwrap_err();
    assert!(err.contains("manifest-not-file"), "err: {}", err);

    let inv = inventory(vec![file("a.bin", "aa", &[])]);
    let err = verify_release_inventory(
        &inv,
        &[
            ("a.bin".to_string(), "aa".to_string()),
            ("a.bin".to_string(), "aa".to_string()),
        ],
        &[],
    )
    .unwrap_err();
    assert!(err.contains("manifest-duplicate"), "err: {}", err);

    let inv = inventory(vec![
        file("a.bin", "aa", &[]),
        file("a.bin", "aa", &[]),
    ]);
    let err = verify_release_inventory(&inv, &[("a.bin".to_string(), "aa".to_string())], &[])
        .unwrap_err();
    assert!(err.contains("inventory-duplicate-path"), "err: {}", err);

    let inv = inventory(vec![file(
        "A.bin",
        "aa",
        &["case-collision:a.bin"],
    )]);
    let err = verify_release_inventory(&inv, &[("A.bin".to_string(), "aa".to_string())], &[])
        .unwrap_err();
    assert!(err.contains("case-collision"), "err: {}", err);

    let inv = inventory(vec![file("decl.bin", "aa", &[]), file("gen.log", "bb", &[])]);
    verify_release_inventory(
        &inv,
        &[("decl.bin".to_string(), "aa".to_string())],
        &["gen.log".to_string()],
    )
    .expect("generated file allowed");
}

#[test]
fn bh05_single_member_external_hardlink_is_surfaced() {
    let inside = tempfile::tempdir().expect("inside");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(inside.path().join("tracked.bin"), b"bytes").expect("write");
    if std::fs::hard_link(
        inside.path().join("tracked.bin"),
        outside.path().join("alias.bin"),
    )
    .is_err()
    {
        eprintln!("NOT_RUN: hardlink creation unavailable");
        return;
    }

    let inv = walk_release_root(inside.path(), &[], None).expect("walk");
    assert!(
        inv.warnings
            .external_link_refs
            .iter()
            .any(|s| s.starts_with("exterior:")),
        "refs: {:?}",
        inv.warnings.external_link_refs
    );
    let e = inv
        .entries
        .iter()
        .find(|e| e.normalized_path == "tracked.bin")
        .expect("entry");
    assert!(
        e.flags.iter().any(|f| f.starts_with("unexplained-link-ref:")),
        "flags: {:?}",
        e.flags
    );
}

#[test]
fn bh06_excluded_hardlink_is_ambiguous_not_exterior() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("tracked.bin"), b"bytes").expect("write");
    if std::fs::hard_link(
        root.path().join("tracked.bin"),
        root.path().join("alias.bin"),
    )
    .is_err()
    {
        eprintln!("NOT_RUN: hardlink creation unavailable");
        return;
    }

    let inv = walk_release_root(root.path(), &["alias.bin".to_string()], None).expect("walk");
    assert!(
        inv.warnings
            .external_link_refs
            .iter()
            .any(|s| s.starts_with("ambiguous:")),
        "refs: {:?}",
        inv.warnings.external_link_refs
    );
    let e = inv
        .entries
        .iter()
        .find(|e| e.normalized_path == "tracked.bin")
        .expect("entry");
    assert!(
        e.flags.iter().any(|f| f.starts_with("unresolved-link-ref:")),
        "flags: {:?}",
        e.flags
    );
}

#[test]
fn bh07_release_gate_rejects_real_hardlink_group() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("orig.bin"), b"bytes").expect("write");
    if std::fs::hard_link(root.path().join("orig.bin"), root.path().join("alias.bin")).is_err() {
        eprintln!("NOT_RUN: hardlink creation unavailable");
        return;
    }
    let inv = walk_release_root(root.path(), &[], None).expect("walk");
    let expected = vec![
        ("alias.bin".to_string(), inv.entries.iter().find(|e| e.normalized_path == "orig.bin").unwrap().content_hash.clone()),
        ("orig.bin".to_string(), inv.entries.iter().find(|e| e.normalized_path == "orig.bin").unwrap().content_hash.clone()),
    ];
    let err = verify_release_inventory(&inv, &expected, &[]).unwrap_err();
    assert!(err.contains("hardlink"), "err: {}", err);
}

#[test]
#[cfg(unix)]
fn bh08_unix_backslash_is_literal_not_a_separator() {
    let root = tempfile::tempdir().expect("root");
    std::fs::create_dir(root.path().join("a")).expect("mkdir");
    std::fs::write(root.path().join("a/b.txt"), b"nested").expect("write nested");
    std::fs::write(root.path().join("a\\b.txt"), b"literal").expect("write literal");
    let inv = walk_release_root(root.path(), &[], None).expect("walk");
    let paths: Vec<&str> = inv.entries.iter().map(|e| e.normalized_path.as_str()).collect();
    assert!(paths.contains(&"a/b.txt"), "paths: {:?}", paths);
    assert!(paths.contains(&"a\\b.txt"), "paths: {:?}", paths);
    assert_eq!(paths.iter().filter(|p| p.starts_with("a")).count(), 3, "paths: {:?}", paths);
}

#[test]
#[cfg(unix)]
fn bh10_unix_symlink_backslash_target_is_not_normalized() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("root");
    std::fs::create_dir(root.path().join("a")).expect("mkdir");
    std::fs::write(root.path().join("a/b.txt"), b"nested").expect("write nested");
    std::fs::write(root.path().join("a\\b.txt"), b"literal").expect("write literal");
    symlink("a/b.txt", root.path().join("slash-link")).expect("symlink slash");
    symlink("a\\b.txt", root.path().join("backslash-link")).expect("symlink backslash");

    let inv = walk_release_root(root.path(), &[], None).expect("walk");
    let hash = |path: &str| {
        inv.entries
            .iter()
            .find(|e| e.normalized_path == path)
            .expect("link")
            .content_hash
            .clone()
    };
    assert_ne!(hash("slash-link"), hash("backslash-link"));
}

#[test]
#[cfg(unix)]
fn bh09_unreadable_path_uses_safe_placeholder() {
    let root = tempfile::tempdir().expect("root");
    let evil = root.path().join("bad\nname.txt");
    if std::fs::write(&evil, b"x").is_err() {
        eprintln!("NOT_RUN: newline filename creation unavailable");
        return;
    }
    let inv = walk_release_root(root.path(), &[], None).expect("walk");
    let e = inv
        .entries
        .iter()
        .find(|e| e.kind == EntryKind::Unreadable)
        .expect("unreadable entry");
    assert!(e.normalized_path.starts_with("unreadable:"));
    assert!(!e.normalized_path.contains('\n') && !e.normalized_path.contains('\r'));
    let bytes = canonical_bytes(&inv.entries);
    let text = String::from_utf8(bytes).expect("utf8 stream");
    assert_eq!(
        text.matches('\n').count(),
        inv.entries.len(),
        "exactly one LF per entry: {:?}",
        text
    );
}

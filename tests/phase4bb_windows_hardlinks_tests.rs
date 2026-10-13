//! PHASE 4BB: native Windows hardlink tests (option B, windows-sys).
//!
//! Native Windows execution, fixtures in controlled temp dirs only. No
//! simulated proof is ever presented as a native Windows result: anything
//! requiring unavailable FS/rights records NOT_RUN with the exact cause.
//! Unix behavior is unchanged by construction (no #[cfg(unix)] line
//! modified); w12 wires the unix leg for unix runners and records NOT_RUN
//! on Windows instead of inventing a unix result.

use aether_unified::inventory::{
    canonical_bytes, inventory_digest, walk_release_root, EntryKind,
};
use std::path::{Path, PathBuf};

fn write_file(p: &Path, bytes: &[u8]) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, bytes).expect("write");
}

fn snapshot_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("readdir") {
            let e = e.expect("entry");
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push((p.clone(), std::fs::read(&p).expect("read")));
            }
        }
    }
    out.sort();
    out
}

fn hid_of(e: &aether_unified::inventory::InventoryEntry) -> Option<String> {
    e.flags.iter().find_map(|f| f.strip_prefix("hardlink-id:").map(|s| s.to_string()))
}

// 1. Two independent files get distinct physical identities.
#[test]
fn w01_independent_files_distinct_identities() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows identity requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("one.bin"), b"first-payload-abc");
        write_file(&d.path().join("two.bin"), b"second-payload-xyz");
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        let a = inv.entries.iter().find(|e| e.normalized_path == "one.bin").expect("one");
        let b = inv.entries.iter().find(|e| e.normalized_path == "two.bin").expect("two");
        let (ida, idb) = (hid_of(a).expect("native id a"), hid_of(b).expect("native id b"));
        assert_ne!(ida, idb, "independent files must differ");
    }
}

// 2. Two hardlinked paths share one physical identity.
#[test]
fn w02_linked_pair_shares_identity() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows identity requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("orig.bin"), b"shared-payload-123");
        if std::fs::hard_link(d.path().join("orig.bin"), d.path().join("alias.bin")).is_err() {
            eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
            return;
        }
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        let a = inv.entries.iter().find(|e| e.normalized_path == "orig.bin").expect("orig");
        let b = inv.entries.iter().find(|e| e.normalized_path == "alias.bin").expect("alias");
        assert_eq!(hid_of(a).expect("id a"), hid_of(b).expect("id b"));
        assert_eq!(a.content_hash, b.content_hash);
        for e in [a, b] {
            assert!(e.flags.iter().any(|f| f.starts_with("hardlink-group:")), "grouped");
            assert!(e.flags.iter().any(|f| f.starts_with("hardlink-nlinks:")), "count bound");
        }
    }
}

// 3. Three-or-more group is deterministic (order + classification).
#[test]
fn w03_group_of_three_is_deterministic() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows identity requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("n1.bin"), b"triple-payload");
        for n in ["n2.bin", "n3.bin"] {
            if std::fs::hard_link(d.path().join("n1.bin"), d.path().join(n)).is_err() {
                eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
                return;
            }
        }
        let i1 = walk_release_root(d.path(), &[], None).expect("walk1");
        let i2 = walk_release_root(d.path(), &[], None).expect("walk2");
        assert_eq!(i1.warnings.hardlink_groups.len(), 1, "exactly one group");
        let g = &i1.warnings.hardlink_groups[0];
        let paths = g.split(':').last().unwrap().split(',').collect::<Vec<_>>();
        assert_eq!(paths, vec!["n1.bin", "n2.bin", "n3.bin"], "sorted members");
        let f1: Vec<String> = i1.entries.iter().flat_map(|e| e.flags.clone()).collect();
        let f2: Vec<String> = i2.entries.iter().flat_map(|e| e.flags.clone()).collect();
        assert_eq!(f1, f2, "flags deterministic across walks");
        assert_eq!(i1.warnings.hardlink_groups, i2.warnings.hardlink_groups);
        assert_eq!(i1.warnings.external_link_refs, i2.warnings.external_link_refs);
    }
}

// 4. Native link count is coherent with Windows metadata.
#[test]
fn w04_link_count_matches_system() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows identity requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("c.bin"), b"counted-payload");
        if std::fs::hard_link(d.path().join("c.bin"), d.path().join("c2.bin")).is_err() {
            eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
            return;
        }
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        for name in ["c.bin", "c2.bin"] {
            let e = inv.entries.iter().find(|x| x.normalized_path == name).expect("member");
            let n = e
                .flags
                .iter()
                .find_map(|f| f.strip_prefix("hardlink-nlinks:"))
                .expect("count flag")
                .parse::<u32>()
                .expect("count parses");
            assert_eq!(n, 2, "two links visible to the system");
        }
    }
}

// 5. Surplus links beyond the scope trigger unexplained-reference status.
#[test]
fn w05_surplus_links_flagged_exterior() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows identity requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        let root = d.path().join("root");
        let outside = d.path().join("elsewhere");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        write_file(&root.join("a.bin"), b"surplus-payload");
        // Third link OUTSIDE the inventoried root (same volume: the link
        // call succeeding proves it; hardlinks cannot cross volumes).
        for (src, dst) in [
            (root.join("a.bin"), root.join("b.bin")),
            (root.join("a.bin"), outside.join("c.bin")),
        ] {
            if std::fs::hard_link(&src, &dst).is_err() {
                eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
                return;
            }
        }
        let inv = walk_release_root(&root, &[], None).expect("walk");
        assert!(
            inv.warnings.external_link_refs.iter().any(|s| s.starts_with("exterior:")),
            "surplus must be exterior with no exclusions: {:?}",
            inv.warnings.external_link_refs
        );
        for name in ["a.bin", "b.bin"] {
            let e = inv.entries.iter().find(|x| x.normalized_path == name).expect("member");
            assert!(
                e.flags.iter().any(|f| f.starts_with("unexplained-link-ref:")),
                "member annotated"
            );
        }
        assert!(
            inv.warnings.external_link_refs.iter().all(|s| !s.starts_with("ambiguous:")),
            "no ambiguity without exclusions"
        );
    }
}

// 6. An exclusion is not confused with certain exterior proof.
#[test]
fn w06_exclusion_yields_ambiguous_not_exterior() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows identity requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        let root = d.path().join("root");
        write_file(&root.join("a.bin"), b"excluded-payload");
        std::fs::create_dir_all(root.join("skipped")).unwrap();
        for dst in [root.join("b.bin"), root.join("skipped/c.bin")] {
            if std::fs::hard_link(root.join("a.bin"), &dst).is_err() {
                eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
                return;
            }
        }
        let inv =
            walk_release_root(&root, &["skipped/*".to_string()], None).expect("walk");
        assert!(
            inv.warnings.external_link_refs.iter().any(|s| s.starts_with("ambiguous:")),
            "excluded link must be ambiguous: {:?}",
            inv.warnings.external_link_refs
        );
        assert!(
            inv.warnings.external_link_refs.iter().all(|s| !s.starts_with("exterior:")),
            "exclusion must never read as certain exterior"
        );
        assert!(
            inv.entries.iter().all(|e| !e.flags.iter().any(|f| f.starts_with("unexplained-link-ref:"))),
            "no exterior annotation under exclusions"
        );
    }
}

// 7. Unavailable identity stays explicit (never a silent PASS).
#[test]
fn w07_every_file_has_explicit_identity_state() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows identity requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        // Forcing a native API failure deterministically would need fault
        // injection (NOT attempted): this test locks the exhaustiveness
        // property instead -- every file entry carries either a native id
        // or an explicit unavailable flag. No silent third state exists.
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("x.bin"), b"x");
        write_file(&d.path().join("y.bin"), b"y");
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        for e in inv.entries.iter().filter(|e| e.kind == EntryKind::File) {
            let has_id = e.flags.iter().any(|f| f.starts_with("hardlink-id:"));
            let unavailable = e
                .flags
                .iter()
                .any(|f| f.starts_with("hardlink-detection=unavailable-on-windows"));
            assert!(has_id || unavailable, "explicit state for {}", e.normalized_path);
        }
    }
}

// 8. Groups and diagnostics deterministic across identical inventories.
#[test]
fn w08_determinism_across_identical_walks() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows groups require a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("k1.bin"), b"det-payload");
        if std::fs::hard_link(d.path().join("k1.bin"), d.path().join("k2.bin")).is_err() {
            eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
            return;
        }
        let a = walk_release_root(d.path(), &[], None).expect("walk a");
        let b = walk_release_root(d.path(), &[], None).expect("walk b");
        assert_eq!(a.warnings.hardlink_groups, b.warnings.hardlink_groups);
        assert_eq!(a.warnings.external_link_refs, b.warnings.external_link_refs);
        assert_eq!(a.diagnostics, b.diagnostics);
        let fa: Vec<Vec<String>> = a.entries.iter().map(|e| e.flags.clone()).collect();
        let fb: Vec<Vec<String>> = b.entries.iter().map(|e| e.flags.clone()).collect();
        assert_eq!(fa, fb);
    }
}

// 9. Canonical digest identical when only side-car detection changes.
#[test]
fn w09_digest_independent_of_sidecar() {
    let d = tempfile::tempdir().expect("tempdir");
    write_file(&d.path().join("s.bin"), b"sidecar-payload");
    let inv = walk_release_root(d.path(), &[], None).expect("walk");
    let before = inventory_digest(&inv.entries);
    let before_bytes = canonical_bytes(&inv.entries);
    let mut mutated = inv.entries.clone();
    mutated[0].flags.push("hardlink-group:simulated".to_string());
    mutated[0].diagnostic.push_str("simulated");
    assert_eq!(inventory_digest(&mutated), before, "flags/diagnostics never hashed");
    assert_eq!(canonical_bytes(&mutated), before_bytes);
}

// 10. Inventory and preflight stay read-only.
#[test]
fn w10_walk_writes_nothing() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows walk requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("r.bin"), b"readonly-payload");
        if std::fs::hard_link(d.path().join("r.bin"), d.path().join("r2.bin")).is_err() {
            eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
            return;
        }
        let before = snapshot_bytes(d.path());
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        assert!(!inv.entries.is_empty());
        assert_eq!(snapshot_bytes(d.path()), before, "walk must not write");
    }
}

// 11. Symlinks beside hardlinks keep symlink policy (never grouped).
#[test]
fn w11_symlinks_never_grouped_with_hardlinks() {
    #[cfg(not(windows))]
    {
        eprintln!("NOT_RUN: native Windows walk requires a Windows runner");
        return;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("real.bin"), b"link-target-payload");
        if std::fs::hard_link(d.path().join("real.bin"), d.path().join("hard.bin")).is_err() {
            eprintln!("NOT_RUN: hardlink creation refused by FS/rights");
            return;
        }
        if symlink_file(d.path().join("real.bin"), d.path().join("soft.bin")).is_err() {
            eprintln!("NOT_RUN: symlink creation refused (privileges)");
            return;
        }
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        let soft = inv.entries.iter().find(|e| e.normalized_path == "soft.bin").expect("link");
        assert_eq!(soft.kind, EntryKind::Symlink, "symlink stays symlink");
        assert!(soft.content_hash.starts_with("link:"), "target-bound, never content");
        assert!(
            !soft.flags.iter().any(|f| f.starts_with("hardlink-")),
            "symlink never grouped: {:?}",
            soft.flags
        );
    }
}

// 12. Unix behavior unchanged (runs on unix; NOT_RUN recorded on Windows).
#[test]
fn w12_unix_behavior_unchanged() {
    #[cfg(unix)]
    {
        let d = tempfile::tempdir().expect("tempdir");
        write_file(&d.path().join("u.bin"), b"unix-payload");
        std::fs::hard_link(d.path().join("u.bin"), d.path().join("u2.bin")).expect("hardlink");
        let inv = walk_release_root(d.path(), &[], None).expect("walk");
        assert!(!inv.warnings.hardlink_groups.is_empty(), "unix grouping intact");
    }
    #[cfg(not(unix))]
    {
        // Unix code paths (#[cfg(unix)] blocks) are byte-identical to the
        // 4AQ/4AR state: this phase touched only #[cfg(windows)] regions
        // plus shared ordering code whose digest output is covered by w09
        // and the 4AQ suite. Exact unix execution needs a unix runner.
        eprintln!("NOT_RUN: unix legs not compiled on this runner; unchanged-by-inspection");
    }
}

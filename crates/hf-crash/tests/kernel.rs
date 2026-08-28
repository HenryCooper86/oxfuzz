//! Kernel crash-report parsing: syzkaller's findings are kernel oops text, not
//! sanitizer logs, so they get their own parser rather than a userspace one
//! bent to fit.

use hf_crash::kernel::{parse_kernel_report, KernelBugClass};

/// A KASAN slab-out-of-bounds, in the shape syz-manager retains it.
const KASAN: &str = "\
==================================================================
BUG: KASAN: slab-out-of-bounds in ext4_xattr_set_entry+0x1234/0x1500 fs/ext4/xattr.c:1650
Read of size 4 at addr ffff88810a3b2c84 by task syz-executor.0/1234

CPU: 0 PID: 1234 Comm: syz-executor.0 Not tainted 5.15.0-syzkaller #1
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x8d/0xcf lib/dump_stack.c:106
 print_address_description.constprop.0+0x1f/0x140 mm/kasan/report.c:233
 kasan_report+0x8a/0xb0 mm/kasan/report.c:495
 ext4_xattr_set_entry+0x1234/0x1500 fs/ext4/xattr.c:1650
 ext4_xattr_block_set+0x2a1/0x900 fs/ext4/xattr.c:1990
 ext4_xattr_set_handle+0x7c9/0xd00 fs/ext4/xattr.c:2318
 </TASK>
==================================================================
";

#[test]
fn a_kasan_report_classifies_and_titles_itself() {
    let report = parse_kernel_report(KASAN).expect("a KASAN report is a kernel report");
    assert_eq!(report.class, KernelBugClass::Kasan);
    assert!(
        report.title.contains("slab-out-of-bounds"),
        "title should carry the bug class: {}",
        report.title
    );
    assert!(
        report.title.contains("ext4_xattr_set_entry"),
        "title should carry the faulting symbol: {}",
        report.title
    );
}

/// The reporting machinery appears in every KASAN report. Keeping those frames
/// would give every KASAN bug in the kernel the same top-of-stack, collapsing
/// distinct bugs into one signature.
#[test]
fn kasan_reporting_frames_are_not_part_of_the_signature() {
    let report = parse_kernel_report(KASAN).unwrap();
    for noise in [
        "__dump_stack",
        "dump_stack_lvl",
        "print_address_description",
        "kasan_report",
    ] {
        assert!(
            !report.frames.iter().any(|frame| frame.contains(noise)),
            "reporting machinery must be skipped, found {noise} in {:?}",
            report.frames
        );
    }
    assert_eq!(
        report.frames.first().map(String::as_str),
        Some("ext4_xattr_set_entry"),
        "the faulting function is the top frame: {:?}",
        report.frames
    );
}

/// Offsets and sizes move with every kernel build; symbols do not. Two builds
/// of the same bug must share a signature or nothing dedups across kernels.
#[test]
fn the_signature_survives_a_rebuild_but_separates_distinct_bugs() {
    let rebuilt = KASAN
        .replace("+0x1234/0x1500", "+0x99/0x2000")
        .replace("+0x2a1/0x900", "+0x5/0x40")
        .replace("fs/ext4/xattr.c:1650", "fs/ext4/xattr.c:1702");
    let first = parse_kernel_report(KASAN).unwrap();
    let second = parse_kernel_report(&rebuilt).unwrap();
    assert_eq!(
        first.signature, second.signature,
        "an offset change must not fork the signature"
    );
    assert!(!first.signature.is_empty(), "a kernel crash must dedup");

    let elsewhere = KASAN.replace("ext4_xattr_set_entry", "btrfs_setxattr");
    let other = parse_kernel_report(&elsewhere).unwrap();
    assert_ne!(
        first.signature, other.signature,
        "a different faulting function is a different bug"
    );
}

#[test]
fn every_kernel_report_class_is_recognized() {
    let cases: [(&str, KernelBugClass); 8] = [
        (
            "BUG: KASAN: use-after-free in foo+0x1/0x2 fs/a.c:1",
            KernelBugClass::Kasan,
        ),
        (
            "BUG: KMSAN: uninit-value in bar+0x1/0x2 fs/b.c:2",
            KernelBugClass::Kmsan,
        ),
        (
            "BUG: KCSAN: data-race in baz / qux",
            KernelBugClass::Kcsan,
        ),
        ("kernel BUG at fs/ext4/inode.c:1234!", KernelBugClass::KernelBug),
        (
            "WARNING: CPU: 0 PID: 12 at fs/ext4/inode.c:99 ext4_write_inode+0x1/0x2",
            KernelBugClass::Warning,
        ),
        (
            "general protection fault, probably for non-canonical address 0xdff: 0000 [#1] SMP KASAN",
            KernelBugClass::GeneralProtectionFault,
        ),
        (
            "BUG: kernel NULL pointer dereference, address: 0000000000000000",
            KernelBugClass::NullDeref,
        ),
        (
            "INFO: task syz-executor:1234 blocked for more than 143 seconds.",
            KernelBugClass::HungTask,
        ),
    ];
    for (log, expected) in cases {
        let report = parse_kernel_report(log)
            .unwrap_or_else(|| panic!("should parse as a kernel report: {log}"));
        assert_eq!(report.class, expected, "for {log}");
    }
    assert_eq!(
        parse_kernel_report("Kernel panic - not syncing: Attempted to kill init!")
            .unwrap()
            .class,
        KernelBugClass::Panic
    );
}

/// The parser must say "not mine" rather than guessing, so the userspace path
/// keeps its own reports.
#[test]
fn userspace_sanitizer_reports_are_not_kernel_reports() {
    for log in [
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff4",
        "src/parse.c:12:5: runtime error: signed integer overflow",
        "==1==ERROR: LeakSanitizer: detected memory leaks",
        "",
        "Done 1 runs in 2 second(s)",
    ] {
        assert!(
            parse_kernel_report(log).is_none(),
            "must not claim a userspace log: {log:?}"
        );
    }
}

/// A general protection fault names its faulting symbol on the `RIP:` line
/// rather than in the headline, and its call trace uses the older bracketed
/// address format.
#[test]
fn a_fault_report_extracts_frames_from_the_older_bracketed_format() {
    let gpf = "\
general protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1] SMP KASAN
CPU: 1 PID: 4567 Comm: syz-executor Not tainted 5.15.0-syzkaller #1
RIP: 0010:tcp_recvmsg+0x12/0x34 net/ipv4/tcp.c:2100
Call Trace:
 [<ffffffff81234567>] inet_recvmsg+0x1a/0x40 net/ipv4/af_inet.c:850
 [<ffffffff81234599>] sock_recvmsg+0x9d/0xb0 net/socket.c:1010
";
    let report = parse_kernel_report(gpf).unwrap();
    assert_eq!(report.class, KernelBugClass::GeneralProtectionFault);
    assert_eq!(
        report.frames,
        vec!["tcp_recvmsg", "inet_recvmsg", "sock_recvmsg"],
        "the RIP symbol leads, then the bracketed trace"
    );
}

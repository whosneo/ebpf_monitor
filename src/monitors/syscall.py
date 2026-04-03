#!/usr/bin/env python
# encoding: utf-8
"""
系统调用监控器

负责加载和管理系统调用监控eBPF程序，统计系统调用频率和错误率。
采用统计模式，在内核态累积调用次数和错误次数，定期批量输出，避免高频调用导致的事件丢失。

统计维度：
- 单表统计：按 (进程名, 系统调用号) 聚合，记录总调用次数和错误次数

支持的分析场景：
- 识别哪些进程调用了哪些系统调用
- 统计系统调用的成功率和失败率
- 分析系统调用的分类分布（文件IO、网络、内存等）
"""

# 兼容性导入
try:
    from enum import Enum
except ImportError:
    from ..utils.py2_compat import Enum
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 第三方库导入
try:
    # noinspection PyUnresolvedReferences
    from bpfcc import syscall  # pyright: ignore[reportMissingImports]
except ImportError:
    from bcc import syscall  # pyright: ignore[reportMissingImports]

# 本地模块导入
from .base import BaseMonitor
from ..utils.decorators import register_monitor

# 系统调用分类映射（基于 x86_64 架构）
# 使用字符串作为键以避免Python 2 Enum兼容性问题
_SYSCALL_CATEGORIES_MAP = {
    "file_io": {
        # 基础文件操作
        0,  # read
        1,  # write
        2,  # open
        3,  # close
        4,  # stat
        5,  # fstat
        6,  # lstat
        7,  # poll
        8,  # lseek
        16,  # ioctl
        17,  # pread64
        18,  # pwrite64
        19,  # readv
        20,  # writev
        21,  # access
        23,  # select
        32,  # dup
        33,  # dup2
        40,  # sendfile
        72,  # fcntl
        73,  # flock
        74,  # fsync
        75,  # fdatasync
        76,  # truncate
        77,  # ftruncate
        78,  # getdents
        79,  # getcwd
        80,  # chdir
        81,  # fchdir
        82,  # rename
        83,  # mkdir
        84,  # rmdir
        85,  # creat
        86,  # link
        87,  # unlink
        88,  # symlink
        89,  # readlink
        90,  # chmod
        91,  # fchmod
        92,  # chown
        93,  # fchown
        94,  # lchown
        133,  # mknod
        137,  # statfs
        138,  # fstatfs
        161,  # chroot
        165,  # mount
        166,  # umount2
        217,  # getdents64
        # *at 系列系统调用
        257,  # openat
        258,  # mkdirat
        259,  # mknodat
        260,  # fchownat
        261,  # futimesat
        262,  # newfstatat
        263,  # unlinkat
        264,  # renameat
        265,  # linkat
        266,  # symlinkat
        267,  # readlinkat
        268,  # fchmodat
        269,  # faccessat
        270,  # pselect6
        271,  # ppoll
        # 高级文件操作
        275,  # splice
        276,  # tee
        277,  # sync_file_range
        278,  # vmsplice
        280,  # utimensat
        285,  # fallocate
        291,  # epoll_create1
        292,  # dup3
        294,  # inotify_init1
        306,  # syncfs
        316,  # renameat2
        322,  # execveat
        323,  # copy_file_range
        # epoll 系列
        232,  # epoll_wait
        233,  # epoll_ctl
        281,  # epoll_pwait
        # inotify 系列
        253,  # inotify_init
        254,  # inotify_add_watch
        255,  # inotify_rm_watch
    },
    "network": {
        41,  # socket
        42,  # connect
        43,  # accept
        44,  # sendto
        45,  # recvfrom
        46,  # sendmsg
        47,  # recvmsg
        48,  # shutdown
        49,  # bind
        50,  # listen
        51,  # getsockname
        52,  # getpeername
        53,  # socketpair
        54,  # setsockopt
        55,  # getsockopt
        288,  # accept4
        299,  # recvmmsg
        307,  # sendmmsg
    },
    "memory": {
        9,  # mmap
        10,  # mprotect
        11,  # munmap
        12,  # brk
        25,  # mremap
        26,  # msync
        27,  # mincore
        28,  # madvise
        149,  # mlock
        150,  # munlock
        151,  # mlockall
        152,  # munlockall
        279,  # mlock2
        319,  # memfd_create
        # 共享内存（也属于 IPC，但主要是内存操作）
        29,  # shmget
        30,  # shmat
        31,  # shmctl
        67,  # shmdt
    },
    "process": {
        24,  # sched_yield
        39,  # getpid
        56,  # clone
        57,  # fork
        58,  # vfork
        59,  # execve
        60,  # exit
        61,  # wait4
        95,  # umask
        102,  # getuid
        104,  # getgid
        105,  # setuid
        106,  # setgid
        107,  # geteuid
        108,  # getegid
        109,  # setpgid
        110,  # getppid
        111,  # getpgrp
        112,  # setsid
        113,  # setreuid
        114,  # setregid
        115,  # getgroups
        116,  # setgroups
        117,  # setresuid
        118,  # getresuid
        119,  # setresgid
        120,  # getresgid
        125,  # capget
        126,  # capset
        155,  # pivot_root
        157,  # prctl
        158,  # arch_prctl
        186,  # gettid
        231,  # exit_group
        247,  # waitid
        250,  # keyctl (密钥管理)
        272,  # unshare
        273,  # set_robust_list
        274,  # get_robust_list
        318,  # getrandom (Linux 3.17+)
        321,  # bpf (Linux 3.18+)
        # ptrace 也可以归类为调试/跟踪
        101,  # ptrace
    },
    "signal": {
        13,  # rt_sigaction
        14,  # rt_sigprocmask
        15,  # rt_sigreturn
        34,  # pause
        62,  # kill
        127,  # rt_sigpending
        128,  # rt_sigtimedwait
        129,  # rt_sigqueueinfo
        130,  # rt_sigsuspend
        131,  # sigaltstack
        200,  # tkill
        234,  # tgkill
        282,  # signalfd
        289,  # signalfd4
    },
    "time": {
        35,  # nanosleep
        36,  # getitimer
        37,  # alarm
        38,  # setitimer
        96,  # gettimeofday
        201,  # time
        222,  # timer_create
        223,  # timer_settime
        224,  # timer_gettime
        226,  # timer_delete
        227,  # clock_settime
        228,  # clock_gettime
        229,  # clock_getres
        230,  # clock_nanosleep
        283,  # timerfd_create
        286,  # timerfd_settime
        287,  # timerfd_gettime
    },
    "ipc": {
        # 管道
        22,  # pipe
        293,  # pipe2
        # 消息队列
        68,  # msgget
        69,  # msgsnd
        70,  # msgrcv
        71,  # msgctl
        # 信号量
        64,  # semget
        65,  # semop
        66,  # semctl
        220,  # semtimedop
        # eventfd
        284,  # eventfd
        290,  # eventfd2
        # futex（快速用户空间互斥锁）
        202,  # futex
        240,  # futex (requeue)
    }
}


class SyscallCategory(Enum):
    """系统调用分类枚举"""
    FILE_IO = "file_io"
    NETWORK = "network"
    MEMORY = "memory"
    PROCESS = "process"
    SIGNAL = "signal"
    TIME = "time"
    IPC = "ipc"
    UNKNOWN = "unknown"

    @classmethod
    def classify(cls, syscall_nr):
        # type: (int) -> SyscallCategory
        """对系统调用进行分类"""
        for category_str, syscall_numbers in _SYSCALL_CATEGORIES_MAP.items():
            if syscall_nr in syscall_numbers:
                return getattr(cls, category_str.upper())
        return cls.UNKNOWN


@register_monitor("syscall")
class SyscallMonitor(BaseMonitor):
    """系统调用监控器"""
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        "raw_syscalls:sys_exit"
    ]

    # 配置模式定义
    # monitor_categories: 控制要监控的系统调用分类，每个分类的布尔值决定是否收集该分类的数据
    # show_errors_only: 仅显示错误的系统调用，为True时过滤掉成功的调用
    CONFIG_SCHEMA = {
        "monitor_categories": {
            "type": dict,
            "required": True,
            "required_keys": ["file_io", "network", "memory", "process", "signal", "time", "ipc"],
            "value_type": bool,
            "default": {
                "file_io": True,    # 文件IO类系统调用（read, write, open等）
                "network": True,    # 网络类系统调用（socket, connect, sendto等）
                "memory": True,     # 内存类系统调用（mmap, mprotect, munmap等）
                "process": True,    # 进程类系统调用（fork, execve, clone等）
                "signal": False,    # 信号类系统调用（kill, sigaction等），默认关闭
                "time": False,      # 时间类系统调用（clock_gettime, nanosleep等），默认关闭
                "ipc": True         # 进程间通信类系统调用（pipe, msgget, semget等）
            }
        },
        "show_errors_only": {
            "type": bool,
            "required": True,
            "default": False  # 默认显示所有调用，包括成功的
        }
    }

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("syscall_nr", "syscall_nr"),
        ("syscall_name", "syscall_nr", syscall.syscall_name),
        ("category", "syscall_nr", lambda nr: SyscallCategory.classify(nr).value),
        ("count", "count"),
        ("error_count", "error_count"),
        ("error_rate", ("count", "error_count"),
         lambda c, e: (e / float(c)) * 100.0 if c > 0 else 0.0),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:<20} {:<10} {:>8} {:>8} {:>8.1f}%",
        [
            "comm",
            ("syscall_nr", syscall.syscall_name),
            ("syscall_nr", lambda nr: SyscallCategory.classify(nr).value),
            "count",
            "error_count",
            (("count", "error_count"), lambda c, e: (e / float(c)) * 100.0 if c > 0 else 0.0),
        ],
        ["COMM", "SYSCALL", "CATEGORY", "COUNT", "ERRORS", "ERR_RATE"],
    )

    def should_collect(self, key, value):
        """判断是否应该收集数据"""
        category = SyscallCategory.classify(key.syscall_nr)
        if category == SyscallCategory.FILE_IO and not self.monitor_categories["file_io"]:
            return False
        if category == SyscallCategory.NETWORK and not self.monitor_categories["network"]:
            return False
        if category == SyscallCategory.MEMORY and not self.monitor_categories["memory"]:
            return False
        if category == SyscallCategory.PROCESS and not self.monitor_categories["process"]:
            return False
        if category == SyscallCategory.SIGNAL and not self.monitor_categories["signal"]:
            return False
        if category == SyscallCategory.TIME and not self.monitor_categories["time"]:
            return False
        if category == SyscallCategory.IPC and not self.monitor_categories["ipc"]:
            return False

        if self.show_errors_only and value.error_count == 0:
            return False

        return True

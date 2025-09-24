#!/usr/bin/env python3
# encoding: utf-8
"""
内核兼容性检查器

提供统一的内核版本检查、eBPF支持检测和系统兼容性验证功能。
集中管理所有兼容性相关的检查逻辑，避免代码重复。
"""

import ctypes
import errno
import os
import platform
import subprocess
from typing import Any, Dict, List, Tuple

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # noinspection PyUnusedImports
    from .application_context import ApplicationContext


class CapabilityChecker:
    """
    内核兼容性检查器
    
    提供统一的内核版本检查、eBPF支持检测和系统兼容性验证功能。
    不再使用单例模式，通过依赖注入获取所需组件。
    """

    def __init__(self, context: 'ApplicationContext'):
        """
        初始化内核兼容性检查器
        
        Args:
            context: 应用上下文，提供所需的依赖组件
        """
        self.context = context
        self.logger = context.get_logger(self)

        # 解析内核信息
        self.kernel_version = self._get_kernel_version()
        self.kernel_release = platform.uname().release
        self.architecture = self._get_architecture()

        # 缓存检查结果
        self._ebpf_support_cache = None
        self._capabilities_cache = None

    def _get_kernel_version(self) -> Tuple[int, int, int]:
        """
        获取内核版本

        Returns:
            Tuple[int, int, int]: (major, minor, patch) 版本号
        """
        try:
            kernel_release = platform.uname().release
            # 解析版本号，处理像 "4.19.90-2107.6.0.el7.x86_64" 这样的版本
            version_parts = kernel_release.split(".")

            major = int(version_parts[0]) if len(version_parts) > 0 and version_parts[0].isdigit() else 0
            minor = int(version_parts[1]) if len(version_parts) > 1 and version_parts[1].isdigit() else 0

            # 处理patch版本，可能包含非数字字符
            patch = 0
            if len(version_parts) > 2:
                patch_str = version_parts[2].split('-')[0]  # 移除后续的发行版信息
                if patch_str.isdigit():
                    patch = int(patch_str)

            self.logger.debug(f"解析内核版本: {kernel_release} -> ({major}, {minor}, {patch})")
            return major, minor, patch

        except Exception as e:
            self.logger.error(f"解析内核版本失败: {e}")
            return 0, 0, 0

    @staticmethod
    def _get_architecture() -> str:
        """获取系统架构"""
        return platform.machine()

    def check_minimum_kernel_version(self, min_major: int = 4, min_minor: int = 1) -> bool:
        """
        检查是否满足最低内核版本要求

        Args:
            min_major: 最低主版本号
            min_minor: 最低次版本号

        Returns:
            bool: 是否满足要求
        """
        major, minor = self.kernel_version[0], self.kernel_version[1]

        if major > min_major:
            return True
        elif major == min_major and minor >= min_minor:
            return True
        else:
            self.logger.warning(
                f"内核版本 {major}.{minor} 低于最低要求 {min_major}.{min_minor}"
            )
            return False

    def check_ebpf_syscall_support(self) -> bool:
        """
        检查eBPF系统调用支持

        Returns:
            bool: 是否支持eBPF系统调用
        """
        try:
            # 加载libc
            libc = ctypes.CDLL(None)

            # 尝试调用bpf系统调用
            # 使用BPF_PROG_LOAD命令进行测试，这是一个基础的eBPF操作
            libc.syscall(321, 0, 0, 0)

            self.logger.debug("eBPF系统调用支持检查通过")
            return True

        except OSError as e:
            if e.errno == errno.ENOSYS:
                self.logger.error("eBPF系统调用不支持 (ENOSYS)")
            else:
                self.logger.error(f"eBPF系统调用检查失败: {e}")
            return False
        except Exception as e:
            self.logger.error(f"eBPF系统调用检查异常: {e}")
            return False

    def check_ebpf_filesystem(self) -> bool:
        """
        检查eBPF文件系统支持

        Returns:
            bool: 是否支持eBPF文件系统
        """
        bpf_fs_path = "/sys/fs/bpf"

        if os.path.exists(bpf_fs_path) and os.path.isdir(bpf_fs_path):
            self.logger.debug("eBPF文件系统已挂载")
            return True
        else:
            self.logger.warning("eBPF文件系统未挂载或不可访问")
            return False

    def check_bpftool_availability(self) -> bool:
        """
        检查bpftool工具可用性

        Returns:
            bool: bpftool是否可用
        """
        try:
            result = subprocess.run(
                ["bpftool", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version_info = result.stdout.strip()
                self.logger.debug(f"bpftool可用: {version_info}")
                return True
            else:
                self.logger.debug("bpftool命令执行失败")
                return False

        except FileNotFoundError:
            self.logger.debug("bpftool未安装")
            return False
        except subprocess.TimeoutExpired:
            self.logger.warning("bpftool检查超时")
            return False
        except Exception as e:
            self.logger.warning(f"bpftool检查异常: {e}")
            return False

    @staticmethod
    def check_root_privileges() -> bool:
        """
        检查root权限

        Returns:
            bool: 是否有root权限
        """
        return os.geteuid() == 0

    def check_ebpf_support(self) -> bool:
        """
        综合检查eBPF支持

        Returns:
            bool: 是否支持eBPF
        """
        if self._ebpf_support_cache is not None:
            return self._ebpf_support_cache

        checks = [
            ("内核版本", self.check_minimum_kernel_version()),
            ("eBPF系统调用", self.check_ebpf_syscall_support()),
            ("eBPF文件系统", self.check_ebpf_filesystem()),
        ]

        all_passed = True
        for check_name, result in checks:
            if not result:
                self.logger.error(f"eBPF支持检查失败: {check_name}")
                all_passed = False
            else:
                self.logger.debug(f"eBPF支持检查通过: {check_name}")

        self._ebpf_support_cache = all_passed
        return all_passed

    def get_available_capabilities(self) -> Dict[str, bool]:
        """
        获取可用的内核功能

        Returns:
            Dict[str, bool]: 功能名称到可用性的映射
        """
        if self._capabilities_cache is not None:
            return self._capabilities_cache

        capabilities = {
            "kprobes": self._check_kprobe_support(),
            "tracepoints": self._check_tracepoint_support(),
            "perf_events": self._check_perf_event_support(),
            "bpf_syscall": self.check_ebpf_syscall_support(),
            "bpf_filesystem": self.check_ebpf_filesystem(),
            "bpftool": self.check_bpftool_availability(),
        }

        # 添加版本特定功能
        major, minor = self.kernel_version[0], self.kernel_version[1]

        capabilities.update({
            "enhanced_features": (major, minor) >= (4, 18),
            "enhanced_process_info": (major, minor) >= (5, 0),
            "new_tracepoints": (major, minor) >= (5, 4),
            "security_features": (major, minor) >= (5, 8),
        })

        self._capabilities_cache = capabilities
        return capabilities

    @staticmethod
    def _check_kprobe_support() -> bool:
        """检查kprobe支持"""
        kprobe_path = "/sys/kernel/debug/tracing/kprobe_events"
        alt_kprobe_path = "/sys/kernel/tracing/kprobe_events"

        return os.path.exists(kprobe_path) or os.path.exists(alt_kprobe_path)

    @staticmethod
    def _check_tracepoint_support() -> bool:
        """检查tracepoint支持"""
        tracepoint_path = "/sys/kernel/debug/tracing/events"
        alt_tracepoint_path = "/sys/kernel/tracing/events"

        return os.path.exists(tracepoint_path) or os.path.exists(alt_tracepoint_path)

    @staticmethod
    def _check_perf_event_support() -> bool:
        """检查perf event支持"""
        perf_path = "/proc/sys/kernel/perf_event_paranoid"
        return os.path.exists(perf_path)

    def get_compile_flags(self) -> List[str]:
        """
        根据内核版本获取eBPF编译标志

        Returns:
            List[str]: 编译标志列表
        """
        flags = []
        major, minor = self.kernel_version[0], self.kernel_version[1]

        # 基础内核版本支持（Linux 4.0+）
        if (major, minor) >= (4, 0):
            flags.append("-DKERNEL_VERSION_4_0_PLUS")

        # 高级功能支持（Linux 4.18+）
        if (major, minor) >= (4, 18):
            flags.append("-DADVANCED_FEATURES")

        # 进程执行监控特定功能（Linux 5.0+）
        if (major, minor) >= (5, 0):
            flags.append("-DENHANCED_PROCESS_INFO")

        # 新的tracepoint支持（Linux 5.4+）
        if (major, minor) >= (5, 4):
            flags.append("-DNEW_TRACEPOINT_SUPPORT")

        # 内核安全功能（Linux 5.8+）
        if (major, minor) >= (5, 8):
            flags.append("-DSECURITY_FEATURES")

        self.logger.debug(f"eBPF编译标志: {flags}")
        return flags

    def validate_environment(self) -> bool:
        """
        验证完整的运行环境

        Returns:
            bool: 环境是否有效
        """
        self.logger.info("开始环境兼容性验证")

        # 检查权限
        if not self.check_root_privileges():
            self.logger.error("需要root权限运行eBPF程序")
            return False

        # 检查eBPF支持
        if not self.check_ebpf_support():
            self.logger.error("系统不支持eBPF功能")
            return False

        self.logger.info("环境兼容性验证通过")
        return True

    def get_system_info(self) -> Dict[str, Any]:
        """
        获取系统信息摘要

        Returns:
            Dict: 系统信息
        """
        return {
            "kernel_version": self.kernel_version,
            "kernel_release": self.kernel_release,
            "architecture": self.architecture,
            "ebpf_support": self.check_ebpf_support(),
            "root_privileges": self.check_root_privileges(),
            "capabilities": self.get_available_capabilities(),
        }


if __name__ == "__main__":
    """测试函数"""
    from .application_context import ApplicationContext

    test_context = ApplicationContext()
    capability = test_context.get_capability_checker()

    print("=== 内核兼容性检查 ===")
    print(f"内核版本: {capability.kernel_version}")
    print(f"系统架构: {capability.architecture}")
    print(f"eBPF支持: {capability.check_ebpf_support()}")
    print(f"Root权限: {capability.check_root_privileges()}")

    print("\n=== 可用功能 ===")
    test_capabilities = capability.get_available_capabilities()
    for name, available in test_capabilities.items():
        status = "✅" if available else "❌"
        print(f"{status} {name}")

    print(f"\n=== 编译标志 ===")
    test_flags = capability.get_compile_flags()
    for flag in test_flags:
        print(f"  {flag}")

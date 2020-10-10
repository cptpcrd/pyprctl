import ctypes
import ctypes.util
import os
from typing import Union, cast

_libc_path = ctypes.util.find_library("c")
libc = ctypes.CDLL(_libc_path, use_errno=True)

libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
libc.prctl.restype = ctypes.c_int

libc.syscall.argtypes = (ctypes.c_long,)
libc.syscall.restype = ctypes.c_long


def build_oserror(
    eno: int,
    filename: Union[str, bytes, None] = None,
    filename2: Union[str, bytes, None] = None,
) -> OSError:
    return OSError(eno, os.strerror(eno), filename, None, filename2)


def prctl(
    option: int,
    arg2: Union[  # type: ignore
        int,
        ctypes.Structure,
        ctypes._SimpleCData,  # pylint: disable=protected-access
    ],
    arg3: Union[  # type: ignore
        int,
        ctypes.Structure,
        ctypes._SimpleCData,  # pylint: disable=protected-access
    ],
    arg4: Union[  # type: ignore
        int,
        ctypes.Structure,
        ctypes._SimpleCData,  # pylint: disable=protected-access
    ],
    arg5: Union[  # type: ignore
        int,
        ctypes.Structure,
        ctypes._SimpleCData,  # pylint: disable=protected-access
    ],
) -> int:
    raw_args = [
        arg if isinstance(arg, int) else ctypes.addressof(arg) for arg in [arg2, arg3, arg4, arg5]
    ]

    res = libc.prctl(option, *raw_args)
    if res < 0:
        raise build_oserror(ctypes.get_errno())

    return cast(int, res)


_machine = os.uname().machine

# Mini-syscall table
if _machine == "x86_64":
    _SYS_SETRESUID = 117
    _SYS_SETRESGID = 119
    _SYS_EXIT = 60
elif _machine.startswith("aarch64"):
    _SYS_SETRESUID = 147
    _SYS_SETRESGID = 149
    _SYS_EXIT = 93
elif _machine.startswith("arm"):
    _SYS_SETRESUID = 208
    _SYS_SETRESGID = 210
    _SYS_EXIT = 1
elif _machine in ("i386", "i486", "i586", "i686"):
    _SYS_SETRESUID = 208
    _SYS_SETRESGID = 210
    _SYS_EXIT = 1
elif _machine.startswith("riscv"):
    _SYS_SETRESUID = 147
    _SYS_SETRESGID = 149
    _SYS_EXIT = 93
elif _machine.startswith("sparc"):
    _SYS_SETRESUID = 108
    _SYS_SETRESGID = 110
    _SYS_EXIT = 1
elif _machine.startswith("ppc"):
    _SYS_SETRESUID = 164
    _SYS_SETRESGID = 169
    _SYS_EXIT = 1
elif _machine.startswith("s390"):
    _SYS_SETRESUID = 208
    _SYS_SETRESGID = 210
    _SYS_EXIT = 1
elif _machine == "sh":
    _SYS_SETRESUID = 164
    _SYS_SETRESGID = 170
    _SYS_EXIT = 1
else:
    raise RuntimeError("Unsupported platform")


def sys_setresuid(ruid: int, euid: int, suid: int) -> None:
    libc.syscall(_SYS_SETRESUID, ruid, euid, suid)


def sys_setresgid(rgid: int, egid: int, sgid: int) -> None:
    libc.syscall(_SYS_SETRESGID, rgid, egid, sgid)


def sys_exit(res: int) -> None:
    """
    Call the ``_exit()`` system call. This exits the calling thread, but does not terminate other
    threads in the same process.
    """
    libc.syscall(_SYS_EXIT, res)

    assert False, "If we got here, something is very wrong"


PR_SET_PDEATHSIG = 1
PR_GET_PDEATHSIG = 2
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_GET_KEEPCAPS = 7
PR_SET_KEEPCAPS = 8
PR_GET_TIMING = 13
PR_SET_TIMING = 14
PR_TIMING_STATISTICAL = 0
PR_TIMING_TIMESTAMP = 1
PR_SET_NAME = 15
PR_GET_NAME = 16
PR_GET_SECCOMP = 21
PR_SET_SECCOMP = 22
PR_CAPBSET_READ = 23
PR_CAPBSET_DROP = 24
PR_GET_SECUREBITS = 27
PR_SET_SECUREBITS = 28
PR_SET_TIMERSLACK = 29
PR_GET_TIMERSLACK = 30
PR_MCE_KILL = 33
PR_MCE_KILL_CLEAR = 0
PR_MCE_KILL_SET = 1
PR_MCE_KILL_LATE = 0
PR_MCE_KILL_EARLY = 1
PR_MCE_KILL_DEFAULT = 2
PR_MCE_KILL_GET = 34
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_IS_SET = 1
PR_CAP_AMBIENT_RAISE = 2
PR_CAP_AMBIENT_LOWER = 3
PR_CAP_AMBIENT_CLEAR_ALL = 4

_LINUX_CAPABILITY_VERSION_3 = 0x20080522

SECCOMP_MODE_STRICT = 1

VFS_CAP_REVISION_MASK = 0xFF000000
VFS_CAP_FLAGS_MASK = ~VFS_CAP_REVISION_MASK

VFS_CAP_FLAGS_EFFECTIVE = 0x000001

VFS_CAP_REVISION_1 = 0x01000000
XATTR_CAPS_SZ_1 = 12
VFS_CAP_REVISION_2 = 0x02000000
XATTR_CAPS_SZ_2 = 20
VFS_CAP_REVISION_3 = 0x03000000
XATTR_CAPS_SZ_3 = 24

XATTR_NAME_CAPS = "security.capability"

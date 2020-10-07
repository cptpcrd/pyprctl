import ctypes
import ctypes.util
import os
import sys
from typing import Union, cast

_libc_path = ctypes.util.find_library("c")

if _libc_path is None:
    # If we couldn't find a libc, sys.executable is probably statically linked.
    # So we may be able to load *it*.
    # Statically linked executables may not have all the symbols defined, but there's
    # a good chance.

    if not sys.executable:
        raise RuntimeError(
            "Could not find libc (is your system statically linked? are you in a chroot?) "
            "and sys.executable is not set"
        )

    _libc_path = sys.executable

try:
    libc = ctypes.CDLL(_libc_path, use_errno=True)
except OSError as ex:
    if _libc_path == sys.executable:
        raise RuntimeError(
            "Could not find libc, and encountered an error trying to load the Python "
            "executable as a shared library (are you in a chroot?): {}".format(ex)
        ) from ex
    else:
        raise RuntimeError("Error loading libc at {}: {}".format(_libc_path, ex)) from ex


libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
libc.prctl.restype = ctypes.c_int


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

VFS_CAP_FLAGS_EFFECTIVE = 0x000001

VFS_CAP_REVISION_1 = 0x01000000
XATTR_CAPS_SZ_1 = 12
VFS_CAP_REVISION_2 = 0x02000000
XATTR_CAPS_SZ_2 = 20
VFS_CAP_REVISION_3 = 0x03000000
XATTR_CAPS_SZ_3 = 24

XATTR_NAME_CAPS = "security.capability"

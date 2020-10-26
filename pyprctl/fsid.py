import ctypes
import errno
from typing import cast

from . import ffi

ffi.libc.setfsuid.argtypes = (ctypes.c_uint32,)
ffi.libc.setfsuid.restype = ctypes.c_uint
ffi.libc.setfsgid.argtypes = (ctypes.c_uint32,)
ffi.libc.setfsgid.restype = ctypes.c_uint

UGID_MAX = 2 ** 32 - 2


def getfsuid() -> int:
    """
    Get the current thread's filesystem UID (see setfsuid(2) for details).

    This calls the ``setfsuid()`` syscall with the argument -1 (which will make it always fail) and
    returns the result.
    """

    return cast(int, ffi.libc.setfsuid(-1))


def getfsgid() -> int:
    """
    Get the current thread's filesystem GID (see setfsgid(2) for details).

    This calls the ``setfsgid()`` syscall with the argument -1 (which will make it always fail) and
    returns the result.
    """

    return cast(int, ffi.libc.setfsgid(-1))


def setfsuid(uid: int) -> None:
    """
    Set the current thread's filesystem UID (see setfsuid(2) for details).

    This is a helper that calls the ``setfsuid()`` syscall up to twice to ensure that the filesystem
    UID has been changed properly. If it has not, this helper raises a ``PermissionError``.
    """

    if uid < 0 or uid > UGID_MAX:
        raise OverflowError("UID is out of range")

    # If the first call returns `uid`, that means the filesystem UID was already `uid` and it hasn't
    # changed.
    # Otherwise, if the second call returns `uid`, that means it was successfully changed.

    if ffi.libc.setfsuid(uid) != uid and ffi.libc.setfsuid(-1) != uid:
        raise ffi.build_oserror(errno.EPERM)


def setfsgid(gid: int) -> None:
    """
    Set the current thread's filesystem GID (see setfsgid(2) for details).

    This is a helper that calls the ``setfsgid()`` syscall up to twice to ensure that the filesystem
    GID has been changed properly. If it hds not, this helper raises a ``PermissionError``.
    """

    if gid < 0 or gid > UGID_MAX:
        raise OverflowError("GID is out of range")

    # If the first call returns `gid`, that means the filesystem GID was already `gid` and it hasn't
    # changed.
    # Otherwise, if the second call returns `gid`, that means it was successfully changed.

    if ffi.libc.setfsgid(gid) != gid and ffi.libc.setfsgid(-1) != gid:
        raise ffi.build_oserror(errno.EPERM)

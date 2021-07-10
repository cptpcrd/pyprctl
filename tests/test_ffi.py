import errno
import os

import pytest

import pyprctl


def test_build_oserror() -> None:
    assert str(pyprctl.ffi.build_oserror(errno.EINVAL)) == "[Errno {}] Invalid argument".format(
        errno.EINVAL
    )
    assert str(
        pyprctl.ffi.build_oserror(errno.EINVAL, None)
    ) == "[Errno {}] Invalid argument".format(errno.EINVAL)
    assert str(
        pyprctl.ffi.build_oserror(errno.EINVAL, None, None)
    ) == "[Errno {}] Invalid argument".format(errno.EINVAL)

    assert str(
        pyprctl.ffi.build_oserror(errno.EINVAL, "")
    ) == "[Errno {}] Invalid argument: ''".format(errno.EINVAL)
    assert str(
        pyprctl.ffi.build_oserror(errno.EINVAL, "a")
    ) == "[Errno {}] Invalid argument: 'a'".format(errno.EINVAL)

    assert str(
        pyprctl.ffi.build_oserror(errno.EINVAL, "", "")
    ) == "[Errno {}] Invalid argument: '' -> ''".format(errno.EINVAL)
    assert str(
        pyprctl.ffi.build_oserror(errno.EINVAL, "a", "b")
    ) == "[Errno {}] Invalid argument: 'a' -> 'b'".format(errno.EINVAL)


def test_setresid_same() -> None:
    uid = os.getuid()
    gid = os.getgid()

    # These calls will succeed without changing anything

    pyprctl.ffi.sys_setresuid(-1, -1, -1)
    pyprctl.ffi.sys_setresuid(uid, uid, uid)

    pyprctl.ffi.sys_setresgid(-1, -1, -1)
    pyprctl.ffi.sys_setresgid(gid, gid, gid)


def test_setresid_error() -> None:
    uid = os.getuid()
    gid = os.getgid()

    # Drop CAP_SETUID and CAP_SETGID if we have them
    orig_state = pyprctl.CapState.get_current()
    state = orig_state.copy()
    state.effective.discard(pyprctl.Cap.SETUID)
    state.effective.discard(pyprctl.Cap.SETGID)
    state.set_current()

    # This makes sure we're using the 32-bit UID/GID syscalls

    with pytest.raises(OSError) as exc_info:
        pyprctl.ffi.sys_setresuid(uid | 0xFFFF0000, uid | 0xFFFF0000, uid | 0xFFFF0000)
    assert exc_info.value.errno in (errno.EINVAL, errno.EPERM)

    with pytest.raises(OSError) as exc_info:
        pyprctl.ffi.sys_setresgid(gid | 0xFFFF0000, gid | 0xFFFF0000, gid | 0xFFFF0000)
    assert exc_info.value.errno in (errno.EINVAL, errno.EPERM)

    orig_state.set_current()


def test_setgroups_error() -> None:
    orig_state = False
    if pyprctl.cap_effective.setgid:
        pyprctl.cap_effective.setgid = False
        orig_state = True

    with pytest.raises(PermissionError):
        pyprctl.ffi.sys_setgroups([])

    pyprctl.cap_effective.setgid = orig_state

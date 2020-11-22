import errno
import os

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

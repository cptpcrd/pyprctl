import errno

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

import os

import pytest

import pyprctl


def test_getfsid() -> None:
    # The effective UID/GID should be equal to the filesystem UID/GID
    # except in very specific scenarios
    assert pyprctl.getfsuid() == os.geteuid()
    assert pyprctl.getfsgid() == os.getegid()


def test_setfsid_overflow() -> None:
    for bad_id in [-1, 2 ** 32 - 1, 2 ** 64]:
        with pytest.raises(OverflowError):
            pyprctl.setfsuid(bad_id)  # pytype: disable=not-callable

        with pytest.raises(OverflowError):
            pyprctl.setfsgid(bad_id)


def test_setfsid_same() -> None:
    # This is a no-op
    pyprctl.setfsuid(os.geteuid())
    pyprctl.setfsgid(os.getegid())


def test_setfsuid_failure() -> None:
    bad_uid = max(os.getresuid()) + 1

    orig_state = False
    if pyprctl.cap_effective.setuid:
        pyprctl.cap_effective.setuid = False
        orig_state = True

    with pytest.raises(PermissionError):
        pyprctl.setfsuid(bad_uid)

    pyprctl.cap_effective.setuid = orig_state


def test_setfsgid_failure() -> None:
    bad_gid = max(os.getresgid()) + 1

    orig_state = False
    if pyprctl.cap_effective.setgid:
        pyprctl.cap_effective.setgid = False
        orig_state = True

    with pytest.raises(PermissionError):
        pyprctl.setfsgid(bad_gid)

    pyprctl.cap_effective.setgid = orig_state

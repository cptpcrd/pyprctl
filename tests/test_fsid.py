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

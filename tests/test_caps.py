import subprocess
import sys

import pytest

import pyprctl

from .util import restore_old_value


def test_no_new_privs_set() -> None:
    assert not pyprctl.get_no_new_privs()
    pyprctl.set_no_new_privs()
    assert pyprctl.get_no_new_privs()


@restore_old_value(pyprctl.get_keepcaps, pyprctl.set_keepcaps)
def test_keepcaps_toggle() -> None:
    pyprctl.set_keepcaps(True)
    assert pyprctl.get_keepcaps()
    assert pyprctl.Secbits.KEEP_CAPS in pyprctl.get_securebits()
    assert pyprctl.securebits.keep_caps

    pyprctl.set_keepcaps(False)
    assert not pyprctl.get_keepcaps()
    assert pyprctl.Secbits.KEEP_CAPS not in pyprctl.get_securebits()
    assert not pyprctl.securebits.keep_caps


def test_ambient_supported() -> None:
    assert pyprctl.cap_ambient_supported()


def test_ambient_probe() -> None:
    pyprctl.cap_ambient_probe()


def test_ambient_clear() -> None:
    pyprctl.cap_ambient_clear_all()
    assert pyprctl.cap_ambient_probe() == set()


def test_bset_probe() -> None:
    pyprctl.capbset_probe()


def test_capstate() -> None:
    capstate = pyprctl.CapState.get_current()

    # This should match
    assert capstate == pyprctl.CapState.get_for_pid(0)

    # We can reset it to the same value
    capstate.set_current()
    assert capstate == pyprctl.CapState.get_current()


def test_capstate_copy() -> None:
    capstate = pyprctl.CapState(
        effective={pyprctl.Cap.CHOWN},
        inheritable={pyprctl.Cap.SYS_CHROOT},
        permitted={pyprctl.Cap.CHOWN, pyprctl.Cap.SYS_CHROOT},
    )

    assert capstate.copy() == capstate


def test_capstate_pid_1() -> None:
    capstate = pyprctl.CapState.get_for_pid(1)
    assert capstate == pyprctl.CapState.get_for_pid(1)


def test_capstate_dead_proc() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-c", ""],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    assert proc.wait() == 0

    with pytest.raises(ProcessLookupError):
        pyprctl.CapState.get_for_pid(proc.pid)


def test_capabilityset() -> None:
    assert pyprctl.capbset.chown == pyprctl.capbset_read(pyprctl.Cap.CHOWN)
    assert pyprctl.cap_ambient.chown == pyprctl.cap_ambient_is_set(pyprctl.Cap.CHOWN)
    assert pyprctl.cap_effective.chown == (
        pyprctl.Cap.CHOWN in pyprctl.CapState.get_current().effective
    )

    with pytest.raises(ValueError, match="Cannot add bounding capabilities"):
        pyprctl.capbset.chown = True

    pyprctl.cap_ambient.clear()
    pyprctl.cap_ambient.limit()
    assert pyprctl.cap_ambient.probe() == set()


@restore_old_value(
    lambda: pyprctl.cap_ambient.chown, lambda val: setattr(pyprctl.cap_ambient, "chown", val)
)
@restore_old_value(pyprctl.CapState.get_current, pyprctl.CapState.set_current)
def test_ambient_raise_error() -> None:
    pyprctl.cap_inheritable.chown = False

    assert not pyprctl.cap_inheritable.chown
    # It was lowered in ambient set automatically if it was previously raised
    assert not pyprctl.cap_ambient.chown

    # We can make sure it's lowered in the ambient set
    pyprctl.cap_ambient.chown = False
    with pytest.raises(PermissionError):
        # But we can't raise it -- it's not in the inheritable set
        pyprctl.cap_ambient.chown = True


def test_capset_from_bitmask() -> None:
    assert pyprctl.caps._capset_from_bitmask(0b101) == {  # pylint: disable=protected-access
        pyprctl.Cap(0),
        pyprctl.Cap(2),
    }

    with pytest.warns(RuntimeWarning, match=r"^Unrecognized capability"):
        assert (
            pyprctl.caps._capset_from_bitmask(1 << 64) == set()  # pylint: disable=protected-access
        )


def test_capset_to_bitmask() -> None:
    assert (
        pyprctl.caps._capset_to_bitmask(  # pylint: disable=protected-access
            [pyprctl.Cap(0), pyprctl.Cap(2)]
        )
        == 0b101
    )

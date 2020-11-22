# pylint: disable=protected-access
import errno
import os
import shutil

import pytest

import pyprctl


def test_filecaps_from_data() -> None:
    with pytest.raises(ValueError, match="too short"):
        pyprctl.FileCaps._from_data(b"")

    with pytest.raises(ValueError, match="too short"):
        pyprctl.FileCaps._from_data(b"\x00\x00\x00")

    with pytest.raises(ValueError, match="Invalid capability version"):
        pyprctl.FileCaps._from_data(b"\x00\x00\x00\x00")

    # Version 1
    assert pyprctl.FileCaps._from_data(
        b"\x00\x00\x00\x01\x01\x00\x00\x00\x01\x00\x00\x00"
    ) == pyprctl.FileCaps(
        effective=False,
        permitted={pyprctl.Cap.CHOWN},
        inheritable={pyprctl.Cap.CHOWN},
        rootid=None,
    )

    # Version 2 (real example, from Wireshark's /usr/bin/dumpcap)
    assert pyprctl.FileCaps._from_data(
        b"\x01\x00\x00\x02\x020\x00\x00\x020\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ) == pyprctl.FileCaps(
        effective=True,
        permitted={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
        inheritable={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
        rootid=None,
    )

    # Version 3
    assert pyprctl.FileCaps._from_data(
        b"\x01\x00\x00\x03\x020\x00\x00\x020\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xe8\x03\x00\x00"
    ) == pyprctl.FileCaps(
        effective=True,
        permitted={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
        inheritable={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
        rootid=1000,
    )


def test_filecaps_into_data() -> None:
    assert (
        pyprctl.FileCaps(
            effective=True,
            permitted={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            inheritable={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            rootid=None,
        )._into_data()
        == b"\x01\x00\x00\x02\x020\x00\x00\x020\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    assert (
        pyprctl.FileCaps(
            effective=True,
            permitted={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            inheritable={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            rootid=1000,
        )._into_data()
        == b"\x01\x00\x00\x03\x020\x00\x00\x020\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xe8\x03\x00\x00"
    )


def test_filecaps_copy() -> None:
    for fcaps in [
        pyprctl.FileCaps(
            effective=False,
            permitted={pyprctl.Cap.CHOWN},
            inheritable={pyprctl.Cap.SYS_CHROOT},
            rootid=None,
        ),
        pyprctl.FileCaps(
            effective=True,
            permitted={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            inheritable={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            rootid=None,
        ),
        pyprctl.FileCaps(
            effective=True,
            permitted={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            inheritable={pyprctl.Cap.DAC_OVERRIDE, pyprctl.Cap.NET_ADMIN, pyprctl.Cap.NET_RAW},
            rootid=1000,
        ),
    ]:
        assert fcaps.copy() == fcaps


def test_filecaps_get_newuidmap() -> None:
    newuidmap_exe = shutil.which("newuidmap")

    if newuidmap_exe is None:
        pytest.skip("'newuidmap' is not installed")

    newuidmap_exe = os.path.realpath(newuidmap_exe)

    fcaps = pyprctl.FileCaps.get_for_file(newuidmap_exe)

    with open(newuidmap_exe) as file:
        assert pyprctl.FileCaps.get_for_file(file.fileno()) == fcaps

    assert fcaps == pyprctl.FileCaps(
        effective=True, permitted={pyprctl.Cap.SETUID}, inheritable=set()
    )


def test_filecaps_get_ping() -> None:
    ping_exe = shutil.which("ping")

    if ping_exe is None:
        pytest.skip("'ping' is not installed")

    ping_exe = os.path.realpath(ping_exe)

    try:
        fcaps = pyprctl.FileCaps.get_for_file(ping_exe)
    except OSError as ex:
        if ex.errno == errno.ENODATA:
            pytest.skip("{} does not have file capabilities attached".format(ping_exe))
        else:
            raise

    assert fcaps == pyprctl.FileCaps(
        effective=True, permitted={pyprctl.Cap.NET_RAW}, inheritable=set()
    )


def test_filecaps_error() -> None:
    with pytest.raises(FileNotFoundError):
        pyprctl.FileCaps.get_for_file("/NOEXIST")

    with pytest.raises(OSError, match="No data"):
        pyprctl.FileCaps.get_for_file(os.path.realpath("/bin/sh"))

    with pytest.raises(FileNotFoundError):
        pyprctl.FileCaps(effective=False, permitted=set(), inheritable=set()).set_for_file(
            "/NOEXIST"
        )

    with pytest.raises(FileNotFoundError):
        pyprctl.FileCaps.remove_for_file("/NOEXIST")

# pylint: disable=protected-access
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

import pytest

import pyprctl

ALL_CAPS_SET = set(pyprctl.Cap)


def test_capstate_to_text() -> None:
    assert str(pyprctl.CapState()) == "="

    assert str(pyprctl.CapState(effective={pyprctl.Cap.CHOWN})) == "cap_chown=e"

    assert str(pyprctl.CapState(effective=ALL_CAPS_SET - {pyprctl.Cap.CHOWN})) == "=e cap_chown-e"

    assert (
        str(
            pyprctl.CapState(
                effective=ALL_CAPS_SET - {pyprctl.Cap.CHOWN},
                permitted=ALL_CAPS_SET,
            )
        )
        == "=ep cap_chown-e"
    )

    assert (
        str(
            pyprctl.CapState(
                effective=ALL_CAPS_SET,
                inheritable=ALL_CAPS_SET,
                permitted=ALL_CAPS_SET,
            )
        )
        == "=eip"
    )

    assert (
        str(
            pyprctl.CapState(
                effective=ALL_CAPS_SET,
                inheritable=ALL_CAPS_SET - {pyprctl.Cap.CHOWN},
                permitted=ALL_CAPS_SET - {pyprctl.Cap.SYS_CHROOT},
            )
        )
        == "=eip cap_chown-i cap_sys_chroot-p"
    )

    assert (
        str(
            pyprctl.CapState(
                effective=ALL_CAPS_SET - {pyprctl.Cap.CHOWN},
                inheritable={pyprctl.Cap.CHOWN},
                permitted=ALL_CAPS_SET,
            )
        )
        == "=ep cap_chown+i cap_chown-e"
    )

    assert (
        str(
            pyprctl.CapState(
                effective=ALL_CAPS_SET - {pyprctl.Cap.CHOWN},
                inheritable=ALL_CAPS_SET - {pyprctl.Cap.CHOWN},
                permitted=ALL_CAPS_SET - {pyprctl.Cap.CHOWN},
            )
        )
        == "=eip cap_chown-eip"
    )


def test_capstate_from_text() -> None:
    empty_state = pyprctl.CapState()

    assert pyprctl.CapState.from_text("") == empty_state
    assert pyprctl.CapState.from_text("=") == empty_state
    assert pyprctl.CapState.from_text("all=") == empty_state
    assert pyprctl.CapState.from_text("all=eip all-eip") == empty_state
    assert pyprctl.CapState.from_text("all+eip all-eip") == empty_state

    assert pyprctl.CapState.from_text("cap_chown=e") == pyprctl.CapState(
        effective={pyprctl.Cap.CHOWN}, permitted=set(), inheritable=set()
    )

    # Case-insensitive
    assert pyprctl.CapState.from_text("ALL=") == empty_state
    assert pyprctl.CapState.from_text("CAP_CHOWN=e") == pyprctl.CapState(
        effective={pyprctl.Cap.CHOWN}, permitted=set(), inheritable=set()
    )

    assert pyprctl.CapState.from_text("cap_chown=ei") == pyprctl.CapState(
        effective={pyprctl.Cap.CHOWN}, permitted=set(), inheritable={pyprctl.Cap.CHOWN}
    )
    assert pyprctl.CapState.from_text("cap_chown+ei") == pyprctl.CapState(
        effective={pyprctl.Cap.CHOWN}, permitted=set(), inheritable={pyprctl.Cap.CHOWN}
    )

    assert pyprctl.CapState.from_text("cap_chown=ei cap_chown-i") == pyprctl.CapState(
        effective={pyprctl.Cap.CHOWN}, permitted=set(), inheritable=set()
    )

    with pytest.raises(ValueError, match="Invalid capability set clause"):
        pyprctl.CapState.from_text("cap_chown")

    with pytest.raises(ValueError, match="Repeated flag characters"):
        pyprctl.CapState.from_text("cap_chown+-e")

    with pytest.raises(ValueError, match="Repeated flag characters"):
        pyprctl.CapState.from_text("cap_chown++e")

    with pytest.raises(ValueError, match="Invalid character"):
        pyprctl.CapState.from_text("cap_chown=E")

    with pytest.raises(ValueError, match="Invalid character"):
        pyprctl.CapState.from_text("cap_chown=o")

    with pytest.raises(ValueError, match="Unknown capability"):
        pyprctl.CapState.from_text("cap_noexist=e")

    with pytest.raises(ValueError, match="Unknown capability"):
        pyprctl.CapState.from_text("noexist=e")

    with pytest.raises(ValueError, match="Unknown capability"):
        pyprctl.CapState.from_text("chown=e")


def test_capstate_to_from_text() -> None:
    for capstate in [
        pyprctl.CapState(),
        pyprctl.CapState(effective=set(pyprctl.Cap)),
        pyprctl.CapState(
            permitted=set(pyprctl.Cap), inheritable={pyprctl.Cap.CHOWN, pyprctl.Cap.SYS_CHROOT}
        ),
        pyprctl.CapState(
            permitted=set(pyprctl.Cap),
            inheritable=set(pyprctl.Cap) - {pyprctl.Cap.CHOWN, pyprctl.Cap.SYS_CHROOT},
        ),
    ]:
        assert pyprctl.CapState.from_text(str(capstate)) == capstate


def test_filecaps_to_text() -> None:
    assert (
        str(pyprctl.FileCaps(effective=False, permitted=set(), inheritable=set(), rootid=None))
        == "="
    )

    assert (
        str(
            pyprctl.FileCaps(
                effective=False, permitted=ALL_CAPS_SET, inheritable=set(), rootid=None
            )
        )
        == "=p"
    )
    assert (
        str(
            pyprctl.FileCaps(
                effective=False, permitted=ALL_CAPS_SET, inheritable=ALL_CAPS_SET, rootid=0
            )
        )
        == "=ip"
    )

    assert (
        str(
            pyprctl.FileCaps(
                effective=True, permitted=ALL_CAPS_SET, inheritable=ALL_CAPS_SET, rootid=None
            )
        )
        == "=eip"
    )
    assert (
        str(
            pyprctl.FileCaps(effective=True, permitted=ALL_CAPS_SET, inheritable=set(), rootid=None)
        )
        == "=ep"
    )
    assert (
        str(
            pyprctl.FileCaps(effective=True, permitted=set(), inheritable=ALL_CAPS_SET, rootid=None)
        )
        == "=i"
    )


def test_filecaps_from_text() -> None:
    empty_state = pyprctl.FileCaps(effective=False, permitted=set(), inheritable=set(), rootid=None)

    assert pyprctl.FileCaps.from_text("") == empty_state
    assert pyprctl.FileCaps.from_text("=") == empty_state

    assert pyprctl.FileCaps.from_text("all=eip") == pyprctl.FileCaps(
        effective=True, permitted=ALL_CAPS_SET, inheritable=ALL_CAPS_SET, rootid=None
    )

    assert pyprctl.FileCaps.from_text("all=ip") == pyprctl.FileCaps(
        effective=False, permitted=ALL_CAPS_SET, inheritable=ALL_CAPS_SET, rootid=None
    )

    with pytest.raises(
        ValueError, match="non-empty effective set that is not equal to permitted set"
    ):
        pyprctl.FileCaps.from_text("all=eip cap_chown-p")

    with pytest.raises(
        ValueError, match="non-empty effective set that is not equal to permitted set"
    ):
        pyprctl.FileCaps.from_text("all=eip cap_chown-e")

    with pytest.raises(
        ValueError, match="non-empty effective set that is not equal to permitted set"
    ):
        pyprctl.FileCaps.from_text("cap_chown+p cap_sys_chroot+e")

    with pytest.raises(
        ValueError, match="non-empty effective set that is not equal to permitted set"
    ):
        pyprctl.FileCaps.from_text("cap_chown+ep cap_sys_chroot+p")

    with pytest.raises(
        ValueError, match="non-empty effective set that is not equal to permitted set"
    ):
        pyprctl.FileCaps.from_text("cap_chown+ep cap_sys_chroot+e")


def test_filecaps_to_from_text() -> None:
    for filecaps in [
        pyprctl.FileCaps(permitted=set(), inheritable=set(), effective=False, rootid=None),
        pyprctl.FileCaps(
            permitted=set(pyprctl.Cap), inheritable=set(), effective=False, rootid=None
        ),
        pyprctl.FileCaps(
            permitted=set(pyprctl.Cap),
            inheritable={pyprctl.Cap.CHOWN, pyprctl.Cap.SYS_CHROOT},
            effective=False,
            rootid=None,
        ),
        pyprctl.FileCaps(
            permitted=set(pyprctl.Cap),
            inheritable=set(pyprctl.Cap) - {pyprctl.Cap.CHOWN, pyprctl.Cap.SYS_CHROOT},
            effective=True,
            rootid=None,
        ),
    ]:
        print(repr(filecaps))
        print(repr(pyprctl.FileCaps.from_text(str(filecaps))))
        print(str(filecaps))
        print(pyprctl.FileCaps.from_text(str(filecaps)))
        assert pyprctl.FileCaps.from_text(str(filecaps)) == filecaps

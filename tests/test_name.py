import pyprctl

from .util import restore_old_value


@restore_old_value(pyprctl.get_name, pyprctl.set_name)
def test_get_set_name() -> None:
    pyprctl.set_name("")
    assert pyprctl.get_name() == ""

    pyprctl.set_name("a" * 14)
    assert pyprctl.get_name() == "a" * 14

    pyprctl.set_name("a" * 15)
    assert pyprctl.get_name() == "a" * 15

    # Silent truncation to 15 bytes + nul
    pyprctl.set_name("a" * 16)
    assert pyprctl.get_name() == "a" * 15

    pyprctl.set_name(b"a" * 17)
    assert pyprctl.get_name() == "a" * 15

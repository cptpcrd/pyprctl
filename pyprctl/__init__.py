import ctypes
import enum
from typing import Callable, Union

from . import ffi
from .caps import (
    Cap,
    CapState,
    Secbits,
    cap_ambient,
    cap_ambient_clear_all,
    cap_ambient_is_set,
    cap_ambient_lower,
    cap_ambient_probe,
    cap_ambient_raise,
    cap_effective,
    cap_inheritable,
    cap_permitted,
    capbset,
    capbset_drop,
    capbset_probe,
    capbset_read,
    get_securebits,
    set_securebits,
)

__all__ = (
    "Cap",
    "CapState",
    "Secbits",
    "cap_ambient_clear_all",
    "cap_ambient_is_set",
    "cap_ambient_lower",
    "cap_ambient_probe",
    "cap_ambient_raise",
    "capbset_drop",
    "capbset_probe",
    "capbset_read",
    "get_securebits",
    "set_securebits",
    "capbset",
    "cap_permitted",
    "cap_inheritable",
    "cap_effective",
    "cap_ambient",
    "set_child_subreaper",
    "get_child_subreaper",
    "set_dumpable",
    "get_dumpable",
    "set_keepcaps",
    "get_keepcaps",
    "set_no_new_privs",
    "get_no_new_privs",
    "set_name",
    "get_name",
    "set_pdeathsig",
    "get_pdeathsig",
    "set_timerslack",
    "get_timerslack",
)

__version__ = "0.1.0"


class MCEKillPolicy(enum.Enum):
    EARLY = ffi.PR_MCE_KILL_EARLY
    LATE = ffi.PR_MCE_KILL_LATE
    DEFAULT = ffi.PR_MCE_KILL_DEFAULT


class TimingMethod(enum.Enum):
    STATISTICAL = ffi.PR_TIMING_STATISTICAL
    TIMESTAMP = ffi.PR_TIMING_TIMESTAMP


def _make_bool_setter(option: int) -> Callable[[bool], None]:
    def func(flag: bool) -> None:
        ffi.prctl(option, int(bool(flag)), 0, 0, 0)

    return func


def _make_ptr_bool_getter(option: int) -> Callable[[], bool]:
    def func() -> bool:
        flag = ctypes.c_int()
        ffi.prctl(option, flag, 0, 0, 0)
        return flag.value != 0

    return func


def _make_res_bool_getter(option: int) -> Callable[[], bool]:
    def func() -> bool:
        return ffi.prctl(option, 0, 0, 0, 0) != 0

    return func


def _make_integer_setter(option: int) -> Callable[[int], None]:
    def func(val: int) -> None:
        ffi.prctl(option, val, 0, 0, 0)

    return func


def _make_ptr_integer_getter(option: int) -> Callable[[], int]:
    def func() -> int:
        flag = ctypes.c_int()
        ffi.prctl(option, flag, 0, 0, 0)
        return flag.value

    return func


def _make_res_integer_getter(option: int) -> Callable[[], int]:
    def func() -> int:
        return ffi.prctl(option, 0, 0, 0, 0)

    return func


set_child_subreaper = _make_bool_setter(ffi.PR_SET_CHILD_SUBREAPER)
get_child_subreaper = _make_ptr_bool_getter(ffi.PR_GET_CHILD_SUBREAPER)

set_dumpable = _make_bool_setter(ffi.PR_SET_DUMPABLE)
get_dumpable = _make_res_bool_getter(ffi.PR_GET_DUMPABLE)

set_keepcaps = _make_bool_setter(ffi.PR_SET_KEEPCAPS)
get_keepcaps = _make_res_bool_getter(ffi.PR_GET_KEEPCAPS)


def set_mce_kill(policy: MCEKillPolicy) -> None:
    ffi.prctl(ffi.PR_MCE_KILL, ffi.PR_MCE_KILL_SET, policy.value, 0, 0)


def get_mce_kill() -> MCEKillPolicy:
    return MCEKillPolicy(ffi.prctl(ffi.PR_MCE_KILL_GET, 0, 0, 0, 0))


def set_no_new_privs() -> None:
    ffi.prctl(ffi.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


get_no_new_privs = _make_res_bool_getter(ffi.PR_GET_NO_NEW_PRIVS)


def set_name(name: Union[str, bytes]) -> None:
    if not isinstance(name, bytes):
        name = name.encode()

    raw_name = ctypes.create_string_buffer(name)
    ffi.prctl(ffi.PR_SET_NAME, raw_name, 0, 0, 0)  # type: ignore


def get_name() -> str:
    name = (ctypes.c_char * 16)()  # pytype: disable=not-callable
    ffi.prctl(ffi.PR_GET_NAME, name, 0, 0, 0)  # type: ignore
    return name.value.decode()


set_pdeathsig = _make_integer_setter(ffi.PR_SET_PDEATHSIG)
get_pdeathsig = _make_ptr_integer_getter(ffi.PR_GET_PDEATHSIG)


def set_seccomp_mode_strict() -> None:
    ffi.prctl(ffi.PR_SET_SECCOMP, ffi.SECCOMP_MODE_STRICT, 0, 0, 0)


set_timerslack = _make_integer_setter(ffi.PR_SET_TIMERSLACK)
get_timerslack = _make_res_integer_getter(ffi.PR_GET_TIMERSLACK)


def set_timing(timing: TimingMethod) -> None:
    ffi.prctl(ffi.PR_SET_TIMING, timing.value, 0, 0, 0)


def get_timing() -> TimingMethod:
    return TimingMethod(ffi.prctl(ffi.PR_GET_TIMING, 0, 0, 0, 0))

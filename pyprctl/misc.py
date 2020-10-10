import ctypes
import enum
import signal
from typing import Callable, Union

from . import ffi


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
set_child_subreaper.__doc__ = """
Set the "child subreaper" attribute on the current process.

When a process dies, its children are reparented to the nearest ancestor with the "child subreaper"
attribute set.
"""

get_child_subreaper = _make_ptr_bool_getter(ffi.PR_GET_CHILD_SUBREAPER)
set_child_subreaper.__doc__ = """
Get the "child subreaper" attribute of the current process.

See ``set_child_subreaper()``.
"""

set_dumpable = _make_bool_setter(ffi.PR_SET_DUMPABLE)
set_dumpable.__doc__ = """
Set the "dumpable" attribute on the current process.

This controls whether a core dump will be produced if the process receives a signal whose default
behavior is to produce a core dump.

In addition, processes that are not dumpable cannot be attached with ``ptrace()`` ``PTRACE_ATTACH``.
"""

get_dumpable = _make_res_bool_getter(ffi.PR_GET_DUMPABLE)
get_dumpable.__doc__ = """
Get whether the "dumpable" attribute is set on the current process.

See ``set_dumpable()``.
"""

set_keepcaps = _make_bool_setter(ffi.PR_SET_KEEPCAPS)
set_keepcaps.__doc__ = """
Set the "keep capabilities" flag on the current thread.

This flag, which is always cleared across an ``exec()``, allows a thread to preserve its permitted
capability set when switching all of its UIDs to nonzero values. See capabilities(7) for more
information.
"""

get_keepcaps = _make_res_bool_getter(ffi.PR_GET_KEEPCAPS)
get_keepcaps.__doc__ = """
Get the "keep capabilities" flag on the current process.

See ``set_keepcaps()``.
"""


def set_mce_kill(policy: MCEKillPolicy) -> None:
    ffi.prctl(ffi.PR_MCE_KILL, ffi.PR_MCE_KILL_SET, policy.value, 0, 0)


def get_mce_kill() -> MCEKillPolicy:
    return MCEKillPolicy(ffi.prctl(ffi.PR_MCE_KILL_GET, 0, 0, 0, 0))


def set_no_new_privs() -> None:
    """
    Set the no-new-privileges flag on the current thread.

    Once this flag is set, it cannot be unset. This flag guarantees that in this thread and in all
    of its children, no ``exec()`` call can ever result in elevated privileges. See prctl(2) for
    more information.

    """
    ffi.prctl(ffi.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


get_no_new_privs = _make_res_bool_getter(ffi.PR_GET_NO_NEW_PRIVS)
get_no_new_privs.__doc__ = """
Get whether the no-new-privileges flag is set on the current thread.

See ``set_no_new_privs()``.
"""


def set_name(name: Union[str, bytes]) -> None:
    """
    Set the name of the current thread.

    The name is silently truncated to the first 16 bytes. This includes the trailing NUL, so only
    the first 15 characters of the given ``name`` will be used.

    """

    if not isinstance(name, bytes):
        name = name.encode()

    raw_name = ctypes.create_string_buffer(name)
    ffi.prctl(ffi.PR_SET_NAME, raw_name, 0, 0, 0)  # type: ignore


def get_name() -> str:
    """Get the name of the current thread as a string."""

    name = (ctypes.c_char * 16)()  # pytype: disable=not-callable
    ffi.prctl(ffi.PR_GET_NAME, name, 0, 0, 0)  # type: ignore
    return name.value.decode()


def set_pdeathsig(sig: Union[signal.Signals, int, None]) -> None:  # pylint: disable=no-member
    """
    Set the parent-death signal of the current process.

    If ``sig`` is 0 or ``None``, the parent-death signal is cleared. Otherwise, ``sig`` specifies
    the signal that will be sent to the current process when its parent dies.

    This flag is is cleared in the following cases:

    1. In children of a ``fork()``.
    2. When ``exec()``-ing a binary that is setuid, setgid, or has file capabilities.
    3. When the effective UID, effective GID, filesystem UID, or filesystem GID is changed.

    See prctl(2) for more details.
    """
    ffi.prctl(ffi.PR_SET_PDEATHSIG, sig or 0, 0, 0, 0)


def get_pdeathsig() -> Union[signal.Signals, int, None]:  # pylint: disable=no-member
    """
    Get the parent-death signal of the current process (see ``set_pdeathsig()`` for details).

    If the parent-death signal is cleared, this function returns ``None``. Otherwise, it returns a
    ``signal.Signals`` object.
    """

    sig = ctypes.c_int()
    ffi.prctl(ffi.PR_GET_PDEATHSIG, sig, 0, 0, 0)

    if sig.value == 0:
        return None

    try:
        return signal.Signals(sig.value)  # pylint: disable=no-member
    except ValueError:
        return sig.value


def set_seccomp_mode_strict() -> None:
    """
    Enable strict seccomp mode.

    After this function is is called, the only syscalls that can be made are ``read()``,
    ``write()``, ``sigreturn()``, and ``_exit()``. Making any other syscall will result in SIGKILL
    being sent to the thread.

    Note: ``sys.exit()`` and ``os._exit()`` will call the ``exit_group()`` syscall, not ``_exit()``.
    ``pyprctl`` exposes a function :py:func:`_sys_exit()` that calls the ``_exit()`` syscall
    directly.

    """

    ffi.prctl(ffi.PR_SET_SECCOMP, ffi.SECCOMP_MODE_STRICT, 0, 0, 0)


set_timerslack = _make_integer_setter(ffi.PR_SET_TIMERSLACK)
get_timerslack = _make_res_integer_getter(ffi.PR_GET_TIMERSLACK)


def set_timing(timing: TimingMethod) -> None:
    ffi.prctl(ffi.PR_SET_TIMING, timing.value, 0, 0, 0)


def get_timing() -> TimingMethod:
    return TimingMethod(ffi.prctl(ffi.PR_GET_TIMING, 0, 0, 0, 0))

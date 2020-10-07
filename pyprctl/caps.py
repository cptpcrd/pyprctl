import ctypes
import enum
import errno
import warnings
from typing import Any, Callable, Iterable, Optional, Set, Tuple, cast

from . import ffi


class _CapUserHeader(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]


class _CapUserData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


ffi.libc.capget.argtypes = (ctypes.POINTER(_CapUserHeader), ctypes.POINTER(_CapUserData))
ffi.libc.capget.restype = ctypes.c_int
ffi.libc.capset.argtypes = (ctypes.POINTER(_CapUserHeader), ctypes.POINTER(_CapUserData))
ffi.libc.capset.restype = ctypes.c_int


@enum.unique
class Cap(enum.Enum):
    CHOWN = 0
    DAC_OVERRIDE = 1
    DAC_READ_SEARCH = 2
    FOWNER = 3
    FSETID = 4
    KILL = 5
    SETGID = 6
    SETUID = 7
    SETPCAP = 8
    LINUX_IMMUTABLE = 9
    NET_BIND_SERVICE = 10
    NET_BROADCAST = 11
    NET_ADMIN = 12
    NET_RAW = 13
    IPC_LOCK = 14
    IPC_OWNER = 15
    SYS_MODULE = 16
    SYS_RAWIO = 17
    SYS_CHROOT = 18
    SYS_PTRACE = 19
    SYS_PACCT = 20
    SYS_ADMIN = 21
    SYS_BOOT = 22
    SYS_NICE = 23
    SYS_RESOURCE = 24
    SYS_TIME = 25
    SYS_TTY_CONFIG = 26
    MKNOD = 27
    LEASE = 28
    AUDIT_WRITE = 29
    AUDIT_CONTROL = 30
    SETFCAP = 31
    MAC_OVERRIDE = 32
    MAC_ADMIN = 33
    SYSLOG = 34
    WAKE_ALARM = 35
    BLOCK_SUSPEND = 36
    AUDIT_READ = 37
    PERFMON = 38
    BPF = 39
    CHECKPOINT_RESTORE = 40

    # Note: When adding capabilities to this list, make sure to add type annotations to the
    # _CapabilitySet class below.


_LAST_CAP = max(Cap, key=lambda cap: cap.value)


class _CapabilitySet:
    # These properties will be automatically added by a loop outside of the class declaration.
    # However, we need to tell mypy about them.

    chown: bool
    dac_override: bool
    dac_read_search: bool
    fowner: bool
    fsetid: bool
    kill: bool
    setgid: bool
    setuid: bool
    setpcap: bool
    linux_immutable: bool
    net_bind_service: bool
    net_broadcast: bool
    net_admin: bool
    net_raw: bool
    ipc_lock: bool
    ipc_owner: bool
    sys_module: bool
    sys_rawio: bool
    sys_chroot: bool
    sys_ptrace: bool
    sys_pacct: bool
    sys_admin: bool
    sys_boot: bool
    sys_nice: bool
    sys_resource: bool
    sys_time: bool
    sys_tty_config: bool
    mknod: bool
    lease: bool
    audit_write: bool
    audit_control: bool
    setfcap: bool
    mac_override: bool
    mac_admin: bool
    syslog: bool
    wake_alarm: bool
    block_suspend: bool
    audit_read: bool
    perfmon: bool
    bpf: bool
    checkpoint_restore: bool

    def __init__(self, name: str) -> None:
        assert name in ("effective", "inheritable", "permitted", "ambient", "bounding")

        self._name = name

    def drop(self, *drop_caps: Cap) -> None:
        if self._name == "bounding":
            for cap in drop_caps:
                capbset_drop(cap)

        elif self._name == "ambient":
            for cap in drop_caps:
                cap_ambient_lower(cap)

        else:
            state = CapState.get_current()
            getattr(state, self._name).difference_update(drop_caps)
            state.set_current()

    def add(self, *add_caps: Cap) -> None:
        if self._name == "bounding":
            raise ValueError("Cannot add bounding capabilities")

        elif self._name == "ambient":
            for cap in add_caps:
                cap_ambient_raise(cap)

        else:
            state = CapState.get_current()
            getattr(state, self._name).update(add_caps)
            state.set_current()

    def has(self, *caps: Cap) -> bool:
        if self._name == "bounding":
            return all(map(capbset_read, caps))
        elif self._name == "ambient":
            return all(map(cap_ambient_is_set, caps))
        else:
            state = CapState.get_current()
            capset = getattr(state, self._name)
            return all(cap in capset for cap in caps)

    def probe(self) -> Set[Cap]:
        if self._name == "bounding":
            return capbset_probe()
        elif self._name == "ambient":
            return cap_ambient_probe()
        else:
            state = CapState.get_current()
            return cast(Set[Cap], getattr(state, self._name))

    def limit(self, *limit_caps: Cap) -> None:
        if not limit_caps:
            self.clear()
        else:
            self.drop(*(set(Cap) - set(limit_caps)))

    def clear(self) -> None:
        if self._name == "ambient":
            cap_ambient_clear_all()
        else:
            self.drop(*Cap)


def _create_capabilityset_getter_setter(
    cap: Cap,
) -> Tuple[Callable[[_CapabilitySet], bool], Callable[[_CapabilitySet, bool], None]]:
    def getter(self: _CapabilitySet) -> bool:
        return self.has(cap)

    def setter(self: _CapabilitySet, val: bool) -> None:
        if val:
            self.add(cap)
        else:
            self.drop(cap)

    return getter, setter


for _cap in Cap:
    setattr(_CapabilitySet, _cap.name.lower(), property(*_create_capabilityset_getter_setter(_cap)))


capbset = _CapabilitySet("bounding")
cap_permitted = _CapabilitySet("permitted")
cap_inheritable = _CapabilitySet("inheritable")
cap_effective = _CapabilitySet("effective")
cap_ambient = _CapabilitySet("ambient")


class CapState:
    def __init__(self) -> None:
        self.effective: Set[Cap] = set()
        self.permitted: Set[Cap] = set()
        self.inheritable: Set[Cap] = set()

    @classmethod
    def get_current(cls) -> "CapState":
        return cls.get_for_pid(0)

    @classmethod
    def get_for_pid(cls, pid: int) -> "CapState":
        header = _CapUserHeader(
            version=ffi._LINUX_CAPABILITY_VERSION_3, pid=pid  # pylint: disable=protected-access
        )
        data = (_CapUserData * 2)()  # pytype: disable=not-callable

        if ffi.libc.capget(ctypes.byref(header), data) < 0:
            raise ffi.build_oserror(ctypes.get_errno())

        res = cls()
        res.effective = _capset_from_bitmask(
            _combine_bitmask_32(data[1].effective, data[0].effective)
        )
        res.permitted = _capset_from_bitmask(
            _combine_bitmask_32(data[1].permitted, data[0].permitted)
        )
        res.inheritable = _capset_from_bitmask(
            _combine_bitmask_32(data[1].inheritable, data[0].inheritable)
        )

        return res

    def set_current(self) -> None:
        header = _CapUserHeader(
            version=ffi._LINUX_CAPABILITY_VERSION_3, pid=0  # pylint: disable=protected-access
        )
        data = (_CapUserData * 2)()  # pytype: disable=not-callable

        data[1].effective, data[0].effective = _split_bitmask_32(_capset_to_bitmask(self.effective))
        data[1].permitted, data[0].permitted = _split_bitmask_32(_capset_to_bitmask(self.permitted))
        data[1].inheritable, data[0].inheritable = _split_bitmask_32(
            _capset_to_bitmask(self.inheritable)
        )

        if ffi.libc.capset(ctypes.byref(header), data) < 0:
            raise ffi.build_oserror(ctypes.get_errno())

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, CapState):
            return (
                self.effective == other.effective
                and self.permitted == other.permitted
                and self.inheritable == other.inheritable
            )

        return NotImplemented  # pytype: disable=bad-return-type

    def __repr__(self) -> str:
        return "{}(effective={!r}, permitted={!r}, inheritable={!r})".format(
            self.__class__.__name__, self.effective, self.permitted, self.inheritable
        )


def _capset_from_bitmask(bitmask: int) -> Set[Cap]:
    res = set()

    i = 0
    while bitmask:
        if bitmask & 1:
            if i <= _LAST_CAP.value:
                res.add(Cap(i))
            else:
                warnings.warn(
                    "Unrecognized capability (number {}) found in capability set. This may result "
                    "in strange behavior. Are you using an old version of pyprctl on a newer "
                    "kernel?".format(i),
                    RuntimeWarning,
                )

        bitmask >>= 1
        i += 1

    return res


def _capset_to_bitmask(caps: Iterable[Cap]) -> int:
    res = 0
    for cap in caps:
        res |= 1 << cap.value
    return res


def _split_bitmask_32(bitmask: int) -> Tuple[int, int]:
    return bitmask >> 32, bitmask & ((1 << 32 - 1))


def _combine_bitmask_32(upper: int, lower: int) -> int:
    return (upper << 32) | lower


@enum.unique
class Secbits(enum.Flag):
    NOROOT = 1 << 0
    NOROOT_LOCKED = 1 << 1
    NO_SETUID_FIXUP = 1 << 2
    NO_SETUID_FIXUP_LOCKED = 1 << 3
    KEEP_CAPS = 1 << 4
    KEEP_CAPS_LOCKED = 1 << 5
    NO_CAP_AMBIENT_RAISE = 1 << 6
    NO_CAP_AMBIENT_RAISE_LOCKED = 1 << 7


def get_securebits() -> Secbits:
    return Secbits(ffi.prctl(ffi.PR_GET_SECUREBITS, 0, 0, 0, 0))


def set_securebits(secbits: Secbits) -> None:
    ffi.prctl(ffi.PR_SET_SECUREBITS, secbits.value, 0, 0, 0)


def capbset_read(cap: Cap) -> Optional[bool]:
    try:
        return bool(ffi.prctl(ffi.PR_CAPBSET_READ, cap.value, 0, 0, 0))
    except OSError as ex:
        if ex.errno == errno.EINVAL:
            return None
        else:
            raise


def capbset_drop(cap: Cap) -> None:
    ffi.prctl(ffi.PR_CAPBSET_DROP, cap.value, 0, 0, 0)


def capbset_probe() -> Set[Cap]:
    return set(filter(capbset_read, Cap))


def cap_ambient_raise(cap: Cap) -> None:
    ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_RAISE, cap.value, 0, 0)


def cap_ambient_lower(cap: Cap) -> None:
    ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_LOWER, cap.value, 0, 0)


def cap_ambient_clear_all() -> None:
    ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)


def cap_ambient_is_set(cap: Cap) -> Optional[bool]:
    try:
        return bool(ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_IS_SET, cap.value, 0, 0))
    except OSError as ex:
        if ex.errno == errno.EINVAL:
            return None
        else:
            raise


def cap_ambient_probe() -> Set[Cap]:
    return set(filter(cap_ambient_is_set, Cap))

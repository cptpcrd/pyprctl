import ctypes
import dataclasses
import enum
import errno
import re
import warnings
from typing import Callable, Iterable, List, Optional, Set, Tuple, cast

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

    def _to_name(self) -> str:
        return "cap_" + self.name.lower()  # pylint: disable=no-member

    @classmethod
    def from_name(cls, name: str) -> "Cap":
        """Look up a capability by name.

        Roughly equivalent to cap_from_name() in libcap.
        Names should be in the format "cap_chown", NOT "CAP_CHOWN"/"CHOWN"/"chown".

        """

        if name.islower() and name.startswith("cap_"):
            try:
                return cast(Cap, getattr(cls, name[4:].upper()))
            except AttributeError:
                pass

        raise ValueError("Unknown capability {!r}".format(name))


_LAST_CAP = max(Cap, key=lambda cap: cap.value)
_ALL_CAPS_SET = set(Cap)


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


@dataclasses.dataclass
class CapState:
    effective: Set[Cap] = dataclasses.field(default_factory=set)
    permitted: Set[Cap] = dataclasses.field(default_factory=set)
    inheritable: Set[Cap] = dataclasses.field(default_factory=set)

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

        res = cls(
            effective=_capset_from_bitmask(
                _combine_bitmask_32(data[1].effective, data[0].effective)
            ),
            permitted=_capset_from_bitmask(
                _combine_bitmask_32(data[1].permitted, data[0].permitted)
            ),
            inheritable=_capset_from_bitmask(
                _combine_bitmask_32(data[1].inheritable, data[0].inheritable)
            ),
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

    @classmethod
    def from_text(cls, text: str) -> "CapState":
        effective, inheritable, permitted = _capstate_from_text(text)
        return cls(effective=effective, inheritable=inheritable, permitted=permitted)

    def __str__(self) -> str:
        return _capstate_to_text(
            effective=self.effective, inheritable=self.inheritable, permitted=self.permitted
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
    return bitmask >> 32, bitmask & ((1 << 32) - 1)


def _combine_bitmask_32(upper: int, lower: int) -> int:
    return (upper << 32) | lower


def _capstate_from_text(text: str) -> Tuple[Set[Cap], Set[Cap], Set[Cap]]:
    # Returns (effective, inheritable, permitted)

    effective: Set[Cap] = set()
    inheritable: Set[Cap] = set()
    permitted: Set[Cap] = set()

    for clause in text.split():
        if not any(ch in clause for ch in "=+-"):
            raise ValueError("Invalid capability set clause")

        cap_names, action_spec = re.split(r"(?=[-+=])", clause, maxsplit=1)

        caps = (
            list(Cap)
            if cap_names in ("", "all")
            else [Cap.from_name(name) for name in cap_names.split(",")]
        )

        should_raise = True

        last_ch = None

        for ch in action_spec:
            if ch in "+-=":
                if last_ch is not None and last_ch not in "eip":
                    raise ValueError("Repeated flag characters in capability set clause")

            if ch == "=":
                # Drop the listed capabilities in all sets
                effective.difference_update(caps)
                inheritable.difference_update(caps)
                permitted.difference_update(caps)
                # Now only raise it in the specified sets
                should_raise = True

            elif ch == "+":
                should_raise = True

            elif ch == "-":
                should_raise = False

            elif ch == "e":
                if should_raise:
                    effective.update(caps)
                else:
                    effective.difference_update(caps)

            elif ch == "i":
                if should_raise:
                    inheritable.update(caps)
                else:
                    inheritable.difference_update(caps)

            elif ch == "p":
                if should_raise:
                    permitted.update(caps)
                else:
                    permitted.difference_update(caps)

            else:
                raise ValueError("Invalid character {!r} in capability set clause".format(ch))

            last_ch = ch

    return effective, inheritable, permitted


def _capstate_to_text(*, effective: Set[Cap], inheritable: Set[Cap], permitted: Set[Cap]) -> str:
    if not effective and not inheritable and not permitted:
        return "="

    def cap_set_to_text(caps: Set[Cap]) -> str:
        if caps == _ALL_CAPS_SET:
            return ""

        return ",".join(
            cap._to_name()  # pylint: disable=protected-access
            for cap in sorted(caps, key=lambda cap: cap.value)
        )

    # These are the capabilities that need to be added.
    effective = set(effective)
    inheritable = set(inheritable)
    permitted = set(permitted)

    # These are the capabilities that need to be dropped (perhaps because we batch-added "extra"
    # capabilities, for example as in "=e cap_chown-e").
    drop_effective: Set[Cap] = set()
    drop_inheritable: Set[Cap] = set()
    drop_permitted: Set[Cap] = set()

    parts: List[str] = []

    def add_part(
        caps: Set[Cap],
        *,
        eff: bool = False,
        inh: bool = False,
        perm: bool = False,
        drop: bool = False
    ) -> None:
        if not caps:
            # Nothing to do!
            return

        # If we're pretty close to a full set, just use a full set.
        if not drop and caps != _ALL_CAPS_SET and len(_ALL_CAPS_SET - caps) <= 10:
            caps = _ALL_CAPS_SET

        if drop:
            prefix_ch = "-"
        elif not parts:
            # No previous values that the resetting behavior of "=" might mess up
            prefix_ch = "="
        else:
            prefix_ch = "+"

        parts.append(
            cap_set_to_text(caps)
            + prefix_ch
            + ("e" if eff else "")
            + ("i" if inh else "")
            + ("p" if perm else "")
        )

        if drop:
            # We just dropped these capabilities; we don't need to keep track of them any more
            if eff:
                drop_effective.difference_update(caps)
            if inh:
                drop_inheritable.difference_update(caps)
            if perm:
                drop_permitted.difference_update(caps)

        else:
            if eff:
                # If there were any capabilities in "caps" that aren't in "effective",
                # then those were extraneous and we need to remove them later.
                drop_effective.update(caps - effective)
                # All of the capabilities in "caps" have been added; we don't need to
                # keep track of them in "effective" any more.
                effective.difference_update(caps)
            if inh:
                drop_inheritable.update(caps - inheritable)
                inheritable.difference_update(caps)
            if perm:
                drop_permitted.update(caps - permitted)
                permitted.difference_update(caps)

    # First, add the ones that are common to all 3 sets.
    add_part(effective & inheritable & permitted, eff=True, inh=True, perm=True)

    # If we "overshot" by adding too many capabilities (for example, if all three sets had every
    # capability except CAP_CHOWN), then we need to drop the "extra" ones -- at least, the "extras"
    # that are common to all 3 sets.
    add_part(
        drop_effective & drop_inheritable & drop_permitted, eff=True, inh=True, perm=True, drop=True
    )

    # Now, go through and add the various combinations (cap_chown+ei, cap_chown+ep, etc.).
    add_part(effective & inheritable, eff=True, inh=True)
    add_part(effective & permitted, eff=True, perm=True)
    add_part(inheritable & permitted, inh=True, perm=True)

    # Again remove any "extras" that are common to 2 sets.
    add_part(drop_effective & drop_inheritable, eff=True, inh=True, drop=True)
    add_part(drop_effective & drop_permitted, eff=True, perm=True, drop=True)
    add_part(drop_inheritable & drop_permitted, inh=True, perm=True, drop=True)

    # Now add the remaining ones that are set-specific.
    add_part(effective, eff=True)
    add_part(inheritable, inh=True)
    add_part(permitted, perm=True)

    # Nothing should be left to add
    assert not effective
    assert not inheritable
    assert not permitted

    # Finally, drop the ones that are set-specific.
    add_part(drop_effective, eff=True, drop=True)
    add_part(drop_inheritable, inh=True, drop=True)
    add_part(drop_permitted, perm=True, drop=True)

    # And now nothing should be left to remove
    assert not drop_effective
    assert not drop_inheritable
    assert not drop_permitted

    return " ".join(parts)


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

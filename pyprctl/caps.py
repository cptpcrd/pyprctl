import contextlib
import ctypes
import dataclasses
import enum
import errno
import os
import re
import warnings
from typing import Callable, Iterable, Iterator, List, Optional, Set, Tuple, cast

from . import ffi
from .misc import get_keepcaps, set_keepcaps


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
    """
    An enum representing the different Linux capabilities.

    See capabilities(7) for more information on each capability.
    """

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

    @classmethod
    def from_name(cls, name: str) -> "Cap":
        """Look up a capability by name.

        Roughly equivalent to ``cap_from_name()`` in libcap. Names are matched case-insensitively,
        but they must include a ``cap_`` prefix (also case-insensitive; ``CAP_`` and ``Cap_`` are
        valid too).

        """

        upper_name = name.upper()

        if upper_name.startswith("CAP_"):
            try:
                return cast(Cap, getattr(cls, upper_name[4:]))
            except AttributeError:
                pass

        raise ValueError("Unknown capability {!r}".format(name))


_LAST_CAP = max(Cap, key=lambda cap: cap.value)  # type: ignore
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

    def __repr__(self) -> str:
        return "<{} capability set: {}>".format(self._name.title(), self)

    def __str__(self) -> str:
        return "=" + ",".join(
            "cap_" + cap.name.lower()
            for cap in sorted(self.probe(), key=lambda cap: cap.value)  # type: ignore
        )


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
    """
    Represents a thread's capability state (i.e. the effective, permitted and inheritable capability
    sets).
    """

    #: The effective capability set (used for permission checks)
    effective: Set[Cap] = dataclasses.field(default_factory=set)
    #: The permitted capability set. This is the bounding set for the thread's effective
    #: capabilities. It also limits which capabilities a thread that does not have CAP_SETPCAP can
    #: add to its inheritable set. See capabilities(7) for more details.
    permitted: Set[Cap] = dataclasses.field(default_factory=set)
    #: The inheritable capabilities set. This is preserved across ``exec()``. In addition, when
    #: ``exec()``-ing a program that has the corresponding capabilities in its inheritable set,
    #: these capabilities will be added to the permitted set. See capabilities(7) for more details.
    inheritable: Set[Cap] = dataclasses.field(default_factory=set)

    @classmethod
    def get_current(cls) -> "CapState":
        """
        Get the capability state of the current thread.
        """
        return cls.get_for_pid(0)

    @classmethod
    def get_for_pid(cls, pid: int) -> "CapState":
        """
        Get the capability state of the process (or thread) with the given PID (or TID).

        If ``pid`` is 0, this is equivalent to ``CapState.get_current()``.
        """

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
        """
        Set the capability state of the current thread to the capability set represented by this
        object.
        """

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

    def copy(self) -> "CapState":
        return CapState(
            effective=self.effective.copy(),
            permitted=self.permitted.copy(),
            inheritable=self.inheritable.copy(),
        )

    @classmethod
    def from_text(cls, text: str) -> "CapState":
        """
        Reconstruct a capability state from a textual representation. For example: ``=``, ``=p``,
        or ``cap_chown=ep``.
        """

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
        match = re.search(r"[-+=]", clause)
        if match is None:
            raise ValueError("Invalid capability set clause")

        cap_names = clause[: match.start()]
        action_spec = clause[match.start():]

        caps = (
            list(Cap)
            if cap_names.lower() in ("", "all")
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

    def cap_set_to_text(caps: Set[Cap], prefix_ch: str) -> str:
        if caps == _ALL_CAPS_SET:
            return "" if prefix_ch == "=" else "all"

        return ",".join(
            "cap_" + cap.name.lower()
            for cap in sorted(caps, key=lambda cap: cap.value)  # type: ignore
        )

    orig_effective = effective
    orig_inheritable = inheritable
    orig_permitted = permitted

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
        drop: bool = False,
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
            cap_set_to_text(caps, prefix_ch)
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
                # If there were any capabilities in "caps" that aren't in "orig_effective",
                # then those were extraneous and we need to remove them later.
                drop_effective.update(caps - orig_effective)
                # All of the capabilities in "caps" have been added; we don't need to
                # keep track of them in "effective" any more.
                effective.difference_update(caps)
            if inh:
                drop_inheritable.update(caps - orig_inheritable)
                inheritable.difference_update(caps)
            if perm:
                drop_permitted.update(caps - orig_permitted)
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
    """
    Represents the different securebits that can be used to change the kernel's handling of
    capabilities for UID 0.
    """

    #: If this bit is set, the kernel will not grant capabilities to set-user-ID-root programs, or
    #: to processes with an effective or real user ID of 0 on ``exec()``. See capabilities(7) for
    #: more details.
    NOROOT = 1 << 0
    #: "Locks" the NOROOT securebit so it cannot be changed.
    NOROOT_LOCKED = 1 << 1
    #: Stops the kernel from adjusting the process's permitted/effective/ambient capabilities when
    #: the process's effective and filesystem UIDs are switched between 0 and nonzero. See
    #: capabilities(7) for more details.
    NO_SETUID_FIXUP = 1 << 2
    #: "Locks" the NO_SETUID_FIXUP securebit so it cannot be changed.
    NO_SETUID_FIXUP_LOCKED = 1 << 3
    #: Provides the same functionality as :py:func:`get_keepcaps()` and :py:func:`set_keepcaps()`.
    #:
    #: Note that changes made with :py:func:`get_keepcaps()`/:py:func:`set_keepcaps()` are reflected
    #: in the value of this flag as returned by :py:func:`get_securebits()`, and vice versa. Since
    #: changing the securebits requires CAP_SETPCAP, it may be better to use those functions instead
    #: if this is the only securebit that you need to change.
    KEEP_CAPS = 1 << 4
    #: "Locks" the KEEP_CAPS securebit so it cannot be changed.
    #:
    #: Note: If the KEEP_CAPS securebit is set, even if it is "locked" using this flag, the kernel
    #: will still clear it on an ``exec()``. So this setting is only really useful to lock the
    #: KEEP_CAPS securebit as "off".
    KEEP_CAPS_LOCKED = 1 << 5
    #: Disables raising ambient capabilities (such as with :py:func:`cap_ambient_raise()`).
    NO_CAP_AMBIENT_RAISE = 1 << 6
    #: "Locks" the NO_CAP_AMBIENT_RAISE securebit so it cannot be changed.
    NO_CAP_AMBIENT_RAISE_LOCKED = 1 << 7


def get_securebits() -> Secbits:
    """
    Get the current secure bits.
    """
    return Secbits(ffi.prctl(ffi.PR_GET_SECUREBITS, 0, 0, 0, 0))


def set_securebits(secbits: Secbits) -> None:
    """
    Set the current secure bits.

    (This requires CAP_SETPCAP.)
    """
    ffi.prctl(ffi.PR_SET_SECUREBITS, secbits.value, 0, 0, 0)


class _SecurebitsAccessor:  # pylint: disable=too-few-public-methods
    def _make_property(  # type: ignore  # pylint: disable=no-self-argument
        secbit: Secbits,
    ) -> property:
        def getter(self: "_SecurebitsAccessor") -> bool:  # pylint: disable=unused-argument
            return bool(get_securebits() & secbit)

        def setter(
            self: "_SecurebitsAccessor", value: bool  # pylint: disable=unused-argument
        ) -> None:
            cur_secbits = get_securebits()

            if value:
                cur_secbits |= secbit
            else:
                cur_secbits &= ~secbit  # pylint: disable=invalid-unary-operand-type

            set_securebits(cur_secbits)

        return property(getter, setter)

    noroot = _make_property(Secbits.NOROOT)
    noroot_locked = _make_property(Secbits.NOROOT_LOCKED)
    no_setuid_fixup = _make_property(Secbits.NO_SETUID_FIXUP)
    no_setuid_fixup_locked = _make_property(Secbits.NO_SETUID_FIXUP_LOCKED)
    keep_caps = _make_property(Secbits.KEEP_CAPS)
    keep_caps_locked = _make_property(Secbits.KEEP_CAPS_LOCKED)
    no_cap_ambient_raise = _make_property(Secbits.NO_CAP_AMBIENT_RAISE)
    no_cap_ambient_raise_locked = _make_property(Secbits.NO_CAP_AMBIENT_RAISE_LOCKED)

    del _make_property

    _lock_map = {
        secbit: getattr(Secbits, secbit.name + "_LOCKED")
        for secbit in Secbits
        if not secbit.name.endswith("_LOCKED")
    }

    def __repr__(self) -> str:
        return "<Securebits: {}>".format(self)

    def __str__(self) -> str:
        cur_secbits = get_securebits()

        return ", ".join(
            "secure-{}: {} ({})".format(
                secbit.name.lower().replace("_", "-"),
                "yes" if secbit in cur_secbits else "no",
                "locked" if lock_secbit in cur_secbits else "unlocked",
            )
            for secbit, lock_secbit in self._lock_map.items()
        )


securebits = _SecurebitsAccessor()


def capbset_read(cap: Cap) -> Optional[bool]:
    """
    Check whether the given capability is present in the current thread's bounding capability set.

    This returns ``True`` if the capability is present, ``False`` if it is not, and ``None``
    if the kernel does not support this capability (may arise when using newer capabilities on older
    kernels).
    """

    try:
        return bool(ffi.prctl(ffi.PR_CAPBSET_READ, cap.value, 0, 0, 0))
    except OSError as ex:
        if ex.errno == errno.EINVAL:
            return None
        else:
            raise


def capbset_drop(cap: Cap) -> None:
    """
    Remove the given capability from the current thread's bounding capability set.

    (This requires the CAP_SETPCAP capability.)
    """
    ffi.prctl(ffi.PR_CAPBSET_DROP, cap.value, 0, 0, 0)


def capbset_probe() -> Set[Cap]:
    """
    "Probe" the current thread's bounding capability set and return a set of all the capabilities
    that are present in this thread's bounding capability set.
    """
    return set(filter(capbset_read, Cap))


def cap_ambient_raise(cap: Cap) -> None:
    """
    Raise the given capability in the current thread's ambient set.

    (The capability must already be present in the thread's permitted set and and the thread's
    inheritable set, and the SECBIT_NO_CAP_AMBIENT_RAISE securebit must not be set.)
    """
    ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_RAISE, cap.value, 0, 0)


def cap_ambient_lower(cap: Cap) -> None:
    """
    Lower the given capability in the current thread's ambient set.
    """
    ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_LOWER, cap.value, 0, 0)


def cap_ambient_clear_all() -> None:
    """
    Clear all ambient capabilities from the current thread.
    """
    ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)


def cap_ambient_is_set(cap: Cap) -> Optional[bool]:
    """
    Check whether the given capability is raised in the current thread's ambient capability set.

    This returns ``True`` if the capability is raised, ``False`` if it is lowered, and ``None``
    if the kernel does not support this capability (may arise when using newer capabilities on older
    kernels).
    """

    try:
        return bool(ffi.prctl(ffi.PR_CAP_AMBIENT, ffi.PR_CAP_AMBIENT_IS_SET, cap.value, 0, 0))
    except OSError as ex:
        if ex.errno == errno.EINVAL:
            return None
        else:
            raise


def cap_ambient_supported() -> bool:
    """
    Check whether the running kernel supports ambient capabilities.
    """
    return cap_ambient_is_set(Cap.CHOWN) is not None


def cap_ambient_probe() -> Set[Cap]:
    """
    "Probe" the current thread's ambient capability set and return a set of all the capabilities
    that are raised in this thread's ambient capability set.
    """
    return set(filter(cap_ambient_is_set, Cap))


def cap_set_ids(
    *,
    uid: Optional[int] = None,
    gid: Optional[int] = None,
    groups: Optional[Iterable[int]] = None,
    preserve_effective_caps: bool = False,
) -> None:
    """
    Set UID/GID/supplementary groups while preserving permitted capabilities.

    This combines the functionality of ``libcap``'s ``cap_setuid()`` and ``cap_setgroups()``, while
    also providing greater flexibility.

    Note: This function only operates on the current thread, not the process as a whole. This is
    because of the way Linux operates. If you call this function from a multithreaded program, you
    are responsible for synchronizing changes across threads to ensure proper security.

    This function performs the following actions in order. (Note: If ``gid`` is not ``None`` or
    ``groups`` is not ``None``, CAP_SETGID will first be raised in the thread's effective set, and
    if ``uid`` is not ``None`` then CAP_SETUID will be raised.)

    - If ``gid`` is not ``None``, the thread's real, effective and saved GIDs will be set to
      ``gid``.
    - If ``groups`` is not ``None``, the thread's supplementary group list will be set to
      ``groups``.
    - If ``uid`` is not ``None``, the thread's real, effective and saved UIDs will be set to
      ``uid``.
    - If ``preserve_effective_caps`` is ``True``, after this is done, the effective capability set
      will be restored to its original contents. By default, this function mimics ``libcap`` and
      empties the effective capability set before returning.

    Note: If an error occurs while this function is attempting to change the thread's
    UID/GID/supplementary groups, this function will still attempt to set the effective capability
    set as specified by ``preserve_effective_caps``. However, this may fail. Programs that plan on
    performing further actions if this function returns an error should first check the thread's
    capability set and ensure that the correct capabilities are raised/lowered.
    """

    # We do type checks up front to avoid errors in the middle of changing the UIDs/GIDs.

    if uid is not None and not isinstance(uid, int):
        raise TypeError("Invalid type {!r} for 'uid' argument".format(uid.__class__.__name__))

    if gid is not None and not isinstance(gid, int):
        raise TypeError("Invalid type {!r} for 'gid' argument".format(gid.__class__.__name__))

    if groups is not None:
        groups = list(groups)

        for supp_gid in groups:
            if not isinstance(supp_gid, int):
                raise TypeError(
                    "Invalid type {!r} for value in 'groups' list".format(
                        supp_gid.__class__.__name__
                    )
                )

    if uid is None and gid is None and groups is None:
        raise ValueError("One of 'uid', 'gid', or 'groups' must be passed")

    capstate = CapState.get_current()

    # Save the original effective capability set for future reference.
    orig_effective = capstate.effective.copy()

    # Add the correct capabilities
    if gid is not None or groups is not None:
        capstate.effective.add(Cap.SETGID)
    if uid is not None:
        capstate.effective.add(Cap.SETUID)

    # Don't call capset() if we already had those capabilities
    if capstate.effective != orig_effective:
        capstate.set_current()

    try:
        orig_keepcaps = get_keepcaps()
        set_keepcaps(True)

        try:
            # Now actually set the UIDs/GIDs

            if gid is not None:
                ffi.sys_setresgid(gid, gid, gid)

            if groups is not None:
                os.setgroups(groups)

            if uid is not None:
                ffi.sys_setresuid(uid, uid, uid)

        finally:
            set_keepcaps(orig_keepcaps)

    finally:
        # Set the effective capability set to the correct value
        capstate.effective = orig_effective if preserve_effective_caps else set()
        capstate.set_current()


@contextlib.contextmanager
def scoped_effective_caps(effective: Iterable[Cap]) -> Iterator[None]:
    """
    When used as a context manager, this function sets the effective capability set to contain only
    the specified capabilities, then restores it to its original contents after the body of the
    context manager has executed.

    For example::

        with scoped_effective_caps([Cap.CHOWN]):
            ...  # CAP_CHOWN is raised in the effective set; all other capabilites are lowered

    .. note::

        Changes made to the effective capability set in the body of the context manager will **not**
        be preserved. This function will still revert the effective capability set to its original
        contents when the body of the context manager finishes executing.

        However, changes made to any of the other 4 capability sets (permitted, inheritable,
        ambient, and bounding) in the body of the context manager *will* be preserved. (Be careful
        not to remove any of the capabilities present in the original effective set from the
        permitted set, or this function may fail to revert to the original effective set.)

    """

    effective = set(effective)

    capstate = CapState.get_current()
    orig_effective = capstate.effective.copy()

    if effective != orig_effective:
        # Swap in the new effective set if it's different
        capstate.effective = effective
        capstate.set_current()

    try:
        yield
    finally:
        # Replace the original effective set.
        # We re-retrieve the capability state because the code in the context manager might have
        # made other changes.
        capstate = CapState.get_current()
        capstate.effective = orig_effective
        capstate.set_current()

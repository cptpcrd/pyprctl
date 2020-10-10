import dataclasses
import os
import struct
from typing import Optional, Set, Union

from . import ffi
from .caps import (
    Cap,
    _capset_from_bitmask,
    _capset_to_bitmask,
    _capstate_from_text,
    _capstate_to_text,
    _split_bitmask_32,
)


@dataclasses.dataclass
class FileCaps:
    """
    Represents the capability sets attached to an executable file.
    """

    #: If this is ``True``, it indicates a "capability-dumb" binary. When this program is executed,
    #: all capabilities defined in the file's permitted set will also be copied to the thread's
    #: effective set.
    #:
    #: In addition, if a binary has this bit set, the kernel will refuse to launch it if the new
    #: process would not obtain the full set of capabilities specified in the permitted set. See
    #: capabilities(7) for more details.
    effective: bool
    #: The permitted set; automatically added to the thread's permitted set.
    permitted: Set[Cap]
    #: The inheritable set. This set is ANDed with the inheritable set of the launching program and
    #: the resulting capabilities are added to the thread's permitted set.
    inheritable: Set[Cap]
    #: For version 3 capability sets, this represents the root user ID of the user namespace in
    #: which the file capability extended attribute was created. See capabilities(7) for more
    #: details.
    rootid: Optional[int] = None

    @classmethod
    def _from_data(cls, data: bytes) -> "FileCaps":
        if len(data) < 4:
            raise ValueError("Capability data is too short")

        magic = struct.unpack("<I", data[:4])[0]

        version = magic & ffi.VFS_CAP_REVISION_MASK

        flags = magic & ffi.VFS_CAP_FLAGS_MASK
        effective = bool(flags & ffi.VFS_CAP_FLAGS_EFFECTIVE)

        rootid = None

        if version == ffi.VFS_CAP_REVISION_1 and len(data) == ffi.XATTR_CAPS_SZ_1:
            permitted = _capset_from_bitmask(struct.unpack("<I", data[4:8])[0])
            inheritable = _capset_from_bitmask(struct.unpack("<I", data[8:12])[0])
        elif version == ffi.VFS_CAP_REVISION_2 and len(data) == ffi.XATTR_CAPS_SZ_2:
            permitted = _capset_from_bitmask(struct.unpack("<Q", data[4:8] + data[12:16])[0])
            inheritable = _capset_from_bitmask(struct.unpack("<Q", data[8:12] + data[16:20])[0])
        elif version == ffi.VFS_CAP_REVISION_3 and len(data) == ffi.XATTR_CAPS_SZ_3:
            permitted = _capset_from_bitmask(struct.unpack("<Q", data[4:8] + data[12:16])[0])
            inheritable = _capset_from_bitmask(struct.unpack("<Q", data[8:12] + data[16:20])[0])
            rootid = struct.unpack("<I", data[20:24])[0]
        else:
            raise ValueError("Invalid capability version")

        return cls(
            effective=effective,
            permitted=permitted,
            inheritable=inheritable,
            rootid=rootid,
        )

    def _into_data(self) -> bytes:
        magic = ffi.VFS_CAP_FLAGS_EFFECTIVE if self.effective else 0

        permitted_upper, permitted_lower = _split_bitmask_32(_capset_to_bitmask(self.permitted))
        inheritable_upper, inheritable_lower = _split_bitmask_32(
            _capset_to_bitmask(self.inheritable)
        )

        if self.rootid is None:
            magic |= ffi.VFS_CAP_REVISION_2
            data = struct.pack(
                "<IIIII",
                magic,
                permitted_lower,
                inheritable_lower,
                permitted_upper,
                inheritable_upper,
            )
        else:
            magic |= ffi.VFS_CAP_REVISION_3
            data = struct.pack(
                "<IIIIII",
                magic,
                permitted_lower,
                inheritable_lower,
                permitted_upper,
                inheritable_upper,
                self.rootid,
            )

        return data

    def copy(self) -> "FileCaps":
        return FileCaps(
            effective=self.effective,
            permitted=self.permitted.copy(),
            inheritable=self.inheritable.copy(),
            rootid=self.rootid,
        )

    @classmethod
    def get_for_file(
        cls,
        path: Union[int, str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"],
        *,
        follow_symlinks: bool = True,
    ) -> "FileCaps":
        """
        Retrieves the file capabilities attached to the given file. ``path`` and ``follow_symlinks``
        are as for ``os.getxattr()``.
        """

        return cls._from_data(
            os.getxattr(path, ffi.XATTR_NAME_CAPS, follow_symlinks=follow_symlinks)
        )

    def set_for_file(
        self,
        path: Union[int, str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"],
        *,
        follow_symlinks: bool = True,
    ) -> None:
        """
        Sets the file capabilities attached to the given file to the state represented by this
        object. ``path`` and ``follow_symlinks`` are as for ``os.setxattr()``.
        """

        os.setxattr(path, ffi.XATTR_NAME_CAPS, self._into_data(), follow_symlinks=follow_symlinks)

    @classmethod
    def remove_for_file(
        cls,
        path: Union[int, str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"],
        *,
        follow_symlinks: bool = True,
    ) -> None:
        """
        Removes the file capabilities attached to the given file. ``path`` and ``follow_symlinks``
        are as for ``os.removexattr()``.
        """

        os.removexattr(path, ffi.XATTR_NAME_CAPS, follow_symlinks=follow_symlinks)

    @classmethod
    def from_text(cls, text: str) -> "FileCaps":
        """
        Reconstruct a set of file capabilities from a textual representation. For example:
        ``=``, ``=p``, or ``cap_chown=ep``.

        Note that this method will raise an error if the specified "effective" set is not empty
        and is also different from the "permitted" set. This is because Linux file capabilities
        only have a single bit for specifying the "effective" permissions, which indicates whether
        or not the permitted set should be copied to the effective set.
        """

        effective, inheritable, permitted = _capstate_from_text(text)

        if effective and effective != permitted:
            raise ValueError(
                "Cannot construct FileCaps with non-empty effective set that is not equal to "
                "permitted set"
            )

        return cls(
            effective=bool(effective), inheritable=inheritable, permitted=permitted, rootid=None
        )

    def __str__(self) -> str:
        return _capstate_to_text(
            effective=(self.permitted if self.effective else set()),
            inheritable=self.inheritable,
            permitted=self.permitted,
        )

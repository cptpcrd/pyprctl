import dataclasses
import os
import struct
from typing import Optional, Set, Union

from . import ffi
from .caps import Cap, _capset_from_bitmask, _capset_to_bitmask, _capstate_from_text


@dataclasses.dataclass
class FileCaps:
    effective: bool
    permitted: Set[Cap]
    inheritable: Set[Cap]
    rootid: Optional[int]

    @classmethod
    def _from_data(cls, data: bytes) -> "FileCaps":
        if len(data) < 4:
            raise ValueError("Capability data is too short")

        magic = struct.unpack("<I", data[:4])[0]

        effective = bool(magic & ffi.VFS_CAP_FLAGS_EFFECTIVE)
        version = (magic - ffi.VFS_CAP_FLAGS_EFFECTIVE) if effective else magic

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

        permitted = _capset_to_bitmask(self.permitted)
        inheritable = _capset_to_bitmask(self.inheritable)

        if self.rootid is None:
            magic |= ffi.VFS_CAP_REVISION_2
            data = struct.pack("<IQQ", magic, permitted, inheritable)
        else:
            magic |= ffi.VFS_CAP_REVISION_3
            data = struct.pack("<IQQI", magic, permitted, inheritable, self.rootid)

        return data

    @classmethod
    def get_for_file(
        cls,
        path: Union[int, str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"],
        follow_symlinks: bool = True,
    ) -> "FileCaps":
        return cls._from_data(
            os.getxattr(path, ffi.XATTR_NAME_CAPS, follow_symlinks=follow_symlinks)
        )

    def set_for_file(
        self,
        path: Union[int, str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"],
        follow_symlinks: bool = True,
    ) -> None:
        os.setxattr(path, ffi.XATTR_NAME_CAPS, self._into_data(), follow_symlinks=follow_symlinks)

    @classmethod
    def remove_for_file(
        cls,
        path: Union[int, str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"],
        follow_symlinks: bool = True,
    ) -> None:
        os.removexattr(path, ffi.XATTR_NAME_CAPS, follow_symlinks=follow_symlinks)
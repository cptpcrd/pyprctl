import contextlib
from typing import Callable, Iterator, TypeVar

T = TypeVar("T")


@contextlib.contextmanager
def restore_old_value(getter: Callable[[], T], setter: Callable[[T], None]) -> Iterator[None]:
    val = getter()
    try:
        yield
    finally:
        setter(val)

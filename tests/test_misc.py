import os
import signal
import subprocess
import sys
from typing import Any, Callable

import pytest

import pyprctl

from .util import restore_old_value


@restore_old_value(pyprctl.get_dumpable, pyprctl.set_dumpable)
def test_dumpable_toggle() -> None:
    pyprctl.set_dumpable(True)
    assert pyprctl.get_dumpable()

    pyprctl.set_dumpable(False)
    assert not pyprctl.get_dumpable()


@restore_old_value(pyprctl.get_child_subreaper, pyprctl.set_child_subreaper)
def test_child_subreaper_toggle() -> None:
    pyprctl.set_child_subreaper(True)
    assert pyprctl.get_child_subreaper()

    pyprctl.set_child_subreaper(False)
    assert not pyprctl.get_child_subreaper()


@restore_old_value(pyprctl.get_pdeathsig, pyprctl.set_pdeathsig)
def test_pdeathsig_toggle() -> None:
    pyprctl.set_pdeathsig(signal.SIGCHLD)
    assert pyprctl.get_pdeathsig() == signal.SIGCHLD

    pyprctl.set_pdeathsig(signal.SIGURG)
    assert pyprctl.get_pdeathsig() == signal.SIGURG

    pyprctl.set_pdeathsig(signal.SIGRTMIN + 1)
    assert pyprctl.get_pdeathsig() == signal.SIGRTMIN + 1

    pyprctl.set_pdeathsig(None)
    assert pyprctl.get_pdeathsig() is None


@restore_old_value(pyprctl.get_timerslack, pyprctl.set_timerslack)
def test_timerslack_toggle() -> None:
    pyprctl.set_timerslack(0)
    # 0 means the "default" value
    timerslack = pyprctl.get_timerslack()
    assert timerslack != 0
    with open("/proc/self/timerslack_ns") as file:
        assert int(file.readline().strip()) == timerslack

    pyprctl.set_timerslack(50)
    assert pyprctl.get_timerslack() == 50
    with open("/proc/self/timerslack_ns") as file:
        assert int(file.readline().strip()) == 50


@restore_old_value(pyprctl.get_mce_kill, pyprctl.set_mce_kill)
def test_mce_kill_toggle() -> None:
    pyprctl.set_mce_kill(pyprctl.MCEKillPolicy.EARLY)
    assert pyprctl.get_mce_kill() == pyprctl.MCEKillPolicy.EARLY

    pyprctl.set_mce_kill(pyprctl.MCEKillPolicy.LATE)
    assert pyprctl.get_mce_kill() == pyprctl.MCEKillPolicy.LATE

    pyprctl.set_mce_kill(pyprctl.MCEKillPolicy.DEFAULT)
    assert pyprctl.get_mce_kill() == pyprctl.MCEKillPolicy.DEFAULT


@restore_old_value(pyprctl.get_timing, pyprctl.set_timing)
def test_timing_toggle() -> None:
    pyprctl.set_timing(pyprctl.TimingMethod.STATISTICAL)
    assert pyprctl.get_timing() == pyprctl.TimingMethod.STATISTICAL

    with pytest.raises(OSError, match="Invalid argument"):
        pyprctl.set_timing(pyprctl.TimingMethod.TIMESTAMP)


def test_seccomp_mode_strict() -> None:
    if hasattr(sys, "pypy_version_info"):
        pytest.skip("Fails on PyPy for unknown reasons")

    def do_test(callback: Callable[[], Any], res: int) -> None:
        pid = os.fork()
        if pid == 0:
            pyprctl.set_seccomp_mode_strict()
            callback()
            pyprctl._sys_exit(0)  # pylint: disable=protected-access

        _, wstatus = os.waitpid(pid, 0)
        assert res == (
            -os.WTERMSIG(wstatus) if os.WIFSIGNALED(wstatus) else os.WEXITSTATUS(wstatus)
        )

    # Sanity check
    do_test(lambda: None, 0)

    # We can read() and write() data
    r_fd, w_fd = os.pipe()
    do_test(lambda: [os.write(w_fd, b"a"), os.read(r_fd, 1)], 0)

    # But nothing else
    do_test(os.getpid, -signal.SIGKILL)


@restore_old_value(pyprctl.get_child_subreaper, pyprctl.set_child_subreaper)
def test_subreaper_pdeathsig_child() -> None:
    # This tests the behavior of both set_child_subreaper() and set_pdeathsig().
    # We call set_child_subreaper(True), then launch a child process. That child
    # launches another child (the grandchild). The grandchild calls set_pdeathsig(SIGTERM),
    # then the child exit()s.
    # We wait for the child to exit.
    # Now, because we called set_pdeathsig() in the grandchild, it will get SIGTERM'd.
    # Because we called set_child_subreaper(True), it will get reparented to us. So we can
    # wait() for it and check that it was in fact SIGTERM'd.

    pyprctl.set_child_subreaper(True)

    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import subprocess, sys

proc = subprocess.Popen(
    [
        sys.executable,
        "-c",
        '''
import signal, time, pyprctl
pyprctl.set_pdeathsig(signal.SIGTERM)

# Tell the parent we're ready
print(flush=True)
time.sleep(10)
''',
    ],
    stdout=subprocess.PIPE,
)

# Wait for it to set the death signal
proc.stdout.read(1)

print(proc.pid)
""",
        ],
        stdout=subprocess.PIPE,
    ) as proc:
        stdout, _ = proc.communicate()

    pid = int(stdout.strip())

    _, wstatus = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(wstatus)
    assert os.WTERMSIG(wstatus) == signal.SIGTERM

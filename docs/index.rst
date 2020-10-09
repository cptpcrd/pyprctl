Welcome to pyprctl's documentation!
===================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

``pyprctl`` provides an interface to Linux's ``prctl()`` system call, and to Linux capabilities in general, that is written in pure Python with no external dependencies. (You don't even need to have ``libcap`` installed!)

This library and portions of its API were inspired by ``python-prctl``, but it is not a fork.

Important security note!
========================

On Linux, credentials (real/effective/saved UIDs, real/effective/saved GIDs, supplementary groups, and all of the capability sets) are **per-thread** attributes. If you change these attributes in one thread, other threads in the same process are unaffected. This can lead to `security issues <https://ewontfix.com/17/>`_.

To try to mitigate this, glibc and musl make clever use of realtime signals to synchronize changes made to the real/effective/saved UIDs/GIDs across all threads. libcap offers "libpsx", which enables similar synchronization of capability changes.

``pyprctl``, however, makes **no attempt** to synchronize any changes it makes to a thread's UIDs/GIDs/capabilities. In fact, when changing UIDs/GIDs it deliberately works around glibc/musl's UID/GID synchronization. If you use ``pyprctl``'s capability manipulation functions in multithreaded programs, you are responsible for synchronizing any changes across threads (if this is necessary to properly secure your application).

(Note: ``python-prctl`` doesn't link against libpsx, so it behaves the same way! It just doesn't document this.)

Platform support
================

Architecture support
--------------------

``pyprctl`` should work on at least the following architectures (both 32-bit and 64-bit versions): x86, ARM, RISC-V, SPARC, and PowerPC. However, it has only been tested on x86_64 and 32-bit ARM.

musl libc
---------

``pyprctl`` *should* work on systems using musl libc. It's been tested on Alpine Linux and on the musl-based distribution of Void Linux.

Statically linked systems
-------------------------

``pyprctl`` *might* work on statically linked systems, but this has not been tested.

API documentation
=================

.. automodule:: pyprctl
   :members:
   :private-members: _sys_exit
   :undoc-members:
   :show-inheritance:

Capability set objects
======================

.. note::
   This interface is designed after ``python-prctl``'s interface.

.. note::
   This interface makes it easier to manipulate the permitted/inheritable/effective sets than using :py:class:`CapState`.
   However, for "bulk" operations (for example, clearing both the permitted and effective sets), this interface, by design, may result in significantly more syscalls than using :py:class:`CapState` would, since it has to get and then set the full capability state every time something is changed.

   If efficiency is important for your application, make sure to take this into account.

In addition to :py:class:`CapState` and the ambient/bounding set manipulation functions, ``pyprctl`` provides five objects that provide alternate ways of interacting with the capability sets:

.. py:attribute:: cap_permitted

   The permitted capability set.

.. py:attribute:: cap_inheritable

   The inheritable capability set.

.. py:attribute:: cap_effective

   The effective capability set.

.. py:attribute:: cap_ambient

   The ambient capability set.

.. py:attribute:: capbset

   The bounding capability set.

These set objects have boolean properties corresponding to each of the capabilities listed for :py:class:`Cap` (except with lowercase names, for example ``chown``, ``sys_chroot``, etc.). Accessing any of these properties will check whether that capability is present in the given set, assigning ``True`` to any of these properties will raise them in the given set (if possible), and assigning ``False`` to any of these properties will lower them in the given set.

The sets also have a few helper methods:

.. py:method:: set.drop(\*caps)

   Drop all the given capabilities from this set.

.. py:method:: set.add(\*caps)

   Raise all the given capabilities in this set. (This raises a :py:class:`ValueError` for the ``capbset`` object.)

.. py:method:: set.limit(\*caps)

   Drop all capabilities except the given ones from this set.

.. py:method:: set.clear()

   Remove all capabilities from this set. This is equivalent to ``set.limit()`` (i.e. with no arguments), but it is easier to understand.

.. py:method:: set.has(\*caps)

   Return ``True`` if the set contains all of the given capabilities, and ``False`` if it does not.

Similarly, ``pyprctl`` provides a ``securebits`` object with read/write properties that provide an alternate method of access to the secure bits. This object has a boolean property corresponding to each of the securebits listed for :py:class:`Secbits` (with lowercase names, for example ``noroot`` and ``keep_caps``).

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

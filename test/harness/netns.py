"""Open sockets inside a network namespace from the test process."""

import contextlib
import os
import socket

from . import topology


@contextlib.contextmanager
def entered(host):
    """Switch this thread into the network namespace of host for the duration of the block.
    Sockets created inside the block stay in that namespace after leaving it."""
    own = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
    target = os.open("/run/netns/" + topology.ns(host), os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        yield
    finally:
        os.setns(own, os.CLONE_NEWNET)
        os.close(target)
        os.close(own)


def connect(host, addr, port, timeout=5.0):
    with entered(host):
        return socket.create_connection((addr, port), timeout=timeout)

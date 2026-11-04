"""Locations of the binaries under test (override with environment variables)."""

import glob
import os

GK_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _find(env, pattern):
    if os.environ.get(env):
        return os.environ[env]
    matches = sorted(glob.glob(os.path.join(GK_DIR, pattern)))
    return matches[0] if matches else os.path.join(GK_DIR, pattern)


GNUGK = _find("GKTEST_GNUGK", "obj_*_s/gnugk")
ADDPASSWD = _find("GKTEST_ADDPASSWD", "addpasswd/obj_*_s/addpasswd")
ENDPOINT = _find("GKTEST_ENDPOINT", "test/endpoint/obj_*_s/gktestep")

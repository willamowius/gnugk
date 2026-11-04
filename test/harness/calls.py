"""Helpers to run calls between test endpoints."""

import time


def run_call(gk, caller, call, callee=None, duration=3, callee_duration=None, timeout=10, callee_timeout=10):
    """Start callee (if given, waiting for its registration unless it doesn't use a gatekeeper),
    then let caller call `call`. Returns (caller result, callee result or None)."""
    if callee is not None:
        callee.start(duration=callee_duration or duration + 25, timeout=callee_timeout)
    try:
        if callee is not None and not callee.no_gk:
            assert gk.wait_registered(callee.alias.split(",")[0]), "%s didn't register" % callee.alias
        caller.start(call=call, duration=duration, timeout=timeout)
        caller_result = caller.wait()
        callee_result = callee.wait() if callee is not None else None
    finally:
        caller.kill()
        if callee is not None:
            callee.kill()
    time.sleep(0.3)	# let GnuGk finish the call cleanup
    return caller_result, callee_result

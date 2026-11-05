"""Many calls in a row: GnuGk must not leak memory, file descriptors or threads."""

import json
import time

from harness.endpoint import Endpoint

CALLS = 100


def run_calls(gk, workdir, name, count):
    callee = Endpoint(workdir, "pub2", "callee", name="callee-" + name).start(duration=count * 4 + 30, calls=count)
    caller = Endpoint(workdir, "pub1", "caller", name="caller-" + name)
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=1, calls=count)
        caller_result, callee_result = caller.wait(timeout=count * 5 + 60), callee.wait()
    finally:
        caller.kill()
        callee.kill()
    return caller_result, callee_result


def settled_resources(gk):
    time.sleep(12)	# GnuGk deletes closed sockets a few seconds after the call
    return gk.resources()


def test_soak_100_calls(start_gk, workdir):
    """100 calls one after the other (after 5 warm-up calls): all connect with media and get a CDR, and GnuGk's
    file descriptors, threads (each at most +10) and memory (at most +20 MB) stay flat"""
    gk = start_gk()
    run_calls(gk, workdir, "warmup", 5)
    before = settled_resources(gk)
    caller, callee = run_calls(gk, workdir, "soak", CALLS)
    after = settled_resources(gk)
    with open(workdir + "/resources.json", "w") as f:
        json.dump({"before": before, "after": after}, f, indent=2)

    assert caller["callsConnected"] == CALLS, "%d of %d calls connected" % (caller["callsConnected"], CALLS)
    assert callee["callsConnected"] == CALLS, callee["callsConnected"]
    broken = [c for c in caller["calls"] if c["rtpReceived"] < 20]
    assert not broken, "calls without media: %s" % broken
    assert len(gk.cdrs()) == CALLS + 5
    assert gk.number_of_calls() == 0
    assert after["fds"] - before["fds"] <= 10, "file descriptors leaked: %s -> %s" % (before, after)
    assert after["threads"] - before["threads"] <= 10, "threads leaked: %s -> %s" % (before, after)
    assert after["rss_kb"] - before["rss_kb"] <= 20 * 1024, "memory grew: %s -> %s" % (before, after)

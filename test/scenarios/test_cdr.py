"""Call detail records: which calls get one on the status port, FileAcct formats, timestamps and rotation."""

import glob
import os
import re
import time

import pytest

from harness import topology
from harness.calls import run_call
from harness.gnugk import StatusSession
from harness.endpoint import Endpoint

from scenarios.test_multi_gk import neighbor


def status_events(gk_host, make_calls, wait=1.5):
    """everything a status port session of the GnuGk on gk_host gets while make_calls() runs"""
    session = StatusSession(gk=gk_host)
    try:
        session.read_for(0.3)
        make_calls()
        return session.read_for(wait)
    finally:
        session.close()


@pytest.mark.parametrize("generate,expected", [("0", 1), ("1", 2)], ids=["default", "GenerateUCCDR"])
def test_unconnected_call_cdr(start_gk, workdir, generate, expected):
    """[CallTable] GenerateUCCDR: a call the callee refuses only gets a CDR on the status port with
    GenerateUCCDR=1 (duration 0), an answered call always gets one; FileAcct writes both in any case"""
    gk = start_gk({"CallTable": {"GenerateUCCDR": generate}})

    def calls():
        refused, _ = run_call(gk, Endpoint(workdir, "pub1", "caller", name="caller-refused"), "busy",
                              callee=Endpoint(workdir, "pub2", "busy", reject="busy"), callee_duration=8)
        assert not refused["connected"], refused
        answered, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                               callee=Endpoint(workdir, "pub2", "callee"), duration=2)
        assert answered["connected"], answered

    events = status_events("gk", calls)
    cdrs = [line.split("|") for line in events.splitlines() if line.startswith("CDR|")]
    assert len(cdrs) == expected, events
    assert int(cdrs[-1][3]) >= 1, "the answered call's CDR has no duration: %s" % cdrs[-1]
    if expected == 2:
        assert cdrs[0][3] == "0", "the refused call's CDR has a duration: %s" % cdrs[0]
    assert len(gk.cdrs()) == 2, gk.cdrs()


@pytest.mark.parametrize("generate,expected", [("1", 1), ("0", 0)], ids=["default", "GenerateNBCDR-off"])
def test_neighbor_call_cdr(start_gk, workdir, generate, expected):
    """[CallTable] GenerateNBCDR: the gatekeeper of the callee only shows the CDR of a call from a neighbor zone
    on its status port with GenerateNBCDR=1 (the default), with empty caller IP and endpoint ID; FileAcct
    gets the call in both cases"""
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, neighbor("GK2", topology.HOST_IPS["gk2"]))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}, "CallTable": {"GenerateNBCDR": generate}},
                   neighbor("GK1", topology.GK_IP), host="gk2", name="gk2")

    def calls():
        caller, callee = run_call(gk2, Endpoint(workdir, "pub1", "alice", gk="gk"), "bob",
                                  callee=Endpoint(workdir, "pub2", "bob", gk="gk2"), duration=2)
        assert caller["connected"] and callee["connected"], caller

    events = status_events("gk2", calls)
    cdrs = [line.split("|") for line in events.splitlines() if line.startswith("CDR|")]
    assert len(cdrs) == expected, events
    if cdrs:
        # CDR|n|call id|duration|start|end|caller ip:port|caller epid|callee ip:port|callee epid|dest|src|gk;
        assert cdrs[0][7].strip() == "", "caller endpoint ID should be empty for a neighbor call: %s" % cdrs[0]
        assert cdrs[0][8].startswith(topology.HOST_IPS["pub2"]), cdrs[0]
    assert len(gk2.cdrs()) == 1 and len(gk1.cdrs()) == 1, (gk1.cdrs(), gk2.cdrs())


ZONE = r"([+-]\d{4}|[A-Z]+)"	# UTC is written as GMT or Z
RFC822 = r"[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d " + ZONE


def test_standard_cdr_format(start_gk, workdir):
    """[FileAcct] StandardCDRFormat=1: the file gets the same line as the status port,
    CDR|n|call id|duration|start|end|caller ip:port|caller epid|callee ip:port|callee epid|dest|src|gk; with
    RFC822 timestamps"""
    gk = start_gk({"FileAcct": {"StandardCDRFormat": "1", "CDRString": None}})
    events = status_events("gk", lambda: run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                                                  callee=Endpoint(workdir, "pub2", "callee"), duration=2))
    lines = [line.strip() for line in open(gk.cdr_file) if line.strip()]
    assert len(lines) == 1, lines
    assert lines[0].endswith(";"), lines[0]
    fields = lines[0].rstrip(";").split("|")
    assert len(fields) == 13 and fields[0] == "CDR", fields
    assert re.fullmatch(r"([0-9a-f]{2}[ -]){15}[0-9a-f]{2}", fields[2]), "call id: %r" % fields[2]
    assert 1 <= int(fields[3]) <= 4, "duration: %r" % fields[3]
    assert re.fullmatch(RFC822, fields[4]) and re.fullmatch(RFC822, fields[5]), fields[4:6]
    assert fields[6].startswith(topology.HOST_IPS["pub1"] + ":") and fields[7].endswith("_endp"), fields[6:8]
    assert fields[8].startswith(topology.HOST_IPS["pub2"] + ":") and fields[9].endswith("_endp"), fields[8:10]
    assert "callee:h323_ID" in fields[10] and "caller:h323_ID" in fields[11], fields[10:12]
    assert fields[12] == "GnuGkTest", fields[12]
    status_line = [line.strip() for line in events.splitlines() if line.startswith("CDR|")]
    assert status_line == lines, "the status port shows another CDR than the file: %s" % status_line


TIMESTAMPS = {
    "RFC822": RFC822,
    "ISO8601": r"\d{4}-\d\d-\d\d T \d\d:\d\d:\d\d " + ZONE,
    "Cisco": r"\d\d:\d\d:\d\d\.\d{3} \S+ [A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{4}",
    "MySQL": r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d",
}


@pytest.mark.parametrize("section", ["FileAcct", "Gatekeeper::Main"])
@pytest.mark.parametrize("name", list(TIMESTAMPS))
def test_cdr_timestamp_format(start_gk, workdir, name, section):
    """TimestampFormat in [FileAcct], or as the global default in [Gatekeeper::Main]: the connect and disconnect
    times of a custom CDRString are written in that format"""
    gk = start_gk({"FileAcct": {"CDRString": "%{connect-time}|%{disconnect-time}|%d"}},
                  {section: {"TimestampFormat": name}})
    run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee", callee=Endpoint(workdir, "pub2", "callee"), duration=1)
    lines = [line.strip() for line in open(gk.cdr_file) if line.strip()]
    assert len(lines) == 1, lines
    connect, disconnect, duration = lines[0].split("|")
    assert re.fullmatch(TIMESTAMPS[name], connect), "connect-time %r isn't %s" % (connect, name)
    assert re.fullmatch(TIMESTAMPS[name], disconnect), "disconnect-time %r isn't %s" % (disconnect, name)


def test_cdr_file_rotation(start_gk, workdir):
    """[FileAcct] Rotate=L2: after every 2 CDRs the file is renamed to <name>.YYYYMMDD-HHMMSS and a new one
    started, no CDR is lost"""
    gk = start_gk({"FileAcct": {"Rotate": "L2"}})
    callee = Endpoint(workdir, "pub2", "callee").start(duration=40, calls=5)
    try:
        assert gk.wait_registered("callee")
        caller = Endpoint(workdir, "pub1", "caller").start(call="callee", duration=1, calls=5).wait()
    finally:
        callee.kill()
    assert caller["callsConnected"] == 5, caller
    time.sleep(1)
    rotated = sorted(glob.glob(gk.cdr_file + ".*"))
    assert len(rotated) == 2, "expected 2 rotated files after 5 CDRs: %s" % os.listdir(workdir)
    for name in rotated:
        assert re.fullmatch(r"\d{8}-\d{6}(-\d+)?", name[len(gk.cdr_file) + 1:]), name
        assert len([line for line in open(name) if line.strip()]) == 2, name
    assert len(gk.cdrs()) == 1, "the current file should have the 5th CDR: %s" % gk.cdrs()

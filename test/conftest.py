import inspect
import os
import re
import shutil
import textwrap
import subprocess
import time

import pytest

from harness import gnugk, topology
from harness.paths import ADDPASSWD, ENDPOINT, GNUGK

RESULTS = os.environ.get("GKTEST_RESULTS", os.path.join(os.path.dirname(__file__), "results"))


def pytest_addoption(parser):
    parser.addoption("--describe", action="store_true",
                     help="with -v: show what each test checks below its result (--collect-only always shows it)")


def describe(item):
    """what a test checks: its docstring, plus a description of its parameters if the module has
    describe_params(params)"""
    text = inspect.getdoc(getattr(item, "function", None)) or ""
    text = " ".join(text.split())
    params = getattr(getattr(item, "callspec", None), "params", None)
    describe_params = getattr(getattr(item, "module", None), "describe_params", None)
    if params and describe_params:
        extra = describe_params(params)
        if extra:
            text = (text + " [" + extra + "]") if text else extra
    return text


_config = []


@pytest.hookimpl(trylast=True)	# after the terminal reporter is registered
def pytest_configure(config):
    _config.append(config)
    if not config.getoption("collectonly"):
        return
    reporter = config.pluginmanager.getplugin("terminalreporter")
    if reporter is None:
        return
    def print_items(items):
        # --collect-only: each test ID with its description below it
        for item in items:
            reporter.write_line(item.nodeid)
            for line in textwrap.wrap(describe(item), 100):
                reporter.write_line("    " + line)
    reporter._printcollecteditems = print_items


_descriptions = {}


def pytest_collection_modifyitems(config, items):
    for item in items:
        _descriptions[item.nodeid] = describe(item)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    text = _descriptions.get(item.nodeid)
    if text and report.when == "call":
        report.sections.append(("what this test checks", text))	# shown in the failure report


@pytest.hookimpl(trylast=True)
def pytest_runtest_logreport(report):
    # with --describe and -v: the description below each result line
    config = _config[0] if _config else None
    if config is None or not config.getoption("describe") or config.option.verbose <= 0 or report.when != "teardown":
        return
    reporter = config.pluginmanager.getplugin("terminalreporter")
    text = _descriptions.get(report.nodeid)
    if reporter and text:
        reporter.ensure_newline()
        for line in textwrap.wrap(text, 100):
            reporter.write_line("    " + line)


def pytest_sessionstart(session):
    if session.config.option.collectonly:
        return	# only listing the tests, needs no root and no binaries
    if os.geteuid() != 0:
        pytest.exit("the GnuGk test harness needs root to create network namespaces", returncode=2)
    for binary in (GNUGK, ENDPOINT, ADDPASSWD):
        if not os.access(binary, os.X_OK):
            pytest.exit("missing %s - run test/build-deps.sh first" % binary, returncode=2)
    if shutil.which("ip") is None:
        pytest.exit("the 'ip' command (iproute2) is missing", returncode=2)


@pytest.fixture(scope="session")
def network():
    topology.setup()
    yield
    if not os.environ.get("GKTEST_KEEP_NETNS"):
        topology.teardown()


@pytest.fixture(autouse=True)
def clean_namespaces(request):
    """after every test (set up first, so torn down last): kill whatever still runs in the test namespaces,
    so no GnuGk, endpoint or tcpdump of one test holds ports in the next one"""
    yield
    if "network" not in request.fixturenames:
        return
    killed = topology.kill_leftovers()
    if killed:
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.name)
        path = os.path.join(RESULTS, name)
        if os.path.isdir(path):
            with open(os.path.join(path, "leftover-processes.txt"), "w") as f:
                for ns_name, pid, cmd in killed:
                    f.write("%s %d %s\n" % (ns_name, pid, cmd))


@pytest.fixture
def workdir(request):
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.name)
    path = os.path.join(RESULTS, name)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    return path


@pytest.fixture
def capture(network, workdir):
    """pcap of everything the gatekeeper host sees, kept in the test's result directory"""
    if shutil.which("tcpdump") is None:
        yield None
        return
    pcap = os.path.join(workdir, "gk.pcap")
    log = os.path.join(workdir, "tcpdump.log")
    # -Z root: don't switch to the tcpdump user, it may not be allowed to write into the result directory
    with open(log, "w") as log_file:
        proc = subprocess.Popen(["ip", "netns", "exec", topology.ns("gk"),
                                 "tcpdump", "-Z", "root", "-i", "eth0", "-U", "-w", pcap],
                                stdout=subprocess.DEVNULL, stderr=log_file)
    time.sleep(0.5)	# let tcpdump open the interface
    if proc.poll() is not None or not os.path.exists(pcap):
        proc.kill()
        proc.wait()
        with open(log) as f:
            pytest.fail("tcpdump didn't start (tests that check the pcap would fail), see %s:\n%s" % (log, f.read()))
    yield pcap
    proc.terminate()
    proc.wait()


@pytest.fixture
def start_gk(network, workdir, capture):
    """start_gk(config_overrides..., users={alias: password}, host="gk", name="gnugk", trace=None) -> running GnuGk,
    stopped after the test.
    The test fails if GnuGk died while it ran."""
    started = []

    def start(*overrides, users=None, host="gk", name="gnugk", trace=None):
        gk = gnugk.GnuGk(workdir, gnugk.merge_config(*overrides), users=users, host=host, name=name, trace=trace)
        started.append(gk)	# before start(): stopped after the test even if start() fails
        return gk.start()

    yield start
    for gk in started:
        if gk.proc is None:
            continue
        crashed = not gk.alive() and not gk.stopped	# a test may have stopped it itself
        gk.stop()
        if crashed:
            pytest.fail("gnugk exited during the test (code %s), see %s" % (gk.proc.returncode, gk.stdout_file))

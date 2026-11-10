"""Send fake RTP from a host to the RTP proxy ports GnuGk has open (RTP bleed / injection tests)."""

import socket
import struct
import threading
import time

from . import netns, topology


def proxy_ports(gk_host="gk", low=40000, high=41999):
    """the UDP ports in [low, high] GnuGk listens on right now"""
    ports = set()
    for line in topology.sockets(gk_host).splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 5 and fields[0] == "udp":
            port = fields[4].rsplit(":", 1)[-1]
            if port.isdigit() and low <= int(port) <= high:
                ports.add(int(port))
    return ports


class RtpSprayer:
    """from host, send an RTP packet (G.711 payload, own SSRC) every interval seconds to every RTP proxy port of the
    GnuGk on gk_host, and count what comes back; runs in a thread until stop()"""

    SSRC = 0x0BADF00D

    def __init__(self, host, gk_host="gk", interval=0.02, low=40000, high=41999):
        self.host, self.gk_host, self.interval, self.low, self.high = host, gk_host, interval, low, high
        self.sent = 0
        self.received = 0	# packets GnuGk sent back to us (media of the call = RTP bleed)
        self.ports = set()
        with netns.entered(host):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((topology.HOST_IPS[host], 0))
        self.sock.setblocking(False)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _run(self):
        seq, next_scan = 0, 0
        gk_ip = topology.HOST_IPS[self.gk_host]
        while not self._stop.is_set():
            if time.time() >= next_scan:
                self.ports |= proxy_ports(self.gk_host, self.low, self.high)
                next_scan = time.time() + 0.2
            seq = (seq + 1) & 0xffff
            packet = struct.pack("!BBHII", 0x80, 0, seq, seq * 160, self.SSRC) + b"\xff" * 160
            for port in sorted(self.ports):
                try:
                    self.sock.sendto(packet, (gk_ip, port))
                    self.sent += 1
                except OSError:
                    pass
            try:
                while True:
                    self.sock.recvfrom(2048)
                    self.received += 1
            except (BlockingIOError, OSError):
                pass
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()
        self._thread.join(5)
        self.sock.close()
        return self

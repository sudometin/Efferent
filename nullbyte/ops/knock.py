"""Port knocking: the SSH port stays closed (invisible to scanners) until the right sequence of TCP SYNs arrives.
The knock comes from the gateway's IP, which is exactly where the SSH connection will come from next.

Server side (knockd):
  [openSSH]
    sequence    = 7000,8000,9000
    seq_timeout = 10
    tcpflags    = syn
    command     = /usr/sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    cmd_timeout = 60
    stop_command = /usr/sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
"""
from __future__ import annotations

import asyncio


def parse(seq: str) -> list[int]:
    ports = []
    for part in (seq or "").replace(" ", "").split(","):
        if part.isdigit() and 0 < int(part) < 65536:
            ports.append(int(part))
    return ports[:8]


async def knock(host: str, ports: list[int], gap: float = 0.25) -> int:
    """Fire one SYN per port (a refused/filtered connect is expected: the SYN itself is the knock)."""
    sent = 0
    for p in ports:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=0.6)
            w.close()
        except (OSError, asyncio.TimeoutError):
            pass
        sent += 1
        await asyncio.sleep(gap)
    await asyncio.sleep(0.4)        # give knockd time to open the door
    return sent


def knockd_snippet(ports: list[int], ssh_port: int = 22) -> str:
    seq = ",".join(map(str, ports)) or "7000,8000,9000"
    return (f"[openSSH]\n  sequence    = {seq}\n  seq_timeout = 10\n  tcpflags    = syn\n"
            f"  command     = /usr/sbin/iptables -I INPUT -s %IP% -p tcp --dport {ssh_port} -j ACCEPT\n"
            f"  cmd_timeout = 60\n"
            f"  stop_command = /usr/sbin/iptables -D INPUT -s %IP% -p tcp --dport {ssh_port} -j ACCEPT")

"""SSH certificate authority.

Servers trust the CA once (TrustedUserCAKeys in sshd_config). After that nobody needs passwords or long-lived
keys: the gateway mints a fresh key + certificate for every session, valid for minutes. Friends get grants whose
certificates expire on their own. The CA private key never leaves the bot's data dir, and can be split with
Shamir among guardians for break-glass recovery.
"""
from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

import asyncssh

CLOCK_SKEW = 120          # backdate certs a little: servers with slightly-off clocks still accept them


class CA:
    def __init__(self, path: Path, passphrase: str = ""):
        self.path = Path(path)
        self.passphrase = passphrase or None
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            key = asyncssh.generate_private_key("ssh-ed25519", comment="nullbyte-ops-ca")
            key.write_private_key(str(self.path), passphrase=self.passphrase)
            os.chmod(self.path, 0o600)
        self.key = asyncssh.read_private_key(str(self.path), self.passphrase)

    # ------------------------------------------------------------------ public side
    @property
    def public_line(self) -> str:
        return self.key.export_public_key("openssh").decode().strip()

    @property
    def fingerprint(self) -> str:
        return self.key.get_fingerprint("sha256")

    def install_snippet(self) -> str:
        """Commands to paste on a server so it trusts this CA."""
        return (
            f"echo '{self.public_line}' | sudo tee /etc/ssh/nullbyte_ca.pub\n"
            "echo 'TrustedUserCAKeys /etc/ssh/nullbyte_ca.pub' | sudo tee -a /etc/ssh/sshd_config\n"
            "sudo systemctl reload ssh || sudo systemctl reload sshd"
        )

    # ------------------------------------------------------------------ issuing
    def sign(self, public_key: asyncssh.SSHKey, principals: list[str], ttl: float, key_id: str,
             force_command: str | None = None, source_address: list[str] | None = None,
             port_forwarding: bool = False) -> asyncssh.SSHCertificate:
        now = int(time.time())
        return self.key.generate_user_certificate(
            public_key, key_id, serial=secrets.randbits(63), principals=principals,
            valid_after=now - CLOCK_SKEW, valid_before=now + int(ttl),
            force_command=force_command, source_address=source_address,
            permit_x11_forwarding=False, permit_agent_forwarding=False, permit_port_forwarding=port_forwarding,
            comment=key_id)

    def ephemeral(self, principal: str, ttl: float, key_id: str, force_command: str | None = None,
                  port_forwarding: bool = False) -> tuple[asyncssh.SSHKey, asyncssh.SSHCertificate]:
        """Throwaway keypair + cert for one gateway session. Lives only in memory."""
        k = asyncssh.generate_private_key("ssh-ed25519")
        return k, self.sign(k, [principal], ttl, key_id, force_command, port_forwarding=port_forwarding)

    def sign_openssh_pubkey(self, pubkey_line: str, principal: str, ttl: float, key_id: str) -> str:
        """For friends who bring their own key: returns the -cert.pub contents to save next to it."""
        pub = asyncssh.import_public_key(pubkey_line.strip())
        cert = self.sign(pub, [principal], ttl, key_id)
        return cert.export_certificate("openssh").decode().strip()

    # ------------------------------------------------------------------ break-glass
    def export_private(self) -> bytes:
        return self.key.export_private_key("openssh")

    @staticmethod
    def restore(path: Path, private_bytes: bytes, passphrase: str = "") -> "CA":
        key = asyncssh.import_private_key(private_bytes)
        key.write_private_key(str(path), passphrase=passphrase or None)
        os.chmod(path, 0o600)
        return CA(path, passphrase)

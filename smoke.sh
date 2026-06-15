#!/bin/bash
# Smoke test for moat. Starts the daemon, probes each service, exercises the
# rate limiter, then shuts down and prints the telemetry.
set -u
cd /home/claude
rm -f /tmp/moat.log

# Start fully detached so no fd is shared with the parent shell.
./moat -p 2222:ssh -p 8080:http -p 2323:telnet -p 9000:generic \
       -o /tmp/moat.log -u nobody </dev/null >/tmp/moat.err 2>&1 &
PID=$!
sleep 0.6

echo "### process identity"
grep '^Uid' /proc/$PID/status 2>/dev/null || echo "process not running"
echo

probe() {  # host port  payload  read_banner
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import socket, sys
host, port, payload, readb = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
s = socket.socket(); s.settimeout(1.5)
try:
    s.connect((host, port))
    banner = b""
    if readb == "1":
        try: banner = s.recv(256)
        except Exception: pass
    if payload:
        s.sendall(payload.encode())
    resp = b""
    try: resp = s.recv(256)
    except Exception: pass
    if banner: print(f"  [{port}] banner: {banner[:60]!r}")
    if resp:   print(f"  [{port}] resp:   {resp[:60]!r}")
finally:
    s.close()
PY
}

echo "### service probes"
probe 127.0.0.1 2222 "admin\r\n" 1          # ssh: expect banner
probe 127.0.0.1 2323 "root\r\n"  1          # telnet: expect login prompt
probe 127.0.0.1 8080 $'GET /admin HTTP/1.1\r\nHost: x\r\n\r\n' 0   # http: expect 401
probe 127.0.0.1 9000 "ATTACK_PAYLOAD_DEADBEEF" 0                  # generic: silent capture
echo

echo "### rate-limit storm (60 rapid connects from one source)"
python3 - <<'PY'
import socket
ok=0
for i in range(60):
    try:
        s=socket.socket(); s.settimeout(0.5); s.connect(("127.0.0.1",9000))
        s.close(); ok+=1
    except Exception:
        pass
print(f"  completed {ok}/60 connect attempts")
PY
echo

sleep 1.2   # let one stats/sweep tick fire
kill -TERM $PID 2>/dev/null
wait $PID 2>/dev/null

echo "### stderr from daemon"
cat /tmp/moat.err
echo
echo "### telemetry (JSON-Lines)"
cat /tmp/moat.log

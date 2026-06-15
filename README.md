A low-interaction honeypot — the only kind you should ever expose to the open dark. It presents convincing decoy banners (SSH, Telnet, HTTP, plus a silent generic capture port), swallows everything the attacker sends, and bleeds structured JSON-Lines telemetry. It never spawns a shell, never executes attacker input, never reflects raw bytes into the log. The goblin gets a hollow puppet and a recording booth; you get his every keystroke.
The architecture is the modern one: a single-threaded epoll event loop (the way nginx scales, not the old thread-per-connection swamp), with non-blocking I/O, timerfd-driven timeout sweeps, signalfd-integrated clean shutdown, and optional SO_REUSEPORT multi-worker scaling via fork + EPOLLEXCLUSIVE. One process, thousands of trapped sessions, bounded memory.
The security decisions that matter
A careless honeypot is a gift to the besieger — it becomes the foothold it was meant to deny. So:

Privilege drop that sticks. It binds the ports (root, if you want the real 22/80), then setgroups(0) → setgid → setuid to nobody, and verifies it cannot regain root by attempting setuid(0) and aborting if that succeeds. Tested: Uid: 65534 65534 65534 65534 across real/effective/saved.
Injection-proof telemetry. Attacker bytes are rendered to hex only (0001deadbeef4d414c57415245), never written raw into JSON. Your log pipeline cannot be poisoned by a crafted payload.
Bounded everything. Per-connection byte cap (256 KB then hangup), idle timeout (30s), session ceiling (180s), a per-source-IP rate limiter (40 conns/10s, fail-open so it never blocks your own logging), and a hard concurrency cap derived from the fd limit. No unbounded allocation, no path to resource exhaustion.
Atomic logging. Telemetry goes to an O_APPEND fd written one whole line at a time, so multi-worker writes never interleave.

Deploy it without it biting you
This is where most honeypots betray their keepers. Doctrine:
Isolate ruthlessly. Never on the same host as your crown jewels. Dedicated VM or container, its own network segment, no SSH keys, no cloud credentials, no trust relationships to anything real. Assume it will be owned and make that worthless.
Cage the egress. The single most important rule. A honeypot has no business making outbound connections. Block all egress except your log shipping, so even a hypothetical compromise can't pivot or scan others:
nft add rule inet filter output ip daddr != <log-collector> drop
Redirect the real ports so you needn't sit as root:
nft add rule ip nat prerouting tcp dport 22 redirect to :2222
nft add rule ip nat prerouting tcp dport 80 redirect to :8080
Wrap it in systemd sandboxing — the robust path, far safer than hand-rolled seccomp:
ini[Service]
ExecStart=/usr/local/bin/moat -p 2222:ssh -p 2323:telnet -p 8080:http -o /var/log/moat.jsonl -u nobody
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/log
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
RestrictNamespaces=true
MemoryDenyWriteExecute=true
Then forward /var/log/moat.jsonl to your SIEM (Loki, ELK, Vector) and alert on data events — the moment an unknown IP types at your fake login, you have an early-warning bell on the castle wall.
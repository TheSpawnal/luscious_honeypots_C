/*
 * moat - a low-interaction honeypot daemon.
 *
 * Listens on a set of TCP ports, presents decoy service banners, captures
 * every byte an attacker sends, and emits structured JSON-Lines telemetry.
 * It never executes a shell, never reflects attacker bytes into the log
 * unescaped (hex only), and drops privileges after binding.
 *
 * Design:
 *   - Single-threaded epoll event loop (level-triggered, non-blocking I/O).
 *   - Optional SO_REUSEPORT-style multi-worker scaling via fork + EPOLLEXCLUSIVE.
 *   - timerfd drives idle/session timeout sweeps and periodic stats.
 *   - signalfd integrates SIGINT/SIGTERM into the loop for clean shutdown.
 *   - Per-source-IP rate limiting (bounded hash table, fail-open).
 *   - Bounded reads, bounded log lines, no unbounded allocation.
 *
 * Build:  see Makefile (strict warnings + hardening flags).
 * Usage:  ./moat -h
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1u << 28)
#endif

/* ---- tunables ---------------------------------------------------------- */
#define MAX_LISTENERS       16
#define READ_BUF            4096
#define HEX_SAMPLE_BYTES    256          /* bytes per data event rendered to hex */
#define MAX_BYTES_PER_CONN  (256 * 1024) /* hang up after this much input */
#define IDLE_TIMEOUT_MS     30000
#define MAX_SESSION_MS      180000
#define RL_BUCKETS          8192
#define RL_WINDOW_MS        10000
#define RL_MAX_PER_WINDOW   40
#define RL_PROBE            8
#define STATS_INTERVAL_S    60
#define FD_HEADROOM         32           /* reserve fds for log, epoll, etc. */
#define LOGLINE_MAX         2048

/* ---- service profiles -------------------------------------------------- */
typedef struct {
    const char *name;
    const char *banner;       /* sent on connect; NULL = stay silent */
    bool        http;         /* respond to first request, then close */
} profile_t;

static const profile_t PROFILES[] = {
    { "ssh",
      "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", false },
    { "telnet",
      "\r\nUbuntu 22.04.4 LTS\r\nlogin: ", false },
    { "http",
      NULL, true },
    { "generic",
      NULL, false },
};
static const size_t N_PROFILES = sizeof(PROFILES) / sizeof(PROFILES[0]);

static const char *HTTP_RESPONSE =
    "HTTP/1.1 401 Unauthorized\r\n"
    "Server: Apache/2.4.52 (Ubuntu)\r\n"
    "WWW-Authenticate: Basic realm=\"Restricted\"\r\n"
    "Content-Length: 0\r\n"
    "Connection: close\r\n\r\n";

/* ---- connection state -------------------------------------------------- */
typedef struct {
    int             fd;
    char            src_ip[INET6_ADDRSTRLEN];
    uint16_t        src_port;
    uint16_t        dst_port;
    const profile_t *prof;
    uint64_t        session_id;
    uint64_t        start_mono;
    uint64_t        last_mono;
    size_t          bytes_in;
    bool            http_done;
} conn_t;

/* ---- rate-limit table -------------------------------------------------- */
typedef struct {
    char     ip[INET6_ADDRSTRLEN];
    uint64_t window_start;
    uint32_t count;
    bool     used;
} rl_entry_t;

/* ---- per-worker context ------------------------------------------------ */
typedef struct {
    int         epfd;
    int         timerfd;
    int         sigfd;
    int         log_fd;
    int         maxfd;
    conn_t    **conns;          /* indexed by fd */
    rl_entry_t *rl;
    int         n_listeners;
    int         listeners[MAX_LISTENERS];
    const profile_t *listener_prof[MAX_LISTENERS];
    uint16_t    listener_port[MAX_LISTENERS];
    uint64_t    next_session;
    int         active;
    int         max_active;
    /* stats */
    uint64_t    s_accept, s_close, s_bytes, s_rl, s_cap;
    uint64_t    last_stats_mono;
    volatile sig_atomic_t running;
} ctx_t;

/* ---- time helpers ------------------------------------------------------ */
static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void iso_now(char *buf, size_t n)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    size_t k = strftime(buf, n, "%Y-%m-%dT%H:%M:%S", &tm);
    if (k && k + 6 < n)
        snprintf(buf + k, n - k, ".%03ldZ", ts.tv_nsec / 1000000L);
}

/* ---- low-level I/O helpers --------------------------------------------- */
static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;          /* EAGAIN on a blocking log fd is unexpected */
        }
        off += (size_t)w;
    }
    return (ssize_t)off;
}

/* best-effort write to a non-blocking client socket; -1 only on hard error */
static int send_best_effort(int fd, const char *s, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, s + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; /* drop rest */
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static void bytes_to_hex(char *dst, const unsigned char *src, size_t n)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = H[src[i] >> 4];
        dst[2 * i + 1] = H[src[i] & 0x0f];
    }
    dst[2 * n] = '\0';
}

/* ---- telemetry --------------------------------------------------------- */
/* All emitted strings are program-controlled (profile names, inet_ntop IPs,
 * numbers, hex). No attacker-controlled bytes are ever written unescaped. */

static void emit(ctx_t *c, const char *line, size_t len)
{
    (void)write_all(c->log_fd, line, len); /* one append-mode write per line */
}

static void emit_listen(ctx_t *c, uint16_t port, const profile_t *p)
{
    char ts[40], buf[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    int n = snprintf(buf, sizeof buf,
        "{\"ts\":\"%s\",\"event\":\"listen\",\"port\":%u,\"service\":\"%s\",\"pid\":%d}\n",
        ts, port, p->name, (int)getpid());
    if (n > 0) emit(c, buf, (size_t)n);
}

static void emit_accept(ctx_t *c, const conn_t *k)
{
    char ts[40], buf[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    int n = snprintf(buf, sizeof buf,
        "{\"ts\":\"%s\",\"event\":\"accept\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"src_port\":%u,\"dst_port\":%u,\"service\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, k->src_port,
        k->dst_port, k->prof->name);
    if (n > 0) emit(c, buf, (size_t)n);
}

static void emit_data(ctx_t *c, const conn_t *k, const char *hex,
                      size_t batch, size_t total)
{
    char ts[40], buf[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    int n = snprintf(buf, sizeof buf,
        "{\"ts\":\"%s\",\"event\":\"data\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"dst_port\":%u,\"service\":\"%s\",\"batch_bytes\":%zu,"
        "\"total_bytes\":%zu,\"data_hex\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, k->dst_port,
        k->prof->name, batch, total, hex);
    if (n > 0) emit(c, buf, (size_t)n);
}

static void emit_close(ctx_t *c, const conn_t *k, const char *reason)
{
    char ts[40], buf[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    uint64_t dur = mono_ms() - k->start_mono;
    int n = snprintf(buf, sizeof buf,
        "{\"ts\":\"%s\",\"event\":\"close\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"dst_port\":%u,\"service\":\"%s\",\"total_bytes\":%zu,"
        "\"duration_ms\":%llu,\"reason\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, k->dst_port,
        k->prof->name, k->bytes_in, (unsigned long long)dur, reason);
    if (n > 0) emit(c, buf, (size_t)n);
}

static void emit_reject(ctx_t *c, const char *ip, uint16_t port,
                        const char *reason)
{
    char ts[40], buf[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    int n = snprintf(buf, sizeof buf,
        "{\"ts\":\"%s\",\"event\":\"reject\",\"src_ip\":\"%s\",\"dst_port\":%u,"
        "\"reason\":\"%s\"}\n", ts, ip, port, reason);
    if (n > 0) emit(c, buf, (size_t)n);
}

static void emit_stats(ctx_t *c)
{
    char ts[40], buf[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    int n = snprintf(buf, sizeof buf,
        "{\"ts\":\"%s\",\"event\":\"stats\",\"pid\":%d,\"active\":%d,"
        "\"accepts\":%llu,\"closes\":%llu,\"bytes\":%llu,"
        "\"rejected_ratelimit\":%llu,\"rejected_capacity\":%llu}\n",
        ts, (int)getpid(), c->active,
        (unsigned long long)c->s_accept, (unsigned long long)c->s_close,
        (unsigned long long)c->s_bytes, (unsigned long long)c->s_rl,
        (unsigned long long)c->s_cap);
    if (n > 0) emit(c, buf, (size_t)n);
}

/* ---- rate limiting ----------------------------------------------------- */
static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

/* returns true if the connection should be ALLOWED */
static bool rl_admit(ctx_t *c, const char *ip, uint64_t now)
{
    uint32_t idx = fnv1a(ip) & (RL_BUCKETS - 1);
    for (int i = 0; i < RL_PROBE; i++) {
        rl_entry_t *e = &c->rl[(idx + (uint32_t)i) & (RL_BUCKETS - 1)];
        if (e->used && strcmp(e->ip, ip) == 0) {
            if (now - e->window_start > RL_WINDOW_MS) {
                e->window_start = now;
                e->count = 1;
                return true;
            }
            if (e->count >= RL_MAX_PER_WINDOW) return false;
            e->count++;
            return true;
        }
        if (!e->used || now - e->window_start > RL_WINDOW_MS) {
            e->used = true;
            snprintf(e->ip, sizeof e->ip, "%s", ip);
            e->window_start = now;
            e->count = 1;
            return true;
        }
    }
    return true; /* table congested: fail open, never block legitimate logging */
}

/* ---- connection lifecycle ---------------------------------------------- */
static void conn_close(ctx_t *c, conn_t *k, const char *reason)
{
    emit_close(c, k, reason);
    epoll_ctl(c->epfd, EPOLL_CTL_DEL, k->fd, NULL);
    close(k->fd);
    c->conns[k->fd] = NULL;
    c->active--;
    c->s_close++;
    free(k);
}

static void handle_readable(ctx_t *c, conn_t *k)
{
    unsigned char buf[READ_BUF];
    char hex[2 * HEX_SAMPLE_BYTES + 1];

    for (;;) {
        ssize_t r = read(k->fd, buf, sizeof buf);
        if (r > 0) {
            size_t got = (size_t)r;
            k->bytes_in += got;
            k->last_mono = mono_ms();
            c->s_bytes += got;

            size_t hn = got < HEX_SAMPLE_BYTES ? got : HEX_SAMPLE_BYTES;
            bytes_to_hex(hex, buf, hn);
            emit_data(c, k, hex, got, k->bytes_in);

            if (k->prof->http && !k->http_done) {
                k->http_done = true;
                if (send_best_effort(k->fd, HTTP_RESPONSE,
                                     strlen(HTTP_RESPONSE)) < 0) {
                    conn_close(c, k, "write_error");
                    return;
                }
                conn_close(c, k, "http_served");
                return;
            }
            if (k->bytes_in >= MAX_BYTES_PER_CONN) {
                conn_close(c, k, "byte_cap");
                return;
            }
            continue;
        }
        if (r == 0) {
            conn_close(c, k, "peer_closed");
            return;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return; /* drained */
        conn_close(c, k, "read_error");
        return;
    }
}

static void handle_accept(ctx_t *c, int lfd, uint16_t dst_port,
                          const profile_t *prof)
{
    for (;;) {
        struct sockaddr_in6 sa;
        socklen_t sl = sizeof sa;
        int fd = accept4(lfd, (struct sockaddr *)&sa, &sl,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EMFILE || errno == ENFILE) return; /* fd pressure */
            return;
        }

        char ip[INET6_ADDRSTRLEN] = "?";
        uint16_t sport = 0;
        if (sa.sin6_family == AF_INET6) {
            inet_ntop(AF_INET6, &sa.sin6_addr, ip, sizeof ip);
            sport = ntohs(sa.sin6_port);
            /* unwrap IPv4-mapped addresses for clean logging */
            if (strncmp(ip, "::ffff:", 7) == 0)
                memmove(ip, ip + 7, strlen(ip + 7) + 1);
        } else if (sa.sin6_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
            sport = ntohs(s4->sin_port);
        }

        uint64_t now = mono_ms();
        if (!rl_admit(c, ip, now)) {
            c->s_rl++;
            emit_reject(c, ip, dst_port, "rate_limit");
            close(fd);
            continue;
        }
        if (c->active >= c->max_active || fd >= c->maxfd) {
            c->s_cap++;
            emit_reject(c, ip, dst_port, "capacity");
            close(fd);
            continue;
        }

        conn_t *k = calloc(1, sizeof *k);
        if (!k) { close(fd); continue; }
        k->fd = fd;
        snprintf(k->src_ip, sizeof k->src_ip, "%s", ip);
        k->src_port = sport;
        k->dst_port = dst_port;
        k->prof = prof;
        k->session_id = ++c->next_session;
        k->start_mono = now;
        k->last_mono = now;

        struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
        if (epoll_ctl(c->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            close(fd);
            free(k);
            continue;
        }
        c->conns[fd] = k;
        c->active++;
        c->s_accept++;
        emit_accept(c, k);

        if (k->prof->banner) {
            if (send_best_effort(fd, k->prof->banner,
                                 strlen(k->prof->banner)) < 0) {
                conn_close(c, k, "write_error");
                continue;
            }
        }
    }
}

/* ---- timeout sweep ----------------------------------------------------- */
static void sweep_timeouts(ctx_t *c)
{
    uint64_t now = mono_ms();
    for (int fd = 0; fd < c->maxfd; fd++) {
        conn_t *k = c->conns[fd];
        if (!k) continue;
        if (now - k->last_mono > IDLE_TIMEOUT_MS) {
            conn_close(c, k, "idle_timeout");
        } else if (now - k->start_mono > MAX_SESSION_MS) {
            conn_close(c, k, "session_timeout");
        }
    }
    if (now - c->last_stats_mono > (uint64_t)STATS_INTERVAL_S * 1000u) {
        c->last_stats_mono = now;
        emit_stats(c);
    }
}

/* ---- listener setup ---------------------------------------------------- */
static int make_listener(uint16_t port, bool reuseport)
{
    /* Prefer a dual-stack IPv6 socket; fall back to IPv4 where IPv6 is
     * unavailable (common on hardened or minimal hosts). */
    int family = AF_INET6;
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        family = AF_INET;
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }
    if (fd < 0) {
        fprintf(stderr, "moat: socket port %u: %s\n", port, strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (reuseport)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);

    int rc;
    if (family == AF_INET6) {
        int zero = 0; /* dual-stack: accept both IPv4 and IPv6 */
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = in6addr_any;
        sa.sin6_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&sa, sizeof sa);
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&sa, sizeof sa);
    }
    if (rc < 0) {
        fprintf(stderr, "moat: bind port %u: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) < 0) {
        fprintf(stderr, "moat: listen port %u: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- privilege drop ---------------------------------------------------- */
static int drop_privileges(const char *user)
{
    if (geteuid() != 0) return 0;  /* nothing to drop */
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        fprintf(stderr, "moat: unknown user '%s'\n", user);
        return -1;
    }
    if (setgroups(0, NULL) != 0 ||
        setgid(pw->pw_gid) != 0 ||
        setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "moat: privilege drop failed: %s\n", strerror(errno));
        return -1;
    }
    if (setuid(0) == 0) {        /* must NOT be able to regain root */
        fprintf(stderr, "moat: privilege drop did not stick\n");
        return -1;
    }
    return 0;
}

/* ---- worker event loop ------------------------------------------------- */
static int run_worker(int log_fd, int maxfd, int max_active,
                      int n_listeners, const int *lfds,
                      const uint16_t *lports, const profile_t *const *lprofs,
                      bool exclusive)
{
    ctx_t c;
    memset(&c, 0, sizeof c);
    c.log_fd = log_fd;
    c.maxfd = maxfd;
    c.max_active = max_active;
    c.running = 1;
    c.last_stats_mono = mono_ms();

    c.conns = calloc((size_t)maxfd, sizeof(conn_t *));
    c.rl = calloc(RL_BUCKETS, sizeof(rl_entry_t));
    if (!c.conns || !c.rl) { perror("calloc"); return 1; }

    c.epfd = epoll_create1(EPOLL_CLOEXEC);
    if (c.epfd < 0) { perror("epoll_create1"); return 1; }

    c.n_listeners = n_listeners;
    for (int i = 0; i < n_listeners; i++) {
        c.listeners[i] = lfds[i];
        c.listener_port[i] = lports[i];
        c.listener_prof[i] = lprofs[i];
        struct epoll_event ev;
        ev.events = EPOLLIN | (exclusive ? EPOLLEXCLUSIVE : 0u);
        ev.data.fd = lfds[i];
        if (epoll_ctl(c.epfd, EPOLL_CTL_ADD, lfds[i], &ev) < 0) {
            perror("epoll_ctl listener");
            return 1;
        }
        emit_listen(&c, lports[i], lprofs[i]);
    }

    /* timerfd: 1s periodic */
    c.timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec its = {
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
        .it_value    = { .tv_sec = 1, .tv_nsec = 0 },
    };
    timerfd_settime(c.timerfd, 0, &its, NULL);
    struct epoll_event tev = { .events = EPOLLIN, .data.fd = c.timerfd };
    epoll_ctl(c.epfd, EPOLL_CTL_ADD, c.timerfd, &tev);

    /* signalfd: SIGINT/SIGTERM (already blocked in caller) */
    sigset_t sm;
    sigemptyset(&sm);
    sigaddset(&sm, SIGINT);
    sigaddset(&sm, SIGTERM);
    c.sigfd = signalfd(-1, &sm, SFD_NONBLOCK | SFD_CLOEXEC);
    struct epoll_event sev = { .events = EPOLLIN, .data.fd = c.sigfd };
    epoll_ctl(c.epfd, EPOLL_CTL_ADD, c.sigfd, &sev);

    struct epoll_event events[256];
    while (c.running) {
        int n = epoll_wait(c.epfd, events, 256, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == c.timerfd) {
                uint64_t exp;
                while (read(c.timerfd, &exp, sizeof exp) > 0) { }
                sweep_timeouts(&c);
                continue;
            }
            if (fd == c.sigfd) {
                struct signalfd_siginfo si;
                while (read(c.sigfd, &si, sizeof si) > 0) { }
                c.running = 0;
                continue;
            }

            /* listener? */
            bool is_listener = false;
            for (int j = 0; j < c.n_listeners; j++) {
                if (fd == c.listeners[j]) {
                    handle_accept(&c, fd, c.listener_port[j],
                                  c.listener_prof[j]);
                    is_listener = true;
                    break;
                }
            }
            if (is_listener) continue;

            /* established connection */
            conn_t *k = (fd < c.maxfd) ? c.conns[fd] : NULL;
            if (!k) continue;
            if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                conn_close(&c, k, "hangup");
                continue;
            }
            if (events[i].events & EPOLLIN)
                handle_readable(&c, k);
        }
    }

    /* drain remaining connections */
    for (int fd = 0; fd < c.maxfd; fd++)
        if (c.conns[fd]) conn_close(&c, c.conns[fd], "shutdown");
    emit_stats(&c);

    close(c.epfd);
    close(c.timerfd);
    close(c.sigfd);
    free(c.conns);
    free(c.rl);
    return 0;
}

/* ---- supervisor for multi-worker mode ---------------------------------- */
static volatile sig_atomic_t sup_stop = 0;
static void sup_handler(int sig) { (void)sig; sup_stop = 1; }

/* ---- arg parsing / main ------------------------------------------------ */
static const profile_t *find_profile(const char *name)
{
    for (size_t i = 0; i < N_PROFILES; i++)
        if (strcmp(PROFILES[i].name, name) == 0) return &PROFILES[i];
    return NULL;
}

static void usage(const char *p)
{
    fprintf(stderr,
"Usage: %s [options]\n"
"  -p PORT[:PROFILE]  add a listener (repeatable). PROFILE in {ssh,telnet,http,generic}\n"
"                     default profile is 'generic'\n"
"  -o FILE            telemetry output file (append, JSON-Lines). default stdout\n"
"  -u USER            user to drop to after binding (default: nobody)\n"
"  -m N               max concurrent connections (default: derived from rlimit)\n"
"  -w N               worker processes (default: 1)\n"
"  -h                 this help\n"
"\nIf no -p is given, defaults to 2222:ssh 2323:telnet 8080:http 9000:generic\n",
        p);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    uint16_t ports[MAX_LISTENERS];
    const profile_t *profs[MAX_LISTENERS];
    int n_listeners = 0;
    const char *logpath = NULL;
    const char *user = "nobody";
    int workers = 1;
    long cli_max = 0;

    int opt;
    while ((opt = getopt(argc, argv, "p:o:u:m:w:h")) != -1) {
        switch (opt) {
        case 'p': {
            if (n_listeners >= MAX_LISTENERS) {
                fprintf(stderr, "moat: too many listeners\n"); return 2;
            }
            char *colon = strchr(optarg, ':');
            const profile_t *pr;
            long port;
            if (colon) {
                *colon = '\0';
                pr = find_profile(colon + 1);
                if (!pr) { fprintf(stderr, "moat: bad profile '%s'\n",
                                   colon + 1); return 2; }
            } else {
                pr = find_profile("generic");
            }
            port = strtol(optarg, NULL, 10);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "moat: bad port '%s'\n", optarg); return 2;
            }
            ports[n_listeners] = (uint16_t)port;
            profs[n_listeners] = pr;
            n_listeners++;
            break;
        }
        case 'o': logpath = optarg; break;
        case 'u': user = optarg; break;
        case 'm': cli_max = strtol(optarg, NULL, 10); break;
        case 'w': workers = (int)strtol(optarg, NULL, 10); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    if (n_listeners == 0) {
        struct { uint16_t port; const char *prof; } def[] = {
            { 2222, "ssh" }, { 2323, "telnet" }, { 8080, "http" },
            { 9000, "generic" },
        };
        for (size_t i = 0; i < sizeof def / sizeof def[0]; i++) {
            ports[n_listeners] = def[i].port;
            profs[n_listeners] = find_profile(def[i].prof);
            n_listeners++;
        }
    }
    if (workers < 1) workers = 1;
    if (workers > 64) workers = 64;

    /* raise fd limit toward the hard cap */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    int maxfd = 65536;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < (rlim_t)maxfd)
        maxfd = (int)rl.rlim_cur;
    int max_active = maxfd - FD_HEADROOM;
    if (cli_max > 0 && cli_max < max_active) max_active = (int)cli_max;
    if (max_active < 1) max_active = 1;

    /* telemetry sink: raw append-mode fd so multi-worker writes stay atomic */
    int log_fd = STDOUT_FILENO;
    if (logpath) {
        log_fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
        if (log_fd < 0) {
            fprintf(stderr, "moat: open '%s': %s\n", logpath,
                    strerror(errno));
            return 1;
        }
    }

    /* bind listeners while we may still hold privilege for low ports */
    bool exclusive = workers > 1;
    int lfds[MAX_LISTENERS];
    for (int i = 0; i < n_listeners; i++) {
        lfds[i] = make_listener(ports[i], exclusive);
        if (lfds[i] < 0) {
            for (int j = 0; j < i; j++) close(lfds[j]);
            return 1;
        }
    }

    if (drop_privileges(user) != 0) return 1;

    /* block shutdown signals so signalfd in each worker receives them */
    sigset_t bm;
    sigemptyset(&bm);
    sigaddset(&bm, SIGINT);
    sigaddset(&bm, SIGTERM);
    sigprocmask(SIG_BLOCK, &bm, NULL);

    if (workers == 1) {
        return run_worker(log_fd, maxfd, max_active, n_listeners,
                          lfds, ports, profs, false);
    }

    /* multi-worker: fork children, supervise from parent */
    pid_t kids[64];
    int nkids = 0;
    for (int i = 0; i < workers; i++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); break; }
        if (pid == 0) {
            return run_worker(log_fd, maxfd, max_active, n_listeners,
                              lfds, ports, profs, true);
        }
        kids[nkids++] = pid;
    }

    /* parent: unblock signals, forward shutdown to the worker group */
    sigprocmask(SIG_UNBLOCK, &bm, NULL);
    struct sigaction sa = { 0 };
    sa.sa_handler = sup_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (!sup_stop) {
        int status;
        pid_t done = waitpid(-1, &status, 0);
        if (done > 0) {
            bool any = false;
            for (int i = 0; i < nkids; i++)
                if (kids[i] == done) kids[i] = -1;
            for (int i = 0; i < nkids; i++) if (kids[i] > 0) any = true;
            if (!any) break;
        } else if (errno == EINTR) {
            break;
        } else {
            break;
        }
    }
    for (int i = 0; i < nkids; i++)
        if (kids[i] > 0) kill(kids[i], SIGTERM);
    for (int i = 0; i < nkids; i++)
        if (kids[i] > 0) waitpid(kids[i], NULL, 0);

    return 0;
}

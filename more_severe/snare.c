/*
 * snare - a medium-interaction trap-shell honeypot.
 *
 * Presents a convincing fake Linux login and root shell. It NEVER executes
 * anything an attacker types; it returns canned responses to keep them
 * engaged while it records every credential, command, and indicator of
 * compromise, and writes the full raw session bytestream to an inert
 * quarantine file for later offline reverse engineering.
 *
 * Safety posture:
 *   - No command is ever executed. The "shell" is a logging puppet.
 *   - Captured bytes are stored hex-safe in telemetry and as inert files
 *     (mode 0400, no exec bit, O_NOFOLLOW, size-capped).
 *   - Privileges are dropped after binding; quarantine dir is pre-created
 *     and chowned to the drop user before the drop.
 *   - Per-IP rate limiting, idle/session timeouts, bounded everything.
 *
 * This is a DEFENSIVE collector. Carry captured samples to an isolated,
 * network-segmented lab before any dynamic analysis. Never detonate here.
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
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1u << 28)
#endif

/* ---- tunables ---------------------------------------------------------- */
#define MAX_LISTENERS      16
#define READ_BUF           4096
#define LINE_MAX           1024
#define USER_MAX           64
#define HEX_SAMPLE_BYTES   128
#define CAP_MAX_BYTES      (1024 * 1024)   /* per-session quarantine cap */
#define MAX_COMMANDS       300
#define IDLE_TIMEOUT_MS    60000
#define MAX_SESSION_MS     300000
#define RL_BUCKETS         8192
#define RL_WINDOW_MS       10000
#define RL_MAX_PER_WINDOW  40
#define RL_PROBE           8
#define STATS_INTERVAL_S   60
#define FD_HEADROOM        32
#define LOGLINE_MAX         4096

/* ---- canned banners ---------------------------------------------------- */
static const char *BANNER_LOGIN =
    "Ubuntu 22.04.4 LTS\r\nsvr login: ";
static const char *PROMPT_PASS  = "Password: ";
static const char *MOTD =
    "\r\nWelcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n";
static const char *SHELL_PROMPT = "root@svr:~# ";

/* ---- connection state -------------------------------------------------- */
typedef enum { ST_USER, ST_PASS, ST_SHELL } cstate_t;

typedef struct {
    int        fd;
    char       src_ip[INET6_ADDRSTRLEN];
    uint16_t   src_port;
    uint16_t   dst_port;
    uint64_t   session_id;
    uint64_t   start_mono;
    uint64_t   last_mono;
    cstate_t   st;
    char       line[LINE_MAX];
    size_t     line_len;
    int        iac_skip;
    char       user[USER_MAX];
    int        cmd_count;
    bool       quiet;          /* binary stream detected: stop responding */
    int        cap_fd;         /* quarantine file fd, -1 until first byte */
    size_t     cap_bytes;
    char       cap_name[64];
} conn_t;

/* ---- rate limit -------------------------------------------------------- */
typedef struct {
    char     ip[INET6_ADDRSTRLEN];
    uint64_t window_start;
    uint32_t count;
    bool     used;
} rl_entry_t;

/* ---- worker context ---------------------------------------------------- */
typedef struct {
    int         epfd, timerfd, sigfd, log_fd, maxfd;
    conn_t    **conns;
    rl_entry_t *rl;
    int         n_listeners;
    int         listeners[MAX_LISTENERS];
    uint16_t    listener_port[MAX_LISTENERS];
    const char *quarantine;
    uint64_t    next_session;
    int         active, max_active;
    uint64_t    s_accept, s_close, s_creds, s_cmds, s_iocs, s_payloads,
                s_rl, s_cap;
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

/* ---- I/O helpers ------------------------------------------------------- */
static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)w;
    }
    return (ssize_t)off;
}

static int send_str(int fd, const char *s)
{
    size_t len = strlen(s), off = 0;
    while (off < len) {
        ssize_t w = write(fd, s + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

/* escape a printable-ASCII string for safe JSON embedding */
static void json_escape(char *dst, size_t dn, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dn; i++) {
        unsigned char ch = (unsigned char)src[i];
        if (ch == '"' || ch == '\\') { dst[j++] = '\\'; dst[j++] = (char)ch; }
        else if (ch >= 0x20 && ch < 0x7f) { dst[j++] = (char)ch; }
        /* control/non-ASCII already filtered upstream; drop defensively */
    }
    dst[j] = '\0';
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
static void emit(ctx_t *c, const char *line, int n)
{
    if (n > 0) (void)write_all(c->log_fd, line, (size_t)n);
}

static void emit_listen(ctx_t *c, uint16_t port)
{
    char ts[40], b[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"listen\",\"port\":%u,\"service\":\"trap-shell\",\"pid\":%d}\n",
        ts, port, (int)getpid()));
}

static void emit_accept(ctx_t *c, const conn_t *k)
{
    char ts[40], b[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"accept\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"src_port\":%u,\"dst_port\":%u}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, k->src_port,
        k->dst_port));
}

static void emit_creds(ctx_t *c, const conn_t *k, const char *pass)
{
    char ts[40], b[LOGLINE_MAX], eu[USER_MAX * 2], ep[LINE_MAX * 2];
    iso_now(ts, sizeof ts);
    json_escape(eu, sizeof eu, k->user);
    json_escape(ep, sizeof ep, pass);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"credentials\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"username\":\"%s\",\"password\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, eu, ep));
}

static void emit_command(ctx_t *c, const conn_t *k, const char *cmd)
{
    char ts[40], b[LOGLINE_MAX], ec[LINE_MAX * 2];
    iso_now(ts, sizeof ts);
    json_escape(ec, sizeof ec, cmd);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"command\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"seq\":%d,\"cmd\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, k->cmd_count, ec));
}

static void emit_ioc(ctx_t *c, const conn_t *k, const char *type,
                     const char *value)
{
    char ts[40], b[LOGLINE_MAX], ev[LINE_MAX * 2];
    iso_now(ts, sizeof ts);
    json_escape(ev, sizeof ev, value);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"ioc\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"type\":\"%s\",\"value\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, type, ev));
}

static void emit_binary(ctx_t *c, const conn_t *k, const unsigned char *sample,
                        size_t n)
{
    char ts[40], b[LOGLINE_MAX], hex[2 * HEX_SAMPLE_BYTES + 1];
    iso_now(ts, sizeof ts);
    size_t hn = n < HEX_SAMPLE_BYTES ? n : HEX_SAMPLE_BYTES;
    bytes_to_hex(hex, sample, hn);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"binary_stream\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"sample_hex\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, hex));
}

static void emit_payload(ctx_t *c, const conn_t *k)
{
    char ts[40], b[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"payload_captured\",\"session\":%llu,"
        "\"src_ip\":\"%s\",\"file\":\"%s\",\"bytes\":%zu}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, k->cap_name,
        k->cap_bytes));
}

static void emit_close(ctx_t *c, const conn_t *k, const char *reason)
{
    char ts[40], b[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    uint64_t dur = mono_ms() - k->start_mono;
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"close\",\"session\":%llu,\"src_ip\":\"%s\","
        "\"commands\":%d,\"captured_bytes\":%zu,\"duration_ms\":%llu,"
        "\"reason\":\"%s\"}\n",
        ts, (unsigned long long)k->session_id, k->src_ip, k->cmd_count,
        k->cap_bytes, (unsigned long long)dur, reason));
}

static void emit_reject(ctx_t *c, const char *ip, uint16_t port,
                        const char *reason)
{
    char ts[40], b[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"reject\",\"src_ip\":\"%s\",\"dst_port\":%u,"
        "\"reason\":\"%s\"}\n", ts, ip, port, reason));
}

static void emit_stats(ctx_t *c)
{
    char ts[40], b[LOGLINE_MAX];
    iso_now(ts, sizeof ts);
    emit(c, b, snprintf(b, sizeof b,
        "{\"ts\":\"%s\",\"event\":\"stats\",\"pid\":%d,\"active\":%d,"
        "\"accepts\":%llu,\"closes\":%llu,\"credentials\":%llu,\"commands\":%llu,"
        "\"iocs\":%llu,\"payloads\":%llu,\"rejected_ratelimit\":%llu,"
        "\"rejected_capacity\":%llu}\n",
        ts, (int)getpid(), c->active,
        (unsigned long long)c->s_accept, (unsigned long long)c->s_close,
        (unsigned long long)c->s_creds, (unsigned long long)c->s_cmds,
        (unsigned long long)c->s_iocs, (unsigned long long)c->s_payloads,
        (unsigned long long)c->s_rl, (unsigned long long)c->s_cap));
}

/* ---- rate limiting ----------------------------------------------------- */
static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

static bool rl_admit(ctx_t *c, const char *ip, uint64_t now)
{
    uint32_t idx = fnv1a(ip) & (RL_BUCKETS - 1);
    for (int i = 0; i < RL_PROBE; i++) {
        rl_entry_t *e = &c->rl[(idx + (uint32_t)i) & (RL_BUCKETS - 1)];
        if (e->used && strcmp(e->ip, ip) == 0) {
            if (now - e->window_start > RL_WINDOW_MS) {
                e->window_start = now; e->count = 1; return true;
            }
            if (e->count >= RL_MAX_PER_WINDOW) return false;
            e->count++; return true;
        }
        if (!e->used || now - e->window_start > RL_WINDOW_MS) {
            e->used = true;
            snprintf(e->ip, sizeof e->ip, "%s", ip);
            e->window_start = now; e->count = 1; return true;
        }
    }
    return true; /* fail open */
}

/* ---- quarantine capture ------------------------------------------------ */
static void capture_open(ctx_t *c, conn_t *k)
{
    if (k->cap_fd >= 0) return;
    snprintf(k->cap_name, sizeof k->cap_name, "sess-%llu-%d.bin",
             (unsigned long long)k->session_id, (int)getpid());
    char path[512];
    snprintf(path, sizeof path, "%s/%s", c->quarantine, k->cap_name);
    k->cap_fd = open(path,
        O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0400);
    /* on failure cap_fd stays -1; we simply do not persist raw bytes */
}

/* returns false if the per-session capture cap was exceeded */
static bool capture_raw(ctx_t *c, conn_t *k, const unsigned char *buf, size_t n)
{
    capture_open(c, k);
    if (k->cap_fd < 0) return true;
    size_t room = CAP_MAX_BYTES - k->cap_bytes;
    size_t w = n < room ? n : room;
    if (w) {
        if (write_all(k->cap_fd, buf, w) == (ssize_t)w)
            k->cap_bytes += w;
    }
    return k->cap_bytes < CAP_MAX_BYTES;
}

/* ---- connection lifecycle ---------------------------------------------- */
static void conn_close(ctx_t *c, conn_t *k, const char *reason)
{
    if (k->cap_fd >= 0) {
        close(k->cap_fd);
        k->cap_fd = -1;
        if (k->cap_bytes > 0) { emit_payload(c, k); c->s_payloads++; }
    }
    emit_close(c, k, reason);
    epoll_ctl(c->epfd, EPOLL_CTL_DEL, k->fd, NULL);
    close(k->fd);
    c->conns[k->fd] = NULL;
    c->active--;
    c->s_close++;
    free(k);
}

/* ---- indicator extraction --------------------------------------------- */
static bool url_char(char ch)
{
    return ch > 0x20 && ch != '"' && ch != '\'' && ch != '`' &&
           ch != ';' && ch != '|' && ch != '&' && ch != '<' && ch != '>' &&
           ch != ')' && ch != '(' && (unsigned char)ch < 0x7f;
}

static void extract_iocs(ctx_t *c, conn_t *k, const char *line)
{
    static const char *schemes[] = { "http://", "https://", "ftp://", "tftp://" };
    for (size_t s = 0; s < sizeof schemes / sizeof schemes[0]; s++) {
        const char *p = line;
        while ((p = strstr(p, schemes[s])) != NULL) {
            const char *e = p;
            while (*e && url_char(*e)) e++;
            size_t len = (size_t)(e - p);
            if (len > 7 && len < LINE_MAX) {
                char url[LINE_MAX];
                memcpy(url, p, len);
                url[len] = '\0';
                emit_ioc(c, k, "url", url);
                c->s_iocs++;
            }
            p = e;
        }
    }
}

/* ---- fake shell -------------------------------------------------------- */
static void shell_response(int fd, const char *line)
{
    char tok[64];
    size_t i = 0;
    while (line[i] && line[i] != ' ' && i < sizeof tok - 1) {
        tok[i] = line[i]; i++;
    }
    tok[i] = '\0';

    if (tok[0] == '\0') return;
    if (!strcmp(tok, "ls"))
        send_str(fd, "bin  boot  dev  etc  home  lib  root  run  tmp  usr  var\r\n");
    else if (!strcmp(tok, "pwd"))
        send_str(fd, "/root\r\n");
    else if (!strcmp(tok, "id"))
        send_str(fd, "uid=0(root) gid=0(root) groups=0(root)\r\n");
    else if (!strcmp(tok, "whoami"))
        send_str(fd, "root\r\n");
    else if (!strcmp(tok, "uname"))
        send_str(fd, "Linux svr 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n");
    else if (!strcmp(tok, "wget") || !strcmp(tok, "curl") ||
             !strcmp(tok, "tftp") || !strcmp(tok, "busybox"))
        send_str(fd, "\r\n");   /* stay quiet; URL already logged as IOC */
    else if (!strcmp(tok, "cd") || !strcmp(tok, "chmod") ||
             !strcmp(tok, "export") || !strcmp(tok, "history"))
        send_str(fd, "");       /* silent success */
    else {
        char out[128];
        snprintf(out, sizeof out, "%s: command not found\r\n", tok);
        send_str(fd, out);
    }
}

/* returns true if the connection was closed */
static bool dispatch_line(ctx_t *c, conn_t *k)
{
    switch (k->st) {
    case ST_USER: {
        size_t ul = k->line_len < sizeof k->user - 1
                  ? k->line_len : sizeof k->user - 1;
        memcpy(k->user, k->line, ul);
        k->user[ul] = '\0';
        k->st = ST_PASS;
        send_str(k->fd, PROMPT_PASS);
        return false;
    }

    case ST_PASS:
        emit_creds(c, k, k->line);
        c->s_creds++;
        k->st = ST_SHELL;             /* always grant: maximize shell intel */
        send_str(k->fd, MOTD);
        send_str(k->fd, SHELL_PROMPT);
        return false;

    case ST_SHELL:
        if (k->line[0] == '\0') { send_str(k->fd, SHELL_PROMPT); return false; }
        k->cmd_count++;
        c->s_cmds++;
        emit_command(c, k, k->line);
        extract_iocs(c, k, k->line);

        if (!strncmp(k->line, "exit", 4) || !strncmp(k->line, "logout", 6) ||
            !strncmp(k->line, "quit", 4)) {
            conn_close(c, k, "logout");
            return true;
        }
        shell_response(k->fd, k->line);
        if (k->cmd_count >= MAX_COMMANDS) {
            conn_close(c, k, "command_cap");
            return true;
        }
        send_str(k->fd, SHELL_PROMPT);
        return false;
    }
    return false;
}

/* feed a batch of received bytes through the line state machine */
static bool feed(ctx_t *c, conn_t *k, const unsigned char *buf, size_t n)
{
    /* binary-stream heuristic: a flood of non-text means a pushed payload */
    if (!k->quiet && n >= 32) {
        size_t np = 0;
        for (size_t i = 0; i < n; i++) {
            unsigned char b = buf[i];
            if (!(b == '\n' || b == '\r' || b == '\t' ||
                  (b >= 0x20 && b < 0x7f)))
                np++;
        }
        if (np * 2 > n) {
            k->quiet = true;
            emit_binary(c, k, buf, n);
        }
    }
    if (k->quiet) return false;   /* stop talking; raw bytes still captured */

    for (size_t i = 0; i < n; i++) {
        unsigned char b = buf[i];
        if (k->iac_skip > 0) { k->iac_skip--; continue; }
        if (b == 0xff) { k->iac_skip = 2; continue; }   /* telnet IAC (approx) */
        if (b == '\n') {
            k->line[k->line_len] = '\0';
            bool closed = dispatch_line(c, k);
            if (closed) return true;
            k->line_len = 0;
        } else if (b == '\r') {
            continue;
        } else if (b >= 0x20 && b < 0x7f) {
            if (k->line_len < LINE_MAX - 1)
                k->line[k->line_len++] = (char)b;
            /* overlong lines are truncated; excess silently dropped */
        }
    }
    return false;
}

static void handle_readable(ctx_t *c, conn_t *k)
{
    unsigned char buf[READ_BUF];
    for (;;) {
        ssize_t r = read(k->fd, buf, sizeof buf);
        if (r > 0) {
            size_t got = (size_t)r;
            k->last_mono = mono_ms();
            if (!capture_raw(c, k, buf, got)) {
                conn_close(c, k, "capture_cap");
                return;
            }
            if (feed(c, k, buf, got)) return;   /* conn closed inside */
            continue;
        }
        if (r == 0) { conn_close(c, k, "peer_closed"); return; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        conn_close(c, k, "read_error");
        return;
    }
}

static void handle_accept(ctx_t *c, int lfd, uint16_t dst_port)
{
    for (;;) {
        struct sockaddr_in6 sa;
        socklen_t sl = sizeof sa;
        int fd = accept4(lfd, (struct sockaddr *)&sa, &sl,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return; /* EAGAIN / EMFILE / ENFILE: stop accepting this round */
        }

        char ip[INET6_ADDRSTRLEN] = "?";
        uint16_t sport = 0;
        if (sa.sin6_family == AF_INET6) {
            inet_ntop(AF_INET6, &sa.sin6_addr, ip, sizeof ip);
            sport = ntohs(sa.sin6_port);
            if (strncmp(ip, "::ffff:", 7) == 0)
                memmove(ip, ip + 7, strlen(ip + 7) + 1);
        } else if (sa.sin6_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
            sport = ntohs(s4->sin_port);
        }

        uint64_t now = mono_ms();
        if (!rl_admit(c, ip, now)) {
            c->s_rl++; emit_reject(c, ip, dst_port, "rate_limit");
            close(fd); continue;
        }
        if (c->active >= c->max_active || fd >= c->maxfd) {
            c->s_cap++; emit_reject(c, ip, dst_port, "capacity");
            close(fd); continue;
        }

        conn_t *k = calloc(1, sizeof *k);
        if (!k) { close(fd); continue; }
        k->fd = fd;
        k->cap_fd = -1;
        snprintf(k->src_ip, sizeof k->src_ip, "%s", ip);
        k->src_port = sport;
        k->dst_port = dst_port;
        k->session_id = ++c->next_session;
        k->start_mono = now;
        k->last_mono = now;
        k->st = ST_USER;

        struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
        if (epoll_ctl(c->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            close(fd); free(k); continue;
        }
        c->conns[fd] = k;
        c->active++;
        c->s_accept++;
        emit_accept(c, k);
        if (send_str(fd, BANNER_LOGIN) < 0) conn_close(c, k, "write_error");
    }
}

static void sweep_timeouts(ctx_t *c)
{
    uint64_t now = mono_ms();
    for (int fd = 0; fd < c->maxfd; fd++) {
        conn_t *k = c->conns[fd];
        if (!k) continue;
        if (now - k->last_mono > IDLE_TIMEOUT_MS)
            conn_close(c, k, "idle_timeout");
        else if (now - k->start_mono > MAX_SESSION_MS)
            conn_close(c, k, "session_timeout");
    }
    if (now - c->last_stats_mono > (uint64_t)STATS_INTERVAL_S * 1000u) {
        c->last_stats_mono = now;
        emit_stats(c);
    }
}

/* ---- listener / privilege ---------------------------------------------- */
static int make_listener(uint16_t port, bool reuseport)
{
    int family = AF_INET6;
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { family = AF_INET;
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); }
    if (fd < 0) { fprintf(stderr, "snare: socket %u: %s\n", port,
                          strerror(errno)); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (reuseport) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);

    int rc;
    if (family == AF_INET6) {
        int zero = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        struct sockaddr_in6 sa; memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6; sa.sin6_addr = in6addr_any;
        sa.sin6_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&sa, sizeof sa);
    } else {
        struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(port);
        rc = bind(fd, (struct sockaddr *)&sa, sizeof sa);
    }
    if (rc < 0) { fprintf(stderr, "snare: bind %u: %s\n", port,
                          strerror(errno)); close(fd); return -1; }
    if (listen(fd, SOMAXCONN) < 0) { fprintf(stderr, "snare: listen %u: %s\n",
                          port, strerror(errno)); close(fd); return -1; }
    return fd;
}

static int drop_privileges(const char *user)
{
    if (geteuid() != 0) return 0;
    struct passwd *pw = getpwnam(user);
    if (!pw) { fprintf(stderr, "snare: unknown user '%s'\n", user); return -1; }
    if (setgroups(0, NULL) != 0 || setgid(pw->pw_gid) != 0 ||
        setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "snare: privilege drop failed: %s\n", strerror(errno));
        return -1;
    }
    if (setuid(0) == 0) {
        fprintf(stderr, "snare: privilege drop did not stick\n"); return -1;
    }
    return 0;
}

/* ---- worker loop ------------------------------------------------------- */
static int run_worker(int log_fd, int maxfd, int max_active, const char *quar,
                      int n_listeners, const int *lfds, const uint16_t *lports,
                      bool exclusive)
{
    ctx_t c;
    memset(&c, 0, sizeof c);
    c.log_fd = log_fd; c.maxfd = maxfd; c.max_active = max_active;
    c.quarantine = quar; c.running = 1; c.last_stats_mono = mono_ms();

    c.conns = calloc((size_t)maxfd, sizeof(conn_t *));
    c.rl = calloc(RL_BUCKETS, sizeof(rl_entry_t));
    if (!c.conns || !c.rl) { perror("calloc"); return 1; }

    c.epfd = epoll_create1(EPOLL_CLOEXEC);
    if (c.epfd < 0) { perror("epoll_create1"); return 1; }

    c.n_listeners = n_listeners;
    for (int i = 0; i < n_listeners; i++) {
        c.listeners[i] = lfds[i];
        c.listener_port[i] = lports[i];
        struct epoll_event ev;
        ev.events = EPOLLIN | (exclusive ? EPOLLEXCLUSIVE : 0u);
        ev.data.fd = lfds[i];
        if (epoll_ctl(c.epfd, EPOLL_CTL_ADD, lfds[i], &ev) < 0) {
            perror("epoll_ctl listener"); return 1;
        }
        emit_listen(&c, lports[i]);
    }

    c.timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec its = { .it_interval = { 1, 0 }, .it_value = { 1, 0 } };
    timerfd_settime(c.timerfd, 0, &its, NULL);
    struct epoll_event tev = { .events = EPOLLIN, .data.fd = c.timerfd };
    epoll_ctl(c.epfd, EPOLL_CTL_ADD, c.timerfd, &tev);

    sigset_t sm; sigemptyset(&sm);
    sigaddset(&sm, SIGINT); sigaddset(&sm, SIGTERM);
    c.sigfd = signalfd(-1, &sm, SFD_NONBLOCK | SFD_CLOEXEC);
    struct epoll_event sev = { .events = EPOLLIN, .data.fd = c.sigfd };
    epoll_ctl(c.epfd, EPOLL_CTL_ADD, c.sigfd, &sev);

    struct epoll_event events[256];
    while (c.running) {
        int n = epoll_wait(c.epfd, events, 256, -1);
        if (n < 0) { if (errno == EINTR) continue; perror("epoll_wait"); break; }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == c.timerfd) {
                uint64_t e; while (read(c.timerfd, &e, sizeof e) > 0) {}
                sweep_timeouts(&c); continue;
            }
            if (fd == c.sigfd) {
                struct signalfd_siginfo si;
                while (read(c.sigfd, &si, sizeof si) > 0) {}
                c.running = 0; continue;
            }
            bool is_listener = false;
            for (int j = 0; j < c.n_listeners; j++)
                if (fd == c.listeners[j]) {
                    handle_accept(&c, fd, c.listener_port[j]);
                    is_listener = true; break;
                }
            if (is_listener) continue;
            conn_t *k = (fd < c.maxfd) ? c.conns[fd] : NULL;
            if (!k) continue;
            if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                conn_close(&c, k, "hangup"); continue;
            }
            if (events[i].events & EPOLLIN) handle_readable(&c, k);
        }
    }

    for (int fd = 0; fd < c.maxfd; fd++)
        if (c.conns[fd]) conn_close(&c, c.conns[fd], "shutdown");
    emit_stats(&c);
    close(c.epfd); close(c.timerfd); close(c.sigfd);
    free(c.conns); free(c.rl);
    return 0;
}

/* ---- main -------------------------------------------------------------- */
static void usage(const char *p)
{
    fprintf(stderr,
"Usage: %s [options]\n"
"  -p PORT     add a trap-shell listener (repeatable). default: 2323\n"
"  -d DIR      quarantine directory for captured payloads (default: ./quarantine)\n"
"  -o FILE     telemetry output file (append, JSON-Lines). default stdout\n"
"  -u USER     user to drop to after binding (default: nobody)\n"
"  -m N        max concurrent connections (default: derived from rlimit)\n"
"  -h          this help\n", p);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    uint16_t ports[MAX_LISTENERS];
    int n_listeners = 0;
    const char *quar = "./quarantine";
    const char *logpath = NULL;
    const char *user = "nobody";
    long cli_max = 0;

    int opt;
    while ((opt = getopt(argc, argv, "p:d:o:u:m:h")) != -1) {
        switch (opt) {
        case 'p': {
            if (n_listeners >= MAX_LISTENERS) {
                fprintf(stderr, "snare: too many listeners\n"); return 2; }
            long port = strtol(optarg, NULL, 10);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "snare: bad port '%s'\n", optarg); return 2; }
            ports[n_listeners++] = (uint16_t)port;
            break;
        }
        case 'd': quar = optarg; break;
        case 'o': logpath = optarg; break;
        case 'u': user = optarg; break;
        case 'm': cli_max = strtol(optarg, NULL, 10); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (n_listeners == 0) ports[n_listeners++] = 2323;

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max; setrlimit(RLIMIT_NOFILE, &rl);
    }
    int maxfd = 65536;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < (rlim_t)maxfd)
        maxfd = (int)rl.rlim_cur;
    int max_active = maxfd - FD_HEADROOM;
    if (cli_max > 0 && cli_max < max_active) max_active = (int)cli_max;
    if (max_active < 1) max_active = 1;

    /* prepare quarantine dir and hand it to the drop user (we may be root) */
    if (mkdir(quar, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "snare: mkdir '%s': %s\n", quar, strerror(errno));
        return 1;
    }
    if (geteuid() == 0) {
        struct passwd *pw = getpwnam(user);
        if (pw && chown(quar, pw->pw_uid, pw->pw_gid) != 0)
            fprintf(stderr, "snare: warning: chown quarantine: %s\n",
                    strerror(errno));
    }

    int log_fd = STDOUT_FILENO;
    if (logpath) {
        log_fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
        if (log_fd < 0) { fprintf(stderr, "snare: open '%s': %s\n", logpath,
                                  strerror(errno)); return 1; }
    }

    int lfds[MAX_LISTENERS];
    for (int i = 0; i < n_listeners; i++) {
        lfds[i] = make_listener(ports[i], false);
        if (lfds[i] < 0) { for (int j = 0; j < i; j++) close(lfds[j]); return 1; }
    }

    if (drop_privileges(user) != 0) return 1;

    sigset_t bm; sigemptyset(&bm);
    sigaddset(&bm, SIGINT); sigaddset(&bm, SIGTERM);
    sigprocmask(SIG_BLOCK, &bm, NULL);

    return run_worker(log_fd, maxfd, max_active, quar,
                      n_listeners, lfds, ports, false);
}

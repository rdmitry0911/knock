/* SPDX-License-Identifier: GPL-2.0-or-later
 * Native OpenWrt controller. One short-lived process per CLI/CGI operation;
 * uhttpd owns TLS and connection limits, knockd owns packet capture.
 * Wire format and the schema-2 database are shared with controller/server.py.
 */
#define _GNU_SOURCE
#include "../../src/ice_auth.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <qrencode.h>
#include <setjmp.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <uci.h>
#include <unistd.h>
#include <zlib.h>

typedef struct json_object J;
static jmp_buf main_failure;
static jmp_buf *failure = &main_failure;
static char error_text[256];
static int http_status = 400;
#ifndef KNC_STATE_DIR
#define KNC_STATE_DIR "/etc/knock-control"
#endif
static char directory[1024] = KNC_STATE_DIR;
static char config_path[1100], daemon_path[1100], cert_path[1100], key_path[1100],
    replay_path[1100], rules_path[1100], legacy_path[1100];
static const char *daemon_bin = "/usr/sbin/knock-control-daemon";
static const char *control_bin = "/usr/sbin/knock-control";

static void fail(const char *msg) {
    snprintf(error_text, sizeof(error_text), "%s", msg);
    longjmp(*failure, 1);
}
static void need(bool ok, const char *msg) {
    if (!ok)
        fail(msg);
}
static void *alloc(size_t n) {
    void *p = calloc(1, n);
    need(p != NULL, "Out of memory");
    return p;
}
static char *fmt(const char *format, ...) __attribute__((format(printf, 1, 2)));
#include <stdarg.h>
static char *fmt(const char *format, ...) {
    char *p = NULL;
    va_list ap;
    va_start(ap, format);
    int n = vasprintf(&p, format, ap);
    va_end(ap);
    need(n >= 0, "Out of memory");
    return p;
}
static J *obj(void) {
    J *v = json_object_new_object();
    need(v != NULL, "Out of memory");
    return v;
}
static J *arr(void) {
    J *v = json_object_new_array();
    need(v != NULL, "Out of memory");
    return v;
}
static void put(J *o, const char *k, J *v) {
    need(json_object_object_add(o, k, v) == 0, "JSON allocation failed");
}
static void text(J *o, const char *k, const char *v) {
    put(o, k, json_object_new_string(v));
}
static void number(J *o, const char *k, int64_t v) {
    put(o, k, json_object_new_int64(v));
}
static void boolean(J *o, const char *k, bool v) {
    put(o, k, json_object_new_boolean(v));
}
static void append(J *a, J *v) {
    need(json_object_array_add(a, v) == 0, "JSON allocation failed");
}
static J *get(J *v, const char *k) {
    J *r = NULL;
    need(json_object_is_type(v, json_type_object), "Expected object");
    json_object_object_get_ex(v, k, &r);
    return r;
}
static const char *str(J *v) {
    need(json_object_is_type(v, json_type_string), "Expected string");
    const char *s = json_object_get_string(v);
    need(strlen(s) == (size_t)json_object_get_string_len(v), "NUL in string");
    return s;
}
static const char *sget(J *o, const char *k) {
    return str(get(o, k));
}
static int64_t integer(J *v, int64_t lo, int64_t hi) {
    need(json_object_is_type(v, json_type_int), "Expected integer");
    int64_t n = json_object_get_int64(v);
    need(n >= lo && n <= hi, "Integer outside allowed range");
    return n;
}
static int64_t iget(J *o, const char *k, int64_t lo, int64_t hi) {
    return integer(get(o, k), lo, hi);
}
static bool flag(J *v) {
    need(json_object_is_type(v, json_type_boolean), "Expected boolean");
    return json_object_get_boolean(v);
}
static bool bget(J *v, const char *k) {
    return flag(get(v, k));
}
static const char *json(J *o) {
    return json_object_to_json_string_ext(o,
                                          JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
}
static J *parse(const char *p, size_t n) {
    need(n <= 1024 * 1024, "JSON too large");
    struct json_tokener *t = json_tokener_new_ex(32);
    need(t != NULL, "Out of memory");
    json_tokener_set_flags(t, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    char *terminated = alloc(n + 1);
    memcpy(terminated, p, n);
    J *v = json_tokener_parse_ex(t, terminated, (int)n + 1);
    bool ok = json_tokener_get_error(t) == json_tokener_success;
    size_t end = json_tokener_get_parse_end(t);
    while (end < n && isspace((unsigned char)p[end]))
        end++;
    json_tokener_free(t);
    free(terminated);
    need(ok && end == n && v != NULL, "Invalid JSON");
    return v;
}
static J *copy(J *v) {
    const char *s = json(v);
    return parse(s, strlen(s));
}
static char *read_file(const char *path, size_t limit, size_t *length) {
    FILE *f = fopen(path, "rb");
    need(f != NULL, "Cannot read file");
    char *p = alloc(limit + 1);
    size_t n = fread(p, 1, limit + 1, f);
    bool ok = !ferror(f) && n <= limit;
    fclose(f);
    need(ok, "File too large or unreadable");
    if (length)
        *length = n;
    return p;
}
static bool exists(const char *path) {
    return access(path, F_OK) == 0;
}
static void write_all(int fd, const void *data, size_t n) {
    const char *p = data;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR)
            continue;
        need(w > 0, "Write failed");
        p += w;
        n -= (size_t)w;
    }
}
static void atomic_bytes(const char *path, const void *data, size_t size) {
    char *tmp = fmt("%s.XXXXXX", path);
    int fd = mkostemp(tmp, O_CLOEXEC);
    need(fd >= 0, "Cannot create private temporary file");
    write_all(fd, data, size);
    bool ok = fsync(fd) == 0;
    if (close(fd))
        ok = false;
    if (ok)
        ok = rename(tmp, path) == 0;
    if (!ok) {
        unlink(tmp);
        fail("Atomic file update failed");
    }
    char *parent = strdup(path);
    need(parent != NULL, "Out of memory");
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = 0;
        int d = open(*parent ? parent : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (d >= 0) {
            fsync(d);
            close(d);
        }
    }
    free(parent);
    free(tmp);
}
static void atomic(const char *path, const char *s) {
    atomic_bytes(path, s, strlen(s));
}
static void paths(void) {
    if (!strcmp(directory, "/etc/knock-control"))
        snprintf(config_path, sizeof(config_path), "/etc/config/knock-control");
    else
        snprintf(config_path, sizeof(config_path), "%s/knock-control", directory);
    snprintf(legacy_path, sizeof(legacy_path), "%s/settings.json", directory);
    snprintf(daemon_path, sizeof(daemon_path), "%s/knockd.conf", directory);
    snprintf(cert_path, sizeof(cert_path), "%s/server.crt", directory);
    snprintf(key_path, sizeof(key_path), "%s/server.key", directory);
    snprintf(replay_path, sizeof(replay_path), "%s/api-replays.sqlite3", directory);
    snprintf(rules_path, sizeof(rules_path), "%s/firewall.nft", directory);
}
/* No shell is involved. stdin/stdout use anonymous files to avoid pipe
 * deadlocks; children cannot retain the controller lock after exec. */
static int run(char *const argv[], const char *input, char **output) {
    FILE *in = tmpfile(), *out = tmpfile();
    need(in && out, "Cannot create process pipes");
    if (input) {
        need(fwrite(input, 1, strlen(input), in) == strlen(input), "Cannot write process input");
        rewind(in);
    }
    pid_t pid = fork();
    need(pid >= 0, "Cannot fork");
    if (pid == 0) {
        setpgid(0, 0);
        dup2(fileno(in), 0);
        dup2(fileno(out), 1);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0)
            dup2(null, 2);
        fclose(in);
        fclose(out);
        execv(argv[0], argv);
        _exit(127);
    }
    setpgid(pid, pid);
    int status = 0;
    bool done = false;
    for (int i = 0; i < 2000; i++) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            done = true;
            break;
        }
        if (r < 0 && errno != EINTR)
            break;
        struct timespec delay = {0, 10000000};
        nanosleep(&delay, NULL);
    }
    if (!done) {
        kill(-pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        status = 0x7f00;
    }
    if (output) {
        rewind(out);
        *output = alloc(1024 * 1024 + 1);
        size_t n = fread(*output, 1, 1024 * 1024 + 1, out);
        need(n <= 1024 * 1024, "Process output limit exceeded");
    }
    fclose(in);
    fclose(out);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}
static void checked(char *const argv[], const char *input) {
    need(run(argv, input, NULL) == 0, "Server command failed");
}
static int service(const char *name, const char *operation) {
    if (!strcmp(name, "knock-control") && !strcmp(operation, "reload")) {
        char *args[] = {"/bin/ubus",
                        "call",
                        "service",
                        "signal",
                        "{\"name\":\"knock-control\",\"instance\":\"daemon\",\"signal\":1}",
                        NULL};
        return run(args, NULL, NULL);
    }
    char *p = fmt("/etc/init.d/%s", name);
    char *a[] = {p, (char *)operation, NULL};
    int rc = run(a, NULL, NULL);
    free(p);
    return rc;
}
static bool active(void) {
    return service("knock-control", "running") == 0;
}
static int nft(const char *commands) {
    char *a[] = {"/usr/sbin/nft", "-f", "-", NULL};
    return run(a, commands, NULL);
}
static void valid_id(const char *id) {
    need(strlen(id) == 24, "Invalid profile ID");
    for (int i = 0; i < 24; i++)
        need((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'),
             "Invalid profile ID");
}
static bool is_hex(const char *s, size_t n) {
    if (strlen(s) != n)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}
static bool ipv4(const char *s) {
    struct in_addr a;
    char canonical[INET_ADDRSTRLEN];
    return inet_pton(AF_INET, s, &a) == 1 && inet_ntop(AF_INET, &a, canonical, sizeof(canonical)) &&
           !strcmp(s, canonical);
}
static void valid_host(const char *s) {
    size_t n = strlen(s);
    need(n >= 1 && n <= 253 && isalnum((unsigned char)*s), "Invalid public host");
    for (size_t i = 0; i < n; i++)
        need((unsigned char)s[i] < 128 &&
                 (isalnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '-'),
             "Invalid public host");
}
static void valid_name(const char *s) {
    size_t chars = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        need(*p >= 32, "Invalid profile name");
        if ((*p & 0xc0) != 0x80)
            chars++;
    }
    need(chars >= 1 && chars <= 80, "Use a profile name of 1..80 characters");
}
static void valid_interface(const char *s) {
    need(strlen(s) >= 1 && strlen(s) <= 15, "Invalid interface");
    for (; *s; s++)
        need((unsigned char)*s < 128 && (isalnum((unsigned char)*s) || strchr("_.:-", *s)),
             "Invalid interface");
}
static bool has_port(J *ports, int port) {
    for (size_t i = 0; i < json_object_array_length(ports); i++)
        if (integer(json_object_array_get_idx(ports, i), 1, 65535) == port)
            return true;
    return false;
}
static int intcmp(const void *a, const void *b) {
    return (*(const int *)a > *(const int *)b) - (*(const int *)a < *(const int *)b);
}
static J *ports(J *v, size_t max) {
    need(json_object_is_type(v, json_type_array), "Expected port array");
    size_t n = json_object_array_length(v);
    need(n <= max, "Invalid port count");
    int p[128];
    for (size_t i = 0; i < n; i++)
        p[i] = (int)integer(json_object_array_get_idx(v, i), 1, 65535);
    qsort(p, n, sizeof(*p), intcmp);
    J *r = arr();
    for (size_t i = 0; i < n; i++)
        if (!i || p[i] != p[i - 1])
            append(r, json_object_new_int(p[i]));
    return r;
}
static J *default_protocols(void) {
    J *a = arr();
    for (int i = 0; i < 6; i++)
        append(a, json_object_new_string("udp"));
    return a;
}
static void valid_rule_name(const char *s) {
    need(strlen(s) >= 1 && strlen(s) <= 32 && isalpha((unsigned char)*s), "Invalid rule name");
    for (const char *p = s; *p; p++)
        need(isalnum((unsigned char)*p) || *p == '_', "Invalid rule name");
}
static bool has_string(J *a, const char *s) {
    for (size_t i = 0; a && i < json_object_array_length(a); i++)
        if (!strcmp(str(json_object_array_get_idx(a, i)), s))
            return true;
    return false;
}
static J *rule_names(J *a) {
    need(json_object_is_type(a, json_type_array) && json_object_array_length(a) <= 64,
         "Expected at most 64 rule names");
    J *out = arr();
    for (size_t i = 0; i < json_object_array_length(a); i++) {
        const char *s = str(json_object_array_get_idx(a, i));
        valid_rule_name(s);
        need(!has_string(out, s), "Duplicate rule name");
        append(out, json_object_new_string(s));
    }
    return out;
}
static void rule_bounds(const char *s, int *lo, int *hi) {
    need(strlen(s) >= 1 && strlen(s) <= 11 && *s >= '1' && *s <= '9', "Invalid port range");
    const char *p = s;
    while (isdigit((unsigned char)*p))
        p++;
    need(p - s <= 5 && (!*p || *p == '-'), "Invalid port range");
    *lo = (int)strtol(s, NULL, 10);
    *hi = *lo;
    if (*p) {
        const char *start = ++p;
        need(*p >= '1' && *p <= '9', "Invalid port range");
        while (isdigit((unsigned char)*p))
            p++;
        need(!*p && p - start <= 5, "Invalid port range");
        *hi = (int)strtol(start, NULL, 10);
    }
    need(*lo >= 1 && *lo <= *hi && *hi <= 65535, "Invalid port range");
}
static J *normalize_rule(J *v) {
    need(json_object_is_type(v, json_type_object), "Expected rule object");
    json_object_object_foreach(v, key, entry) {
        (void)entry;
        need(!strcmp(key, "type") || !strcmp(key, "protocol") || !strcmp(key, "ports") ||
                 !strcmp(key, "dest_ip") || !strcmp(key, "dest_port") ||
                 !strcmp(key, "icmp_type") || !strcmp(key, "interface"),
             "Unknown rule field");
    }
    const char *kind = get(v, "type") ? sget(v, "type") : "input";
    const char *proto = get(v, "protocol") ? sget(v, "protocol") : "tcp";
    bool input = !strcmp(kind, "input"), dnat = !strcmp(kind, "dnat"),
         icmp = !strcmp(proto, "icmp");
    need(input || dnat || !strcmp(kind, "forward"), "Rule type must be input/forward/dnat");
    need(icmp || !strcmp(proto, "tcp") || !strcmp(proto, "udp"), "Invalid rule protocol");
    J *r = obj();
    text(r, "type", kind);
    text(r, "protocol", proto);
    if (get(v, "interface")) {
        valid_interface(sget(v, "interface"));
        text(r, "interface", sget(v, "interface"));
    }
    if (icmp) {
        need(!dnat && !get(v, "ports") && !get(v, "dest_port"), "ICMP has no ports or DNAT");
        const char *type = get(v, "icmp_type") ? sget(v, "icmp_type") : "echo-request";
        need(!strcmp(type, "any") || !strcmp(type, "echo-request"), "Invalid ICMP type");
        text(r, "icmp_type", type);
    } else {
        need(!get(v, "icmp_type"), "icmp_type requires ICMP");
        J *ps = get(v, "ports"), *normalized = arr();
        need(json_object_is_type(ps, json_type_array) && json_object_array_length(ps) >= 1 &&
                 json_object_array_length(ps) <= 32,
             "Use 1..32 ports or ranges");
        for (size_t i = 0; i < json_object_array_length(ps); i++) {
            J *p = json_object_array_get_idx(ps, i);
            const char *s = json_object_is_type(p, json_type_int) ? json(p) : str(p);
            int lo, hi;
            rule_bounds(s, &lo, &hi);
            if (!has_string(normalized, s))
                append(normalized, json_object_new_string(s));
        }
        put(r, "ports", normalized);
    }
    if (!input) {
        const char *s = sget(v, "dest_ip");
        struct in_addr a;
        need(inet_pton(AF_INET, s, &a) == 1 && ntohl(a.s_addr) != 0 &&
                 ntohl(a.s_addr) != 0xffffffff && (ntohl(a.s_addr) & 0xf0000000) != 0xe0000000,
             "Destination must be a unicast IPv4 address");
        text(r, "dest_ip", s);
    } else
        need(!get(v, "dest_ip"), "dest_ip requires forward or dnat");
    if (get(v, "dest_port")) {
        need(dnat && !icmp && json_object_array_length(get(r, "ports")) == 1 &&
                 !strchr(str(json_object_array_get_idx(get(r, "ports"), 0)), '-'),
             "Port translation requires one DNAT port; ranges keep their ports");
        number(r, "dest_port", iget(v, "dest_port", 1, 65535));
    }
    return r;
}
static J *settings(J *input) {
    need(json_object_is_type(input, json_type_object), "Expected settings");
    J *r = obj(), *v;
    const char *inter = get(input, "interface") ? sget(input, "interface") : "eth0";
    valid_interface(inter);
    text(r, "interface", inter);
    const char *secret = sget(input, "secret");
    need(strlen(secret) == 32, "Invalid Base32 secret");
    for (int i = 0; i < 32; i++)
        need((secret[i] >= 'A' && secret[i] <= 'Z') || (secret[i] >= '2' && secret[i] <= '7'),
             "Invalid Base32 secret");
    text(r, "secret", secret);
    const char *names[] = {"period", "base", "idle_timeout", "seq_timeout"};
    int defs[] = {30, 20000, 600, 10}, lo[] = {30, 1024, 10, 1}, hi[] = {30, 65280, 86400, 60};
    for (int i = 0; i < 4; i++) {
        v = get(input, names[i]);
        number(r, names[i], v ? integer(v, lo[i], hi[i]) : defs[i]);
    }
    v = get(input, "protocols");
    if (!v)
        v = default_protocols();
    need(json_object_is_type(v, json_type_array), "Expected protocols");
    size_t n = json_object_array_length(v);
    need(n >= 3 && n <= 20, "Use 3..20 TCP/UDP protocols");
    for (size_t i = 0; i < n; i++) {
        const char *p = str(json_object_array_get_idx(v, i));
        need(!strcmp(p, "tcp") || !strcmp(p, "udp"), "Invalid protocol");
    }
    put(r, "protocols", copy(v));
    need(iget(r, "seq_timeout", 1, 60) > n * .25, "Sequence timeout is too short");
    v = get(input, "ip_protection");
    boolean(r, "ip_protection", v ? flag(v) : true);
    v = get(input, "ports");
    if (!v) {
        v = arr();
        append(v, json_object_new_int(22));
    }
    J *ps = ports(v, 15);
    need(json_object_array_length(ps) || get(input, "rules"), "Specify ports or named rules");
    if (get(input, "rules"))
        put(r, "rules", rule_names(get(input, "rules")));
    int base = iget(r, "base", 1024, 65280);
    for (size_t i = 0; i < json_object_array_length(ps); i++) {
        int p = integer(json_object_array_get_idx(ps, i), 1, 65535);
        need(p < base || p > base + 255, "Protected port overlaps knock range");
    }
    put(r, "ports", ps);
    if (get(input, "profile_id")) {
        valid_id(sget(input, "profile_id"));
        text(r, "profile_id", sget(input, "profile_id"));
    }
    return r;
}
static J *public_settings(J *v) {
    J *r = copy(v);
    json_object_object_del(r, "secret");
    return r;
}
static J *config_for(J *db, J *profile) {
    J *v = copy(get(profile, "settings"));
    text(v, "secret", sget(profile, "secret"));
    text(v, "profile_id", sget(profile, "id"));
    text(v, "interface", sget(db, "interface"));
    return settings(v);
}
static void validate_database(J *db) {
    need(iget(db, "schema", 2, 2) == 2, "Initialize a schema-2 database");
    valid_interface(sget(db, "interface"));
    need(ipv4(sget(db, "api_bind")), "Invalid API bind address");
    iget(db, "api_port", 1, 65535);
    bget(db, "activated");
    J *protected = get(db, "protected_ports");
    need(json_object_is_type(protected, json_type_array) &&
             json_object_array_length(protected) <= 16384,
         "Invalid protected ports");
    for (size_t i = 0; i < json_object_array_length(protected); i++)
        need(integer(json_object_array_get_idx(protected, i), 1, 65535) !=
                 iget(db, "api_port", 1, 65535),
             "API port cannot be protected");
    J *p = get(db, "profiles");
    need(json_object_is_type(p, json_type_object) && json_object_object_length(p) <= 128,
         "Invalid profile database");
    J *rules = get(db, "rules");
    need(!rules || (json_object_is_type(rules, json_type_object) &&
                    json_object_object_length(rules) <= 128),
         "Invalid named rules");
    if (rules) {
        json_object_object_foreach(rules, name, entry) {
            valid_rule_name(name);
            J *r = normalize_rule(entry);
            put(rules, name, r);
            if (strcmp(sget(r, "type"), "forward") && strcmp(sget(r, "protocol"), "icmp")) {
                J *ps = get(r, "ports");
                for (size_t i = 0; i < json_object_array_length(ps); i++) {
                    int lo, hi;
                    rule_bounds(str(json_object_array_get_idx(ps, i)), &lo, &hi);
                    int api = iget(db, "api_port", 1, 65535);
                    need(strcmp(sget(r, "protocol"), "tcp") || api < lo || api > hi,
                         "Rule overlaps API port");
                    json_object_object_foreach(p, id, profile) {
                        (void)id;
                        int base = iget(get(profile, "settings"), "base", 1024, 65280);
                        need(hi < base || lo > base + 255, "Rule overlaps knock range");
                    }
                }
            }
        }
        json_object_object_foreach(rules, left_name, left) {
            if (!strcmp(sget(left, "protocol"), "icmp") || !strcmp(sget(left, "type"), "forward"))
                continue;
            json_object_object_foreach(rules, right_name, right) {
                if (strcmp(left_name, right_name) >= 0 ||
                    strcmp(sget(left, "protocol"), sget(right, "protocol")) ||
                    !strcmp(sget(right, "type"), "forward") ||
                    (strcmp(sget(left, "type"), "dnat") && strcmp(sget(right, "type"), "dnat")))
                    continue;
                const char *li =
                    get(left, "interface") ? sget(left, "interface") : sget(db, "interface");
                const char *ri =
                    get(right, "interface") ? sget(right, "interface") : sget(db, "interface");
                if (strcmp(li, ri))
                    continue;
                bool same = !strcmp(sget(left, "type"), sget(right, "type"));
                if (same)
                    same = !strcmp(sget(left, "dest_ip"), sget(right, "dest_ip")) &&
                           ((get(left, "dest_port") && get(right, "dest_port"))
                                ? iget(left, "dest_port", 1, 65535) ==
                                      iget(right, "dest_port", 1, 65535)
                                : !get(left, "dest_port") && !get(right, "dest_port"));
                if (same)
                    continue;
                J *lp = get(left, "ports"), *rp = get(right, "ports");
                for (size_t i = 0; i < json_object_array_length(lp); i++)
                    for (size_t j = 0; j < json_object_array_length(rp); j++) {
                        int a, b, c, d;
                        rule_bounds(str(json_object_array_get_idx(lp, i)), &a, &b);
                        rule_bounds(str(json_object_array_get_idx(rp, j)), &c, &d);
                        need(b < c || d < a, "Conflicting input/DNAT mappings");
                    }
            }
        }
    }
    json_object_object_foreach(p, id, profile) {
        valid_id(id);
        need(!strcmp(id, sget(profile, "id")), "Profile ID mismatch");
        J *profile_cfg = get(profile, "settings"), *profile_policy = get(profile, "policy");
        if (get(profile_cfg, "rules") || get(profile_policy, "allowed_rules")) {
            if (!get(profile_cfg, "rules"))
                put(profile_cfg, "rules", arr());
            if (!get(profile_policy, "allowed_rules"))
                put(profile_policy, "allowed_rules", arr());
        }
        config_for(db, profile);
        iget(profile, "revision", 1, 2147483647);
        bget(profile, "enabled");
        bget(profile, "revoked");
        valid_name(sget(profile, "name"));
        J *policy = get(profile, "policy"), *allowed = ports(get(policy, "allowed_ports"), 128);
        if (get(get(profile, "settings"), "rules")) {
            J *selected = rule_names(get(get(profile, "settings"), "rules"));
            J *permitted = rule_names(get(policy, "allowed_rules"));
            for (size_t i = 0; i < json_object_array_length(permitted); i++)
                need(rules && get(rules, str(json_object_array_get_idx(permitted, i))),
                     "Unknown allowed rule");
            for (size_t i = 0; i < json_object_array_length(selected); i++)
                need(has_string(permitted, str(json_object_array_get_idx(selected, i))),
                     "Rule outside policy");
            json_object_put(selected);
            json_object_put(permitted);
        } else
            need(!get(policy, "allowed_rules"), "Rule policy requires rules list");
        int api_port = iget(db, "api_port", 1, 65535);
        need(!has_port(allowed, api_port), "API port cannot be protected");
        int maximum = iget(policy, "max_idle_timeout", 10, 86400);
        J *cfg = get(profile, "settings"), *initial = get(cfg, "ports");
        need(iget(cfg, "idle_timeout", 10, 86400) <= maximum, "Idle timeout outside policy");
        for (size_t i = 0; i < json_object_array_length(initial); i++)
            need(has_port(allowed, integer(json_object_array_get_idx(initial, i), 1, 65535)),
                 "Protected port outside policy");
        bget(policy, "can_configure");
        if (get(policy, "allow_browser_transport"))
            bget(policy, "allow_browser_transport");
        else
            boolean(policy, "allow_browser_transport", true);
        for (size_t i = 0; i < json_object_array_length(allowed); i++) {
            int port = integer(json_object_array_get_idx(allowed, i), 1, 65535);
            if (!has_port(protected, port))
                append(protected, json_object_new_int(port));
        }
        json_object_put(allowed);
    }
    need(json_object_is_type(get(db, "protected_ports"), json_type_array),
         "Invalid protected ports");
}
/* The authoritative OpenWrt configuration is a real UCI package, not JSON
 * hidden in /etc/config. JSON remains the in-memory and client wire format. */
static struct uci_package *uci_parse_text(struct uci_context *ctx, const char *raw) {
    FILE *f = fmemopen((void *)raw, strlen(raw), "r");
    need(f != NULL, "Cannot read UCI configuration");
    struct uci_package *package = NULL;
    int rc = uci_import(ctx, f, "knock-control", &package, true);
    fclose(f);
    need(rc == UCI_OK && package != NULL, "Invalid UCI configuration");
    return package;
}
static const char *uci_string(struct uci_context *ctx, struct uci_section *s, const char *key) {
    struct uci_option *v = uci_lookup_option(ctx, s, key);
    need(v && v->type == UCI_TYPE_STRING, "Missing or invalid UCI option");
    return v->v.string;
}
static J *uci_number(const char *s) {
    need(*s && strlen(s) <= 12, "Invalid UCI integer");
    for (const char *p = s; *p; p++)
        need(isdigit((unsigned char)*p), "Invalid UCI integer");
    return json_object_new_int64(strtoll(s, NULL, 10));
}
static J *uci_bool(const char *s) {
    need(!strcmp(s, "0") || !strcmp(s, "1"), "UCI boolean must be 0 or 1");
    return json_object_new_boolean(!strcmp(s, "1"));
}
static J *uci_list_value(struct uci_context *ctx, struct uci_section *s, const char *key,
                         bool numeric) {
    J *a = arr();
    struct uci_option *v = uci_lookup_option(ctx, s, key);
    if (!v)
        return a;
    need(v->type == UCI_TYPE_LIST, "Expected UCI list");
    struct uci_element *e;
    uci_foreach_element(&v->v.list, e)
        append(a, numeric ? uci_number(e->name) : json_object_new_string(e->name));
    return a;
}
static J *decode_config(const char *raw, bool require_initialized) {
    struct uci_context *ctx = uci_alloc_context();
    need(ctx != NULL, "Out of memory");
    struct uci_package *package = uci_parse_text(ctx, raw);
    struct uci_section *main = uci_lookup_section(ctx, package, "main");
    need(main && !strcmp(main->type, "server"), "Missing UCI server main section");
    bool initialized = flag(uci_bool(uci_string(ctx, main, "initialized")));
    if (!initialized) {
        uci_free_context(ctx);
        need(!require_initialized, "Initialize with knock-control init");
        return NULL;
    }
    J *db = obj(), *profiles = obj();
    put(db, "profiles", profiles);
    const char *const texts[] = {"interface",  "api_bind",           "server_url",
                                 "knock_host", "certificate_sha256", NULL};
    for (int i = 0; texts[i]; i++)
        text(db, texts[i], uci_string(ctx, main, texts[i]));
    put(db, "schema", uci_number(uci_string(ctx, main, "schema")));
    put(db, "api_port", uci_number(uci_string(ctx, main, "api_port")));
    put(db, "activated", uci_bool(uci_string(ctx, main, "activated")));
    put(db, "protected_ports", uci_list_value(ctx, main, "protected_ports", true));
    struct uci_element *e;
    uci_foreach_element(&package->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (s == main)
            continue;
        if (!strcmp(s->type, "rule")) {
            valid_rule_name(s->e.name);
            if (!get(db, "rules"))
                put(db, "rules", obj());
            J *r = obj();
            const char *const keys[] = {"type",    "protocol",  "interface",
                                        "dest_ip", "icmp_type", NULL};
            for (int i = 0; keys[i]; i++)
                if (uci_lookup_option(ctx, s, keys[i]))
                    text(r, keys[i], uci_string(ctx, s, keys[i]));
            if (uci_lookup_option(ctx, s, "ports"))
                put(r, "ports", uci_list_value(ctx, s, "ports", false));
            if (uci_lookup_option(ctx, s, "dest_port"))
                put(r, "dest_port", uci_number(uci_string(ctx, s, "dest_port")));
            put(get(db, "rules"), s->e.name, r);
            continue;
        }
        need(!strcmp(s->type, "profile"), "Unknown UCI section");
        valid_id(s->e.name);
        J *p = obj(), *cfg = obj(), *policy = obj();
        text(p, "id", s->e.name);
        text(p, "name", uci_string(ctx, s, "name"));
        text(p, "secret", uci_string(ctx, s, "secret"));
        put(p, "revision", uci_number(uci_string(ctx, s, "revision")));
        put(p, "enabled", uci_bool(uci_string(ctx, s, "enabled")));
        put(p, "revoked", uci_bool(uci_string(ctx, s, "revoked")));
        const char *const numbers[] = {"period", "base", "idle_timeout", "seq_timeout", NULL};
        for (int i = 0; numbers[i]; i++)
            put(cfg, numbers[i], uci_number(uci_string(ctx, s, numbers[i])));
        put(cfg, "ip_protection", uci_bool(uci_string(ctx, s, "ip_protection")));
        put(cfg, "ports", uci_list_value(ctx, s, "ports", true));
        if (uci_lookup_option(ctx, s, "named_rules") || uci_lookup_option(ctx, s, "rules") ||
            uci_lookup_option(ctx, s, "allowed_rules")) {
            put(cfg, "rules", uci_list_value(ctx, s, "rules", false));
            put(policy, "allowed_rules", uci_list_value(ctx, s, "allowed_rules", false));
        }
        put(cfg, "protocols", uci_list_value(ctx, s, "protocols", false));
        put(policy, "allowed_ports", uci_list_value(ctx, s, "allowed_ports", true));
        put(policy, "max_idle_timeout", uci_number(uci_string(ctx, s, "max_idle_timeout")));
        put(policy, "can_configure", uci_bool(uci_string(ctx, s, "can_configure")));
        put(policy, "allow_browser_transport",
            uci_bool(uci_string(ctx, s, "allow_browser_transport")));
        put(p, "settings", cfg);
        put(p, "policy", policy);
        put(profiles, s->e.name, p);
    }
    uci_free_context(ctx);
    validate_database(db);
    return db;
}
static J *load(void) {
    char *raw = read_file(config_path, 1024 * 1024, NULL);
    J *db = decode_config(raw, true);
    free(raw);
    return db;
}
static bool configured(void) {
    if (!exists(config_path))
        return false;
    char *raw = read_file(config_path, 1024 * 1024, NULL);
    J *db = decode_config(raw, false);
    free(raw);
    bool ready = db != NULL;
    if (db)
        json_object_put(db);
    return ready;
}
static void uci_quote(FILE *f, const char *s) {
    fputc('\'', f);
    for (; *s; s++) {
        if (*s == '\'')
            fputs("'\\''", f);
        else
            fputc(*s, f);
    }
    fputc('\'', f);
}
static void uci_field(FILE *f, const char *key, J *value) {
    if (json_object_is_type(value, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(value); i++) {
            J *v = json_object_array_get_idx(value, i);
            fprintf(f, "\tlist %s ", key);
            uci_quote(f, json_object_is_type(v, json_type_string) ? str(v) : json(v));
            fputc('\n', f);
        }
    } else {
        fprintf(f, "\toption %s ", key);
        uci_quote(f, json_object_is_type(value, json_type_boolean)  ? (flag(value) ? "1" : "0")
                     : json_object_is_type(value, json_type_string) ? str(value)
                                                                    : json(value));
        fputc('\n', f);
    }
}
static void save_config(J *db) {
    validate_database(db);
    char *raw = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&raw, &size);
    need(f != NULL, "Out of memory");
    fputs("# Managed by knock-control. Contains client secrets: keep mode 0600.\nconfig server "
          "'main'\n\toption initialized '1'\n",
          f);
    json_object_object_foreach(db, k, v) {
        if (strcmp(k, "profiles") && strcmp(k, "rules"))
            uci_field(f, k, v);
    }
    if (get(db, "rules")) {
        json_object_object_foreach(get(db, "rules"), name, r) {
            fprintf(f, "\nconfig rule '%s'\n", name);
            json_object_object_foreach(r, key, value) {
                uci_field(f, key, value);
            }
        }
    }
    json_object_object_foreach(get(db, "profiles"), id, p) {
        fprintf(f, "\nconfig profile '%s'\n", id);
        if (get(get(p, "settings"), "rules"))
            fputs("\toption named_rules '1'\n", f);
        json_object_object_foreach(p, key, value) {
            if (!strcmp(key, "settings") || !strcmp(key, "policy")) {
                json_object_object_foreach(value, name, entry) {
                    uci_field(f, name, entry);
                }
            } else if (strcmp(key, "id"))
                uci_field(f, key, value);
        }
        if (!get(get(p, "policy"), "allow_browser_transport"))
            fputs("\toption allow_browser_transport '1'\n", f);
    }
    need(fclose(f) == 0, "Cannot serialize UCI configuration");
    J *roundtrip = decode_config(raw, true);
    need(json_object_equal(roundtrip, db), "UCI serialization mismatch");
    json_object_put(roundtrip);
    atomic(config_path, raw);
    free(raw);
}
static void migrate_configuration(void) {
    if (!exists(legacy_path) || configured())
        return;
    char *raw = read_file(legacy_path, 1024 * 1024, NULL);
    J *db = parse(raw, strlen(raw));
    validate_database(db);
    char *backup = fmt("%s.pre-uci", legacy_path);
    if (exists(backup)) {
        char *previous = read_file(backup, 1024 * 1024, NULL);
        need(!strcmp(previous, raw), "Different legacy backup exists; inspect before migrating");
        free(previous);
    } else
        atomic(backup, raw);
    save_config(db);
    need(unlink(legacy_path) == 0, "Cannot retire migrated JSON configuration");
    free(backup);
    free(raw);
    json_object_put(db);
}
static char *hex(const unsigned char *bytes, size_t n) {
    static const char digits[] = "0123456789abcdef";
    char *s = alloc(n * 2 + 1);
    for (size_t i = 0; i < n; i++) {
        s[i * 2] = digits[bytes[i] >> 4];
        s[i * 2 + 1] = digits[bytes[i] & 15];
    }
    return s;
}
static void digest(const EVP_MD *md, const void *data, size_t size, unsigned char *out) {
    unsigned int n;
    need(EVP_Digest(data, size, out, &n, md, NULL) == 1, "Digest failed");
}
static char *sha256hex(const void *data, size_t n) {
    unsigned char d[32];
    digest(EVP_sha256(), data, n, d);
    return hex(d, 32);
}
static void random_bytes(unsigned char *out, int n) {
    need(RAND_bytes(out, n) == 1, "Secure random generator failed");
}
static char *random_hex(int n) {
    unsigned char buf[32];
    need(n > 0 && n <= 32, "Invalid random size");
    random_bytes(buf, n);
    return hex(buf, n);
}
static char *new_secret(void) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned char raw[20];
    random_bytes(raw, 20);
    char *s = alloc(33);
    unsigned int bits = 0, acc = 0;
    int j = 0;
    for (int i = 0; i < 20; i++) {
        acc = (acc << 8) | raw[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            s[j++] = chars[(acc >> bits) & 31];
        }
    }
    return s;
}
static void secret_key(const char *s, unsigned char out[20]) {
    unsigned int acc = 0, bits = 0;
    int j = 0;
    need(strlen(s) == 32, "Invalid key");
    for (int i = 0; i < 32; i++) {
        int v = s[i] >= 'A' && s[i] <= 'Z'   ? s[i] - 'A'
                : s[i] >= '2' && s[i] <= '7' ? s[i] - '2' + 26
                                             : -1;
        need(v >= 0, "Invalid key");
        acc = (acc << 5) | (unsigned int)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (acc >> bits) & 255;
        }
    }
}
static void mac(const EVP_MD *md, const char *secret, const void *data, size_t n,
                unsigned char *out) {
    unsigned char key[20];
    secret_key(secret, key);
    unsigned int len;
    need(HMAC(md, key, 20, data, n, out, &len) != NULL, "HMAC failed");
    OPENSSL_cleanse(key, sizeof(key));
}
static char *tag(J *p) {
    char *s = fmt("%s:%lld", sget(p, "secret"), (long long)iget(p, "revision", 1, 2147483647));
    char *h = sha256hex(s, strlen(s));
    free(s);
    h[16] = 0;
    return h;
}
static void counter_bytes(uint64_t step, unsigned char out[8]) {
    for (int i = 7; i >= 0; i--) {
        out[i] = step & 255;
        step >>= 8;
    }
}
static void totp(const char *secret, uint64_t step, char out[7]) {
    unsigned char c[8], d[20];
    counter_bytes(step, c);
    mac(EVP_sha1(), secret, c, 8, d);
    unsigned int o = d[19] & 15;
    uint32_t v = ((uint32_t)(d[o] & 127) << 24) | ((uint32_t)d[o + 1] << 16) |
                 ((uint32_t)d[o + 2] << 8) | d[o + 3];
    snprintf(out, 7, "%06u", v % 1000000);
}
static char *render(J *db) {
    char *buffer = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&buffer, &size);
    need(f != NULL, "Out of memory");
    fprintf(f,
            "# Server-issued profiles. Generated by knock-control.\n[options]\n    Interface = "
            "%s\n    UseSyslog\n",
            sget(db, "interface"));
    json_object_object_foreach(get(db, "profiles"), id, p) {
        if (bget(p, "revoked") || !bget(p, "enabled"))
            continue;
        J *cfg = config_for(db, p);
        char *credential = tag(p);
        const char *actions[] = {"open", "close"};
        for (int a = 0; a < 2; a++) {
            fprintf(f, "[%s.%s]\n    totp = %s, 30, %lld, %s", id, actions[a], sget(cfg, "secret"),
                    (long long)iget(cfg, "base", 1024, 65280),
                    bget(cfg, "ip_protection") ? "on" : "off");
            J *protocols = get(cfg, "protocols");
            for (size_t i = 0; i < json_object_array_length(protocols); i++)
                fprintf(f, ", %s", str(json_object_array_get_idx(protocols, i)));
            fprintf(f,
                    "\n    seq_timeout = %lld\n    tcpflags = syn,!ack,!rst\n    command = %s "
                    "access-%s %s %s %%IP%%\n",
                    (long long)iget(cfg, "seq_timeout", 1, 60), control_bin, actions[a], id,
                    credential);
            if (!get(get(p, "policy"), "allow_browser_transport") ||
                bget(get(p, "policy"), "allow_browser_transport"))
                fprintf(f,
                        "    ice_revision = %lld\n    ice_command = %s access-ice %s %s %%IP%%\n",
                        (long long)iget(p, "revision", 1, 2147483647), control_bin, id, credential);
        }
        free(credential);
        json_object_put(cfg);
    }
    need(fclose(f) == 0, "Render failed");
    return buffer;
}
static char *set_name(const char *id) {
    valid_id(id);
    return fmt("kc_%s", id);
}
static bool contains(const char *id, const char *ip) {
    need(ipv4(ip), "Invalid IPv4 address");
    char *s = fmt("get element inet fw4 kc_%s { %s }\n", id, ip);
    valid_id(id);
    int rc = nft(s);
    free(s);
    return rc == 0;
}
static void flush(const char *id) {
    valid_id(id);
    char *name = set_name(id);
    char *a[] = {"/usr/sbin/nft", "list", "set", "inet", "fw4", name, NULL};
    if (run(a, NULL, NULL) == 0) {
        char *s = fmt("flush set inet fw4 %s\n", name);
        need(nft(s) == 0, "Cannot flush profile grants");
        free(s);
    }
    free(name);
}
static void set_definition(FILE *f, J *p) {
    fprintf(f, "{ type ipv4_addr; flags dynamic,timeout; timeout %llds; size 4096; }",
            (long long)iget(get(p, "settings"), "idle_timeout", 10, 86400));
}
static char *port_text(J *p) {
    char *s = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&s, &n);
    need(f != NULL, "Out of memory");
    fputs("{ ", f);
    for (size_t i = 0; i < json_object_array_length(p); i++)
        fprintf(f, "%s%lld", i ? ", " : "",
                (long long)integer(json_object_array_get_idx(p, i), 1, 65535));
    fputs(" }", f);
    need(fclose(f) == 0, "Render failed");
    return s;
}
static char *rule_ports(J *r) {
    J *ps = get(r, "ports");
    char *s = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&s, &size);
    need(f != NULL, "Out of memory");
    fputs("{ ", f);
    for (size_t i = 0; i < json_object_array_length(ps); i++)
        fprintf(f, "%s%s", i ? ", " : "", str(json_object_array_get_idx(ps, i)));
    fputs(" }", f);
    need(fclose(f) == 0, "Render failed");
    return s;
}
static char *rule_match(J *db, J *r, bool reply, bool direct) {
    const char *kind = sget(r, "type"), *proto = sget(r, "protocol");
    const char *inter = get(r, "interface") ? sget(r, "interface") : sget(db, "interface");
    bool input = direct || !strcmp(kind, "input"), icmp = !strcmp(proto, "icmp");
    char *s = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&s, &size);
    need(f != NULL, "Out of memory");
    fprintf(f, "%s \"%s\" ", reply ? "oifname" : "iifname", inter);
    if (input) {
        if (icmp) {
            fputs("meta nfproto ipv4 meta l4proto icmp", f);
            if (strcmp(sget(r, "icmp_type"), "any"))
                fprintf(f, " icmp type %s", reply ? "echo-reply" : "echo-request");
        } else {
            char *ps = rule_ports(r);
            fprintf(f, "%s %s %s", proto, reply ? "sport" : "dport", ps);
            free(ps);
        }
    } else {
        fprintf(f, "ct direction %s meta l4proto %s ", reply ? "reply" : "original", proto);
        if (!strcmp(kind, "dnat"))
            fputs("ct status dnat ", f);
        else
            fprintf(f, "ct original ip daddr %s ", sget(r, "dest_ip"));
        if (!icmp) {
            char *ps = rule_ports(r);
            fprintf(f, "ct original proto-dst %s", ps);
            free(ps);
        } else if (strcmp(sget(r, "icmp_type"), "any"))
            fprintf(f, "icmp type %s", reply ? "echo-reply" : "echo-request");
    }
    need(fclose(f) == 0, "Render failed");
    return s;
}
/* INPUT/OUTPUT/FORWARD/PREROUTING, with filter guards preceding fw4's
 * established and flow-offload rules. A grant never bypasses the idle lease. */
static void named_rule_lines(FILE *f, J *db, int chain, const char *prefix) {
    J *definitions = get(db, "rules");
    if (!bget(db, "activated") || !definitions)
        return;
    json_object_object_foreach(get(db, "profiles"), id, p) {
        if (bget(p, "revoked") || !bget(p, "enabled"))
            continue;
        J *cfg = get(p, "settings"), *names = get(cfg, "rules");
        long long idle = iget(cfg, "idle_timeout", 10, 86400);
        for (size_t i = 0; names && i < json_object_array_length(names); i++) {
            J *r = get(definitions, str(json_object_array_get_idx(names, i)));
            bool input = !strcmp(sget(r, "type"), "input"), dnat = !strcmp(sget(r, "type"), "dnat");
            if ((input && chain <= 1) || (!input && chain == 2)) {
                for (int direction = (chain == 1 ? 1 : 0);
                     direction <= (chain == 2 ? 1 : (chain == 1 ? 1 : 0)); direction++) {
                    char *match = rule_match(db, r, direction, false);
                    fprintf(f, "%s%s", prefix, match);
                    free(match);
                    if (!input && dnat) {
                        fprintf(f, " %s %s", direction ? "ip saddr" : "ip daddr",
                                sget(r, "dest_ip"));
                        if (get(r, "dest_port"))
                            fprintf(f, " %s %s %lld", sget(r, "protocol"),
                                    direction ? "sport" : "dport",
                                    (long long)iget(r, "dest_port", 1, 65535));
                    }
                    const char *source =
                        input ? (direction ? "ip daddr" : "ip saddr") : "ct original ip saddr";
                    if (chain == 1)
                        fputs(" ct state established", f);
                    fprintf(f, " %s @kc_%s update @kc_%s { %s timeout %llds }%s\n", source, id, id,
                            source, idle, chain == 1 ? "" : " accept");
                }
            } else if (dnat && chain == 3) {
                char *match = rule_match(db, r, false, true);
                fprintf(f, "%s%s fib daddr type local ip saddr @kc_%s dnat ip to %s", prefix, match,
                        id, sget(r, "dest_ip"));
                if (get(r, "dest_port"))
                    fprintf(f, ":%lld", (long long)iget(r, "dest_port", 1, 65535));
                fputc('\n', f);
                free(match);
            }
        }
    }
    json_object_object_foreach(definitions, name, r) {
        (void)name;
        bool input = !strcmp(sget(r, "type"), "input"), dnat = !strcmp(sget(r, "type"), "dnat");
        if (chain == 0 && (input || dnat)) {
            char *match = rule_match(db, r, false, true);
            fprintf(f, "%s%s drop\n", prefix, match);
            free(match);
        } else if (chain == 2 && !input) {
            for (int direction = 0; direction < 2; direction++) {
                char *match = rule_match(db, r, direction, false);
                fprintf(f, "%s%s drop\n", prefix, match);
                free(match);
            }
        }
    }
}
static void rule_lines(FILE *f, J *db, bool outgoing, const char *prefix) {
    if (!bget(db, "activated"))
        return;
    if (!outgoing)
        fprintf(f, "%smeta nfproto ipv4 tcp dport %lld accept\n", prefix,
                (long long)iget(db, "api_port", 1, 65535));
    json_object_object_foreach(get(db, "profiles"), id, p) {
        if (bget(p, "revoked") || !bget(p, "enabled"))
            continue;
        J *cfg = config_for(db, p);
        if (!json_object_array_length(get(cfg, "ports"))) {
            json_object_put(cfg);
            continue;
        }
        char *pt = port_text(get(cfg, "ports"));
        long long timeout = iget(cfg, "idle_timeout", 10, 86400);
        if (outgoing)
            fprintf(f,
                    "%stcp sport %s ct state established ip daddr @kc_%s update @kc_%s { ip daddr "
                    "timeout %llds }\n",
                    prefix, pt, id, id, timeout);
        else {
            fprintf(f,
                    "%stcp dport %s ct state established ip saddr @kc_%s update @kc_%s { ip saddr "
                    "timeout %llds }\n",
                    prefix, pt, id, id, timeout);
            fprintf(f, "%stcp dport %s ip saddr @kc_%s accept\n", prefix, pt, id);
        }
        free(pt);
        json_object_put(cfg);
    }
    named_rule_lines(f, db, outgoing ? 1 : 0, prefix);
    if (!outgoing && json_object_array_length(get(db, "protected_ports"))) {
        char *pt = port_text(get(db, "protected_ports"));
        fprintf(f, "%smeta nfproto ipv4 tcp dport %s drop\n", prefix, pt);
        free(pt);
    }
}
static char *firewall_render(J *db) {
    char *s = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&s, &n);
    need(f != NULL, "Out of memory");
    fputs("# Managed by knock-control; live IP leases are not persisted.\n", f);
    if (bget(db, "activated")) {
        json_object_object_foreach(get(db, "profiles"), id, p) {
            fprintf(f, "set kc_%s ", id);
            set_definition(f, p);
            fputc('\n', f);
        }
    }
    fputs("chain knock_control_input {\n", f);
    rule_lines(f, db, false, "    ");
    fputs("}\nchain knock_control_output {\n", f);
    rule_lines(f, db, true, "    ");
    fputs("}\nchain knock_control_forward {\n", f);
    named_rule_lines(f, db, 2, "    ");
    fputs("}\nchain knock_control_prerouting {\n    type nat hook prerouting priority -101; policy "
          "accept;\n",
          f);
    named_rule_lines(f, db, 3, "    ");
    fputs("}\n", f);
    need(fclose(f) == 0, "Render failed");
    return s;
}
static void prepare(J *db) {
    char *s = firewall_render(db);
    atomic(rules_path, s);
    free(s);
}
static void firewall(J *db) {
    char *old = exists(rules_path) ? read_file(rules_path, 1024 * 1024, NULL) : NULL;
    prepare(db);
    char *a[] = {"/usr/sbin/nft", "list", "chain", "inet", "fw4", "knock_control_forward", NULL};
    bool reload = run(a, NULL, NULL) != 0;
    /* Drop any flows offloaded before a new protection rule existed. Protected
     * flows subsequently ACCEPT/DROP in our first jump and never reach ft. */
    if (get(db, "rules")) {
        bool forwards = false;
        json_object_object_foreach(get(db, "rules"), name, r) {
            (void)name;
            if (strcmp(sget(r, "type"), "input"))
                forwards = true;
        }
        char *ft[] = {"/usr/sbin/nft", "list", "flowtable", "inet", "fw4", "ft", NULL};
        if (forwards && run(ft, NULL, NULL) == 0)
            reload = true;
    }
    if (reload && service("firewall", "reload")) {
        if (old)
            atomic(rules_path, old);
        fail("Cannot install firewall hooks");
    }
    char *s = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&s, &n);
    need(f != NULL, "Out of memory");
    if (bget(db, "activated")) {
        json_object_object_foreach(get(db, "profiles"), id, p) {
            char *name = set_name(id);
            char *ls[] = {"/usr/sbin/nft", "list", "set", "inet", "fw4", name, NULL};
            if (run(ls, NULL, NULL)) {
                fprintf(f, "add set inet fw4 %s ", name);
                set_definition(f, p);
                fputc('\n', f);
            }
            free(name);
        }
    }
    fputs("flush chain inet fw4 knock_control_input\nflush chain inet fw4 knock_control_output\n",
          f);
    rule_lines(f, db, false, "add rule inet fw4 knock_control_input ");
    rule_lines(f, db, true, "add rule inet fw4 knock_control_output ");
    fputs("flush chain inet fw4 knock_control_forward\nflush chain inet fw4 "
          "knock_control_prerouting\n",
          f);
    named_rule_lines(f, db, 2, "add rule inet fw4 knock_control_forward ");
    named_rule_lines(f, db, 3, "add rule inet fw4 knock_control_prerouting ");
    need(fclose(f) == 0, "Render failed");
    int rc = nft(s);
    free(s);
    if (rc && old)
        atomic(rules_path, old);
    free(old);
    need(rc == 0, "Atomic firewall update failed");
}
static void publish(J *db, J *changed, bool start) {
    char *rendered = render(db), *validate = fmt("%s/.validate-XXXXXX", directory);
    int fd = mkostemp(validate, O_CLOEXEC);
    need(fd >= 0, "Cannot validate daemon configuration");
    write_all(fd, rendered, strlen(rendered));
    close(fd);
    char *a[] = {(char *)daemon_bin, "--check", "--config", validate, NULL};
    int rc = run(a, NULL, NULL);
    unlink(validate);
    free(validate);
    need(rc == 0, "Daemon rejected generated configuration");
    char *old = exists(config_path) ? read_file(config_path, 1024 * 1024, NULL) : NULL,
         *old_daemon = exists(daemon_path) ? read_file(daemon_path, 1024 * 1024, NULL) : NULL;
    bool running = active();
    jmp_buf transaction;
    jmp_buf *previous = failure;
    failure = &transaction;
    if (setjmp(transaction) == 0) {
        save_config(db);
        atomic(daemon_path, rendered);
        if (bget(db, "activated")) {
            if (changed)
                for (size_t i = 0; i < json_object_array_length(changed); i++)
                    flush(str(json_object_array_get_idx(changed, i)));
            firewall(db);
        }
        if (running)
            need(service("knock-control", "reload") == 0, "Daemon reload failed");
        else if (start)
            need(service("knock-control", "start") == 0, "Daemon start failed");
        failure = previous;
    } else {
        char original[sizeof(error_text)];
        memcpy(original, error_text, sizeof(original));
        /* Restore the committed profile and rule definitions before returning.
         * Leases already revoked stay closed; rollback never reopens them. */
        if (setjmp(transaction) == 0) {
            if (old) {
                atomic(config_path, old);
                if (old_daemon)
                    atomic(daemon_path, old_daemon);
                J *before = decode_config(old, true);
                if (bget(before, "activated"))
                    firewall(before);
                if (running)
                    service("knock-control", "reload");
            } else {
                unlink(config_path);
                unlink(daemon_path);
            }
        }
        failure = previous;
        fail(original);
    }
    free(rendered);
    free(old);
    free(old_daemon);
}
static J *own_status(J *db, const char *id) {
    J *p = get(get(db, "profiles"), id);
    need(p != NULL, "Unknown profile");
    J *r = obj();
    boolean(r, "ok", true);
    text(r, "profile_id", id);
    text(r, "name", sget(p, "name"));
    boolean(r, "enabled", bget(p, "enabled"));
    put(r, "revision", copy(get(p, "revision")));
    boolean(r, "daemon_running", active());
    J *cfg = config_for(db, p);
    put(r, "settings", public_settings(cfg));
    json_object_put(cfg);
    put(r, "policy", copy(get(p, "policy")));
    J *definitions = obj(), *names = get(get(p, "policy"), "allowed_rules");
    for (size_t i = 0; names && i < json_object_array_length(names); i++) {
        const char *name = str(json_object_array_get_idx(names, i));
        put(definitions, name, copy(get(get(db, "rules"), name)));
    }
    put(r, "rules", definitions);
    return r;
}
static void access_profile(J *db, const char *action, const char *id, const char *credential,
                           const char *ip) {
    valid_id(id);
    need(ipv4(ip), "Invalid IPv4 address");
    J *p = get(get(db, "profiles"), id);
    need(p != NULL, "Unknown profile");
    char *expected = tag(p);
    need(!bget(p, "revoked") && bget(p, "enabled") && bget(db, "activated") &&
             strlen(credential) == 16 && CRYPTO_memcmp(credential, expected, 16) == 0,
         "Credential disabled, revoked or replaced");
    free(expected);
    bool present = contains(id, ip);
    char *s = NULL;
    if (!strcmp(action, "access-open"))
        s = fmt("%sadd element inet fw4 kc_%s { %s timeout %llds }\n",
                present ? fmt("delete element inet fw4 kc_%s { %s }\n", id, ip) : "", id, ip,
                (long long)iget(get(p, "settings"), "idle_timeout", 10, 86400));
    else {
        need(!strcmp(action, "access-close"), "Unknown access action");
        if (present)
            s = fmt("delete element inet fw4 kc_%s { %s }\n", id, ip);
    }
    if (s) {
        need(nft(s) == 0, "Cannot update profile grant");
        free(s);
    }
}
static void reserve_nonce_order(const char *id, const char *nonce, time_t now, const char *profile,
                                const char *source, uint64_t issued) {
    sqlite3 *db = NULL;
    sqlite3_stmt *q = NULL;
    bool ok = sqlite3_open(replay_path, &db) == SQLITE_OK;
    if (ok) {
        chmod(replay_path, 0600);
        sqlite3_busy_timeout(db, 5000);
        ok = sqlite3_exec(db,
                          "CREATE TABLE IF NOT EXISTS nonces (profile TEXT, nonce TEXT, expires "
                          "INTEGER, PRIMARY KEY(profile,nonce));BEGIN IMMEDIATE;",
                          NULL, NULL, NULL) == SQLITE_OK;
    }
    if (ok)
        ok = sqlite3_prepare_v2(db, "DELETE FROM nonces WHERE expires < ?", -1, &q, NULL) ==
             SQLITE_OK;
    if (ok) {
        sqlite3_bind_int64(q, 1, now);
        ok = sqlite3_step(q) == SQLITE_DONE;
    }
    sqlite3_finalize(q);
    q = NULL;
    if (ok)
        ok = sqlite3_prepare_v2(db, "SELECT count(*) FROM nonces", -1, &q, NULL) == SQLITE_OK;
    if (ok)
        ok = sqlite3_step(q) == SQLITE_ROW && sqlite3_column_int(q, 0) < 10000;
    sqlite3_finalize(q);
    q = NULL;
    if (ok)
        ok = sqlite3_prepare_v2(db, "INSERT INTO nonces VALUES (?,?,?)", -1, &q, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(q, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(q, 2, nonce, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(q, 3, now + 121);
        ok = sqlite3_step(q) == SQLITE_DONE;
    }
    sqlite3_finalize(q);
    q = NULL;
    if (ok && profile) {
        ok = sqlite3_exec(db,
                          "CREATE TABLE IF NOT EXISTS ice_order(profile TEXT,source TEXT,issued "
                          "INTEGER,expires INTEGER,PRIMARY KEY(profile,source));",
                          NULL, NULL, NULL) == SQLITE_OK;
        if (ok)
            ok = sqlite3_prepare_v2(db, "DELETE FROM ice_order WHERE expires < ?", -1, &q, NULL) ==
                 SQLITE_OK;
        if (ok) {
            sqlite3_bind_int64(q, 1, now);
            ok = sqlite3_step(q) == SQLITE_DONE;
        }
        sqlite3_finalize(q);
        q = NULL;
        if (ok)
            ok = sqlite3_prepare_v2(
                     db,
                     "INSERT INTO ice_order VALUES(?,?,?,?) ON CONFLICT(profile,source) DO UPDATE "
                     "SET issued=excluded.issued,expires=excluded.expires WHERE ice_order.issued < "
                     "excluded.issued",
                     -1, &q, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_text(q, 1, profile, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(q, 2, source, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(q, 3, (sqlite3_int64)issued);
            sqlite3_bind_int64(q, 4, now + 121);
            ok = sqlite3_step(q) == SQLITE_DONE && sqlite3_changes(db) == 1;
        }
        sqlite3_finalize(q);
        q = NULL;
    }
    if (ok)
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (db)
        sqlite3_close(db);
    need(ok, "Authentication failed or replay capacity exceeded");
}
static void reserve_nonce(const char *id, const char *nonce, time_t now) {
    reserve_nonce_order(id, nonce, now, NULL, NULL, 0);
}
static void access_ice(J *db, const char *id, const char *credential, const char *ip,
                       const char *token) {
    valid_id(id);
    need(ipv4(ip), "Invalid source IPv4");
    J *p = get(get(db, "profiles"), id);
    need(p && bget(db, "activated") && bget(p, "enabled") && !bget(p, "revoked"),
         "ICE credential disabled");
    need(!get(get(p, "policy"), "allow_browser_transport") ||
             bget(get(p, "policy"), "allow_browser_transport"),
         "Browser transport disabled");
    char *expected = tag(p);
    need(strlen(credential) == 16 && CRYPTO_memcmp(credential, expected, 16) == 0,
         "Stale callback");
    const char *action = strlen(token) == KNC_ICE_LENGTH && token[28] == 'O' ? "open" : "close";
    char *door = fmt("%s.%s", id, action);
    need(knc_ice_verify(token, sget(p, "secret"), door,
                        (unsigned)iget(p, "revision", 1, 2147483647), ip,
                        bget(get(p, "settings"), "ip_protection"), time(NULL)),
         "Invalid ICE authentication");
    uint64_t issued;
    knc_hex(token + 53, 16, &issued);
    char nonce[33];
    memcpy(nonce, token + 69, 32);
    nonce[32] = 0;
    char *scope = fmt("ice:%s", id);
    reserve_nonce_order(scope, nonce, time(NULL), id, ip, issued);
    access_profile(db, !strcmp(action, "open") ? "access-open" : "access-close", id, credential,
                   ip);
    free(expected);
    free(door);
    free(scope);
}
static const char *authenticate(J *db, const char *header, const char *body, size_t n) {
    http_status = 401;
    need(header && strlen(header) < 200 && !strncmp(header, "Knock ", 6), "Authentication failed");
    char *value = strdup(header + 6);
    need(value != NULL, "Out of memory");
    char *p = value, *id = strsep(&p, ":"), *stamp = strsep(&p, ":"), *nonce = strsep(&p, ":"),
         *signature = strsep(&p, ":");
    need(id && stamp && nonce && signature && !p && is_hex(id, 24) && is_hex(nonce, 32) &&
             is_hex(signature, 64),
         "Authentication failed");
    size_t len = strlen(stamp);
    need(len >= 1 && len <= 12, "Authentication failed");
    for (size_t i = 0; i < len; i++)
        need(isdigit((unsigned char)stamp[i]), "Authentication failed");
    time_t now = time(NULL);
    need(llabs((long long)now - strtoll(stamp, NULL, 10)) <= 60, "Authentication failed");
    J *profile = get(get(db, "profiles"), id);
    need(profile && !bget(profile, "revoked"), "Authentication failed");
    char *body_hash = sha256hex(body, n),
         *message = fmt("knock-control:api:v2:POST:/v1/control:%s:%s:%s", stamp, nonce, body_hash);
    unsigned char d[32];
    mac(EVP_sha256(), sget(profile, "secret"), message, strlen(message), d);
    char *expected = hex(d, 32);
    need(CRYPTO_memcmp(signature, expected, 64) == 0, "Authentication failed");
    reserve_nonce(id, nonce, now);
    http_status = 400;
    free(message);
    free(expected);
    free(body_hash);
    return id;
}
static char *verify_browser_proof(J *db, J *profile, J *request, const char *source) {
    J *policy = get(profile, "policy");
    need(!get(policy, "allow_browser_transport") || bget(policy, "allow_browser_transport"),
         "Browser transport disabled");
    need(bget(profile, "enabled") && bget(db, "activated"), "Profile or server inactive");
    need(ipv4(source), "Invalid IPv4 address");
    const char *encoded = sget(request, "confirmation");
    need(strlen(encoded) == 80, "Invalid confirmation");
    for (int i = 0; i < 80; i++)
        need(isalnum((unsigned char)encoded[i]) || encoded[i] == '+' || encoded[i] == '/',
             "Invalid confirmation");
    unsigned char proof[61];
    need(EVP_DecodeBlock(proof, (const unsigned char *)encoded, 80) == 60 &&
             !memcmp(proof, "KNC1", 4),
         "Invalid confirmation");
    uint64_t step = 0;
    for (int i = 4; i < 12; i++)
        step = (step << 8) | proof[i];
    uint64_t now = (uint64_t)time(NULL) / 30;
    need(step <= now + 1 && step + 1 >= now, "Expired confirmation");
    J *cfg = config_for(db, profile);
    const char *id = sget(profile, "id"), *action = sget(request, "action") + 8,
               *ip = bget(cfg, "ip_protection") ? source : "-";
    char *door = fmt("%s.%s:%s", id, action, ip);
    size_t door_len = strlen(door), prefix_len = strlen("knock-control:confirm:v1:");
    unsigned char message[512], expected[32];
    need(prefix_len + 24 + door_len <= sizeof(message), "Confirmation too large");
    memcpy(message, "knock-control:confirm:v1:", prefix_len);
    memcpy(message + prefix_len, proof + 4, 24);
    memcpy(message + prefix_len + 24, door, door_len);
    mac(EVP_sha256(), sget(profile, "secret"), message, prefix_len + 24 + door_len, expected);
    need(CRYPTO_memcmp(expected, proof + 28, 32) == 0, "Invalid confirmation");
    char code[7];
    totp(sget(profile, "secret"), step, code);
    char *mapped = fmt("knock-control:v1:%s:%s", door, code);
    digest(EVP_sha256(), mapped, strlen(mapped), expected);
    J *sequence = get(request, "sequence"), *protocols = get(cfg, "protocols");
    need(json_object_is_type(sequence, json_type_array) &&
             json_object_array_length(sequence) == json_object_array_length(protocols),
         "Incomplete knock sequence");
    for (size_t i = 0; i < json_object_array_length(protocols); i++) {
        J *pair = json_object_array_get_idx(sequence, i);
        need(json_object_is_type(pair, json_type_array) && json_object_array_length(pair) == 2,
             "Incomplete knock sequence");
        need(integer(json_object_array_get_idx(pair, 0), 1, 65535) ==
                     iget(cfg, "base", 1024, 65280) + expected[i] &&
                 !strcmp(str(json_object_array_get_idx(pair, 1)),
                         str(json_object_array_get_idx(protocols, i))),
             "Incomplete knock sequence");
    }
    char *nonce = hex(proof + 12, 16);
    free(door);
    free(mapped);
    json_object_put(cfg);
    return nonce;
}
static void browser_access(J *db, J *profile, J *request, const char *source) {
    char *nonce = verify_browser_proof(db, profile, request, source);
    const char *id = sget(profile, "id");
    char *scope = fmt("confirm:%s", id), *credential = tag(profile),
         *operation = fmt("access-%s", sget(request, "action") + 8);
    reserve_nonce(scope, nonce, time(NULL));
    access_profile(db, operation, id, credential, source);
    free(nonce);
    free(scope);
    free(credential);
    free(operation);
}
static bool allowed_key(const char *key, const char *const *keys) {
    for (; *keys; keys++)
        if (!strcmp(key, *keys))
            return true;
    return false;
}
static J *dispatch(J *db, J *request, const char *id, const char *source) {
    static const char *const fields[] = {"action",   "settings",     "revision",
                                         "sequence", "confirmation", NULL};
    need(json_object_is_type(request, json_type_object), "Expected request object");
    json_object_object_foreach(request, key, value) {
        (void)value;
        need(allowed_key(key, fields), "Only authenticated profile operations are allowed");
    }
    J *profile = get(get(db, "profiles"), id);
    need(profile && !bget(profile, "revoked"), "Credential revoked or unknown");
    const char *action = sget(request, "action");
    if (!strcmp(action, "status"))
        return own_status(db, id);
    if (!strcmp(action, "browser-open") || !strcmp(action, "browser-close")) {
        browser_access(db, profile, request, source);
        J *r = own_status(db, id);
        text(r, "message", !strcmp(action, "browser-open") ? "Access enabled" : "Access disabled");
        return r;
    }
    need(!strcmp(action, "configure"), "Unknown action");
    need(iget(request, "revision", 1, 2147483647) == iget(profile, "revision", 1, 2147483646),
         "Profile changed; refresh status");
    J *policy = get(profile, "policy");
    need(bget(policy, "can_configure"), "Settings changes disabled");
    J *patch = get(request, "settings"), *candidate = copy(profile);
    need(json_object_is_type(patch, json_type_object), "Expected settings object");
    static const char *const editable[] = {
        "ports", "rules", "idle_timeout", "protocols", "seq_timeout", "ip_protection", NULL};
    json_object_object_foreach(patch, k, v) {
        need(allowed_key(k, editable), "Setting is not editable");
        put(get(candidate, "settings"), k, copy(v));
    }
    J *cfg = config_for(db, candidate), *ps = get(cfg, "ports"),
      *allowed = get(policy, "allowed_ports");
    for (size_t i = 0; i < json_object_array_length(ps); i++)
        need(has_port(allowed, integer(json_object_array_get_idx(ps, i), 1, 65535)),
             "Port outside profile policy");
    J *chosen = get(cfg, "rules"), *permitted = get(policy, "allowed_rules");
    for (size_t i = 0; chosen && i < json_object_array_length(chosen); i++)
        need(has_string(permitted, str(json_object_array_get_idx(chosen, i))),
             "Rule outside profile policy");
    need(iget(cfg, "idle_timeout", 10, 86400) <= iget(policy, "max_idle_timeout", 10, 86400),
         "Idle timeout outside profile policy");
    J *published = public_settings(cfg);
    json_object_object_del(published, "interface");
    json_object_object_del(published, "profile_id");
    put(profile, "settings", published);
    number(profile, "revision", iget(profile, "revision", 1, 2147483646) + 1);
    J *changed = arr();
    append(changed, json_object_new_string(id));
    publish(db, changed, false);
    return own_status(db, id);
}
static J *bundle(J *db, const char *id) {
    valid_id(id);
    J *p = get(get(db, "profiles"), id);
    need(p && !bget(p, "revoked"), "Unknown or revoked profile");
    J *r = obj();
    text(r, "format", "knock-control-client-v2");
    text(r, "profile_id", id);
    text(r, "name", sget(p, "name"));
    text(r, "server_url", sget(db, "server_url"));
    text(r, "server_certificate_sha256", sget(db, "certificate_sha256"));
    text(r, "knock_host", sget(db, "knock_host"));
    number(r, "ice_version", 1);
    text(r, "secret", sget(p, "secret"));
    J *cfg = config_for(db, p);
    put(r, "settings", public_settings(cfg));
    put(r, "revision", copy(get(p, "revision")));
    json_object_put(cfg);
    return r;
}
static char *base64url(const char *s) {
    size_t n = strlen(s);
    need(n <= 8192, "Enrollment too large");
    char *out = alloc(4 * ((n + 2) / 3) + 1);
    int len = EVP_EncodeBlock((unsigned char *)out, (const unsigned char *)s, (int)n);
    while (len && out[len - 1] == '=')
        out[--len] = 0;
    for (int i = 0; i < len; i++) {
        if (out[i] == '+')
            out[i] = '-';
        if (out[i] == '/')
            out[i] = '_';
    }
    return out;
}
static char *enrollment(J *b) {
    J *c = obj(), *cfg = get(b, "settings"), *s = arr();
    number(c, "v", 2);
    if (get(b, "ice_version"))
        put(c, "w", copy(get(b, "ice_version")));
    text(c, "u", sget(b, "server_url"));
    text(c, "f", sget(b, "server_certificate_sha256"));
    text(c, "i", sget(b, "profile_id"));
    text(c, "n", sget(b, "name"));
    text(c, "k", sget(b, "secret"));
    text(c, "h", sget(b, "knock_host"));
    put(c, "r", copy(get(b, "revision")));
    append(s, copy(get(cfg, "base")));
    append(s, copy(get(cfg, "ports")));
    append(s, copy(get(cfg, "idle_timeout")));
    J *ps = get(cfg, "protocols");
    char protocols[21] = {0};
    for (size_t i = 0; i < json_object_array_length(ps); i++)
        protocols[i] = !strcmp(str(json_object_array_get_idx(ps, i)), "tcp") ? 't' : 'u';
    append(s, json_object_new_string(protocols));
    append(s, copy(get(cfg, "seq_timeout")));
    append(s, json_object_new_int(bget(cfg, "ip_protection") ? 1 : 0));
    if (get(cfg, "rules"))
        append(s, copy(get(cfg, "rules")));
    put(c, "s", s);
    char *encoded = base64url(json(c)),
         *url = fmt("%s/app/#import=kc2_%s", sget(b, "server_url"), encoded);
    free(encoded);
    json_object_put(c);
    return url;
}
static bool module(QRcode *qr, int x, int y) {
    return x >= 0 && y >= 0 && x < qr->width && y < qr->width && (qr->data[y * qr->width + x] & 1);
}
static void be32(FILE *f, uint32_t n) {
    unsigned char b[] = {n >> 24, n >> 16, n >> 8, n};
    need(fwrite(b, 1, 4, f) == 4, "QR write failed");
}
static void png_chunk(FILE *f, const char *kind, const unsigned char *data, uint32_t n) {
    be32(f, n);
    fwrite(kind, 1, 4, f);
    if (n)
        fwrite(data, 1, n, f);
    uLong crc = crc32(0, (const Bytef *)kind, 4);
    if (n)
        crc = crc32(crc, data, n);
    be32(f, crc);
}
static void qr_output(J *b, const char *path, bool terminal) {
    char *url = enrollment(b);
    QRcode *qr = QRcode_encodeString8bit(url, 0, QR_ECLEVEL_M);
    free(url);
    need(qr != NULL, "Cannot encode enrollment QR");
    if (path) {
        const char *ext = strrchr(path, '.');
        need(ext && (!strcasecmp(ext, ".png") || !strcasecmp(ext, ".svg")),
             "QR output must be .png or .svg");
        char *bytes = NULL;
        size_t n = 0;
        FILE *f = open_memstream(&bytes, &n);
        need(f != NULL, "Out of memory");
        int width = qr->width + 8;
        if (!strcasecmp(ext, ".svg")) {
            fprintf(
                f,
                "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 %d %d\" width=\"%d\" "
                "height=\"%d\"><rect width=\"100%%\" height=\"100%%\" fill=\"white\"/><path d=\"",
                width, width, width * 6, width * 6);
            for (int y = 0; y < qr->width; y++)
                for (int x = 0; x < qr->width; x++)
                    if (module(qr, x, y))
                        fprintf(f, "M%d,%dh1v1h-1z ", x + 4, y + 4);
            fputs("\" fill=\"black\"/></svg>", f);
        } else {
            unsigned int pixels = width * 6;
            size_t raw_size = (pixels + 1) * pixels;
            unsigned char *raw = alloc(raw_size);
            for (unsigned int y = 0; y < pixels; y++)
                for (unsigned int x = 0; x < pixels; x++)
                    raw[y * (pixels + 1) + x + 1] =
                        module(qr, (int)(x / 6) - 4, (int)(y / 6) - 4) ? 0 : 255;
            uLongf zipped_size = compressBound(raw_size);
            unsigned char *zipped = alloc(zipped_size);
            need(compress2(zipped, &zipped_size, raw, raw_size, 9) == Z_OK,
                 "QR compression failed");
            fwrite("\x89PNG\r\n\x1a\n", 1, 8, f);
            unsigned char ihdr[13] = {pixels >> 24,
                                      pixels >> 16,
                                      pixels >> 8,
                                      pixels,
                                      pixels >> 24,
                                      pixels >> 16,
                                      pixels >> 8,
                                      pixels,
                                      8,
                                      0,
                                      0,
                                      0,
                                      0};
            png_chunk(f, "IHDR", ihdr, 13);
            png_chunk(f, "IDAT", zipped, (uint32_t)zipped_size);
            png_chunk(f, "IEND", NULL, 0);
            free(raw);
            free(zipped);
        }
        need(fclose(f) == 0, "QR write failed");
        atomic_bytes(path, bytes, n);
        free(bytes);
    }
    if (terminal) {
        fputs("\033[30;47m", stdout);
        for (int y = -4; y < qr->width + 4; y += 2) {
            for (int x = -4; x < qr->width + 4; x++) {
                bool top = module(qr, x, y), bottom = module(qr, x, y + 1);
                fputs(top ? (bottom ? "█" : "▀") : (bottom ? "▄" : " "), stdout);
            }
            fputc('\n', stdout);
        }
        fputs("\033[0m\n", stdout);
    }
    QRcode_free(qr);
}
static char *certificate_fingerprint(const char *cert, const char *key) {
    FILE *f = fopen(cert, "r");
    need(f != NULL, "Cannot read TLS certificate");
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    need(x != NULL, "Invalid TLS certificate");
    f = fopen(key, "r");
    need(f != NULL, "Cannot read TLS key");
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    need(k && X509_check_private_key(x, k) == 1, "TLS certificate and key do not match");
    unsigned char d[32];
    unsigned int n;
    need(X509_digest(x, EVP_sha256(), d, &n) == 1 && n == 32, "Certificate fingerprint failed");
    X509_free(x);
    EVP_PKEY_free(k);
    return hex(d, 32);
}
static void serve(J *db) {
    char *address = fmt("%s:%lld", sget(db, "api_bind"), (long long)iget(db, "api_port", 1, 65535));
    /* The dedicated docroot contains only the CGI trampoline. Missing URLs
     * go to that trampoline, which serves an exact static whitelist and API.
     * This preserves CSP/security headers without adding a uhttpd module. */
    char *a[] = {"/usr/sbin/uhttpd",
                 "-f",
                 "-s",
                 address,
                 "-C",
                 cert_path,
                 "-K",
                 key_path,
                 "-h",
                 "/usr/share/knock-control/http",
                 "-x",
                 "/cgi-bin",
                 "-E",
                 "/cgi-bin/control",
                 "-D",
                 "-S",
                 "-n",
                 "8",
                 "-N",
                 "32",
                 "-t",
                 "30",
                 "-T",
                 "5",
                 "-k",
                 "0",
                 NULL};
    execv(a[0], a);
    fail("Cannot start dedicated uhttpd instance");
}
static void reply(int code, J *value) {
    const char *s = json(value);
    printf("Status: %d %s\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: "
           "no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %zu\r\nConnection: "
           "close\r\n\r\n%s",
           code, code == 200 ? "OK" : "Error", strlen(s), s);
}
static const char *env(const char *name) {
    const char *v = getenv(name);
    return v ? v : "";
}
static bool rate_allowed(const char *ip) {
    /* Shared tmpfs buckets survive CGI exits, bounded by 4096 active peers.
     * They never write traffic counters to the router's flash. */
    need(mkdir("/var/run/knock-control", 0700) == 0 || errno == EEXIST,
         "Cannot create runtime directory");
    const char *path = "/var/run/knock-control/rates.json";
    J *rates = obj();
    if (exists(path)) {
        size_t n;
        char *data = read_file(path, 1024 * 1024, &n);
        json_object_put(rates);
        rates = parse(data, n);
        free(data);
    }
    int64_t bucket = time(NULL) / 60;
    J *fresh = obj();
    json_object_object_foreach(rates, k, v) {
        if (json_object_is_type(v, json_type_array) && json_object_array_length(v) == 2 &&
            integer(json_object_array_get_idx(v, 0), 0, INT64_MAX) == bucket)
            put(fresh, k, copy(v));
    }
    J *old = get(fresh, ip);
    if (!old && json_object_object_length(fresh) >= 4096)
        return false;
    int count = old ? (int)integer(json_object_array_get_idx(old, 1), 0, INT32_MAX) : 0;
    if (count >= 120)
        return false;
    J *entry = arr();
    append(entry, json_object_new_int64(bucket));
    append(entry, json_object_new_int(count + 1));
    put(fresh, ip, entry);
    atomic(path, json(fresh));
    json_object_put(rates);
    json_object_put(fresh);
    return true;
}
static void lock_controller(void) {
    static int held = -1;
    if (held >= 0)
        return;
    int fd = open("/var/lock/knock-control.lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    need(fd >= 0 && flock(fd, LOCK_EX) == 0, "Cannot lock controller");
    held = fd;
}
static void http(void) {
    struct rlimit memory = {64 * 1024 * 1024, 64 * 1024 * 1024};
    setrlimit(RLIMIT_AS, &memory);
    http_status = 400;
    const char *uri = env("REQUEST_URI"), *method = env("REQUEST_METHOD"),
               *source = env("REMOTE_ADDR");
    need(!strcmp(env("HTTPS"), "on"), "HTTPS required");
    need(ipv4(source), "IPv4 required");
    int rate_lock =
        open("/var/lock/knock-control-rate.lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    need(rate_lock >= 0 && flock(rate_lock, LOCK_EX) == 0, "Cannot lock rate limiter");
    http_status = 429;
    need(rate_allowed(source), "Request limit exceeded");
    close(rate_lock);
    http_status = 400;
    if (!strcmp(method, "GET") || !strcmp(method, "HEAD")) {
        static const char *const files[] = {"app.html",
                                            "app.webmanifest",
                                            "style.css",
                                            "icon.svg",
                                            "app.js",
                                            "bridge.js",
                                            "browser-client.js",
                                            "ice-client.js",
                                            "profile-codec.js",
                                            "transport-config.js",
                                            "qr.js",
                                            "i18n.js",
                                            "ice-operation.js",
                                            "sw.js",
                                            "vendor/jsQR.js",
                                            "icon-48.png",
                                            "_locales/en/messages.json",
                                            "_locales/ru/messages.json",
                                            "_locales/de/messages.json",
                                            "_locales/fr/messages.json",
                                            "_locales/es/messages.json",
                                            "_locales/pt_BR/messages.json",
                                            "_locales/zh_CN/messages.json",
                                            "_locales/ja/messages.json",
                                            "_locales/ar/messages.json",
                                            "_locales/hi/messages.json",
                                            "icon-180.png",
                                            "icon-192.png",
                                            "icon-512.png",
                                            NULL};
        const char *file = !strcmp(uri, "/app/")       ? "app.html"
                           : !strncmp(uri, "/app/", 5) ? uri + 5
                                                       : "";
        http_status = 404;
        need(allowed_key(file, files), "Unknown endpoint");
        size_t n;
        char *path = fmt("/usr/share/knock-control/app/%s", file),
             *data = read_file(path, 1024 * 1024, &n);
        const char *ext = strrchr(file, '.'),
                   *type = !strcmp(ext, ".html")  ? "text/html; charset=utf-8"
                           : !strcmp(ext, ".js")  ? "text/javascript; charset=utf-8"
                           : !strcmp(ext, ".css") ? "text/css; charset=utf-8"
                           : !strcmp(ext, ".png") ? "image/png"
                           : !strcmp(ext, ".svg") ? "image/svg+xml"
                           : !strcmp(ext, ".json") ? "application/json; charset=utf-8"
                                                  : "application/manifest+json";
        printf("Status: 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: "
               "no-cache\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: "
               "no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; "
               "connect-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; object-src "
               "'none'; base-uri 'none'; frame-ancestors 'none'\r\nPermissions-Policy: "
               "camera=(self), microphone=(), geolocation=()\r\nConnection: close\r\n\r\n",
               type, n);
        if (!strcmp(method, "GET"))
            fwrite(data, 1, n, stdout);
        free(path);
        free(data);
        return;
    }
    http_status = 404;
    need(!strcmp(uri, "/v1/control"), "Unknown endpoint");
    http_status = 405;
    need(!strcmp(method, "POST"), "POST required");
    http_status = 400;
    const char *length = env("CONTENT_LENGTH");
    need(*length && strlen(length) <= 5, "Content-Length required");
    for (const char *p = length; *p; p++)
        need(isdigit((unsigned char)*p), "Invalid Content-Length");
    long n = strtol(length, NULL, 10);
    http_status = 413;
    need(n >= 1 && n <= 65536, "Request too large");
    http_status = 400;
    char *body = alloc((size_t)n + 1);
    need(fread(body, 1, (size_t)n, stdin) == (size_t)n, "Incomplete request body");
    lock_controller();
    J *db = load();
    const char *id = authenticate(db, env("HTTP_AUTHORIZATION"), body, (size_t)n);
    J *request = parse(body, (size_t)n), *response = dispatch(db, request, id, source);
    boolean(response, "access_active", contains(id, source));
    text(response, "observed_ip", source);
    reply(200, response);
}
static J *parse_ports(const char *s) {
    J *a = arr();
    char *value = strdup(s), *p = value, *part;
    need(value != NULL, "Out of memory");
    while ((part = strsep(&p, ","))) {
        need(*part, "Invalid port list");
        for (char *q = part; *q; q++)
            need(isdigit((unsigned char)*q), "Invalid port list");
        char *end;
        long n = strtol(part, &end, 10);
        need(!*end && n >= 1 && n <= 65535, "Invalid port");
        append(a, json_object_new_int((int)n));
    }
    free(value);
    return a;
}
static J *options(int argc, char **argv, J *positionals) {
    J *o = obj();
    for (int i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "--", 2)) {
            const char *key = argv[i] + 2;
            need(*key && !get(o, key), "Duplicate or invalid option");
            if (!strcmp(key, "fixed-settings") || !strcmp(key, "native-only") ||
                !strcmp(key, "terminal"))
                boolean(o, key, true);
            else {
                need(i + 1 < argc && strncmp(argv[i + 1], "--", 2),
                     fmt("Option --%s requires a value; run 'knock-control help'.", key));
                text(o, key, argv[++i]);
            }
        } else
            append(positionals, json_object_new_string(argv[i]));
    }
    return o;
}
static J *parse_words(const char *s) {
    J *a = arr();
    if (!*s)
        return a;
    char *value = strdup(s), *p = value, *part;
    need(value != NULL, "Out of memory");
    while ((part = strsep(&p, ","))) {
        need(*part, "Empty list entry");
        append(a, json_object_new_string(part));
    }
    free(value);
    return a;
}
static const char *opt(J *o, const char *k, const char *def) {
    return get(o, k) ? sget(o, k) : def;
}
static int optint(J *o, const char *k, int def, int lo, int hi) {
    if (!get(o, k))
        return def;
    const char *s = sget(o, k);
    need(*s && strlen(s) <= 10, "Invalid numeric option");
    for (const char *p = s; *p; p++)
        need(isdigit((unsigned char)*p), "Invalid numeric option");
    long long n = strtoll(s, NULL, 10);
    need(n >= lo && n <= hi, "Numeric option outside allowed range");
    return (int)n;
}
static J *success(void) {
    J *r = obj();
    boolean(r, "ok", true);
    return r;
}
struct cli_help_entry {
    const char *name, *description, *usage, *details;
    bool internal;
};
static const struct cli_help_entry cli_commands[] = {
    {"init", "Initialize the server and generate TLS files",
     "init --public-host HOST [--interface DEVICE] [--api-port PORT] [--bind IPV4]",
     "Required:\n  --public-host HOST  Public DNS name or IPv4 reachable by clients.\n"
     "Options:\n  --interface DEVICE  Incoming knock interface (default: eth0).\n"
     "  --api-port PORT     HTTPS control port (default: 8443).\n"
     "  --bind IPV4         Listen address (default: 0.0.0.0).\n\n"
     "Example (replace HOST and DEVICE with your values):\n"
     "  knock-control init --public-host router.example.com --interface WAN_DEVICE --api-port "
     "8443\n\n"
     "Find the WAN interface:\n  ubus call network.interface.wan status\n\n"
     "Initialization writes /etc/config/knock-control and generates a self-signed\n"
     "certificate. For browser access, install a browser-trusted certificate with\n"
     "'knock-control tls'. Then issue a client profile and run 'knock-control activate'.\n"
     "Initialization alone does not activate protected ports.",
     false},
    {"issue", "Generate a client secret and export its profile",
     "issue --name NAME [--ports PORTS] [--rules RULES] --out FILE [OPTIONS]",
     "Required: --name NAME, --out FILE, and --ports or --rules\n"
     "PORTS is a comma-separated list of TCP ports.\n"
     "Options:\n  --allowed-ports PORTS    Ports permitted by this profile's policy (default: "
     "--ports).\n"
     "  --rules NAMES            Comma-separated server-owned rule names.\n"
     "  --allowed-rules NAMES    Rule selection policy (default: --rules).\n"
     "  --idle-timeout SECONDS   Traffic idle timeout (default: 600).\n"
     "  --max-idle-timeout SEC   Policy limit (default: 3600).\n"
     "  --fixed-settings        Disable client settings changes.\n"
     "  --native-only           Disable browser ON/OFF transport.\n"
     "  --qr-out FILE.png/.svg  Also export an offline enrollment QR.\n\n"
     "Example:\n  knock-control issue --name Phone --ports 2222 --out /root/phone.json --qr-out "
     "/root/phone.png",
     false},
    {"export", "Export an existing client profile", "export PROFILE_ID --out FILE", NULL, false},
    {"qr", "Create an enrollment QR for an existing profile",
     "qr PROFILE_ID [--out FILE.png/.svg] [--terminal]", "Choose --out, --terminal, or both.",
     false},
    {"tls", "Install a matching TLS certificate and private key", "tls --cert FILE --key FILE",
     "Example:\n  knock-control tls --cert /path/fullchain.pem --key /path/privkey.pem", false},
    {"activate", "Start control services and activate port protection", "activate", NULL, false},
    {"list", "List profiles without revealing their secrets", "list", NULL, false},
    {"rules", "List named server firewall rules", "rules", NULL, false},
    {"rule-set", "Create or replace a named firewall rule",
     "rule-set NAME --type input|forward|dnat --protocol tcp|udp|icmp [OPTIONS]",
     "--ports 22,1000-1010   TCP/UDP ports or ranges.\n"
     "--dest-ip IPV4        Required for forward/dnat.\n"
     "--dest-port PORT      DNAT translation of one port; ranges retain their ports.\n"
     "--icmp-type echo-request|any   Default: echo-request.\n"
     "--interface DEVICE    Default: server incoming interface.\n"
     "Example: knock-control rule-set ssh_lan --type dnat --protocol tcp --ports 2222 --dest-ip "
     "192.168.1.10 --dest-port 22",
     false},
    {"revoke", "Revoke a profile and remove its grants", "revoke PROFILE_ID", NULL, false},
    {"apply", "Apply committed UCI settings and clear current grants", "apply",
     "For manual UCI edits, use:\n  uci commit knock-control\n  /etc/init.d/knock-control reload",
     false},
    {"firewall", "Regenerate and apply Knock Control firewall rules", "firewall", NULL, false},
    {"migrate", "Migrate the legacy JSON configuration to UCI", "migrate", NULL, false},
    {"serve", "Run the dedicated HTTPS server in the foreground", "serve", NULL, true},
    {"configured", "Check whether the server is initialized", "configured", NULL, true},
    {"activated", "Check whether protection is activated", "activated", NULL, true},
    {"generate-config", "Regenerate the daemon configuration", "generate-config", NULL, true},
    {"prepare-firewall", "Prepare the persistent firewall include", "prepare-firewall", NULL, true},
    {"access-open", "Internal authenticated knock callback", "access-open PROFILE_ID TAG IPV4",
     NULL, true},
    {"access-close", "Internal authenticated knock callback", "access-close PROFILE_ID TAG IPV4",
     NULL, true},
    {"access-ice", "Internal authenticated ICE callback", "access-ice PROFILE_ID TAG IPV4 TOKEN",
     NULL, true},
};
static const struct cli_help_entry *cli_command(const char *name) {
    for (size_t i = 0; i < sizeof(cli_commands) / sizeof(cli_commands[0]); i++)
        if (!strcmp(cli_commands[i].name, name))
            return &cli_commands[i];
    fail("Unknown command; run 'knock-control help'.");
    return NULL;
}
static bool help_flag(const char *s) {
    return !strcmp(s, "--help") || !strcmp(s, "-h");
}
static void print_cli_help(const char *command) {
    if (command) {
        const struct cli_help_entry *entry = cli_command(command);
        printf("%s\n\nUsage: knock-control %s\n", entry->description, entry->usage);
        if (entry->details)
            printf("\n%s\n", entry->details);
        return;
    }
    puts("Knock Control for OpenWrt\n\nUsage: knock-control COMMAND [OPTIONS]\n\nCommands:");
    for (size_t i = 0; i < sizeof(cli_commands) / sizeof(cli_commands[0]); i++)
        if (!cli_commands[i].internal)
            printf("  %-12s %s\n", cli_commands[i].name, cli_commands[i].description);
    puts("  help [COMMAND]  Show help without changing configuration\n\n"
         "Use 'knock-control help init' or 'knock-control init --help' for setup.\n"
         "Configuration: /etc/config/knock-control (UCI).\n"
         "Server operations require root; help is available to all users.");
}
static bool cli_help(int argc, char **argv) {
    if (!argc) {
        print_cli_help(NULL);
        return true;
    }
    if (!strcmp(argv[0], "help") || help_flag(argv[0])) {
        need(argc <= 2, "Usage: knock-control help [COMMAND]");
        print_cli_help(argc == 2 ? argv[1] : NULL);
        return true;
    }
    for (int i = 1; i < argc; i++)
        if (help_flag(argv[i])) {
            print_cli_help(argv[0]);
            return true;
        }
    return false;
}
static void validate_cli(const char *action, J *o, J *pos) {
    static const char *const none
        [] = {NULL},
    *const init_opts[] = {"public-host", "interface", "api-port", "bind", NULL},
    *const issue_opts[] = {"name",          "rules",        "allowed-rules",    "ports",
                           "allowed-ports", "idle-timeout", "max-idle-timeout", "fixed-settings",
                           "out",           "qr-out",       "native-only",      NULL},
    *const export_opts[] = {"out", NULL}, *const qr_opts[] = {"out", "terminal", NULL},
    *const tls_opts[] = {"cert", "key", NULL}, *const init_required[] = {"public-host", NULL},
    *const issue_required[] = {"name", "out", NULL}, *const rule_opts[] = {"type",      "protocol",
                                                                           "ports",     "dest-ip",
                                                                           "dest-port", "icmp-type",
                                                                           "interface", NULL};
    const char *const *allowed = none, *const *required = none;
    size_t count = 0;
    if (!strcmp(action, "init")) {
        allowed = init_opts;
        required = init_required;
    } else if (!strcmp(action, "issue")) {
        allowed = issue_opts;
        required = issue_required;
    } else if (!strcmp(action, "rule-set")) {
        allowed = rule_opts;
        count = 1;
    } else if (!strcmp(action, "export")) {
        allowed = export_opts;
        required = export_opts;
        count = 1;
    } else if (!strcmp(action, "qr")) {
        allowed = qr_opts;
        count = 1;
    } else if (!strcmp(action, "tls")) {
        allowed = tls_opts;
        required = tls_opts;
    } else if (!strcmp(action, "revoke"))
        count = 1;
    else if (!strcmp(action, "access-ice"))
        count = 4;
    else if (!strcmp(action, "access-open") || !strcmp(action, "access-close"))
        count = 3;
    json_object_object_foreach(o, key, value) {
        (void)value;
        need(allowed_key(key, allowed),
             fmt("Unknown option --%s; run 'knock-control %s --help'.", key, action));
    }
    need(json_object_array_length(pos) == count,
         fmt("Unexpected or missing argument; run 'knock-control %s --help'.", action));
    for (; *required; required++)
        if (!*opt(o, *required, "")) {
            if (!strcmp(action, "init"))
                fail("Missing required option --public-host. Example: knock-control init "
                     "--public-host router.example.com --interface WAN_DEVICE. Run 'knock-control "
                     "init --help'.");
            fail(fmt("Missing required option --%s; run 'knock-control %s --help'.", *required,
                     action));
        }
    if (!strcmp(action, "issue"))
        need(get(o, "ports") || get(o, "rules"),
             "Missing --ports or --rules; run 'knock-control help issue'.");
    if (!strcmp(action, "qr"))
        need(get(o, "out") || get(o, "terminal"),
             "Choose --out FILE.png/.svg or --terminal; run 'knock-control qr --help'.");
    const char *qr_path = !strcmp(action, "issue") ? opt(o, "qr-out", NULL)
                          : !strcmp(action, "qr")  ? opt(o, "out", NULL)
                                                   : NULL;
    if (qr_path) {
        const char *ext = strrchr(qr_path, '.');
        need(ext && (!strcasecmp(ext, ".png") || !strcasecmp(ext, ".svg")),
             "QR output must be .png or .svg");
    }
}
static J *initialize(J *o) {
    need(!configured(), "Already initialized; credentials will not be overwritten");
    const char *host = opt(o, "public-host", ""), *interface = opt(o, "interface", "eth0"),
               *bind = opt(o, "bind", "0.0.0.0");
    valid_host(host);
    valid_interface(interface);
    need(ipv4(bind), "Invalid bind address");
    int port = optint(o, "api-port", 8443, 1, 65535);
    need(mkdir(directory, 0700) == 0 || errno == EEXIST, "Cannot create configuration directory");
    need(chmod(directory, 0700) == 0, "Cannot protect configuration directory");
    char *san = fmt("subjectAltName=%s:%s", ipv4(host) ? "IP" : "DNS", host);
    char *a[] = {"/usr/bin/openssl", "req",    "-x509",   "-newkey", "rsa:3072",
                 "-sha256",          "-nodes", "-keyout", key_path,  "-out",
                 cert_path,          "-days",  "3650",    "-subj",   "/CN=Knock Control",
                 "-addext",          san,      NULL};
    checked(a, NULL);
    chmod(key_path, 0600);
    free(san);
    J *db = obj();
    number(db, "schema", 2);
    boolean(db, "activated", false);
    text(db, "interface", interface);
    text(db, "api_bind", bind);
    number(db, "api_port", port);
    char *url = fmt("https://%s:%d", host, port),
         *fingerprint = certificate_fingerprint(cert_path, key_path);
    text(db, "server_url", url);
    text(db, "knock_host", host);
    text(db, "certificate_sha256", fingerprint);
    put(db, "profiles", obj());
    put(db, "protected_ports", arr());
    save_config(db);
    char *rendered = render(db);
    atomic(daemon_path, rendered);
    free(rendered);
    free(url);
    free(fingerprint);
    J *r = success();
    text(r, "server_url", sget(db, "server_url"));
    return r;
}
static char *issue(J *db, J *o) {
    J *profiles = get(db, "profiles");
    need(json_object_object_length(profiles) < 128, "Maximum 128 profiles");
    const char *name = opt(o, "name", "");
    valid_name(name);
    J *initial = get(o, "ports") ? ports(parse_ports(sget(o, "ports")), 15) : arr(),
      *allowed = get(o, "allowed-ports") || get(o, "ports")
                     ? ports(parse_ports(opt(o, "allowed-ports", opt(o, "ports", ""))), 128)
                     : arr();
    int api = iget(db, "api_port", 1, 65535);
    need(!has_port(allowed, api), "API port cannot be protected by a profile");
    for (size_t i = 0; i < json_object_array_length(initial); i++)
        need(has_port(allowed, integer(json_object_array_get_idx(initial, i), 1, 65535)),
             "Initial port outside policy");
    int idle = optint(o, "idle-timeout", 600, 10, 86400),
        max_idle = optint(o, "max-idle-timeout", 3600, 10, 86400);
    need(idle <= max_idle, "Initial idle timeout exceeds policy");
    J *all = copy(get(db, "protected_ports"));
    for (size_t i = 0; i < json_object_array_length(allowed); i++) {
        int p = integer(json_object_array_get_idx(allowed, i), 1, 65535);
        if (!has_port(all, p))
            append(all, json_object_new_int(p));
    }
    int base = 0;
    for (int b = 20000; b < 65025; b += 256) {
        bool used = api >= b && api <= b + 255;
        if (get(db, "rules")) {
            json_object_object_foreach(get(db, "rules"), name, r) {
                (void)name;
                if (!strcmp(sget(r, "type"), "forward") || !strcmp(sget(r, "protocol"), "icmp"))
                    continue;
                J *ps = get(r, "ports");
                for (size_t i = 0; i < json_object_array_length(ps); i++) {
                    int lo, hi;
                    rule_bounds(str(json_object_array_get_idx(ps, i)), &lo, &hi);
                    if (hi >= b && lo <= b + 255)
                        used = true;
                }
            }
        }
        for (size_t i = 0; i < json_object_array_length(all); i++) {
            int p = integer(json_object_array_get_idx(all, i), 1, 65535);
            if (p >= b && p <= b + 255)
                used = true;
        }
        json_object_object_foreach(profiles, k, p) {
            (void)k;
            int existing = iget(get(p, "settings"), "base", 1024, 65280);
            if (existing == b)
                used = true;
            for (size_t i = 0; i < json_object_array_length(allowed); i++) {
                int port = integer(json_object_array_get_idx(allowed, i), 1, 65535);
                need(port < existing || port > existing + 255,
                     "Allowed port overlaps existing knock range");
            }
        }
        if (!used) {
            base = b;
            break;
        }
    }
    need(base != 0, "No free knock port range");
    char *id = random_hex(12);
    while (get(profiles, id)) {
        free(id);
        id = random_hex(12);
    }
    char *secret = new_secret();
    J *p = obj(), *cfg = obj(), *policy = obj();
    text(p, "id", id);
    text(p, "name", name);
    text(p, "secret", secret);
    boolean(p, "enabled", true);
    boolean(p, "revoked", false);
    number(p, "revision", 1);
    text(cfg, "secret", secret);
    number(cfg, "base", base);
    number(cfg, "idle_timeout", idle);
    put(cfg, "ports", initial);
    if (get(o, "rules")) {
        put(cfg, "rules", rule_names(parse_words(sget(o, "rules"))));
        put(policy, "allowed_rules",
            rule_names(parse_words(opt(o, "allowed-rules", sget(o, "rules")))));
    } else
        need(!get(o, "allowed-rules"), "--allowed-rules requires --rules");
    J *validated = settings(cfg), *pub = public_settings(validated);
    json_object_object_del(pub, "interface");
    put(p, "settings", pub);
    put(policy, "allowed_ports", allowed);
    number(policy, "max_idle_timeout", max_idle);
    boolean(policy, "can_configure", !get(o, "fixed-settings"));
    boolean(policy, "allow_browser_transport", !get(o, "native-only"));
    put(p, "policy", policy);
    put(profiles, id, p);
    put(db, "protected_ports", all);
    free(secret);
    return id;
}
static void install_tls(J *db, J *o) {
    const char *cert = opt(o, "cert", ""), *key = opt(o, "key", "");
    char *fingerprint = certificate_fingerprint(cert, key),
         *new_cert = read_file(cert, 1024 * 1024, NULL), *new_key = read_file(key, 65536, NULL),
         *old_cert = read_file(cert_path, 1024 * 1024, NULL),
         *old_key = read_file(key_path, 65536, NULL),
         *old_db = read_file(config_path, 1024 * 1024, NULL);
    jmp_buf transaction;
    jmp_buf *previous = failure;
    failure = &transaction;
    if (setjmp(transaction) == 0) {
        atomic(cert_path, new_cert);
        atomic(key_path, new_key);
        text(db, "certificate_sha256", fingerprint);
        save_config(db);
        need(service("knock-control-api", "restart") == 0, "API restart failed");
        failure = previous;
    } else {
        if (setjmp(transaction) == 0) {
            atomic(cert_path, old_cert);
            atomic(key_path, old_key);
            atomic(config_path, old_db);
            service("knock-control-api", "restart");
        }
        failure = previous;
        fail("TLS update failed; attempted restoration of previous configuration");
    }
    free(fingerprint);
    free(new_cert);
    free(new_key);
    free(old_cert);
    free(old_key);
    free(old_db);
}
static J *cli(int argc, char **argv) {
    if (cli_help(argc, argv))
        return NULL;
    const char *action = argv[0];
    cli_command(action);
    J *pos = arr(), *o = options(argc - 1, argv + 1, pos);
    validate_cli(action, o, pos);
    if (exists(legacy_path) && !configured()) {
        lock_controller();
        migrate_configuration();
    }
    if (!strcmp(action, "init")) {
        lock_controller();
        return initialize(o);
    }
    if (!strcmp(action, "migrate")) {
        return NULL;
    }
    if (!strcmp(action, "configured")) {
        need(configured(), "Server not initialized");
        return NULL;
    }
    if (!strcmp(action, "generate-config")) {
        J *db = load();
        char *rendered = render(db);
        char *temp = fmt("%s/.validate-XXXXXX", directory);
        int fd = mkostemp(temp, O_CLOEXEC);
        need(fd >= 0, "Cannot create validation file");
        write_all(fd, rendered, strlen(rendered));
        close(fd);
        char *cmd[] = {(char *)daemon_bin, "--check", "--config", temp, NULL};
        int rc = run(cmd, NULL, NULL);
        unlink(temp);
        free(temp);
        need(rc == 0, "Daemon configuration rejected");
        atomic(daemon_path, rendered);
        free(rendered);
        return NULL;
    }
    if (!strcmp(action, "apply")) {
        lock_controller();
        J *db = load(), *changed = arr();
        json_object_object_foreach(get(db, "profiles"), id, p) {
            number(p, "revision", iget(p, "revision", 1, 2147483646) + 1);
            append(changed, json_object_new_string(id));
        }
        publish(db, changed, false);
        return success();
    }
    if (!strcmp(action, "serve")) {
        serve(load());
    }
    if (!strcmp(action, "activated")) {
        need(bget(load(), "activated"), "Server not activated");
        return NULL;
    }
    if (!strcmp(action, "firewall") || !strcmp(action, "prepare-firewall")) {
        J *db;
        if (!strcmp(action, "prepare-firewall") && !configured()) {
            db = obj();
            boolean(db, "activated", false);
        } else
            db = load();
        if (!strcmp(action, "firewall"))
            firewall(db);
        else
            prepare(db);
        return NULL;
    }
    lock_controller();
    J *db = load(), *r = success();
    if (!strcmp(action, "issue")) {
        char *id = issue(db, o);
        J *changed = arr();
        append(changed, json_object_new_string(id));
        publish(db, changed, false);
        J *b = bundle(db, id);
        if (get(o, "qr-out"))
            qr_output(b, sget(o, "qr-out"), false);
        atomic(sget(o, "out"), json(b));
        text(r, "profile_id", id);
        text(r, "client_file", sget(o, "out"));
        free(id);
    } else if (!strcmp(action, "rules")) {
        return get(db, "rules") ? copy(get(db, "rules")) : obj();
    } else if (!strcmp(action, "rule-set")) {
        const char *name = str(json_object_array_get_idx(pos, 0));
        valid_rule_name(name);
        J *v = obj();
        text(v, "type", opt(o, "type", "input"));
        text(v, "protocol", opt(o, "protocol", "tcp"));
        if (get(o, "ports"))
            put(v, "ports", parse_words(sget(o, "ports")));
        if (get(o, "dest-ip"))
            text(v, "dest_ip", sget(o, "dest-ip"));
        if (get(o, "dest-port"))
            number(v, "dest_port", optint(o, "dest-port", 0, 1, 65535));
        if (get(o, "icmp-type"))
            text(v, "icmp_type", sget(o, "icmp-type"));
        if (get(o, "interface"))
            text(v, "interface", sget(o, "interface"));
        J *normalized = normalize_rule(v);
        if (!get(db, "rules"))
            put(db, "rules", obj());
        put(get(db, "rules"), name, normalized);
        J *changed = arr();
        json_object_object_foreach(get(db, "profiles"), id, p) {
            number(p, "revision", iget(p, "revision", 1, 2147483646) + 1);
            append(changed, json_object_new_string(id));
        }
        publish(db, changed, false);
        text(r, "rule", name);
    } else if (!strcmp(action, "export")) {
        J *b = bundle(db, str(json_object_array_get_idx(pos, 0)));
        need(*opt(o, "out", ""), "--out required");
        atomic(sget(o, "out"), json(b));
        text(r, "client_file", sget(o, "out"));
    } else if (!strcmp(action, "qr")) {
        need(get(o, "out") || get(o, "terminal"), "Choose --out profile.png/.svg or --terminal");
        qr_output(bundle(db, str(json_object_array_get_idx(pos, 0))), opt(o, "out", NULL),
                  get(o, "terminal") != NULL);
        if (get(o, "terminal"))
            return NULL;
        text(r, "qr_file", sget(o, "out"));
    } else if (!strcmp(action, "tls")) {
        install_tls(db, o);
        text(r, "message", "TLS updated; re-export profiles to update certificate pins");
    } else if (!strcmp(action, "activate")) {
        need(service("knock-control-api", "start") == 0, "API start failed");
        boolean(db, "activated", true);
        J *changed = arr();
        json_object_object_foreach(get(db, "profiles"), id, p) {
            (void)p;
            append(changed, json_object_new_string(id));
        }
        publish(db, changed, true);
        boolean(r, "activated", true);
    } else if (!strcmp(action, "list")) {
        r = arr();
        json_object_object_foreach(get(db, "profiles"), id, p) {
            J *item = obj();
            text(item, "id", id);
            text(item, "name", sget(p, "name"));
            boolean(item, "enabled", bget(p, "enabled"));
            boolean(item, "revoked", bget(p, "revoked"));
            put(item, "ports", copy(get(get(p, "settings"), "ports")));
            if (get(get(p, "settings"), "rules"))
                put(item, "rules", copy(get(get(p, "settings"), "rules")));
            append(r, item);
        }
    } else if (!strcmp(action, "revoke")) {
        const char *id = str(json_object_array_get_idx(pos, 0));
        valid_id(id);
        J *p = get(get(db, "profiles"), id);
        need(p != NULL, "Unknown profile");
        boolean(p, "revoked", true);
        boolean(p, "enabled", false);
        number(p, "revision", iget(p, "revision", 1, 2147483646) + 1);
        J *changed = arr();
        append(changed, json_object_new_string(id));
        publish(db, changed, false);
    } else if (!strcmp(action, "access-ice"))
        access_ice(db, str(json_object_array_get_idx(pos, 0)),
                   str(json_object_array_get_idx(pos, 1)), str(json_object_array_get_idx(pos, 2)),
                   str(json_object_array_get_idx(pos, 3)));
    else
        access_profile(db, action, str(json_object_array_get_idx(pos, 0)),
                       str(json_object_array_get_idx(pos, 1)),
                       str(json_object_array_get_idx(pos, 2)));
    return r;
}
int main(int argc, char **argv) {
    umask(0077);
    bool is_http = argc == 2 && !strcmp(argv[1], "http");
    if (setjmp(main_failure)) {
        J *r = obj();
        boolean(r, "ok", false);
        text(r, "error",
             is_http ? (http_status == 401   ? "Authentication failed"
                        : http_status == 429 ? "Request limit exceeded"
                        : http_status == 404 ? "Unknown endpoint"
                                             : "Operation rejected or unavailable")
                     : error_text);
        if (is_http)
            reply(http_status, r);
        else
            puts(json(r));
        return 1;
    }
    if (!is_http && (argc < 2 || strcmp(argv[1], "--state-dir")) && cli_help(argc - 1, argv + 1))
        return 0;
    need(geteuid() == 0, "Run controller as root");
    if (argc >= 4 && !strcmp(argv[1], "--state-dir")) {
        need(!getenv("GATEWAY_INTERFACE"), "Custom state directory is CLI-only");
        need(argv[2][0] == '/' && strlen(argv[2]) < sizeof(directory) - 32,
             "Use an absolute state directory");
        strcpy(directory, argv[2]);
        paths();
        J *r = cli(argc - 3, argv + 3);
        if (r)
            puts(json(r));
        return 0;
    }
    paths();
    if (is_http)
        http();
    else {
        J *r = cli(argc - 1, argv + 1);
        if (r)
            puts(json(r));
    }
    return 0;
}

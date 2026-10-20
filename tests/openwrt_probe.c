/* Native network probe for disposable OpenWrt tests. Never installed in APK.
 * Its JSON stdin keeps test credentials out of argv and shell expansions. */
#define main controller_main
#include "../packaging/openwrt/control.c"
#undef main
#include <openssl/ssl.h>
#include <sys/socket.h>
static const char *destination = "127.0.0.1";

static void socket_timeout(int fd, int seconds) {
    struct timeval value = {seconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value));
}
static int connection(const char *ip, int port, int type, bool connect_now) {
    int fd = socket(AF_INET, type, 0);
    need(fd >= 0, "socket failed");
    socket_timeout(fd, 2);
    struct sockaddr_in local = {.sin_family = AF_INET},
                       remote = {.sin_family = AF_INET, .sin_port = htons(port)};
    need(inet_pton(AF_INET, ip, &local.sin_addr) == 1, "Bad local IP");
    need(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0, "bind failed");
    need(inet_pton(AF_INET, destination, &remote.sin_addr) == 1, "Bad destination");
    if (connect_now && connect(fd, (struct sockaddr *)&remote, sizeof(remote)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}
static bool ping(int fd) {
    char data[2];
    return send(fd, "ok", 2, MSG_NOSIGNAL) == 2 && recv(fd, data, 2, MSG_WAITALL) == 2 &&
           !memcmp(data, "ok", 2);
}
static void echo_listener(int port) {
    signal(SIGCHLD, SIG_IGN);
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    need(fd >= 0, "socket failed");
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in local = {
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_ANY)};
    need(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0 && listen(fd, 32) == 0,
         "echo bind failed");
    for (;;) {
        int client = accept(fd, NULL, NULL);
        if (client < 0)
            continue;
        pid_t pid = fork();
        if (pid == 0) {
            close(fd);
            socket_timeout(client, 30);
            char b[1024];
            ssize_t n;
            while ((n = recv(client, b, sizeof(b), 0)) > 0) {
                if (send(client, b, (size_t)n, MSG_NOSIGNAL) != n)
                    break;
            }
            close(client);
            _exit(0);
        }
        close(client);
    }
}
static void udp_listener(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    need(fd >= 0, "socket failed");
    struct sockaddr_in local = {
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_ANY)};
    need(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0, "UDP echo bind failed");
    for (;;) {
        char data[2048];
        struct sockaddr_in peer;
        socklen_t size = sizeof(peer);
        ssize_t n = recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&peer, &size);
        if (n >= 0)
            sendto(fd, data, (size_t)n, 0, (struct sockaddr *)&peer, size);
    }
}
static J *probe(J *q) {
    const char *op = sget(q, "op");
    if (!strcmp(op, "database")) {
        if (get(q, "state_dir")) {
            const char *state = sget(q, "state_dir");
            need(state[0] == '/' && strlen(state) < sizeof(directory), "Invalid state directory");
            strcpy(directory, state);
        }
        paths();
        return load();
    }
    if (!strcmp(op, "echo") || !strcmp(op, "udp-echo")) {
        J *ps = get(q, "ports");
        for (size_t i = 0; i < json_object_array_length(ps); i++) {
            int port = integer(json_object_array_get_idx(ps, i), 1, 65535);
            pid_t pid = fork();
            need(pid >= 0, "fork failed");
            if (pid == 0) {
                if (!strcmp(op, "udp-echo"))
                    udp_listener(port);
                else
                    echo_listener(port);
            }
        }
        for (;;)
            pause();
    }
    const char *ip = sget(q, "ip");
    destination = get(q, "host") ? sget(q, "host") : "127.0.0.1";
    need(ipv4(destination), "Bad destination IP");
    need(ipv4(ip), "Bad IP");
    if (!strcmp(op, "tcp") || !strcmp(op, "stream") || !strcmp(op, "udp") ||
        !strcmp(op, "udp-stream")) {
        bool udp = !strcmp(op, "udp") || !strcmp(op, "udp-stream");
        int fd = connection(ip, iget(q, "port", 1, 65535), udp ? SOCK_DGRAM : SOCK_STREAM, true);
        bool ok = fd >= 0 && ping(fd);
        if (!strcmp(op, "stream") || !strcmp(op, "udp-stream")) {
            int seconds = iget(q, "seconds", 1, 120);
            for (int i = 0; ok && i < seconds * 2; i++) {
                struct timespec delay = {0, 500000000};
                nanosleep(&delay, NULL);
                ok = ping(fd);
            }
        }
        if (fd >= 0)
            close(fd);
        J *r = success();
        boolean(r, "reachable", ok);
        return r;
    }
    if (!strcmp(op, "noise")) {
        int fd = connection(ip, 1, SOCK_DGRAM, false), base = iget(q, "base", 1024, 65280);
        unsigned char b[60];
        memcpy(b, "KNC1", 4);
        struct sockaddr_in dst = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        uint64_t packets = 0;
        time_t deadline = time(NULL) + iget(q, "seconds", 1, 120);
        while (time(NULL) < deadline) {
            for (int i = 0; i < 50; i++) {
                for (int j = 4; j < 60; j++)
                    b[j] = (unsigned char)rand();
                dst.sin_port = htons(base + (rand() % 256));
                if (sendto(fd, b, sizeof(b), 0, (struct sockaddr *)&dst, sizeof(dst)) == sizeof(b))
                    packets++;
            }
            struct timespec delay = {0, 10000000};
            nanosleep(&delay, NULL);
        }
        close(fd);
        J *r = success();
        number(r, "packets", packets);
        return r;
    }
    if (!strcmp(op, "knock")) {
        J *seq = get(q, "sequence");
        for (size_t i = 0; i < json_object_array_length(seq); i++) {
            J *pair = json_object_array_get_idx(seq, i);
            int port = integer(json_object_array_get_idx(pair, 0), 1, 65535);
            const char *proto = str(json_object_array_get_idx(pair, 1));
            if (!strcmp(proto, "tcp")) {
                int fd = connection(ip, port, SOCK_STREAM, true);
                if (fd >= 0)
                    close(fd);
            } else {
                int fd = connection(ip, port, SOCK_DGRAM, false);
                struct sockaddr_in dst = {.sin_family = AF_INET,
                                          .sin_port = htons(port),
                                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
                sendto(fd, "\0", 1, 0, (struct sockaddr *)&dst, sizeof(dst));
                close(fd);
            }
            struct timespec delay = {0, 100000000};
            nanosleep(&delay, NULL);
        }
        unsigned char proof[128];
        const char *encoded = sget(q, "confirmation");
        need(strlen(encoded) == 80, "Bad proof size");
        int size = EVP_DecodeBlock(proof, (const unsigned char *)encoded, 80);
        need(size == 60, "Bad proof");
        int base = iget(q, "base", 1024, 65280), fd = connection(ip, base, SOCK_DGRAM, false);
        struct sockaddr_in dst = {.sin_family = AF_INET,
                                  .sin_port = htons(base),
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        need(sendto(fd, proof, 60, 0, (struct sockaddr *)&dst, sizeof(dst)) == 60, "send failed");
        close(fd);
        return success();
    }
    need(!strcmp(op, "https"), "Unknown probe operation");
    int fd = connection(ip, iget(q, "port", 1, 65535), SOCK_STREAM, true);
    need(fd >= 0, "API connection failed");
    socket_timeout(fd, 10);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    need(ctx != NULL, "TLS context failed");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL *ssl = SSL_new(ctx);
    need(ssl != NULL, "TLS client failed");
    SSL_set_fd(ssl, fd);
    need(SSL_connect(ssl) == 1, "TLS handshake failed");
    X509 *cert = SSL_get1_peer_certificate(ssl);
    need(cert != NULL, "Missing TLS certificate");
    unsigned char hash[32];
    unsigned int hash_size;
    need(X509_digest(cert, EVP_sha256(), hash, &hash_size) == 1, "TLS digest failed");
    char *pin = hex(hash, 32);
    need(!strcmp(pin, sget(q, "pin")), "TLS pin mismatch");
    free(pin);
    X509_free(cert);
    const char *body = opt(q, "body", ""), *method = opt(q, "method", "POST"),
               *url = opt(q, "url", "/v1/control"), *auth = opt(q, "authorization", "");
    char *request =
        fmt("%s %s HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: %zu\r\nAuthorization: "
            "%s\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n%s",
            method, url, strlen(body), auth, body);
    size_t written = 0;
    while (written < strlen(request)) {
        int n = SSL_write(ssl, request + written, (int)(strlen(request) - written));
        need(n > 0, "TLS write failed");
        written += n;
    }
    char *response = alloc(1024 * 1024 + 1);
    size_t used = 0;
    while (used < 1024 * 1024) {
        int n = SSL_read(ssl, response + used, (int)(1024 * 1024 - used));
        if (n <= 0)
            break;
        used += n;
    }
    need(used < 1024 * 1024, "HTTP response too large");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    free(request);
    char *separator = strstr(response, "\r\n\r\n");
    need(separator != NULL, "Malformed HTTP response");
    *separator = 0;
    int status = 0;
    need(sscanf(response, "HTTP/%*s %d", &status) == 1, "Malformed HTTP status");
    J *result = success();
    number(result, "status", status);
    text(result, "headers", response);
    text(result, "body", separator + 4);
    free(response);
    return result;
}
int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    if (setjmp(main_failure)) {
        fprintf(stderr, "%s\n", error_text);
        return 1;
    }
    char *line = NULL;
    size_t capacity = 0;
    ssize_t n = getline(&line, &capacity, stdin);
    need(n > 0 && n <= 131072, "Expected JSON input");
    J *q = parse(line, (size_t)n), *r = probe(q);
    puts(json(r));
    return 0;
}

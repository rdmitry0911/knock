/* Cross-language protocol tests; run by test_openwrt_native.py. No firewall
 * or root privileges are needed. This TU also runs under ASan/UBSan. */
#define main controller_main
#include "../packaging/openwrt/control.c"
#undef main
#include <assert.h>

static int rejected;
#define REJECT(expression)                                                                         \
    do {                                                                                           \
        jmp_buf expected_failure;                                                                  \
        failure = &expected_failure;                                                               \
        if (setjmp(expected_failure) == 0) {                                                       \
            expression;                                                                            \
            fprintf(stderr, "Unexpectedly accepted: %s\n", #expression);                           \
            abort();                                                                               \
        }                                                                                          \
        failure = &main_failure;                                                                   \
        rejected++;                                                                                \
    } while (0)

static __attribute__((noinline)) void ice_checks(J *fixture, J *profile, const char *id,
                                                 const char *ip) {
    if (get(fixture, "ice_split_token")) {
        const char *token = sget(fixture, "ice_split_token");
        char *door = fmt("%s.open", id), target[16];
        assert(knc_ice_verify(token, sget(profile, "secret"), door,
               (unsigned)iget(profile, "revision", 1, 2147483647), ip, 1, time(NULL)));
        assert(!knc_ice_verify(token, sget(profile, "secret"), door,
               (unsigned)iget(profile, "revision", 1, 2147483647), "127.0.0.99", 1, time(NULL)));
        knc_ice_target(token, ip, target);
        assert(!strcmp(target, "127.0.0.3"));
        for (unsigned i = 0; i < KNC_ICE_TCP_PROOF; i++)
            assert(knc_ice_proof_port(token, (unsigned)iget(get(profile, "settings"), "base", 1024, 65280), i) ==
                   json_object_get_int(json_object_array_get_idx(get(fixture, "ice_split_ports"), i)));
        free(door);
    }
    if (get(fixture, "ice_token")) {
        const char *token = sget(fixture, "ice_token");
        char *door = fmt("%s.open", id);
        assert(knc_ice_verify(token, sget(profile, "secret"), door,
                              (unsigned)iget(profile, "revision", 1, 2147483647), ip, 1,
                              time(NULL)));
        assert(!knc_ice_verify(token, sget(profile, "secret"), door,
                               (unsigned)iget(profile, "revision", 1, 2147483647), "127.0.0.99", 1,
                               time(NULL)));
        unsigned char packet[256] = {0, 1, 0, 176, 0x21, 0x12, 0xa4, 0x42};
        packet[21] = 6;
        packet[23] = 170;
        memcpy(packet + 24, token, 165);
        memcpy(packet + 189, ":abcd", 5);
        char decoded[KNC_ICE_LENGTH + 1];
        assert(knc_ice_stun(packet, 196, decoded));
        assert(!strcmp(decoded, token));
        for (size_t n = 0; n < 196; n++)
            assert(!knc_ice_stun(packet, n, decoded));
        for (unsigned i = 0; i < 10000; i++) {
            unsigned char noise[256];
            for (size_t j = 0; j < sizeof(noise); j++)
                noise[j] = (unsigned char)rand();
            knc_ice_stun(noise, i % 257, decoded);
        }
        uint64_t issued = 0;
        knc_hex(token + 53, 16, &issued);
        char *scope = fmt("ice:%s", id);
        reserve_nonce_order(scope, "11111111111111111111111111111111", time(NULL), id, ip, issued);
        REJECT(reserve_nonce_order(scope, "11111111111111111111111111111111", time(NULL), id, ip,
                                   issued + 1));
        REJECT(reserve_nonce_order(scope, "22222222222222222222222222222222", time(NULL), id, ip,
                                   issued - 1));
        reserve_nonce_order(scope, "33333333333333333333333333333333", time(NULL), id, "127.0.0.3",
                            issued - 1);
    }
}

int main(int argc, char **argv) {
    assert(argc == 3);
    if (setjmp(main_failure)) {
        fprintf(stderr, "%s\n", error_text);
        return 1;
    }
    if (!strcmp(argv[1], "--firewall")) {
        char *raw = read_file(argv[2], 1024 * 1024, NULL);
        J *db = parse(raw, strlen(raw));
        validate_database(db);
        char *rendered = firewall_render(db);
        fputs(rendered, stdout);
        return 0;
    }
    snprintf(directory, sizeof(directory), "%s", argv[1]);
    paths();
    size_t n;
    char *raw = read_file(argv[2], 1024 * 1024, &n);
    J *fixture = parse(raw, n);
    J *db = get(fixture, "db");
    const char *id = sget(fixture, "id");
    J *profile = get(get(db, "profiles"), id);
    const char *ip = sget(fixture, "ip");
    ice_checks(fixture, profile, id, ip);
    J *cfg = config_for(db, profile), *invalid = copy(cfg);
    number(invalid, "idle_timeout", 9);
    REJECT(settings(invalid));
    invalid = copy(cfg);
    boolean(invalid, "base", true);
    REJECT(settings(invalid));
    invalid = copy(cfg);
    number(invalid, "seq_timeout", 1);
    REJECT(settings(invalid));
    char *rendered = render(db);
    atomic(daemon_path, rendered);
    atomic(config_path, "config server 'main'\n\toption schema '2'\n\toption initialized '0'\n");
    atomic(legacy_path, json(db));
    /* Resume safely after an earlier attempt saved its backup but did not
     * yet publish UCI. A differing backup must never be overwritten. */
    atomic(fmt("%s.pre-uci", legacy_path), json(db));
    migrate_configuration();
    assert(json_object_equal(load(), db));
    assert(!exists(legacy_path) && exists(fmt("%s.pre-uci", legacy_path)));
    char *committed = read_file(config_path, 1024 * 1024, NULL);
    migrate_configuration();
    assert(!strcmp(committed, read_file(config_path, 1024 * 1024, NULL)));
    REJECT(decode_config("config server 'main'\n option initialized '1'\n", true));
    atomic(fmt("%s/firewall.nft", directory), firewall_render(db));
    J *b = bundle(db, id);
    atomic(fmt("%s/profile.json", directory), json(b));
    atomic(fmt("%s/enrollment.txt", directory), enrollment(b));
    qr_output(b, fmt("%s/profile.png", directory), false);
    qr_output(b, fmt("%s/profile.svg", directory), false);
    printf("PASS: native ICE HMAC, replay ordering, validation, QR and %d rejections\n", rejected);
    return 0;
}

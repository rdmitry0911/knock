/* Exercise the actual packet parser and OTP state machine without privileges. */
#define main knockd_program_main
#include "../src/knockd.c"
#undef main
#include <assert.h>

static void clear_attempts(void) {
    list_free(attempts);
    attempts = NULL;
}
static char packet_source[16] = "192.0.2.1";
static void packet(unsigned short port, unsigned char flags, time_t timestamp) {
    unsigned char bytes[128] = {0};
    struct ip ip = {0};
    struct tcphdr tcp = {0};
    struct pcap_pkthdr hdr = {0};
    ip.ip_v = 4; ip.ip_hl = 5; ip.ip_p = IPPROTO_TCP;
    ip.ip_len = htons(40);
    inet_aton(packet_source, &ip.ip_src);
    inet_aton("192.0.2.2", &ip.ip_dst);
    tcp.th_dport = htons(port); tcp.th_flags = flags;
    memcpy(bytes, &ip, 20); memcpy(bytes + 20, &tcp, 20);
    hdr.caplen = hdr.len = 40; hdr.ts.tv_sec = timestamp;
    sniff(NULL, &hdr, bytes);
}
int main(void) {
    opendoor_t door = {0};
    ip_literal_t local = {NULL, "192.0.2.2"};
    char otp[] = "testseed-open-123456,45,20000,on,tcp,tcp,tcp,tcp,tcp,tcp";
    unsigned short expected[] = {20091,20102,20186,20218,20127,20102,20014,20027,20141,20050,20162,20072};
    unsigned short ports[12];
    unsigned char bytes[128] = {0};
    struct pcap_pkthdr hdr = {0};
    const char *standard_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    long long times[] = {59,1111111109,1111111111,1234567890,2000000000,20000000000LL};
    const char *codes[] = {"287082","081804","050471","005924","279037","353130"};
    for(unsigned i=0;i<6;i++) { char code[7]; assert(!totp_code(standard_secret,times[i]/30,code)); assert(!strcmp(code,codes[i])); }
    assert(parse_otp_sequence(otp, &door) == 0);
    assert(fill_otp_ports(door.seed, ports, 0, 6, 1700000000LL/45, 20000) == 0);
    assert(fill_otp_ports("testseed-open-123456192.0.2.1", ports, 6, 12, 1700000000LL/45, 20000) == 0);
    assert(!memcmp(ports, expected, sizeof(ports)));
    char *bad[] = {"", "key", "key,0,20000,on,tcp", "key,45,65500,on,tcp", "key,45,20000,on", "key,45,20000,wat,tcp", "key,45,20000,on,", "key,-1,20000,on,tcp"};
    for(unsigned i=0; i<sizeof(bad)/sizeof(*bad); i++) {
        opendoor_t invalid = {0};
        char *copy = strdup(bad[i]);
        assert(parse_otp_sequence(copy, &invalid) != 0);
        free(copy);
    }
    lltype = DLT_RAW; myips = &local;
    doors = list_add(NULL, &door);
    refresh_otp_ports(1700000000);
    door.seq_timeout = 10;
    for(unsigned i=0; i<11; i++) packet(expected[i], TH_SYN, 1700000000);
    assert(attempts && ((knocker_t*)attempts->data)->stage == 11); // Must not complete at base six ports.
    packet(expected[11], TH_SYN, 1700000000);
    assert(((knocker_t*)attempts->data)->stage == 12);
    clear_attempts();
    packet(expected[0], TH_ACK, 1700000000); assert(!attempts);
    packet(expected[0], TH_SYN, 1700000000);
    packet(expected[1]+1, TH_SYN, 1700000000);
    assert(((knocker_t*)attempts->data)->stage == -1);
    clear_attempts();
    // Frozen sequence remains valid when an attempt crosses the OTP boundary.
    time_t boundary = (1700000000/45+1)*45;
    packet(expected[0], TH_SYN, boundary-1);
    for(unsigned i=1; i<12; i++) packet(expected[i], TH_SYN, boundary);
    assert(((knocker_t*)attempts->data)->stage == 12);
    clear_attempts();
    // Truncated frames, invalid IP header lengths and fragments are ignored.
    for(unsigned len=0; len<40; len++) { hdr.caplen=len; sniff(NULL,&hdr,bytes); }
    bytes[0]=0x4f; hdr.caplen=40; sniff(NULL,&hdr,bytes); assert(!attempts);
    // Removing list head preserves the other sources' attempts.
    knocker_t *first = calloc(1,sizeof(*first)), *second = calloc(1,sizeof(*second));
    first->door = second->door = &door; first->stage=-1; second->p_seqcount=12;
    second->seq_start=1700000000; strcpy(second->src,"198.51.100.1");
    attempts=list_add(attempts, first); attempts=list_add(attempts,second);
    packet(1,TH_ACK,1700000000);
    assert(attempts && attempts->data == second);
    clear_attempts();
    // Standard TOTP with deterministic noise inside the monitored range.
    doors->data=NULL; list_free(doors); doors=NULL;
    opendoor_t standard = {0};
    strcpy(standard.name,"open"); standard.totp_enabled=1;
    char totp[]="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ,30,20000,on,tcp,tcp,tcp,tcp,tcp,tcp";
    assert(!parse_otp_sequence(totp,&standard)); standard.seq_timeout=10;
    doors=list_add(NULL,&standard);
    unsigned short required[6];
    assert(!totp_ports(&standard,1700000000/30,"192.0.2.1",required));
    for(unsigned i=0;i<6;i++) {
        for(unsigned noise=0;noise<2000;noise++) {
            unsigned short port=20000+(noise*73+i*19)%256;
            int reserved=0; for(unsigned j=0;j<6;j++) if(port==required[j]) reserved=1;
            if(!reserved) packet(port,TH_SYN,1700000000);
            packet(required[i],TH_ACK,1700000000);
        }
        packet(required[i],TH_SYN,1700000000);
    }
    int complete=0;
    for(PMList *entry=attempts;entry;entry=entry->next) {
        knocker_t *attempt=entry->data;
        if(attempt->tm==1700000000/30 && attempt->stage==6) complete++;
    }
    assert(complete==1);
    clear_attempts();
    // Noise without a complete sequence never grants access, and expires.
    packet(required[0],TH_SYN,1700000000);
    for(unsigned i=0;i<10000;i++) packet(required[0],TH_ACK,1700000000);
    for(PMList *entry=attempts;entry;entry=entry->next) assert(((knocker_t*)entry->data)->stage<6);
    packet(1,TH_ACK,1700000011); assert(!attempts);
    // Spoofed sources cannot grow the attempt list beyond the hard cap.
    for(unsigned i=0;i<4500;i++) {
        snprintf(packet_source,sizeof(packet_source),"198.18.%u.%u",i/256,i%256);
        assert(!totp_ports(&standard,1700000000/30,packet_source,required));
        packet(required[0],TH_SYN,1700000000);
    }
    assert(list_count(attempts)==4096);
    packet(1,TH_ACK,1700000011); assert(!attempts);
    doors->data=NULL; list_free(doors); doors=NULL; myips=NULL;
    puts("C OTP / packet state-machine checks passed");
}

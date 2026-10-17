/*
 *  knockd.c
 *
 *  Copyright (c) 2004-2012 by Judd Vinet <jvinet@zeroflux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#if __APPLE__
/* In MacOSX 10.5+, the daemon function is deprecated and will give a warning.
 * This nasty hack which is used by Apple themselves in mDNSResponder does
 * the trick.
 */
#define daemon deprecated_in_osx_10_5_and_up
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <syslog.h>
#include <pcap.h>
#include <errno.h>
#include "list.h"


// #include <dos.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>


#if __APPLE__
#undef daemon
extern int daemon(int, int);
#endif

// #include "hmac/hmac_sha1.c"


static char version[] = "0.9.0";

#define SEQ_TIMEOUT 25 /* default knock timeout in seconds */
#define CMD_TIMEOUT 10 /* default timeout in seconds between start and stop commands */
#define SEQ_MAX     32 /* maximum number of ports in a knock sequence */
#define  MAX_SEED_LEN 129 /* maximum length of hmac_sha1 key */

typedef enum _flag_stat {
	DONT_CARE,  /* 0 */
	SET,        /* 1 */
	NOT_SET     /* 2 */
} flag_stat;

/* knock/event tuples */
typedef struct opendoor {
	char name[128];
	unsigned short seqcount;
	unsigned short sequence[SEQ_MAX];
	unsigned short protocol[SEQ_MAX];
	char *target;
	time_t seq_timeout;
	char *start_command;
	time_t cmd_timeout;
	char *stop_command;
	flag_stat flag_fin;
	flag_stat flag_syn;
	flag_stat flag_rst;
	flag_stat flag_psh;
	flag_stat flag_ack;
	flag_stat flag_urg;
	FILE *one_time_sequences_fd;
/*
 * We will use time-based otp with sender ip masking to make sure only the one who has otp_key will be granted access
 */

	char seed[MAX_SEED_LEN]; //key for hmac_sha1 hash
    unsigned short otp_change_time;
    unsigned short otp_port_range;
    long long tm; // time based variable
    unsigned short ip_protection; // if door has one
    int otp_enabled;
    int totp_enabled;
    long long cached_steps[3];
    char cached_codes[3][7];
} opendoor_t;

PMList *doors = NULL;

/* we keep one list of knock attempts per IP address,
 * and increment the stage as they progress through the sequence.
 */
typedef struct knocker {
	opendoor_t *door;
	short stage;
    int confirmed;
	char src[16];   /* IP address */
	char *srchost;  /* Hostname */
	time_t seq_start;

/* For ip-protected knocking */

    long long tm; // time based variable
    unsigned short p_seqcount;
    unsigned short p_sequence[SEQ_MAX*2];
    unsigned short p_protocol[SEQ_MAX*2];
} knocker_t;
PMList *attempts = NULL;

typedef struct p_attempt {
    struct p_attempt *next;
    char *filter;
    struct knocker *p_guy;

} pa;
pa *head_pa = NULL;

/* function prototypes */
void dprint(char *fmt, ...);
void vprint(char *fmt, ...);
void logprint(char *fmt, ...);
void dprint_sequence(opendoor_t *door, char *fmt, ...);
void cleanup(int signum);
void child_exit(int signum);
void reload(int signum);
void ver(void);
void usage(int exit_code);
char* strtoupper(char *str);
char* trim(char *str);
int parseconfig(char *configfile);
static int parse_uint(const char *, unsigned long, unsigned long, unsigned short *);
int parse_port_sequence(char *sequence, opendoor_t *door);
int get_new_one_time_sequence(opendoor_t *door);
long get_next_one_time_sequence(opendoor_t *door);
int disable_used_one_time_sequence(opendoor_t *door);
long get_current_one_time_sequence_position(opendoor_t *door);
void generate_pcap_filter(void);
size_t realloc_strcat(char **dest, const char *src, size_t size);
void free_door(opendoor_t *door);
void close_door(opendoor_t *door);
char* get_ip(const char *iface, char *buf, int bufsize);
size_t parse_cmd(char *dest, size_t size, const char *command, const char *src);
int exec_cmd(char *command, char *name);
void sniff(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *packet);
int target_strcmp(char *ip, char *target);
int parse_otp_sequence(char *sequence, opendoor_t *door);
int totp_code(const char *secret, long long step, char code[7]);
int totp_ports(opendoor_t *door, long long step, const char *src, unsigned short *ports);
void refresh_otp_ports(time_t now);
int fill_otp_ports(char *seed, unsigned short *sequence, unsigned start_index, unsigned end_index, long long tm, unsigned short otp_port_range );

pcap_t *cap = NULL;
FILE *logfd = NULL;
int lltype = -1;
/* list of IP addresses for given interface
 */
typedef struct ip_literal {
	struct ip_literal *next;
	char *value;
} ip_literal_t;
ip_literal_t *myips = NULL;

int  o_usesyslog = 0;
int  o_verbose   = 0;
int  o_debug     = 0;
int  o_daemon    = 0;
int  o_lookup    = 0;
char o_int[32]           = "";		/* default (eth0) is set after parseconfig() */
char o_cfg[PATH_MAX]     = "/etc/knockd.conf";
char o_pidfile[PATH_MAX] = "/var/run/knockd.pid";
char o_logfile[PATH_MAX] = "";

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t reload_requested = 0;
static int filter_dirty = 1;
static void request_stop(int sig) { (void)sig; stop_requested = 1; if(cap) pcap_breakloop(cap); }
static void request_reload(int sig) { (void)sig; reload_requested = 1; if(cap) pcap_breakloop(cap); }

unsigned char *hmac_sha1(const void *key, int keylen, const unsigned char *data, int datalen, unsigned char *result, unsigned int *resultlen) {
    return HMAC(EVP_sha1(), key, keylen, data, datalen, result, resultlen);
}

int main(int argc, char **argv)
{
	struct ifaddrs *ifaddr, *ifa;
	ip_literal_t *myip;
	char pcapErr[PCAP_ERRBUF_SIZE] = "";
	int opt, ret, optidx = 1, check_only = 0;

	static struct option opts[] =
	{
		{"check",     no_argument,       0, 't'},
		{"verbose",   no_argument,       0, 'v'},
        {"debug",     no_argument,       0, 'D'},
        {"debug_flg", no_argument,       0, 'F'},
		{"daemon",    no_argument,       0, 'd'},
		{"lookup",    no_argument,       0, 'l'},
		{"interface", required_argument, 0, 'i'},
		{"config",    required_argument, 0, 'c'},
		{"help",      no_argument,       0, 'h'},
		{"pidfile",   required_argument, 0, 'p'},
		{"logfile",   required_argument, 0, 'g'},
		{"version",   no_argument,       0, 'V'},
		{0, 0, 0, 0}
	};

	while((opt = getopt_long(argc, argv, "tvDFdli:c:p:g:hV", opts, &optidx))) {
		if(opt < 0) {
			break;
		}
		switch(opt) {
			case 0:   break;
            case 't': check_only = 1; break;
			case 'v': o_verbose = 1; break;
            case 'D': o_debug = 1; break;
            case 'F': o_debug = 1; break;
			case 'd': o_daemon = 1; break;
			case 'l': o_lookup = 1; break;
			case 'i': strncpy(o_int, optarg, sizeof(o_int)-1);
								o_int[sizeof(o_int)-1] = '\0';
								break;
			case 'c': strncpy(o_cfg, optarg, sizeof(o_cfg)-1);
								o_cfg[sizeof(o_cfg)-1] = '\0';
								break;
			case 'p': strncpy(o_pidfile, optarg, sizeof(o_pidfile)-1);
								o_pidfile[sizeof(o_pidfile)-1] = '\0';
								break;
			case 'g': strncpy(o_logfile, optarg, sizeof(o_logfile)-1);
								o_logfile[sizeof(o_logfile)-1] = '\0';
								break;
			case 'V': ver(); break;
			case 'h': /* fallthrough */
			default: usage(0);
		}
	}

	if(parseconfig(o_cfg)) {
		usage(1);
	}

    if(check_only) return 0;

	/* set o_int to a default value if it has not been set by the -i switch nor by
	 * the config file */
	if(strlen(o_int) == 0) {
		strncpy(o_int, "eth0", sizeof(o_int));	/* no explicit termination needed */
	}
	if(o_usesyslog) {
		openlog("knockd", 0, LOG_USER);
	}
	if(strlen(o_logfile)) {
		/* open the log file */
		logfd = fopen(o_logfile, "a");
		if(logfd == NULL) {
			perror("warning: cannot open logfile");
		}
	}

	/* 50ms timeout for packet capture. See pcap(3pcap) manpage, which
	 * recommends that a timeout of 0 not be used. */
	cap = pcap_open_live(o_int, 65535, 0, 50, pcapErr);
	if(strlen(pcapErr)) {
		fprintf(stderr, "could not open %s: %s\n", o_int, pcapErr);
	}
	if(cap == NULL) {
		exit(1);
	}

	lltype = pcap_datalink(cap);
	switch(lltype) {
		case DLT_EN10MB:
			dprint("ethernet interface detected\n");
			break;
#ifdef __linux__
		case DLT_LINUX_SLL:
			dprint("ppp interface detected (linux \"cooked\" encapsulation)\n");
			break;
#endif
		case DLT_RAW:
			dprint("raw interface detected, no encapsulation\n");
			break;
		default:
			fprintf(stderr, "error: unsupported link-layer type: %d\n", lltype);
			cleanup(1);
			break;
	}

	/* get our local IP addresses */
	if(getifaddrs(&ifaddr) != 0) {
		fprintf(stderr, "error: could not get IP address for %s: %s\n", o_int, strerror(errno));
		cleanup(1);
	} else {
		for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL)
				continue;

			if((strcmp(ifa->ifa_name, o_int) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
				if((myip = calloc(1, sizeof(ip_literal_t))) == NULL) {
					perror("malloc");
					exit(1);
				} else if ((myip->value = calloc(1,NI_MAXHOST)) == NULL) {
					perror("malloc");
					exit(1);
				} else {
					if(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), myip->value, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0) {
						fprintf(stderr, "error: could not get IP address for %s: %s\n", o_int, strerror(errno));
						freeifaddrs(ifaddr);
						cleanup(1);
					} else {
						if(myips)
							myip->next = myips;
						myips = myip;
						dprint("Local IP: %s\n", myip->value);
					}
				}
			}
		}
		freeifaddrs(ifaddr);
	}

/*
 * door structures are ready. It's time to build pcap filter
 */
    generate_pcap_filter();

	if(o_daemon) {
		FILE *pidfp;
		if(daemon(0, 0) < 0) {
			perror("daemon");
			cleanup(1);
		}
		/* write our PID to the pidfile*/
		if((pidfp = fopen(o_pidfile, "w"))) {
			fprintf(pidfp, "%d\n", getpid());
			fclose(pidfp);
		} else {
			dprint("could not create pid file %s: %s\n", o_pidfile, strerror(errno));
			logprint("could not create pid file %s: %s", o_pidfile, strerror(errno));
		}
	}

	signal(SIGINT, request_stop);
	signal(SIGTERM, request_stop);
	signal(SIGCHLD, child_exit);
	signal(SIGHUP, request_reload);

    /* A capture timeout need not return when the BPF filter accepts no packets.
     * Nonblocking capture plus a bounded poll keeps empty-profile reloads and
     * TOTP maintenance responsive even on libpcap builds without wakeup support. */
    if(pcap_setnonblock(cap, 1, pcapErr) < 0) {
        fprintf(stderr, "pcap: %s\n", pcapErr);
        cleanup(1);
    }

	vprint("listening on %s...\n", o_int);
	logprint("starting up, listening on %s", o_int);

    ret = 0;
    while(!stop_requested && ret >= 0) {
        if(reload_requested) {
            reload_requested = 0;
            reload(0);
        }
        refresh_otp_ports(time(NULL));
        if(filter_dirty) generate_pcap_filter();
        ret = pcap_dispatch(cap, 64, sniff, NULL);
        if(ret == PCAP_ERROR_BREAK) ret = 0;
        if(ret == 0 && !reload_requested && !stop_requested) {
            struct pollfd capture = {pcap_get_selectable_fd(cap), POLLIN, 0};
            poll(&capture, 1, 50);
        }
    }
    if(ret < 0) pcap_perror(cap, "pcap");

    cleanup(0);
    /* notreached */
    exit(0);
}

void dprint(char *fmt, ...)
{
	va_list args;
	if(o_debug) {
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		fflush(stdout);
	}
}

void vprint(char *fmt, ...)
{
	va_list args;
	if(o_verbose) {
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		fflush(stdout);
	}
}

/* Output a message to syslog and/or a logfile */
void logprint(char *fmt, ...)
{
	char msg[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, 1024, fmt, args);
	va_end(args);
	if(o_usesyslog) {
		syslog(LOG_NOTICE, "%s", msg);
	}
	if(logfd) {
		time_t t;
		struct tm *tm;
		t = time(NULL);
		tm = localtime(&t);

		fprintf(logfd, "[%04d-%02d-%02d %02d:%02d] %s\n", tm->tm_year+1900,
			tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, msg);
		fflush(logfd);
	}
}

/* Output current sequence of door for debugging */
void dprint_sequence(opendoor_t *door, char *fmt, ...)
{
	va_list args;
	int i;

	if(o_debug) {
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		for(i = 0; i < door->seqcount; i++) {
			switch(door->protocol[i]){
				case IPPROTO_UDP:
					printf((i == door->seqcount-1 ? "%u:udp\n" : "%u:udp,"), door->sequence[i]);
					break;
				case IPPROTO_TCP: /* fallthrough */
				default:
					printf((i == door->seqcount-1 ? "%u:tcp\n" : "%u:tcp,"), door->sequence[i]);
			}
		}
		fflush(stdout);
	}
}

/* Signal handlers */
void cleanup(int signum)
{
	ip_literal_t *myip = myips, *next;
	int status;

	vprint("waiting for child processes...\n");
	logprint("waiting for child processes...");
	while(waitpid(-1, &status, WNOHANG) > 0) {}

	vprint("closing...\n");
	logprint("shutting down");
	if(cap) pcap_close(cap);
	if(o_daemon) {
		unlink(o_pidfile);
	}

	for (; myip; myip = next) {
		if (myip->value) {
			free(myip->value);
		}
		next = myip->next;
		free(myip);
	}

	exit(signum);
}

void child_exit(int signum)
{
	int status;
    int saved_errno = errno;

	while ( waitpid( (pid_t)-1, &status, WNOHANG ) > 0 ) continue;
    errno = saved_errno;
	return;
}

void reload(int signum)
{
	PMList *lp;
	opendoor_t *door;
	int res_cfg;
    knocker_t *attempt;

	vprint("Re-reading config file: %s\n", o_cfg);
	logprint("Re-reading config file: %s\n", o_cfg);

	for(lp = doors; lp; lp = lp->next) {
		door = (opendoor_t*)lp->data;

		free_door(door);
		lp->data = NULL;
	}
	list_free(doors);
	doors = NULL;

    for(lp = attempts; lp; lp = lp->next) {
        attempt = (knocker_t*)lp->data;
        if (attempt->srchost) {
            free(attempt->srchost);
            attempt->srchost = NULL;
        }
        free(attempt);
        lp->data = NULL;
    }
	list_free(attempts);
	attempts = NULL;

	res_cfg = parseconfig(o_cfg);

	vprint("Closing log file: %s\n", o_logfile);
	logprint("Closing log file: %s\n", o_logfile);

	/* close the log file */
	if(logfd) {
		fclose(logfd);
		logfd = NULL;
	}

	if(res_cfg) {
		exit(1);
	}

	vprint("Re-opening log file: %s\n", o_logfile);
	logprint("Re-opening log file: %s\n", o_logfile);

	/* re-open the log file */
	logfd = fopen(o_logfile, "a");
	if(logfd == NULL) {
		perror("warning: cannot open logfile");
	}

	/* Fix issue #2 by regenerating the PCAP filter post config file re-read */
	filter_dirty = 1;

	return;
}

void usage(int exit_code) {
	printf("usage: knockd [options]\n");
	printf("options:\n");
	printf("  -i, --interface <int>  network interface to listen on (default \"eth0\")\n");
	printf("  -d, --daemon           run as a daemon\n");
	printf("  -c, --config <file>    use an alternate config file\n");
    printf("  -t, --check            validate config without capture or commands\n");
    printf("  -D, --debug            output debug messages\n");
    printf("  -F, --debug_flg        legacy alias for --debug\n");
	printf("  -l, --lookup           lookup DNS names (may be a security risk)\n");
	printf("  -p, --pidfile          use an alternate pidfile\n");
	printf("  -g, --logfile          use an alternate logfile\n");
	printf("  -v, --verbose          be verbose\n");
	printf("  -V, --version          display version\n");
	printf("  -h, --help             this help\n");
	printf("\n");
	exit(exit_code);
}

void ver() {
	printf("knockd %s\n", version);
	printf("Copyright (C) 2004-2012 Judd Vinet <jvinet@zeroflux.org>\n");
	exit(0);
}

/* Convert a string to uppercase
 */
char* strtoupper(char *str)
{
	char *ptr = str;

	while(*ptr) {
		(*ptr) = toupper((unsigned char)*ptr);
		ptr++;
	}
	return str;
}

/* Trim whitespace and newlines from a string
 */
char* trim(char *str)
{
	char *pch = str;
	while(isspace(*pch)) {
		pch++;
	}
	if(pch != str) {
		memmove(str, pch, (strlen(pch) + 1));
	}

	size_t len = strlen(str);
	if (len == 0) {
		return str;
	}

	pch = (char*)(str + (len - 1));
	while(isspace(*pch)) {
		pch--;
	}
	*++pch = '\0';

	return str;
}

/* Parse a config file
 */
int parseconfig(char *configfile)
{
	FILE *fp = NULL;
	char line[PATH_MAX+1];
	char *ptr = NULL;
	char *key = NULL;
	int linenum = 0;
	char section[256] = "";
	opendoor_t *door = NULL;
	PMList *lp;

	if((fp = fopen(configfile, "r")) == NULL) {
		perror(configfile);
		return(1);
	}

	while(fgets(line, PATH_MAX, fp)) {
		linenum++;
		trim(line);
		if(strlen(line) == 0 || line[0] == '#') {
			continue;
		}
		if(line[0] == '[' && line[strlen(line)-1] == ']') {
			/* new config section */
			ptr = line;
			ptr++;
			strncpy(section, ptr, sizeof(section));
            section[sizeof(section)-1] = '\0';
            section[strlen(section)-1] = '\0';
			dprint("config: new section: '%s'\n", section);
			if(!strlen(section)) {
				fprintf(stderr, "config: line %d: bad section name\n", linenum);
				return(1);
			}
			if(strcmp(section, "options")) {
				/* start a new knock/event record */
				door = calloc(1, sizeof(opendoor_t));
				if(door == NULL) {
					perror("malloc");
					exit(1);
				}
				strncpy(door->name, section, sizeof(door->name)-1);
				door->name[sizeof(door->name)-1] = '\0';
				door->target = 0;
				door->seqcount = 0;
				door->seq_timeout  = SEQ_TIMEOUT; /* default sequence timeout (seconds)  */
				door->start_command = NULL;
				door->cmd_timeout = CMD_TIMEOUT; /* default command timeout (seconds) */
				door->stop_command = NULL;
				door->flag_fin = DONT_CARE;
				door->flag_syn = DONT_CARE;
				door->flag_rst = DONT_CARE;
				door->flag_psh = DONT_CARE;
				door->flag_ack = DONT_CARE;
				door->flag_urg = DONT_CARE;
				door->one_time_sequences_fd = NULL;
                door->otp_enabled = 0; // make sure we know all the time if we have otp ports in settings
				doors = list_add(doors, door);
			}
		} else {
			/* directive */
			if(!strlen(section)) {
				fprintf(stderr, "config: line %d: all directives must belong to a section\n", linenum);
				return(1);
			}
			ptr = line;
			key = strsep(&ptr, "=");
			if(key == NULL) {
				fprintf(stderr, "config: line %d: syntax error\n", linenum);
				return(1);
			}
			trim(key);
			key = strtoupper(key);
			if(ptr == NULL) {
				if(!strcmp(key, "USESYSLOG")) {
					o_usesyslog = 1;
					dprint("config: usesyslog\n");
				} else {
					fprintf(stderr, "config: line %d: syntax error\n", linenum);
					return(1);
				}
			} else {
				trim(ptr);
				if(!strcmp(section, "options")) {
					if(!strcmp(key, "LOGFILE")) {
						strncpy(o_logfile, ptr, PATH_MAX-1);
						o_logfile[PATH_MAX-1] = '\0';
						dprint("config: log file: %s\n", o_logfile);
					} else if(!strcmp(key, "PIDFILE")) {
						strncpy(o_pidfile, ptr, PATH_MAX-1);
						o_pidfile[PATH_MAX-1] = '\0';
						dprint("config: pid file: %s\n", o_pidfile);
					} else if(!strcmp(key, "INTERFACE")) {
						/* set interface only if it has not already been set by the -i switch */
						if(strlen(o_int) == 0) {
							strncpy(o_int, ptr, sizeof(o_int)-1);
							o_int[sizeof(o_int)-1] = '\0';
							dprint("config: interface: %s\n", o_int);
						}
					} else {
						fprintf(stderr, "config: line %d: syntax error\n", linenum);
						return(1);
					}
				} else {
					if(door == NULL) {
						fprintf(stderr, "config: line %d: \"%s\" can only be used within a Door section\n",
								linenum, key);
						return(1);
					}
					if(!strcmp(key, "TARGET")) {
						door->target = malloc(sizeof(char) * (strlen(ptr)+1));
						if(door->target == NULL) {
							perror("malloc");
							exit(1);
						}
						strcpy(door->target, ptr);
						dprint("config: %s: target: %s\n", door->name, door->target);
					} else if(!strcmp(key, "SEQUENCE")) {
						int i;
						i = parse_port_sequence(ptr, door);
						if (i > 0) {
							return(i);
						}
						dprint_sequence(door, "config: %s: sequence: ", door->name);
					} else if(!strcmp(key, "OTP") || !strcmp(key, "TOTP")) {
                        door->totp_enabled = !strcmp(key, "TOTP");
						int i;
						i = parse_otp_sequence(ptr, door);
						if (i > 0) {
							return(i);
						}
						dprint_sequence(door, "config: %s: otp sequence: ", door->name);
					} else if(!strcmp(key, "ONE_TIME_SEQUENCES")) {
						if((door->one_time_sequences_fd = fopen(ptr, "r+")) == NULL) {
							perror(ptr);
							return(1);
						}
						dprint("config: %s: one time sequences file: %s\n", door->name, ptr);
						if (get_new_one_time_sequence(door) == 0) {
							dprint_sequence(door, "config: %s: sequence: ", door->name);
						} else {	/* no more sequences left in the one time sequences file */
							dprint("config: no more sequences left in the one time sequences file %s\n", ptr);
							return(1);
						}
					} else if(!strcmp(key, "SEQ_TIMEOUT") || !strcmp(key, "TIMEOUT")) {
						unsigned short timeout;
                        if(parse_uint(ptr, 1, 3600, &timeout)) return 1;
                        door->seq_timeout = timeout;
						dprint("config: %s: seq_timeout: %d\n", door->name, door->seq_timeout);
					} else if(!strcmp(key, "START_COMMAND") || !strcmp(key, "COMMAND")) {
						door->start_command = malloc(sizeof(char) * (strlen(ptr)+1));
						if(door->start_command == NULL) {
							perror("malloc");
							exit(1);
						}
						strcpy(door->start_command, ptr);
						dprint("config: %s: start_command: %s\n", door->name, door->start_command);
					} else if(!strcmp(key, "CMD_TIMEOUT")) {
						unsigned short timeout;
                        if(parse_uint(ptr, 1, 65535, &timeout)) return 1;
                        door->cmd_timeout = timeout;
						dprint("config: %s: cmd_timeout: %d\n", door->name, door->cmd_timeout);
					} else if(!strcmp(key, "STOP_COMMAND")) {
						door->stop_command = malloc(sizeof(char) * (strlen(ptr)+1));
						if(door->stop_command == NULL) {
							perror("malloc");
							exit(1);
						}
						strcpy(door->stop_command, ptr);
						dprint("config: %s: stop_command: %s\n", door->name, door->stop_command);
					} else if(!strcmp(key, "TCPFLAGS")) {
						char *flag;
						strtoupper(ptr);
						while((flag = strsep(&ptr, ","))) {
							/* allow just some flags to be specified */
							if(!strcmp(flag,"FIN")) {
								door->flag_fin = SET;
							} else if(!strcmp(flag,"!FIN")) {
								door->flag_fin = NOT_SET;
							} else if(!strcmp(flag, "SYN")) {
								door->flag_syn = SET;
							} else if(!strcmp(flag, "!SYN")) {
								door->flag_syn = NOT_SET;
							} else if(!strcmp(flag, "RST")) {
								door->flag_rst = SET;
							} else if(!strcmp(flag, "!RST")) {
								door->flag_rst = NOT_SET;
							} else if(!strcmp(flag, "PSH")) {
								door->flag_psh = SET;
							} else if(!strcmp(flag, "!PSH")) {
								door->flag_psh = NOT_SET;
							} else if(!strcmp(flag, "ACK")) {
								door->flag_ack = SET;
							} else if(!strcmp(flag, "!ACK")) {
								door->flag_ack = NOT_SET;
							} else if(!strcmp(flag, "URG")) {
								door->flag_urg = SET;
							} else if(!strcmp(flag, "!URG")) {
								door->flag_urg = NOT_SET;
							} else {
								fprintf(stderr, "config: line %d: unrecognized flag \"%s\"\n",
										linenum, flag);
								return(1);
							}
							dprint("config: tcp flag: %s\n", flag);
						}
					} else {
						fprintf(stderr, "config: line %d: syntax error\n", linenum);
						return(1);
					}
				}
				line[0] = '\0';
			}
		}
	}
	fclose(fp);

	/* sanity checks */
	for(lp = doors; lp; lp = lp->next) {
		door = (opendoor_t*)lp->data;
		if(door->seqcount == 0) {
			fprintf(stderr, "error: section '%s' has an empty knock sequence\n", door->name);
			return(1);
		}
	}

	return(0);
}

/*
 * Parse a key, -otp_change_time, -ports starting point, ip_protection, protocol,protocol... sequence. Returns a positive integer on error.
 * -seed - used to generate one time port sequence
 * -otp_change_time - in secs how often we are changing dynamic ports
 * -psp (unsigned short) ports starting point of the 256 bytes area for port generation. Usually is bigger then 1000
 * -ip_protection on/off - specifies if we need additional ports generated based on mix of the key and sender ip to validate sender
 * -protocol - protocols used for these port sequence. The number of protocol names defines the number of ports derived from the key
 * Example: otp    = AAgR%XXx30O$#, 45, 20000, on, tcp, udp, tcp
 * in this example tcp, udp and tcp ports will be generated in the range of 20000 - 20255 using the hash sum of AAgR%XXx30O$# and current time and this port sequence will be re regenerated every 45 seconds.
 * When th first packet hits the first port (tcp) in our case an additional sequesnce of the same protocols (tcp, udp, tcp)
 * will be generated based on hash sum of concatenation of AAgR%XXx30O$# and source ip address of the packet arrived and current time thus protecting us from mitm attack
 */

static int parse_uint(const char *text, unsigned long min, unsigned long max, unsigned short *out)
{
    char *end;
    unsigned long n;
    if(!text || !*text || *text == '-') return 1;
    errno = 0;
    n = strtoul(text, &end, 10);
    while(isspace((unsigned char)*end)) end++;
    if(errno || *end || n < min || n > max) return 1;
    *out = (unsigned short)n;
    return 0;
}

int parse_otp_sequence(char *sequence, opendoor_t *door)
{
    char *seed = strsep(&sequence, ",");
    char *period = strsep(&sequence, ",");
    char *base = strsep(&sequence, ",");
    char *protection = strsep(&sequence, ",");
    char *protocol;
    if(!seed || !period || !base || !protection || !sequence ||
       !*trim(seed) || strlen(seed) >= MAX_SEED_LEN ||
       parse_uint(trim(period), 1, 65535, &door->otp_change_time) ||
       parse_uint(trim(base), 1, 65280, &door->otp_port_range)) {
        fprintf(stderr, "config: section %s: invalid OTP seed, period or port range\n", door->name);
        return 1;
    }
    protection = strtoupper(trim(protection));
    if(strcmp(protection, "ON") && strcmp(protection, "OFF")) return 1;
    door->ip_protection = !strcmp(protection, "ON");
    strcpy(door->seed, seed);
    door->seqcount = 0;
    while((protocol = strsep(&sequence, ","))) {
        /* SHA1 has 20 bytes; never repeat digest bytes to extend a sequence. */
        if(door->seqcount >= 20) return 1;
        protocol = strtoupper(trim(protocol));
        if(strcmp(protocol, "TCP") && strcmp(protocol, "UDP")) return 1;
        door->protocol[door->seqcount++] = !strcmp(protocol, "TCP") ? IPPROTO_TCP : IPPROTO_UDP;
    }
    if(!door->seqcount) return 1;
    door->otp_enabled = 1;
    door->flag_syn = SET;
    door->flag_ack = NOT_SET;
    door->flag_rst = NOT_SET;
    if(door->totp_enabled) {
        char code[7];
        if(door->seqcount < 3 || door->otp_change_time != 30 || totp_code(door->seed, 0, code)) {
            fprintf(stderr, "config: TOTP requires a 32-character Base32 secret and period 30\n");
            return 1;
        }
    }
    door->tm = (long long)time(NULL) / door->otp_change_time;
    return fill_otp_ports(door->seed, door->sequence, 0, door->seqcount,
                          door->tm, door->otp_port_range);
}

/* RFC 4226 / RFC 6238: Base32 key, 64-bit network-order counter,
 * dynamic truncation, SHA1, six decimal digits. */
static int base32_key(const char *secret, unsigned char key[20])
{
    unsigned int bits = 0, accumulator = 0, used = 0;
    if(strlen(secret) != 32) return 1;
    for(unsigned i = 0; i < 32; i++) {
        unsigned char ch = (unsigned char)toupper((unsigned char)secret[i]);
        unsigned value;
        if(ch >= 'A' && ch <= 'Z') value = ch - 'A';
        else if(ch >= '2' && ch <= '7') value = ch - '2' + 26;
        else return 1;
        accumulator = (accumulator << 5) | value;
        bits += 5;
        if(bits >= 8) { bits -= 8; key[used++] = (accumulator >> bits) & 255; }
    }
    return 0;
}

int totp_code(const char *secret, long long step, char code[7])
{
    unsigned char key[20], counter[8], digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if(step < 0 || base32_key(secret, key)) return 1;
    for(unsigned i = 0; i < 8; i++) counter[7-i] = ((uint64_t)step >> (i*8)) & 255;
    if(!HMAC(EVP_sha1(), key, sizeof(key), counter, sizeof(counter), digest, &length)) return 1;
    unsigned offset = digest[19] & 15;
    uint32_t binary = ((uint32_t)(digest[offset] & 127) << 24) |
                      ((uint32_t)digest[offset+1] << 16) | ((uint32_t)digest[offset+2] << 8) | digest[offset+3];
    snprintf(code, 7, "%06u", binary % 1000000);
    return 0;
}

int totp_ports(opendoor_t *door, long long step, const char *src, unsigned short *ports)
{
    char message[256];
    unsigned slot = (unsigned)((uint64_t)step % 3);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if(door->cached_steps[slot] != step || !door->cached_codes[slot][0]) {
        if(totp_code(door->seed, step, door->cached_codes[slot])) return 1;
        door->cached_steps[slot] = step;
    }
    snprintf(message, sizeof(message), "knock-control:v1:%s:%s:%s", door->name,
             door->ip_protection ? src : "-", door->cached_codes[slot]);
    SHA256((const unsigned char *)message, strlen(message), digest);
    for(unsigned i = 0; i < door->seqcount; i++) ports[i] = door->otp_port_range + digest[i];
    return 0;
}

/* Standard-mode commands require an authenticated final UDP datagram.
 * This prevents random high-rate traffic from authorizing a command merely
 * by containing the required port sequence as a subsequence. */
static struct { unsigned char tag[32]; time_t expires; } replay_cache[1024];
static int verify_confirmation(opendoor_t *door, const unsigned char *proof,
                               const char *src, time_t now, long long *step)
{
    unsigned char key[20], message[256], tag[EVP_MAX_MD_SIZE];
    unsigned length = 0;
    uint64_t counter = 0;
    if(memcmp(proof, "KNC1", 4) || base32_key(door->seed, key)) return 0;
    for(unsigned i = 0; i < 8; i++) counter = (counter << 8) | proof[4+i];
    if(counter > (uint64_t)LLONG_MAX || (long long)counter < (long long)now/30-1 ||
       (long long)counter > (long long)now/30+1) return 0;
    const char *prefix = "knock-control:confirm:v1:";
    size_t used = strlen(prefix);
    memcpy(message, prefix, used);
    memcpy(message+used, proof+4, 24); used += 24;
    int appended = snprintf((char*)message+used, sizeof(message)-used, "%s:%s", door->name,
                            door->ip_protection ? src : "-");
    if(appended < 0 || (size_t)appended >= sizeof(message)-used) return 0;
    used += appended;
    if(!HMAC(EVP_sha256(), key, sizeof(key), message, used, tag, &length) ||
       CRYPTO_memcmp(tag, proof+28, 32)) return 0;
    *step = (long long)counter;
    return 1;
}

static int reserve_confirmation(const unsigned char *proof, long long step, time_t now)
{
    int free_slot = -1;
    for(unsigned i = 0; i < 1024; i++) {
        if(replay_cache[i].expires <= now) { if(free_slot < 0) free_slot = (int)i; }
        else if(!CRYPTO_memcmp(replay_cache[i].tag, proof+28, 32)) return 0;
    }
    if(free_slot < 0) return 0;
    memcpy(replay_cache[free_slot].tag, proof+28, 32);
    replay_cache[free_slot].expires = (time_t)(step+2)*30 + 60;
    return 1;
}

void refresh_otp_ports(time_t now)
{
    PMList *lp;
    for(lp = doors; lp; lp = lp->next) {
        opendoor_t *door = lp->data;
        if(door->otp_enabled && !door->totp_enabled) {
            long long step = (long long)now / door->otp_change_time;
            if(step != door->tm) {
                door->tm = step;
                fill_otp_ports(door->seed, door->sequence, 0, door->seqcount,
                               step, door->otp_port_range);
            }
        }
    }
}

int fill_otp_ports(char *seed, unsigned short *sequence, unsigned start_index, unsigned end_index, long long tm, unsigned short otp_port_range ) {
    unsigned char time_buf[40];
    unsigned char out[256] = {0};
    unsigned int len = sizeof(out), i, l;


    sprintf((char *)time_buf, "%lld", tm); //Prepared a time in secs, that will be changed every otp_change_time sec
    if(!hmac_sha1((unsigned char *)seed, (int)strlen((const char *)seed), time_buf, (int)strlen((const char *)time_buf), out, &len)) return 1; //get random number out of time and seed. Should be 20 bytes long


    l = 0;
/*
    dprint("tm = '%s' key = '%s' sha = '", time_buf, seed);
    for (i = 0; i < len; i++) {
        status |= out[i];
        dprint("%02X", (unsigned int)(status & 0xFF) );
        status = 0x00;
    }
    dprint("'\n");
 */

    for (i = start_index; i < end_index; i++) {
        if (l >= len) l = 0; // If seqcount > len
        sequence[i] = otp_port_range + (unsigned short)out[l];
//        dprint("port = %d ", (int)((unsigned short)out[l]));
        l++;
    }
//    dprint("\n");

	return(0);
}

/*
 * Parse a port:protocol sequence. Returns a positive integer on error.
 */
int parse_port_sequence(char *sequence, opendoor_t *door)
{
	char *num;
	char *protocol;
	char *port;

	door->seqcount = 0;	/* reset seqcount */
	while((num = strsep(&sequence, ","))) {
		if(door->seqcount >= SEQ_MAX) {
			fprintf(stderr, "config: section %s: too many ports in knock sequence\n", door->name);
			logprint("error: section %s: too many ports in knock sequence\n", door->name);
			return(1);
		}
		port = strsep(&num, ":");
		if(parse_uint(trim(port), 1, 65535, &door->sequence[door->seqcount])) return 1;
        door->seqcount++;
		if((protocol = strsep(&num, ":"))){
			protocol = strtoupper(trim(protocol));
			if(!strcmp(protocol, "TCP")){
				door->protocol[door->seqcount-1] = IPPROTO_TCP;
			} else if(!strcmp(protocol, "UDP")) {
				door->protocol[door->seqcount-1] = IPPROTO_UDP;
			} else {
				fprintf(stderr,"config: section %s: unknown protocol in knock sequence\n", door->name);
				logprint("error: section %s: unknown protocol in knock sequence\n", door->name);
				return(1);
			}
		} else {
			door->protocol[door->seqcount-1] = IPPROTO_TCP; /* default protocol */
		}
	}
	return(0);
}

/* Read a new sequence from the one time sequences file and update the door.
 */
int get_new_one_time_sequence(opendoor_t *door)
{
	rewind(door->one_time_sequences_fd);
	if(get_next_one_time_sequence(door) < 0) {
		/* disable the door by removing it from the doors list if there are no sequences anymore */
		fprintf(stderr, "no more sequences left in the one time sequences file for door %s --> disabling the door\n", door->name);
		logprint("no more sequences left in the one time sequences file for door %s --> disabling the door\n", door->name);
		close_door(door);
		return(1);
	}
	dprint_sequence(door, "new sequence for door %s: ", door->name);

	return(0);
}

/* Search from the current position in the one time sequence file for the next
 * valid sequence and insert it into the door structure. Returns the position of
 * the beginning of the found line within the file or a negative value if no
 * valid sequence has been found.
 */
long get_next_one_time_sequence(opendoor_t *door)
{
	char line[PATH_MAX+1];
	int pos;

	pos = (int)ftell(door->one_time_sequences_fd);
	while(fgets(line, PATH_MAX, door->one_time_sequences_fd)) {
		trim(line);
		if(strlen(line) == 0 || line[0] == '#') {
			pos = (int)ftell(door->one_time_sequences_fd);
			continue;
		}
		if(parse_port_sequence(line, door) > 0) {
			/* continue searching if parse_port_sequnce returned with an error */
			continue;
		}
		return(pos);
	}
	/* no valid line found */
	return(-1);
}

/* Remove a one time sequence from the corresponding file (after a successful
 * knock attempt)
 */
int disable_used_one_time_sequence(opendoor_t *door)
{
	long pos = get_current_one_time_sequence_position(door);
	if(pos >= 0) {
		if(fseek(door->one_time_sequences_fd, pos, SEEK_SET) < 0) {
			fprintf(stderr, "error while disabling used one time sequence for door %s --> disabling the door\n", door->name);
			logprint("error while disabling used one time sequence for door %s --> disabling the door\n", door->name);
			close_door(door);
			return(1);
		}
		if(fputc('#', door->one_time_sequences_fd) == EOF) {
			fprintf(stderr, "error while disabling used one time sequence for door %s --> disabling the door\n", door->name);
			logprint("error while disabling used one time sequence for door %s --> disabling the door\n", door->name);
			close_door(door);
			return(1);
		}
	}
	return(0);
}

/* Get the position (beginning of line) in the one time sequence file of the
 * current sequence such that we know where to insert a '#' to disable the
 * sequence in the one time sequence file
 */
long get_current_one_time_sequence_position(opendoor_t *door)
{
	opendoor_t pseudo_door = {0};	/* used to compare sequences in the file and the current sequence in door */
	long pos;

	rewind(door->one_time_sequences_fd);
	pseudo_door.one_time_sequences_fd = door->one_time_sequences_fd;

	pos = get_next_one_time_sequence(&pseudo_door);
	while(pos >= 0) {
		if(door->seqcount == pseudo_door.seqcount) {
			if((memcmp((void*) door->sequence, (void*) pseudo_door.sequence, door->seqcount * sizeof(unsigned short)) == 0)
					&& (memcmp((void*) door->protocol, (void*) pseudo_door.protocol, door->seqcount * sizeof(unsigned short)) == 0)) {
				return(pos);
			}
		}
		pos = get_next_one_time_sequence(&pseudo_door);
	}
	return(-1);
}

/* A stable capture filter includes the complete OTP range. The sequence is
 * checked in the capture thread, including the source-IP-bound suffix. This
 * avoids racing pcap_setfilter against capture and losing packets on rollover. */
void generate_pcap_filter(void)
{
    PMList *lp;
    char *filter = calloc(1, 256);
    size_t size = 256;
    struct bpf_program program;
    if(!filter) { perror("calloc"); cleanup(1); }
    for(lp = doors; lp; lp = lp->next) {
        opendoor_t *door = lp->data;
        if(!door->seqcount) continue;
        ip_literal_t *ip;
        char ports[128];
        unsigned i;
        if(*filter) size = realloc_strcat(&filter, " or ", size);
        size = realloc_strcat(&filter, "((", size);
        if(door->target) {
            size = realloc_strcat(&filter, "dst host ", size);
            size = realloc_strcat(&filter, door->target, size);
        } else {
            if(!myips) { fprintf(stderr, "interface has no IPv4 address\n"); cleanup(1); }
            for(ip = myips; ip; ip = ip->next) {
                if(ip != myips) size = realloc_strcat(&filter, " or ", size);
                size = realloc_strcat(&filter, "dst host ", size);
                size = realloc_strcat(&filter, ip->value, size);
            }
        }
        size = realloc_strcat(&filter, ") and (", size);
        if(door->otp_enabled) {
            snprintf(ports, sizeof(ports), "(tcp or udp) and dst portrange %u-%u",
                     door->otp_port_range, door->otp_port_range + 255);
            size = realloc_strcat(&filter, ports, size);
        } else {
            for(i = 0; i < door->seqcount; i++) {
                snprintf(ports, sizeof(ports), "%s%s dst port %u", i ? " or " : "",
                         door->protocol[i] == IPPROTO_TCP ? "tcp" : "udp", door->sequence[i]);
                size = realloc_strcat(&filter, ports, size);
            }
        }
        size = realloc_strcat(&filter, "))", size);
        if(!size) { perror("realloc"); cleanup(1); }
    }
    if(size && filter && !*filter) {
        /* pcap's optimizer rejects logically impossible textual filters.
         * An explicit BPF return-zero program supports zero active profiles. */
        struct bpf_insn drop = BPF_STMT(BPF_RET | BPF_K, 0);
        struct bpf_program empty = {1, &drop};
        if(pcap_setfilter(cap, &empty) < 0) { pcap_perror(cap, "filter"); cleanup(1); }
        free(filter);
        filter_dirty = 0;
        return;
    }
    if(!size || !filter || pcap_compile(cap, &program, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        free(filter); if(cap) pcap_perror(cap, "filter"); cleanup(1);
    }
    if(pcap_setfilter(cap, &program) < 0) { pcap_perror(cap, "filter"); cleanup(1); }
    pcap_freecode(&program);
    free(filter);
    filter_dirty = 0;
}

/* Reallocating strcat -- appends the src string to the dest string (pointer to
 * char*!) overwriting the `\0' character at the end of dest, and then adds a
 * terminating `\0' character. size is the whole size of the dest buffer (not
 * the remaining space like in strncat). If there is not enough space to append
 * src, the dest buffer will be realloc()ated to hold the src string. The
 * reallocation is done by doubling dest's size until it is large enough. dest
 * will always be NULL terminated. Returns the size of the whole buffer or 0 if
 * realloc() fails.
 *
 * IMPORTANT: dest has to be an allocated buffer (not static!), such that it can
 * be reallocated with realloc() !!!
 */

size_t realloc_strcat(char **dest, const char *src, size_t size)
{
	size_t needed_size;
	size_t new_size;
	char *orig = *dest;

	if(size == 0) {
		free(orig);
		return 0;
	}

	needed_size = strlen(*dest) + strlen(src) + 1;		/* '+ 1' for '\0' */
	new_size = size;

	while(needed_size > new_size) {
		new_size *= 2;
	}
	if(new_size != size) {
		*dest = (char*)realloc(*dest, new_size);
		if(*dest == NULL) {
			free(orig);
			return 0;
		}
	}

	/* now dest is large enough to strcat() the src */
	strcat(*dest, src);

	return new_size;
}

void free_door(opendoor_t *door)
{
	if(door) {
		free(door->target);
		free(door->start_command);
		free(door->stop_command);
		if (door->one_time_sequences_fd) {
			fclose(door->one_time_sequences_fd);
		}
		free(door);
	}
}

/* Disable the door by removing it from the doors list and free all allocated memory.
 */
void close_door(opendoor_t *door)
{
    door->seqcount = 0;
    filter_dirty = 1;
}

/* Get the IP address of an interface
 */
char* get_ip(const char* iface, char *buf, int bufsize)
{
	int s;
	struct ifreq ifr;

	if(bufsize <= 0) {
		return(NULL);
	}
	if(buf == NULL) {
		return(NULL);
	}
	buf[0] = '\0';

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0) {
		return(NULL);
	}

	bzero((void*)(&ifr.ifr_name), sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
	if(ioctl(s, SIOCGIFADDR, &ifr)) {
		close(s);
		return(NULL);
	}
	close(s);

	strncpy(buf, inet_ntoa((*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr), bufsize-1);
	buf[bufsize-1] = '\0';
	return(buf);
}

/* Parse a command line, replacing tokens (eg, %IP%) with their real values and
 * copy the result to dest. At most size-1 characters will be copied and the
 * result will always be NULL terminated (except if size == 0). The return value
 * is the length of the resulting string. If the returned size is larger than the
 * size of dest, then the result has ben truncated.
 */
size_t parse_cmd(char* dest, size_t size, const char* command, const char* src)
{
	char *d = dest;
	const char *c = command;
	const char *s = src;
	char *token;
	size_t n = size;
	size_t command_len = strlen(command);
	size_t total_len = 0;

	/* allows us to calculate total length of result string even if the size */
	/* is zero by setting n to 1 (--> noting will be ever written to dest) */
	int size_larger_than_zero = 1;
	if(size == 0) {
		size_larger_than_zero = 0;
		n = 1;
	}

	/* get location of first token */
	token = strstr(c, "%IP%");
	if(!token) {
		/* point token past command (we won't access it anymore) */
		token = (char*) (c + command_len + 1);
	}
	while(*c != '\0') {
		/* not reached a token yet --> append from command */
		if(c < token) {
			if(n != 1) {
				*d++ = *c;
				n--;
			}
		} else {
			/* we reached a token --> append from src */
			while(*s != '\0') {
				if(n != 1) {
					*d++ = *s;
					n--;
				}
				s++;
				total_len++;
			}
			c += 4;  /* skip the token in command */
			s = src; /* "rewind" src string for next token */
			token = strstr(c, "%IP%"); /* get location of next token */
			if(!token) {
				/* point token past command (we won't access it anymore) */
				token = (char*) (c + command_len + 1);
			}
			c--; /* compensate for the following c++ */
			total_len--; /* compensate for the following total_len++ */
		}
		c++;
		total_len++;
	}
	if(size_larger_than_zero) {
		/* terminate dest if its size is larger than 0 */
		*d = '\0';
	}

	return(total_len);
}

/* Execute a command through the system shell and wait for return
 */
int exec_cmd(char* command, char* name){
	int ret;

	logprint("%s: running command: %s\n", name, command);
	vprint("%s: running command: %s\n", name, command);
	ret = system(command);
	if(ret == -1) {
		fprintf(stderr, "error: command fork failed!\n");
		logprint("error: command fork failed!");
	} else if(ret != 0) {
		fprintf(stderr, "%s: command returned non-zero status code (%d)\n", name, WEXITSTATUS(ret));
		logprint("%s: command returned non-zero status code (%d)", name, WEXITSTATUS(ret));
	}
	return ret;
}

/*
 * If examining a TCP packet, try to match flags against those in
 * the door config.
 */
int flags_match(opendoor_t* door, struct ip* ip, struct tcphdr* tcp)
{
	/* if tcp, check the flags to ignore the packets we don't want
	 * (don't even use it to cancel sequences)
	 */

	if(ip->ip_p == IPPROTO_TCP) {
		if(door->flag_fin != DONT_CARE) {
			if(door->flag_fin == SET && !(tcp->th_flags & TH_FIN)) {
				dprint("packet is not FIN, ignoring...\n");
				return 0;
			}
			if(door->flag_fin == NOT_SET && (tcp->th_flags & TH_FIN)) {
				dprint("packet is not !FIN, ignoring...\n");
				return 0;
			}
		}
		if(door->flag_syn != DONT_CARE) {
			if(door->flag_syn == SET && !(tcp->th_flags & TH_SYN)) {
				dprint("packet is not SYN, ignoring...\n");
				return 0;
			}
			if(door->flag_syn == NOT_SET && (tcp->th_flags & TH_SYN)) {
				dprint("packet is not !SYN, ignoring...\n");
				return 0;
			}
		}
		if(door->flag_rst != DONT_CARE) {
			if(door->flag_rst == SET && !(tcp->th_flags & TH_RST)) {
				dprint("packet is not RST, ignoring...\n");
				return 0;
			}
			if(door->flag_rst == NOT_SET && (tcp->th_flags & TH_RST)) {
				dprint("packet is not !RST, ignoring...\n");
				return 0;
			}
		}
		if(door->flag_psh != DONT_CARE) {
			if(door->flag_psh == SET && !(tcp->th_flags & TH_PUSH)) {
				dprint("packet is not PSH, ignoring...\n");
				return 0;
			}
			if(door->flag_psh == NOT_SET && (tcp->th_flags & TH_PUSH)) {
				dprint("packet is not !PSH, ignoring...\n");
				return 0;
			}
		}
		if(door->flag_ack != DONT_CARE) {
			if(door->flag_ack == SET && !(tcp->th_flags & TH_ACK)) {
				dprint("packet is not ACK, ignoring...\n");
				return 0;
			}
			if(door->flag_ack == NOT_SET && (tcp->th_flags & TH_ACK)) {
				dprint("packet is not !ACK, ignoring...\n");
				return 0;
			}
		}
		if(door->flag_urg != DONT_CARE) {
			if(door->flag_urg == SET && !(tcp->th_flags & TH_URG)) {
				dprint("packet is not URG, ignoring...\n");
				return 0;
			}
			if(door->flag_urg == NOT_SET && (tcp->th_flags & TH_URG)) {
				dprint("packet is not !URG, ignoring...\n");
				return 0;
			}
		}
	}

	return 1;
}

/**
 * Process a knock attempt to see if the knocker has graduated to the next
 * sequence. If they've completed all sequences correctly, then we open the
 * door.
 */
void process_attempt(knocker_t *attempt)
{
    int seqcount;

    /* level up! */
    attempt->stage++;
    if(attempt->srchost) {
        vprint("%s (%s): %s: Stage %d\n", attempt->src, attempt->srchost, attempt->door->name, attempt->stage);
        logprint("%s (%s): %s: Stage %d", attempt->src, attempt->srchost, attempt->door->name, attempt->stage);
    } else {
        vprint("%s: %s: Stage %d\n", attempt->src, attempt->door->name, attempt->stage);
        logprint("%s: %s: Stage %d", attempt->src, attempt->door->name, attempt->stage);
    }
    seqcount = attempt->p_seqcount;
    if(attempt->stage >= seqcount) {
        if(attempt->door->totp_enabled && !attempt->confirmed) return;
        if(attempt->srchost) {
            vprint("%s (%s): %s: OPEN SESAME\n", attempt->src, attempt->srchost, attempt->door->name);
            logprint("%s (%s): %s: OPEN SESAME", attempt->src, attempt->srchost, attempt->door->name);
        } else {
            vprint("%s: %s: OPEN SESAME\n", attempt->src, attempt->door->name);
            logprint("%s: %s: OPEN SESAME", attempt->src, attempt->door->name);
        }
        if(attempt->door->start_command && strlen(attempt->door->start_command)) {
            /* run the associated command */
            if(fork() == 0) {
                /* child */
                char parsed_start_cmd[PATH_MAX];
                char parsed_stop_cmd[PATH_MAX];
                size_t cmd_len = 0;

                setsid();

                /* parse start and stop command and check if the parsed commands fit in the given buffer. Don't
                 * execute any command if one of them has been truncated */
                cmd_len = parse_cmd(parsed_start_cmd, sizeof(parsed_start_cmd), attempt->door->start_command, attempt->src);
                if(cmd_len >= sizeof(parsed_start_cmd)) {    /* command has been truncated --> do NOT execute it */
                    fprintf(stderr, "error: parsed start command has been truncated! --> won't execute it\n");
                    logprint("error: parsed start command has been truncated! --> won't execute it");
                    exit(0); /* exit child */
                }
                if(attempt->door->stop_command) {
                    cmd_len = parse_cmd(parsed_stop_cmd, sizeof(parsed_stop_cmd), attempt->door->stop_command, attempt->src);
                    if(cmd_len >= sizeof(parsed_stop_cmd)) {    /* command has been truncated --> do NOT execute it */
                        fprintf(stderr, "error: parsed stop command has been truncated! --> won't execute start command\n");
                        logprint("error: parsed stop command has been truncated! --> won't execute start command");
                        exit(0); /* exit child */
                    }
                }

                /* all parsing ok --> execute the parsed (%IP% = source IP) command */
                exec_cmd(parsed_start_cmd, attempt->door->name);
                /* if stop_command is set, sleep for cmd_timeout and run it*/
                if(attempt->door->stop_command){
                    sleep((int)attempt->door->cmd_timeout);
                    if(attempt->srchost) {
                        vprint("%s (%s): %s: command timeout\n", attempt->src, attempt->srchost, attempt->door->name);
                        logprint("%s (%s): %s: command timeout", attempt->src, attempt->srchost, attempt->door->name);
                    } else {
                        vprint("%s: %s: command timeout\n", attempt->src, attempt->door->name);
                        logprint("%s: %s: command timeout", attempt->src, attempt->door->name);
                    }
                    exec_cmd(parsed_stop_cmd, attempt->door->name);
                }

                exit(0); /* exit child */
            }
        }
        /* change to next sequence if one time sequences are used.
         * Note that here the door will eventually be closed in
         * get_new_one_time_sequence() if no more sequences are left */
        if(attempt->door->one_time_sequences_fd) {
            if (disable_used_one_time_sequence(attempt->door)) {
                return;
            }

            if(get_new_one_time_sequence(attempt->door)) return;

            /* update pcap filter */
            filter_dirty = 1;
        }
    }
}


/* Sniff an interface, looking for port-knock sequences
 */
void sniff(u_char* arg, const struct pcap_pkthdr* hdr, const u_char* packet)
{
	/* packet structs */

	struct ip* ip = NULL;
	struct tcphdr* tcp = NULL;
	struct udphdr* udp = NULL;
    struct ip aligned_ip;
    struct tcphdr aligned_tcp;
    struct udphdr aligned_udp;
	char proto[8];
	/* TCP/IP data */
	struct in_addr inaddr;
	unsigned short sport, dport;
	char srcIP[16], dstIP[16];
	/* timestamp */
	time_t pkt_secs = hdr->ts.tv_sec;
	struct tm* pkt_tm;
	char pkt_date[11];
	char pkt_time[9];
	PMList *lp;
	knocker_t *attempt = NULL;

    size_t offset = lltype == DLT_EN10MB ? 14 : lltype == DLT_LINUX_SLL ? 16 : 0;
    if(hdr->caplen < offset + sizeof(struct ip)) return;
	if(lltype == DLT_EN10MB) {
        unsigned short ether_type;
        memcpy(&ether_type, packet + 12, sizeof(ether_type));
		if(ntohs(ether_type) != ETHERTYPE_IP) {
			return;
		}

		ip = (struct ip*)(packet + sizeof(struct ether_header));
#ifdef __linux__
	} else if(lltype == DLT_LINUX_SLL) {
		ip = (struct ip*)((u_char*)packet + 16);
#endif
	} else if(lltype == DLT_RAW) {
		ip = (struct ip*)((u_char*)packet);
	} else {
		dprint("link layer header type of packet not recognized, ignoring...\n");
		return;
	}

	memcpy(&aligned_ip, ip, sizeof(aligned_ip));
    ip = &aligned_ip;
	if(ip->ip_hl < 5 || hdr->caplen < offset + ip->ip_hl * 4U ||
       ntohs(ip->ip_len) < ip->ip_hl * 4U || (ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK))) return;
    if(ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return;
    {
        size_t transport = ip->ip_p == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr);
        if(hdr->caplen < offset + ip->ip_hl * 4U + transport ||
           ntohs(ip->ip_len) < ip->ip_hl * 4U + transport) return;
    }
    refresh_otp_ports(pkt_secs);
	if(ip->ip_v != 4) {
		/* no IPv6 yet */
		dprint("packet is not IPv4, ignoring...\n");
		return;
	}
	if(ip->ip_p == IPPROTO_ICMP) {
		/* we don't do ICMP */
		return;
	}

	sport = dport = 0;

	if(ip->ip_p == IPPROTO_TCP) {
		strncpy(proto, "tcp", sizeof(proto));
		memcpy(&aligned_tcp, packet + offset + ip->ip_hl * 4U, sizeof(aligned_tcp));
        tcp = &aligned_tcp;
		sport = ntohs(tcp->th_sport);
		dport = ntohs(tcp->th_dport);
	}
	if(ip->ip_p == IPPROTO_UDP) {
		strncpy(proto, "udp", sizeof(proto));
		memcpy(&aligned_udp, packet + offset + ip->ip_hl * 4U, sizeof(aligned_udp));
        udp = &aligned_udp;
		sport = ntohs(udp->uh_sport);
		dport = ntohs(udp->uh_dport);
	}

	/* get the date/time */
	pkt_tm = localtime(&pkt_secs);
    strftime(pkt_date, sizeof(pkt_date), "%Y-%m-%d", pkt_tm);
    strftime(pkt_time, sizeof(pkt_time), "%H:%M:%S", pkt_tm);

	/* convert IPs from binary to string */
	inaddr.s_addr = ip->ip_src.s_addr;
	strncpy(srcIP, inet_ntoa(inaddr), sizeof(srcIP)-1);
	srcIP[sizeof(srcIP)-1] = '\0';
	inaddr.s_addr = ip->ip_dst.s_addr;
	strncpy(dstIP, inet_ntoa(inaddr), sizeof(dstIP)-1);
	dstIP[sizeof(dstIP)-1] = '\0';

	dprint("%s %s: %s: %s:%d -> %s:%d %d bytes\n", pkt_date, pkt_time,
			proto, srcIP, sport, dstIP, dport, hdr->len);

    /* Attempts have a fixed deadline; noise never extends their lifetime. */
    lp = attempts;
    while(lp) {
        PMList *next = lp->next;
        attempt = lp->data;
        if(attempt->stage < 0 || (attempt->stage >= attempt->p_seqcount &&
           (!attempt->door->totp_enabled || attempt->confirmed)) ||
           pkt_secs - attempt->seq_start >= attempt->door->seq_timeout) {
            if(lp->prev) lp->prev->next = next;
            else attempts = next;
            if(next) next->prev = lp->prev;
            free(attempt->srchost);
            lp->prev = lp->next = NULL;
            list_free(lp);
        }
        lp = next;
    }

    if(udp && dport) {
        size_t payload_offset = offset + ip->ip_hl*4U + sizeof(struct udphdr);
        if(ntohs(udp->uh_ulen) == sizeof(struct udphdr)+60 &&
           hdr->caplen >= payload_offset+60 && ntohs(ip->ip_len) >= ip->ip_hl*4U+sizeof(struct udphdr)+60) {
            const unsigned char *proof = packet+payload_offset;
            for(PMList *entry = attempts; entry; entry = entry->next) {
                knocker_t *candidate = entry->data;
                long long step;
                if(candidate->door->totp_enabled && !candidate->confirmed &&
                   candidate->stage >= candidate->p_seqcount && !strcmp(srcIP, candidate->src) &&
                   !target_strcmp(dstIP, candidate->door->target) && dport == candidate->door->otp_port_range &&
                   verify_confirmation(candidate->door, proof, srcIP, pkt_secs, &step) && step == candidate->tm &&
                   reserve_confirmation(proof, step, pkt_secs)) {
                    candidate->confirmed = 1;
                    process_attempt(candidate);
                    return;
                }
            }
            return; /* A confirmation datagram is never a port-sequence knock. */
        }
    }

    /* Match a subsequence: unrelated TCP/UDP packets, retransmits and noise
     * neither invalidate nor refresh an attempt. Every required knock must
     * still arrive in order before the original deadline. */
    for(lp = attempts; lp; lp = lp->next) {
        attempt = lp->data;
        if(strcmp(srcIP, attempt->src) || target_strcmp(dstIP, attempt->door->target) ||
           !flags_match(attempt->door, ip, tcp)) continue;
        if(attempt->stage < attempt->p_seqcount &&
           ip->ip_p == attempt->p_protocol[attempt->stage] &&
           dport == attempt->p_sequence[attempt->stage]) process_attempt(attempt);
        else if(!attempt->door->totp_enabled) attempt->stage = -1;
    }

    for(lp = doors; lp; lp = lp->next) {
        opendoor_t *door = lp->data;
        unsigned short candidate[SEQ_MAX * 2];
        if(!door->seqcount || target_strcmp(dstIP, door->target) ||
           !flags_match(door, ip, tcp) || ip->ip_p != door->protocol[0]) continue;
        /* Standard TOTP accepts current +/- one 30-second clock window.
         * Keep ALL matching candidates; first-port collisions must not pick
         * the wrong window and discard a valid sequence. */
        int first_shift = door->totp_enabled ? -1 : 0;
        int last_shift = door->totp_enabled ? 1 : 0;
        for(int shift = first_shift; shift <= last_shift; shift++) {
            long long step = door->totp_enabled ? (long long)pkt_secs / 30 + shift : door->tm;
            unsigned count = door->seqcount;
            if(door->totp_enabled) {
                if(totp_ports(door, step, srcIP, candidate)) continue;
            } else {
                memcpy(candidate, door->sequence, count * sizeof(unsigned short));
                if(door->otp_enabled && door->ip_protection) {
                    char key[MAX_SEED_LEN + 16];
                    snprintf(key, sizeof(key), "%s%s", door->seed, srcIP);
                    fill_otp_ports(key, candidate, count, count * 2, step, door->otp_port_range);
                    count *= 2;
                }
            }
            if(candidate[0] != dport) continue;
            unsigned source_count = 0;
            int exists = 0;
            for(PMList *entry = attempts; entry; entry = entry->next) {
                knocker_t *old = entry->data;
                if(!strcmp(srcIP, old->src)) {
                    if(old->door == door) {
                        source_count++;
                        if(old->tm == step) exists = 1;
                    }
                }
            }
            if(exists || source_count >= 8 || list_count(attempts) >= 4096) continue;
            attempt = calloc(1, sizeof(*attempt));
            if(!attempt) { perror("calloc"); cleanup(1); }
            strcpy(attempt->src, srcIP);
            attempt->door = door;
            attempt->seq_start = pkt_secs;
            attempt->tm = step;
            attempt->p_seqcount = count;
            memcpy(attempt->p_sequence, candidate, count * sizeof(unsigned short));
            for(unsigned i = 0; i < count; i++) attempt->p_protocol[i] = door->protocol[i % door->seqcount];
            if(o_lookup) {
                struct hostent *he = gethostbyaddr(&ip->ip_src, sizeof(ip->ip_src), AF_INET);
                if(he) attempt->srchost = strdup(he->h_name);
            }
            attempts = list_add(attempts, attempt);
            process_attempt(attempt);
        }
    }
}

/* Compare ip against door target or all ips of our local interface
 */
int target_strcmp(char *ip, char *target) {
	ip_literal_t *myip;

	if(target && !strcmp(ip, target))
		return 0;

	if (target)
		return 1;

	for(myip = myips; myip != NULL; myip = myip->next) {
		if(!strcmp(ip, myip->value))
			return 0;
	}

	return 1;
}

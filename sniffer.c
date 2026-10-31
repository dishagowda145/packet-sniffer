/*
 * sniffer.c - Simple packet sniffer using Linux raw (AF_PACKET) sockets.
 *
 * Parses Ethernet -> ARP / IPv4 -> TCP / UDP / ICMP headers.
 * Supports filtering by protocol, IP and port, and prints a summary
 * (protocol counts + top talkers) on exit.
 *
 * Needs root:  sudo ./sniffer [options]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#define BUF_SIZE     65536
#define MAX_TALKERS  1024

enum proto_filter { P_ANY = 0, P_TCP, P_UDP, P_ICMP, P_ARP };

struct config {
    char     iface[IFNAMSIZ];   /* empty = all interfaces */
    int      proto;             /* enum proto_filter */
    uint32_t ip;                /* network byte order, 0 = no filter */
    uint16_t port;              /* host byte order, 0 = no filter */
    long     max_packets;       /* 0 = unlimited */
    int      hex_dump;
};

struct talker {
    uint32_t ip;                /* network byte order */
    unsigned long packets;
    unsigned long bytes;
};

static struct {
    unsigned long total, tcp, udp, icmp, arp, other_ip, non_ip;
    unsigned long bytes;
} stats;

static struct talker talkers[MAX_TALKERS];
static int n_talkers;
static volatile sig_atomic_t running = 1;
static struct config cfg;

static void on_sigint(int sig)
{
    (void)sig;
    running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: sudo %s [options]\n"
        "  -I <iface>   capture on this interface (default: all)\n"
        "  -p <proto>   filter: tcp | udp | icmp | arp\n"
        "  -i <ip>      only packets to/from this IPv4 address\n"
        "  -P <port>    only TCP/UDP packets using this port\n"
        "  -n <count>   stop after <count> matching packets\n"
        "  -x           hex dump of each packet\n"
        "  -h           show this help\n", prog);
}

/* ---------- helpers ---------- */

static void update_talker(uint32_t ip, size_t bytes)
{
    for (int i = 0; i < n_talkers; i++) {
        if (talkers[i].ip == ip) {
            talkers[i].packets++;
            talkers[i].bytes += bytes;
            return;
        }
    }
    if (n_talkers < MAX_TALKERS) {
        talkers[n_talkers].ip = ip;
        talkers[n_talkers].packets = 1;
        talkers[n_talkers].bytes = bytes;
        n_talkers++;
    }
}

static int cmp_talker(const void *a, const void *b)
{
    const struct talker *x = a, *y = b;
    if (y->packets > x->packets) return 1;
    if (y->packets < x->packets) return -1;
    return 0;
}

static void print_timestamp(void)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    printf("%02d:%02d:%02d.%06ld ", tm.tm_hour, tm.tm_min, tm.tm_sec,
           ts.tv_nsec / 1000);
}

static void hex_dump(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", buf[i + j]);
            else             printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = buf[i + j];
            putchar((c >= 32 && c < 127) ? c : '.');
        }
        putchar('\n');
    }
}

static void tcp_flags_str(const struct tcphdr *t, char *out)
{
    char *p = out;
    if (t->syn) *p++ = 'S';
    if (t->ack) *p++ = 'A';
    if (t->fin) *p++ = 'F';
    if (t->rst) *p++ = 'R';
    if (t->psh) *p++ = 'P';
    if (t->urg) *p++ = 'U';
    if (p == out) *p++ = '-';
    *p = '\0';
}

/* ---------- packet processing ---------- */

static void handle_packet(const uint8_t *buf, ssize_t len)
{
    if (len < (ssize_t)sizeof(struct ether_header))
        return;

    const struct ether_header *eth = (const struct ether_header *)buf;
    uint16_t etype = ntohs(eth->ether_type);

    /* ---- ARP ---- */
    if (etype == ETHERTYPE_ARP) {
        if (cfg.proto != P_ANY && cfg.proto != P_ARP) return;
        if (cfg.ip || cfg.port) return;   /* ARP has no IP-header/port to match here */
        stats.total++; stats.arp++; stats.bytes += len;
        print_timestamp();
        printf("ARP  %s > ", ether_ntoa((const struct ether_addr *)eth->ether_shost));
        printf("%s  len=%zd\n", ether_ntoa((const struct ether_addr *)eth->ether_dhost), len);
        if (cfg.hex_dump) hex_dump(buf, len);
        return;
    }

    /* ---- not IPv4 ---- */
    if (etype != ETHERTYPE_IP) {
        if (cfg.proto != P_ANY || cfg.ip || cfg.port) return;
        stats.total++; stats.non_ip++; stats.bytes += len;
        return;
    }

    /* ---- IPv4 ---- */
    const uint8_t *ip_start = buf + sizeof(struct ether_header);
    ssize_t ip_avail = len - (ssize_t)sizeof(struct ether_header);
    if (ip_avail < (ssize_t)sizeof(struct iphdr))
        return;

    const struct iphdr *iph = (const struct iphdr *)ip_start;
    size_t ihl = (size_t)iph->ihl * 4;
    if (iph->version != 4 || ihl < sizeof(struct iphdr) || (ssize_t)ihl > ip_avail)
        return;

    const uint8_t *l4 = ip_start + ihl;
    ssize_t l4_avail = ip_avail - (ssize_t)ihl;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));

    /* IP filter */
    if (cfg.ip && iph->saddr != cfg.ip && iph->daddr != cfg.ip)
        return;

    char line[256];
    uint16_t sport = 0, dport = 0;
    int kind = P_ANY;

    switch (iph->protocol) {
    case IPPROTO_TCP: {
        if (l4_avail < (ssize_t)sizeof(struct tcphdr)) return;
        const struct tcphdr *t = (const struct tcphdr *)l4;
        sport = ntohs(t->source);
        dport = ntohs(t->dest);
        char flags[8];
        tcp_flags_str(t, flags);
        snprintf(line, sizeof(line),
                 "TCP  %s:%u > %s:%u  flags=[%s] seq=%u ack=%u win=%u",
                 src, sport, dst, dport, flags,
                 ntohl(t->seq), ntohl(t->ack_seq), ntohs(t->window));
        kind = P_TCP;
        break;
    }
    case IPPROTO_UDP: {
        if (l4_avail < (ssize_t)sizeof(struct udphdr)) return;
        const struct udphdr *u = (const struct udphdr *)l4;
        sport = ntohs(u->source);
        dport = ntohs(u->dest);
        snprintf(line, sizeof(line), "UDP  %s:%u > %s:%u  udp_len=%u",
                 src, sport, dst, dport, ntohs(u->len));
        kind = P_UDP;
        break;
    }
    case IPPROTO_ICMP: {
        if (l4_avail < (ssize_t)sizeof(struct icmphdr)) return;
        const struct icmphdr *ic = (const struct icmphdr *)l4;
        const char *name = ic->type == ICMP_ECHO      ? "echo request" :
                           ic->type == ICMP_ECHOREPLY ? "echo reply"   :
                           ic->type == ICMP_DEST_UNREACH ? "dest unreachable" :
                           ic->type == ICMP_TIME_EXCEEDED ? "time exceeded" : "other";
        snprintf(line, sizeof(line), "ICMP %s > %s  type=%u (%s) code=%u",
                 src, dst, ic->type, name, ic->code);
        kind = P_ICMP;
        break;
    }
    default:
        if (cfg.proto != P_ANY || cfg.port) return;
        stats.total++; stats.other_ip++; stats.bytes += len;
        update_talker(iph->saddr, len);
        print_timestamp();
        printf("IP   %s > %s  proto=%u ttl=%u len=%zd\n",
               src, dst, iph->protocol, iph->ttl, len);
        return;
    }

    /* protocol / port filters */
    if (cfg.proto != P_ANY && cfg.proto != kind) return;
    if (cfg.port && sport != cfg.port && dport != cfg.port) return;

    stats.total++;
    stats.bytes += len;
    if (kind == P_TCP) stats.tcp++;
    else if (kind == P_UDP) stats.udp++;
    else stats.icmp++;
    update_talker(iph->saddr, len);

    print_timestamp();
    printf("%s ttl=%u len=%zd\n", line, iph->ttl, len);
    if (cfg.hex_dump) hex_dump(buf, len);

    if (cfg.max_packets && (long)stats.total >= cfg.max_packets)
        running = 0;
}

static void print_summary(void)
{
    printf("\n========== Summary ==========\n");
    printf("Total packets : %lu (%lu bytes)\n", stats.total, stats.bytes);
    printf("  TCP         : %lu\n", stats.tcp);
    printf("  UDP         : %lu\n", stats.udp);
    printf("  ICMP        : %lu\n", stats.icmp);
    printf("  ARP         : %lu\n", stats.arp);
    printf("  Other IPv4  : %lu\n", stats.other_ip);
    printf("  Non-IP      : %lu\n", stats.non_ip);

    if (n_talkers > 0) {
        qsort(talkers, n_talkers, sizeof(talkers[0]), cmp_talker);
        printf("\nTop talkers (by source IP):\n");
        for (int i = 0; i < n_talkers && i < 5; i++) {
            char a[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &talkers[i].ip, a, sizeof(a));
            printf("  %-16s %8lu packets  %10lu bytes\n",
                   a, talkers[i].packets, talkers[i].bytes);
        }
    }
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "I:p:i:P:n:xh")) != -1) {
        switch (opt) {
        case 'I':
            strncpy(cfg.iface, optarg, IFNAMSIZ - 1);
            break;
        case 'p':
            if      (!strcmp(optarg, "tcp"))  cfg.proto = P_TCP;
            else if (!strcmp(optarg, "udp"))  cfg.proto = P_UDP;
            else if (!strcmp(optarg, "icmp")) cfg.proto = P_ICMP;
            else if (!strcmp(optarg, "arp"))  cfg.proto = P_ARP;
            else { fprintf(stderr, "Unknown protocol: %s\n", optarg); return 1; }
            break;
        case 'i':
            if (inet_pton(AF_INET, optarg, &cfg.ip) != 1) {
                fprintf(stderr, "Invalid IPv4 address: %s\n", optarg);
                return 1;
            }
            break;
        case 'P': {
            long p = strtol(optarg, NULL, 10);
            if (p < 1 || p > 65535) { fprintf(stderr, "Invalid port\n"); return 1; }
            cfg.port = (uint16_t)p;
            break;
        }
        case 'n':
            cfg.max_packets = strtol(optarg, NULL, 10);
            break;
        case 'x':
            cfg.hex_dump = 1;
            break;
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket (are you root?)");
        return 1;
    }

    if (cfg.iface[0]) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = if_nametoindex(cfg.iface);
        if (sll.sll_ifindex == 0) {
            fprintf(stderr, "No such interface: %s\n", cfg.iface);
            close(sock);
            return 1;
        }
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind");
            close(sock);
            return 1;
        }
    }

    /* no SA_RESTART so recvfrom returns EINTR on Ctrl+C */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    uint8_t *buf = malloc(BUF_SIZE);
    if (!buf) { perror("malloc"); close(sock); return 1; }

    printf("Sniffing on %s ... Ctrl+C to stop\n",
           cfg.iface[0] ? cfg.iface : "all interfaces");

    while (running) {
        ssize_t n = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        handle_packet(buf, n);
    }

    print_summary();
    free(buf);
    close(sock);
    return 0;
}

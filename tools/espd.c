/* espd: a tunnel-mode IPsec gateway in user space.
 *
 *   inner IP packet --> TUN device --> esp_encap --> raw IP proto 50 socket --> peer
 *   peer --> raw socket --> esp_decap --> TUN device --> local stack
 *
 * The peer can be another espd or the Linux kernel's own IPsec stack (XFRM)
 * configured with the same SAs; see scripts/netns_interop.sh. */
#include "esp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define MTU_MAX 9000

static volatile sig_atomic_t stop, dump;

static void on_signal(int sig)
{
    if (sig == SIGUSR1)
        dump = 1;
    else
        stop = 1;
}

static void die(const char *what)
{
    perror(what);
    exit(1);
}

static int open_tun(const char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        die("open /dev/net/tun");
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* raw IP packets, no 4-byte packet-info header */
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
        die("TUNSETIFF");
    return fd;
}

static size_t parse_hex(const char *s, uint8_t *out, size_t cap)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    size_t n = strlen(s) / 2;
    if (strlen(s) % 2 || n > cap) {
        fprintf(stderr, "bad hex key\n");
        exit(2);
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            fprintf(stderr, "bad hex key\n");
            exit(2);
        }
        out[i] = (uint8_t)v;
    }
    return n;
}

static void print_stats(const char *dir, const esp_sa *sa)
{
    const esp_stats *s = &sa->stats;
    fprintf(stderr,
            "espd %s spi=0x%08x packets=%llu bytes=%llu auth_fail=%llu replay=%llu "
            "stale=%llu padding=%llu other=%llu\n",
            dir, sa->spi, (unsigned long long)s->packets, (unsigned long long)s->bytes,
            (unsigned long long)s->err_auth, (unsigned long long)s->err_replay,
            (unsigned long long)s->err_stale, (unsigned long long)s->err_padding,
            (unsigned long long)s->err_other);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: espd --tun NAME --peer IP --spi-out N --key-out HEX --spi-in N --key-in HEX\n"
            "            [--esn] [--window N] [--impl ref|table|hw]\n"
            "keys are the RFC 4106 KEYMAT: AES key followed by the 4-byte salt\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *tun_name = NULL, *peer_str = NULL, *key_out = NULL, *key_in = NULL;
    uint32_t spi_out = 0, spi_in = 0, window = 64;
    int esn = 0, impl = -1;
    static const struct option opts[] = {
        {"tun", required_argument, 0, 't'}, {"peer", required_argument, 0, 'p'},
        {"spi-out", required_argument, 0, 'o'}, {"key-out", required_argument, 0, 'O'},
        {"spi-in", required_argument, 0, 'i'}, {"key-in", required_argument, 0, 'I'},
        {"esn", no_argument, 0, 'e'}, {"window", required_argument, 0, 'w'},
        {"impl", required_argument, 0, 'm'}, {0, 0, 0, 0},
    };
    int c;
    while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (c) {
        case 't': tun_name = optarg; break;
        case 'p': peer_str = optarg; break;
        case 'o': spi_out = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'O': key_out = optarg; break;
        case 'i': spi_in = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'I': key_in = optarg; break;
        case 'e': esn = 1; break;
        case 'w': window = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'm':
            impl = !strcmp(optarg, "ref") ? AES_IMPL_REF : !strcmp(optarg, "table") ? AES_IMPL_TABLE
                 : !strcmp(optarg, "hw") ? AES_IMPL_HW : -2;
            if (impl == -2)
                usage();
            break;
        default: usage();
        }
    }
    if (!tun_name || !peer_str || !key_out || !key_in || !spi_out || !spi_in)
        usage();
    if (impl < 0)
        impl = aes_hw_available() ? AES_IMPL_HW : AES_IMPL_TABLE;

    struct sockaddr_in peer = {.sin_family = AF_INET};
    if (inet_pton(AF_INET, peer_str, &peer.sin_addr) != 1)
        usage();

    uint8_t kout[36], kin[36];
    esp_sa tx, rx;
    esp_sa_config cfg = {.esn = esn, .replay_window = window,
                         .aes = (enum aes_impl)impl, .ghash = (enum ghash_impl)impl};
    cfg.spi = spi_out;
    cfg.key = kout;
    cfg.key_len = parse_hex(key_out, kout, sizeof kout);
    if (esp_sa_init(&tx, &cfg) != ESP_OK)
        die("outbound SA");
    cfg.spi = spi_in;
    cfg.key = kin;
    cfg.key_len = parse_hex(key_in, kin, sizeof kin);
    if (esp_sa_init(&rx, &cfg) != ESP_OK)
        die("inbound SA");

    int tun = open_tun(tun_name);
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
    if (raw < 0)
        die("socket(IPPROTO_ESP)");

    struct sigaction sa = {.sa_handler = on_signal};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    fprintf(stderr, "espd: %s <-> %s, out spi=0x%08x in spi=0x%08x, %s crypto%s\n",
            tun_name, peer_str, spi_out, spi_in,
            impl == AES_IMPL_HW ? "hardware" : impl == AES_IMPL_TABLE ? "table" : "reference",
            esn ? ", ESN" : "");

    static uint8_t in[MTU_MAX + 64], out[MTU_MAX + 64];
    struct pollfd fds[2] = {{.fd = tun, .events = POLLIN}, {.fd = raw, .events = POLLIN}};
    while (!stop) {
        if (dump) {
            print_stats("out", &tx);
            print_stats("in", &rx);
            dump = 0;
        }
        if (poll(fds, 2, 500) < 0) {
            if (errno == EINTR)
                continue;
            die("poll");
        }

        if (fds[0].revents & POLLIN) {
            ssize_t n = read(tun, in, MTU_MAX);
            if (n > 0) {
                uint8_t nh = (in[0] >> 4) == 6 ? 41 : 4; /* IPv6-in-ESP or IPv4-in-ESP */
                int m = esp_encap(&tx, in, (size_t)n, nh, out, sizeof out);
                if (m > 0)
                    sendto(raw, out, (size_t)m, 0, (struct sockaddr *)&peer, sizeof peer);
                else
                    fprintf(stderr, "espd: encap: %s\n", esp_strerror(m));
            }
        }

        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            ssize_t n = recvfrom(raw, in, sizeof in, 0, (struct sockaddr *)&from, &fl);
            /* IPv4 raw sockets deliver the outer IP header too; skip it. */
            if (n < 20 || from.sin_addr.s_addr != peer.sin_addr.s_addr)
                continue;
            size_t ihl = (size_t)(in[0] & 0x0f) * 4;
            if ((size_t)n <= ihl)
                continue;
            uint8_t nh;
            int m = esp_decap(&rx, in + ihl, (size_t)n - ihl, out, sizeof out, &nh);
            if (m > 0 && (nh == 4 || nh == 41) && write(tun, out, (size_t)m) < 0)
                perror("espd: write tun");
            /* nh 59 is a dummy packet (RFC 4303 2.6): drop it silently */
        }
    }
    print_stats("out", &tx);
    print_stats("in", &rx);
    return 0;
}

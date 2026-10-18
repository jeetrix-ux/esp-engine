/* espbench: ESP encap/decap throughput per crypto back-end and packet size, plus
 * multi-core scaling with one SA pair per thread (how a NIC/DPU spreads flows
 * across cores with RSS: no shared state, no locks).
 *
 * Output lines start with "RESULT" so scripts/bench_report.pl can tabulate them. */
#include "esp.h"
#include "hwcaps.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(ESP_X86)
#include <x86intrin.h>
#define HAVE_TSC 1
#endif

static const char *impl_name[] = {"ref", "table", "hw"};
static const uint8_t keymat[20] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                                   0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 1, 2, 3, 4};

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static uint64_t ticks(void)
{
#ifdef HAVE_TSC
    return __rdtsc();
#else
    return 0;
#endif
}

static void sa_pair(esp_sa *tx, esp_sa *rx, int impl)
{
    esp_sa_config cfg = {.spi = 0x5000, .key = keymat, .key_len = sizeof keymat, .esn = 1,
                         .replay_window = 1024, .aes = (enum aes_impl)impl,
                         .ghash = (enum ghash_impl)impl};
    if (esp_sa_init(tx, &cfg) || esp_sa_init(rx, &cfg)) {
        fprintf(stderr, "SA init failed for %s\n", impl_name[impl]);
        exit(1);
    }
}

static void report(const char *op, int impl, size_t size, int threads,
                   uint64_t pkts, double secs, uint64_t tsc)
{
    double bytes = (double)pkts * size;
    printf("RESULT op=%s impl=%s size=%zu threads=%d mpps=%.3f gbps=%.3f",
           op, impl_name[impl], size, threads, pkts / secs / 1e6, bytes * 8 / secs / 1e9);
    if (tsc && threads == 1)
        printf(" cpb=%.2f", (double)tsc / bytes);
    else
        printf(" nspb=%.3f", secs * 1e9 * threads / bytes);
    printf("\n");
    fflush(stdout);
}

/* Single-thread encap and decap for one back-end and payload size. */
static void bench_one(int impl, size_t size, double budget)
{
    enum { NPKT = 2048 };
    esp_sa tx, rx;
    sa_pair(&tx, &rx, impl);
    uint8_t *payload = calloc(1, size);
    uint8_t *pkts = malloc((size_t)NPKT * (size + ESP_OVERHEAD));
    int *lens = malloc(NPKT * sizeof *lens);
    uint8_t *out = malloc(size + ESP_OVERHEAD);
    memset(payload, 0x5a, size);

    /* encap */
    uint64_t n = 0, t0 = ticks();
    double start = now(), el;
    do {
        for (int i = 0; i < 256; i++)
            esp_encap(&tx, payload, size, 4, out, size + ESP_OVERHEAD);
        n += 256;
    } while ((el = now() - start) < budget);
    report("encap", impl, size, 1, n, el, ticks() - t0);

    /* decap: replay a fixed batch, resetting the window between passes */
    for (int i = 0; i < NPKT; i++)
        lens[i] = esp_encap(&tx, payload, size, 4, pkts + (size_t)i * (size + ESP_OVERHEAD),
                            size + ESP_OVERHEAD);
    uint64_t base = tx.seq - NPKT;
    n = 0;
    t0 = ticks();
    start = now();
    uint8_t nh;
    do {
        replay_init(&rx.replay, 1024);
        rx.replay.last = base; /* keep the ESN high half in the same subspace */
        for (int i = 0; i < NPKT; i++)
            if (esp_decap(&rx, pkts + (size_t)i * (size + ESP_OVERHEAD), (size_t)lens[i],
                          out, size + ESP_OVERHEAD, &nh) != (int)size) {
                fprintf(stderr, "decap failed during benchmark\n");
                exit(1);
            }
        n += NPKT;
    } while ((el = now() - start) < budget);
    report("decap", impl, size, 1, n, el, ticks() - t0);

    free(payload);
    free(pkts);
    free(lens);
    free(out);
}

struct worker {
    pthread_t th;
    int impl;
    size_t size;
    volatile int *go;
    uint64_t pkts;
};

static void *worker_main(void *arg)
{
    struct worker *w = arg;
    esp_sa tx, rx;
    sa_pair(&tx, &rx, w->impl);
    uint8_t *payload = calloc(1, w->size), *out = malloc(w->size + ESP_OVERHEAD);
    while (*w->go == 0)
        ;
    while (*w->go == 1) {
        for (int i = 0; i < 64; i++)
            esp_encap(&tx, payload, w->size, 4, out, w->size + ESP_OVERHEAD);
        w->pkts += 64;
    }
    free(payload);
    free(out);
    return NULL;
}

static void bench_scaling(int impl, size_t size, int threads, double budget)
{
    struct worker *ws = calloc((size_t)threads, sizeof *ws);
    volatile int go = 0;
    for (int i = 0; i < threads; i++) {
        ws[i].impl = impl;
        ws[i].size = size;
        ws[i].go = &go;
        pthread_create(&ws[i].th, NULL, worker_main, &ws[i]);
    }
    usleep(50000);
    double start = now();
    go = 1;
    usleep((useconds_t)(budget * 1e6));
    go = 2;
    double el = now() - start;
    uint64_t total = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(ws[i].th, NULL);
        total += ws[i].pkts;
    }
    report("encap-mt", impl, size, threads, total, el, 0);
    free(ws);
}

int main(int argc, char **argv)
{
    double budget = argc > 1 ? atof(argv[1]) : 0.5;
    int max_threads = argc > 2 ? atoi(argv[2]) : (int)sysconf(_SC_NPROCESSORS_ONLN);
    int top = aes_hw_available() ? 3 : 2;
    static const size_t sizes[] = {64, 512, 1420};

    printf("# espbench: %d online cores, hardware crypto %s\n",
           (int)sysconf(_SC_NPROCESSORS_ONLN), aes_hw_available() ? "yes" : "no");
    for (int impl = 0; impl < top; impl++)
        for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++)
            bench_one(impl, sizes[s], impl == 0 ? budget / 2 : budget);

    int best = top - 1;
    for (int t = 1; t <= max_threads; t *= 2)
        bench_scaling(best, 1420, t, budget * 2);
    return 0;
}

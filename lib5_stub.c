/*
 * lib5_stub.c - ELF stub loader for GG kernel-docking
 * Keeps lib5.so a valid ELF (GG daemon requirement), sets LD_PRELOAD
 * to libKernelGg.so, then execs the real original lib (lib5.orig.so).
 * Built as static PIE so it runs on Android without runtime linker deps.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

int main(int argc, char **argv) {
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0) return 127;
    self[n] = '\0';

    char *slash = strrchr(self, '/');
    if (!slash) return 127;
    size_t dirlen = (size_t)(slash - self);

    char preload[PATH_MAX];
    snprintf(preload, sizeof(preload), "%.*s/libKernelGg.so", (int)dirlen, self);
    setenv("LD_PRELOAD", preload, 1);

    char target[PATH_MAX];
    snprintf(target, sizeof(target), "%.*s/lib5.orig.so", (int)dirlen, self);

    execv(target, argv);

    perror("execv");
    return 126;
}

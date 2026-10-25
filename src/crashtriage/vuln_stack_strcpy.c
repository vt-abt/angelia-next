/* Deliberately vulnerable target for P0.4 corpus.
 * Classic saved-RIP overwrite via strcpy of file-supplied input into a
 * fixed 64-byte stack buffer.
 *
 * Compiled in three mitigation variants (see src/crashtriage/CMakeLists.txt).
 * The point of the corpus is to observe how the SAME bug manifests
 * differently at each mitigation level — Stage 4 attributes those
 * differences.
 *
 * Not portable, not defensive, not to be linked into anything else.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Force MSVC not to inline or elide the vulnerable frame — we want a real
 * function prologue with a saved return address for the overflow to hit. */
#pragma optimize("", off)

static void __declspec(noinline) vulnerable(const char* input) {
    char buf[64];
    strcpy(buf, input);   /* the whole point */
    /* Touch the buffer so the compiler cannot dead-store-eliminate it. */
    fprintf(stderr, "vuln: copied %zu bytes\n", strlen(buf));
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 2;
    }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 3; }
    static char input[4096];
    size_t n = fread(input, 1, sizeof(input) - 1, f);
    input[n] = 0;
    fclose(f);
    vulnerable(input);
    return 0;
}

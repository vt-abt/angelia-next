/* Heap out-of-bounds write vulnerability. Reads input, memcpy's into
 * a small HeapAlloc'd chunk without bounds checking. The subsequent
 * HeapFree traps on the corrupted chunk-metadata on modern Windows
 * (LFH + HeapEnableTerminationOnCorruption default), raising
 * STATUS_STACK_BUFFER_OVERRUN (0xC0000409) or STATUS_HEAP_CORRUPTION
 * (0xC0000374). Which one lands depends on Windows version + the exact
 * corruption shape.
 *
 * On an "off" build we still see the crash — you can't cleanly disable
 * the built-in heap corruption checks without heap flags, but we keep
 * the same three-variant matrix as the stack vuln so the classifier
 * has a comparable row of mitigation flags to attribute the verdict to.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)

static void vulnerable(const char* input, size_t input_len) {
    HANDLE heap = GetProcessHeap();
    /* 32-byte chunk; write however many bytes the input has. */
    char* chunk = (char*)HeapAlloc(heap, 0, 32);
    if (!chunk) return;
    memcpy(chunk, input, input_len);
    /* Free the (possibly corrupted) chunk. Modern heap validators trap here. */
    HeapFree(heap, 0, chunk);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    static char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    /* Overflow the 32-byte heap chunk with `n` bytes from input. */
    vulnerable(buf, n);
    return 0;
}

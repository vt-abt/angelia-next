/* Positive-signal test target for the static-leg import scanner.
 * Imports the "classic" injection triad from kernel32 in a way that
 * survives link-time dead-code stripping (used through function
 * pointers assigned from GetProcAddress into a volatile write).
 *
 * Does NOT execute the injection — main() writes zero to a volatile
 * sink and returns. The point is only that the PE's import table
 * carries VirtualAllocEx + WriteProcessMemory + CreateRemoteThread. */

#include <windows.h>
#include <stdio.h>

/* Force each import to be observed by the linker: put the address into
 * an array, then print addresses conditionally on argc so the compiler
 * cannot fold. Volatile-only writes get pruned by MSVC's dead-store
 * elimination since nothing reads the sink. */

int main(int argc, char** argv) {
    (void)argv;
    FARPROC fns[] = {
        (FARPROC)VirtualAllocEx,
        (FARPROC)WriteProcessMemory,
        (FARPROC)CreateRemoteThread,
        (FARPROC)OpenProcess,
    };
    unsigned long long acc = 0;
    for (int i = 0; i < (int)(sizeof(fns) / sizeof(fns[0])); ++i) {
        acc ^= (unsigned long long)(uintptr_t)fns[i];
    }
    if (argc > 1000) printf("%llx\n", acc);   /* never true, but observable */
    return (int)(acc & 1);
}

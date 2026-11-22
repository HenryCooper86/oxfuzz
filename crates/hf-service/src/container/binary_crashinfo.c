/*
 * oxfuzz crash reporter for binary-only replays.
 *
 * Preloaded into the emulated target when a saved finding is replayed. On a
 * fatal signal it prints where the target was, in the frame format oxfuzz's
 * crash classifier reads, and then dies from the same signal so the replay's
 * exit status is unchanged. It is never loaded during fuzzing.
 *
 * Frames are printed as module-relative offsets, so the same fault yields
 * the same report whatever addresses the loader picked.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#define MAX_FRAMES 48
#define REPORTED_FRAMES 16
#define ALT_STACK_BYTES (64 * 1024)
#define WATCHDOG_SECS 5
#define LINE_BYTES 512

static char alt_stack[ALT_STACK_BYTES];
static volatile sig_atomic_t fatal_signal;

struct line {
    char text[LINE_BYTES];
    size_t used;
};

static void put(struct line *line, const char *text) {
    while (*text != '\0' && line->used + 1 < sizeof line->text) {
        line->text[line->used++] = *text++;
    }
}

static void put_hex(struct line *line, uintptr_t value) {
    char digits[2 * sizeof value];
    size_t count = 0;
    do {
        digits[count++] = "0123456789abcdef"[value & 0xf];
        value >>= 4;
    } while (value != 0);
    put(line, "0x");
    while (count > 0 && line->used + 1 < sizeof line->text) {
        line->text[line->used++] = digits[--count];
    }
}

static void put_decimal(struct line *line, unsigned value) {
    char digits[12];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (count > 0 && line->used + 1 < sizeof line->text) {
        line->text[line->used++] = digits[--count];
    }
}

static void flush(struct line *line) {
    size_t sent = 0;
    while (sent < line->used) {
        ssize_t wrote = write(STDERR_FILENO, line->text + sent, line->used - sent);
        if (wrote <= 0) {
            break;
        }
        sent += (size_t)wrote;
    }
    line->used = 0;
}

static void die(int sig) {
    sigset_t set;
    signal(sig, SIG_DFL);
    sigemptyset(&set);
    sigaddset(&set, sig);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    raise(sig);
    _exit(128 + sig);
}

/* The report could not be finished in time: keep the original signal. */
static void give_up(int unused) {
    (void)unused;
    die(fatal_signal);
}

static const char *name_of(int sig) {
    switch (sig) {
    case SIGSEGV:
        return "SEGV";
    case SIGBUS:
        return "BUS";
    case SIGFPE:
        return "FPE";
    case SIGILL:
        return "ILL";
    case SIGABRT:
        return "ABORT";
    default:
        return "SIGNAL";
    }
}

static uintptr_t fault_pc(const ucontext_t *context) {
#if defined(__aarch64__)
    return (uintptr_t)context->uc_mcontext.pc;
#elif defined(__x86_64__)
    return (uintptr_t)context->uc_mcontext.gregs[REG_RIP];
#else
    (void)context;
    return 0;
#endif
}

/* "symbol (module+0xoffset)", "(module+0xoffset)", or "(unknown)". */
static void put_location(struct line *line, uintptr_t address, int with_in) {
    Dl_info info;
    if (dladdr((void *)address, &info) == 0 || info.dli_fname == NULL) {
        put(line, "(unknown)");
        return;
    }
    if (info.dli_sname != NULL) {
        put(line, with_in ? "in " : "");
        put(line, info.dli_sname);
        put(line, " ");
    }
    put(line, "(");
    put(line, info.dli_fname);
    put(line, "+");
    put_hex(line, address - (uintptr_t)info.dli_fbase);
    put(line, ")");
}

/* The load address of the module holding `address`, or NULL. */
static const void *module_of(uintptr_t address) {
    Dl_info info;
    if (dladdr((void *)address, &info) == 0) {
        return NULL;
    }
    return info.dli_fbase;
}

static void put_frame(struct line *line, unsigned index, uintptr_t address) {
    put(line, "    #");
    put_decimal(line, index);
    put(line, " ");
    put_hex(line, address);
    put(line, " ");
    put_location(line, address, 1);
    put(line, "\n");
    flush(line);
}

/* "SEGV (signal 11) at ". */
static void put_signal(struct line *line, int sig) {
    put(line, name_of(sig));
    put(line, " (signal ");
    put_decimal(line, (unsigned)sig);
    put(line, ") at ");
}

static void report(int sig, siginfo_t *info, void *raw) {
    struct line line = {.used = 0};
    void *frames[MAX_FRAMES];
    uintptr_t pc = fault_pc(raw);
    uintptr_t top;
    int count;
    int start = -1;
    unsigned printed = 0;

    fatal_signal = sig;
    signal(SIGALRM, give_up);
    alarm(WATCHDOG_SECS);

    put(&line, "==ERROR: oxfuzz-crashinfo: ");
    put_signal(&line, sig);
    put_location(&line, pc, 0);
    if (sig == SIGSEGV || sig == SIGBUS) {
        put(&line, ", fault address ");
        put_hex(&line, (uintptr_t)info->si_addr);
    }
    put(&line, "\n");
    flush(&line);

    count = backtrace(frames, MAX_FRAMES);
    for (int index = 0; index < count; index++) {
        if ((uintptr_t)frames[index] == pc) {
            start = index;
            break;
        }
    }
    /* abort() raises from inside the C library: every abort shares those
     * frames, so the report starts at the first frame outside the module
     * that raised, which is the code that called abort or failed an assert. */
    if (sig == SIGABRT && start >= 0) {
        const void *raiser = module_of(pc);
        int caller = start;
        while (caller < count && module_of((uintptr_t)frames[caller]) == raiser) {
            caller++;
        }
        if (caller < count) {
            start = caller;
        }
    }
    if (start < 0) {
        /* The unwinder did not reach the interrupted frame; it is still
         * known exactly from the signal context. */
        put_frame(&line, printed++, pc);
    }
    for (int index = start; start >= 0 && index < count && printed < REPORTED_FRAMES; index++) {
        put_frame(&line, printed++, (uintptr_t)frames[index]);
    }
    top = start >= 0 ? (uintptr_t)frames[start] : pc;

    put(&line, "SUMMARY: oxfuzz-crashinfo: ");
    put_signal(&line, sig);
    put_location(&line, top, 0);
    put(&line, "\n");
    flush(&line);
    die(sig);
}

__attribute__((constructor)) static void install(void) {
    static const int signals[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT};
    struct sigaction action;
    stack_t stack;
    void *warm[2];

    /* Load the unwinder now, so the handler allocates and loads nothing. */
    (void)backtrace(warm, 2);

    stack.ss_sp = alt_stack;
    stack.ss_size = sizeof alt_stack;
    stack.ss_flags = 0;
    (void)sigaltstack(&stack, NULL);

    memset(&action, 0, sizeof action);
    action.sa_sigaction = report;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&action.sa_mask);
    for (size_t index = 0; index < sizeof signals / sizeof signals[0]; index++) {
        (void)sigaction(signals[index], &action, NULL);
    }
}

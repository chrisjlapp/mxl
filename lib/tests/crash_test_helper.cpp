// SPDX-FileCopyrightText: 2026 Contributors to the Media eXchange Layer project.
// SPDX-License-Identifier: Apache-2.0

// Standalone crash-test helper for null-domain API argument tests.
// Launched via exec by the parent test process.
// Usage: crash_test_helper <function_index> [arg1 [arg2 ...]]
//
// function_index maps to specific API calls to exercise:
//   0 = mxlCreateInstance(nullptr, opts)
//   1 = mxlFlowReaderGetInfo(nullptr, &info)
//   2 = mxlFlowReaderGetInfo(reader, nullptr)
//
// Stdout: STATUS <int> SIGNAL <int> BACKTRACE <count>
//   STATUS  = return value or -1 if crashed
//   SIGNAL  = signal number that killed the process (0 if none)
//   BACKTRACE = number of frames captured before signal re-raise
//
// If the helper is killed by a signal, it prints backtrace info then
// re-raises the signal so the parent's waitpid sees it.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <execinfo.h>
#include <unistd.h>
#include <mxl/mxl.h>
#include <mxl/flow.h>

static int g_backtraceCount = 0;

static void signal_handler(int sig) {
    void *buffer[64];
    g_backtraceCount = backtrace(buffer, 64);
    char **symbols = backtrace_symbols(buffer, g_backtraceCount);
    if (symbols) {
        for (int i = 0; i < g_backtraceCount; i++) {
            fprintf(stderr, "[CRASH-HELPER]   %s\n", symbols[i]);
        }
        free(symbols);
    }
    // Re-raise
    signal(sig, SIG_DFL);
    raise(sig);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "[CRASH-HELPER] Usage: %s <function_index> [args...]\n", argv[0]);
        return 1;
    }

    // Register signal handlers before any API call.
    signal(SIGSEGV, signal_handler);
    signal(SIGBUS, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGFPE, signal_handler);

    int funcIdx = std::atoi(argv[1]);

    mxlStatus result = MXL_STATUS_OK;
    int signalNum = 0;

    try {
        switch (funcIdx) {
        case 0: {
            // mxlCreateInstance(nullptr, opts) — known to crash
            mxlInstance inst = mxlCreateInstance(nullptr, "{}");
            result = inst ? MXL_STATUS_OK : MXL_ERR_UNKNOWN;
            break;
        }
        case 1: {
            // mxlFlowReaderGetInfo(nullptr, &info) — crashes
            mxlFlowInfo_t info{};
            result = mxlFlowReaderGetInfo(nullptr, &info);
            break;
        }
        case 2: {
            // mxlFlowReaderGetInfo(reader, nullptr) — SDK null-checks info
            mxlFlowReader reader = nullptr;  // won't be used, info is null
            mxlFlowInfo_t *info = nullptr;
            result = mxlFlowReaderGetInfo(reader, info);
            break;
        }
        default:
            fprintf(stderr, "[CRASH-HELPER] Unknown function index: %d\n", funcIdx);
            result = MXL_ERR_INVALID_ARG;
            break;
        }
    } catch (...) {
        result = MXL_ERR_UNKNOWN;
    }

    // Print result for parent to read
    printf("STATUS %d SIGNAL %d BACKTRACE %d\n",
           static_cast<int>(result),
           signalNum,
           g_backtraceCount);
    fflush(stdout);

    // Exit normally — if a signal was caught, it was already re-raised above.
    return (result == MXL_STATUS_OK) ? 0 : 1;
}

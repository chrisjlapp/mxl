// SPDX-FileCopyrightText: 2026 Contributors to the Media eXchange Layer project.
// SPDX-License-Identifier: Apache-2.0

// Standalone C3 writer helper — launched via exec by the parent test process.
// Usage: c3_writer_helper <domain_path> <flow_definition_json> [existing_flow_id]
//
// Exit status: 0 = success, 1 = failure.
// Stdout lines (in order):
//   DESCRIPTORS <count> (<fd>:<link> ...)   -- initial descriptor inventory
//   CREATE_STATUS <int> CREATE_CREATED <0|1>
//   OPEN_STATUS <int>
//   COMMIT_STATUS <int>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <execinfo.h>
#include <filesystem>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

#include <mxl/mxl.h>
#include <mxl/flow.h>
#include <mxl/flowinfo.h>

static void signal_handler(int sig) {
    void *buffer[64];
    int nptrs = backtrace(buffer, 64);
    char **symbols = backtrace_symbols(buffer, nptrs);
    if (symbols) {
        fprintf(stderr, "[C3-HELPER] Signal %d (%s) — %d frames\n", sig, strsignal(sig), nptrs);
        for (int i = 0; i < nptrs; i++) {
            fprintf(stderr, "[C3-HELPER]   %s\n", symbols[i]);
        }
        free(symbols);
    } else {
        fprintf(stderr, "[C3-HELPER] Signal %d (%s) — backtrace_symbols failed\n", sig, strsignal(sig));
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "[C3-HELPER] Usage: %s <domain_path> <flow_def_json> [existing_flow_id]\n", argv[0]);
        return 1;
    }

    signal(SIGSEGV, signal_handler);
    signal(SIGBUS, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGFPE, signal_handler);

    // 1. Enumerate and report initial descriptor inventory.
    {
        std::error_code ec;
        std::vector<std::pair<int, std::string>> fdList;
        for (auto const &entry : std::filesystem::directory_iterator("/proc/self/fd", ec)) {
            if (ec) break;
            std::string link;
            std::error_code ec2;
            link = std::filesystem::read_symlink(entry, ec2);
            if (!ec2) {
                try {
                    int fdNum = std::stoi(entry.path().filename());
                    fdList.emplace_back(fdNum, link);
                } catch (...) {}
            }
        }
        std::sort(fdList.begin(), fdList.end());
        printf("DESCRIPTORS %d", static_cast<int>(fdList.size()));
        for (auto const &p : fdList) {
            printf(" %d:%s", p.first, p.second.c_str());
        }
        printf("\n");
        fflush(stdout);
    }

    auto const *domainPath = argv[1];
    auto const *flowDef = argv[2];
    auto const *existingFlowId = (argc > 3) ? argv[3] : nullptr;

    // 2. Create MXL instance.
    mxlInstance inst = mxlCreateInstance(domainPath, "{}");
    if (inst == nullptr) {
        printf("CREATE_STATUS %d CREATE_CREATED 0\n", static_cast<int>(MXL_ERR_UNKNOWN));
        printf("OPEN_STATUS %d (INSTANCE_FAILED)\n", static_cast<int>(MXL_ERR_UNKNOWN));
        printf("COMMIT_STATUS %d (INSTANCE_FAILED)\n", static_cast<int>(MXL_ERR_UNKNOWN));
        fflush(stdout);
        return 1;
    }

    // 3. Create or connect writer.
    mxlFlowWriter writer = nullptr;
    mxlFlowConfigInfo configInfo{};
    bool created = false;

    mxlStatus createStatus = mxlCreateFlowWriter(inst, flowDef, "{}", &writer, &configInfo, &created);

    if (createStatus == MXL_STATUS_OK && writer != nullptr) {
        // 4. Open grain.
        mxlGrainInfo grainInfo{};
        uint8_t *payload = nullptr;
        mxlStatus openStatus = mxlFlowWriterOpenGrain(writer, 0, &grainInfo, &payload);

        if (openStatus == MXL_STATUS_OK && payload != nullptr) {
            // 5. Commit grain.
            std::memset(payload, 0xBB, grainInfo.grainSize);
            grainInfo.validSlices = grainInfo.totalSlices;
            mxlStatus commitStatus = mxlFlowWriterCommitGrain(writer, &grainInfo);

            printf("CREATE_STATUS %d CREATE_CREATED %d\n",
                   static_cast<int>(createStatus), created ? 1 : 0);
            printf("OPEN_STATUS %d\n", static_cast<int>(openStatus));
            printf("COMMIT_STATUS %d\n", static_cast<int>(commitStatus));
            fflush(stdout);

            mxlReleaseFlowWriter(inst, writer);
            mxlDestroyInstance(inst);
            return (commitStatus == MXL_STATUS_OK) ? 0 : 1;
        } else {
            printf("CREATE_STATUS %d CREATE_CREATED %d\n",
                   static_cast<int>(createStatus), created ? 1 : 0);
            printf("OPEN_STATUS %d\n", static_cast<int>(openStatus));
            printf("COMMIT_STATUS %d (OPEN_FAILED)\n", static_cast<int>(openStatus));
            fflush(stdout);

            mxlReleaseFlowWriter(inst, writer);
            mxlDestroyInstance(inst);
            return 1;
        }
    } else {
        printf("CREATE_STATUS %d CREATE_CREATED %d\n",
               static_cast<int>(createStatus), created ? 1 : 0);
        printf("OPEN_STATUS %d (CREATE_FAILED)\n", static_cast<int>(createStatus));
        printf("COMMIT_STATUS %d (CREATE_FAILED)\n", static_cast<int>(createStatus));
        fflush(stdout);

        mxlDestroyInstance(inst);
        return 1;
    }
}

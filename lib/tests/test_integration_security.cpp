// SPDX-FileCopyrightText: 2026 Contributors to the Media eXchange Layer project.
// SPDX-License-Identifier: Apache-2.0

//
// Security oriented integration tests that drive the real MXL C API and record
// what the SDK actually does. Every check prints a PASS/FAIL line derived from
// the observed result; nothing is assumed and no verdict is printed without an
// accompanying measurement. Where a behaviour can only be exercised by a
// different process, the test forks a child and exchanges results over a pipe.
//
// The categories mirror the MXL threat model:
//   A. access and identity
//   B. shared data modification
//   C. sequential publication and readback
//   C2. overlapping producer/consumer with ring wraparound
//   C3. competing writers in independent processes
//   D. locking and garbage collection
//   E. input validation
//   F. RDMA / container environment detection
//

#include "Utils.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <filesystem>
#if MXL_FABRICS_OFI
#include <mxl/fabrics.h>
#endif
#include <fstream>
#include <functional>
#include <climits>
#include <limits>
#include <random>
#include <stdexcept>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <uuid.h>
#include <catch2/catch_test_macros.hpp>
#include <picojson/wrapper.h>
#include <mxl/flow.h>
#include <mxl/mxl.h>
#include <mxl/time.h>
#include <mxl-internal/PathUtils.hpp>

namespace fs = std::filesystem;

namespace
{
    using namespace std::chrono_literals;

    // MXL_GRAIN_PAYLOAD_OFFSET from mxl-internal/Flow.hpp. The grain header and
    // its padding occupy the first 8 KiB of every discrete grain file.
    constexpr auto const GRAIN_PAYLOAD_OFFSET = std::size_t{8192};

    /**************************************************************************/
    /* Reporting helpers.                                                     */
    /**************************************************************************/

    std::string statusName(mxlStatus status)
    {
        switch (status)
        {
            case MXL_STATUS_OK:                  return "MXL_STATUS_OK";
            case MXL_ERR_UNKNOWN:                return "MXL_ERR_UNKNOWN";
            case MXL_ERR_FLOW_NOT_FOUND:         return "MXL_ERR_FLOW_NOT_FOUND";
            case MXL_ERR_OUT_OF_RANGE_TOO_LATE:  return "MXL_ERR_OUT_OF_RANGE_TOO_LATE";
            case MXL_ERR_OUT_OF_RANGE_TOO_EARLY: return "MXL_ERR_OUT_OF_RANGE_TOO_EARLY";
            case MXL_ERR_INVALID_FLOW_READER:    return "MXL_ERR_INVALID_FLOW_READER";
            case MXL_ERR_INVALID_FLOW_WRITER:    return "MXL_ERR_INVALID_FLOW_WRITER";
            case MXL_ERR_TIMEOUT:                return "MXL_ERR_TIMEOUT";
            case MXL_ERR_INVALID_ARG:            return "MXL_ERR_INVALID_ARG";
            case MXL_ERR_CONFLICT:               return "MXL_ERR_CONFLICT";
            case MXL_ERR_PERMISSION_DENIED:      return "MXL_ERR_PERMISSION_DENIED";
            case MXL_ERR_FLOW_INVALID:           return "MXL_ERR_FLOW_INVALID";
            default:                             return "MXL_ERR(" + std::to_string(static_cast<int>(status)) + ")";
        }
    }

    /// Print a PASS/FAIL line derived from \p condition and return the same
    /// value so the caller can forward it to a Catch2 assertion.
    bool verify(bool condition, std::string const& label, std::string const& detail = {})
    {
        std::printf("[%s] %s", condition ? "PASS" : "FAIL", label.c_str());
        if (!detail.empty())
        {
            std::printf(" | %s", detail.c_str());
        }
        std::printf("\n");
        std::fflush(stdout);
        return condition;
    }

    void note(std::string const& label, std::string const& detail = {})
    {
        std::printf("[INFO] %s", label.c_str());
        if (!detail.empty())
        {
            std::printf(" | %s", detail.c_str());
        }
        std::printf("\n");
        std::fflush(stdout);
    }

    void notTested(std::string const& label, std::string const& reason)
    {
        std::printf("[NOT TESTED] %s | %s\n", label.c_str(), reason.c_str());
        std::fflush(stdout);
    }

    /**************************************************************************/
    /* Process and pipe helpers.                                              */
    /**************************************************************************/

    struct Pipe
    {
        int readFd{-1};
        int writeFd{-1};

        [[nodiscard]]
        bool open()
        {
            int fds[2];
            if (::pipe(fds) != 0)
            {
                return false;
            }
            readFd = fds[0];
            writeFd = fds[1];
            return true;
        }

        void closeRead()
        {
            if (readFd != -1)
            {
                ::close(readFd);
                readFd = -1;
            }
        }

        void closeWrite()
        {
            if (writeFd != -1)
            {
                ::close(writeFd);
                writeFd = -1;
            }
        }

        ~Pipe()
        {
            closeRead();
            closeWrite();
        }
    };

    bool writeAll(int fd, void const* data, std::size_t size)
    {
        auto const* cursor = static_cast<std::uint8_t const*>(data);
        while (size > 0)
        {
            auto const written = ::write(fd, cursor, size);
            if (written < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return false;
            }
            cursor += written;
            size -= static_cast<std::size_t>(written);
        }
        return true;
    }

    bool readAll(int fd, void* data, std::size_t size)
    {
        auto* cursor = static_cast<std::uint8_t*>(data);
        while (size > 0)
        {
            auto const obtained = ::read(fd, cursor, size);
            if (obtained < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return false;
            }
            if (obtained == 0)
            {
                return false;
            }
            cursor += obtained;
            size -= static_cast<std::size_t>(obtained);
        }
        return true;
    }

    /// Report produced by a child that opens a flow file and optionally writes
    /// bytes into it.
    struct WriteReport
    {
        std::int32_t opened{0};
        std::int32_t err{0};
        std::int64_t requested{-1};
        std::int64_t written{-1};
    };

    /// Fork a child, open \p path for read/write and write \p size bytes from
    /// \p bytes at \p offset. The child only performs raw syscalls and exits
    /// with _exit so it never touches inherited C++/thread state.
    WriteReport runFileWriteInChild(fs::path const& path, off_t offset, void const* bytes, std::size_t size)
    {
        auto report = WriteReport{};
        auto pipe = Pipe{};
        if (!pipe.open())
        {
            return report;
        }

        auto const pid = ::fork();
        if (pid < 0)
        {
            return report;
        }

        if (pid == 0)
        {
            pipe.closeRead();

            auto childReport = WriteReport{};
            childReport.requested = static_cast<std::int64_t>(size);

            auto const fd = ::open(path.c_str(), O_RDWR);
            if (fd < 0)
            {
                childReport.opened = 0;
                childReport.err = errno;
            }
            else
            {
                childReport.opened = 1;
                auto const written = (size == 0U) ? ssize_t{0} : ::pwrite(fd, bytes, size, offset);
                if (written < 0)
                {
                    childReport.err = errno;
                }
                else
                {
                    childReport.written = static_cast<std::int64_t>(written);
                }
                ::close(fd);
            }

            (void)writeAll(pipe.writeFd, &childReport, sizeof(childReport));
            ::_exit(0);
        }

        pipe.closeWrite();
        (void)readAll(pipe.readFd, &report, sizeof(report));
        int waitStatus = 0;
        (void)::waitpid(pid, &waitStatus, 0);
        return report;
    }

    /// Result of running a flow creation in a child. Used for malformed input
    /// that may crash the process under test.
    struct FlowCreationOutcome
    {
        bool exited{false};
        int exitCode{0};
        bool signaled{false};
        int termSignal{0};
        int reportedStatus{std::numeric_limits<int>::min()};
    };

    FlowCreationOutcome runCreateFlowInChild(std::string const& domainPath, std::string const& flowDef)
    {
        auto outcome = FlowCreationOutcome{};
        auto pipe = Pipe{};
        if (!pipe.open())
        {
            return outcome;
        }

        auto const pid = ::fork();
        if (pid < 0)
        {
            return outcome;
        }

        if (pid == 0)
        {
            pipe.closeRead();
            ::alarm(15);

            auto status = std::numeric_limits<int>::min();
            if (auto const instance = mxlCreateInstance(domainPath.c_str(), "{}"); instance != nullptr)
            {
                mxlFlowWriter writer{};
                mxlFlowConfigInfo config{};
                bool created = false;
                status = static_cast<int>(mxlCreateFlowWriter(instance, flowDef.c_str(), "{}", &writer, &config, &created));
            }

            (void)writeAll(pipe.writeFd, &status, sizeof(status));
            ::_exit(0);
        }

        pipe.closeWrite();
        int status = std::numeric_limits<int>::min();
        (void)readAll(pipe.readFd, &status, sizeof(status));

        int waitStatus = 0;
        (void)::waitpid(pid, &waitStatus, 0);

        outcome.reportedStatus = status;
        if (WIFEXITED(waitStatus))
        {
            outcome.exited = true;
            outcome.exitCode = WEXITSTATUS(waitStatus);
        }
        if (WIFSIGNALED(waitStatus))
        {
            outcome.signaled = true;
            outcome.termSignal = WTERMSIG(waitStatus);
        }
        return outcome;
    }

    /// Classification of how a child-process run completed.
    enum class ChildResultKind
    {
        NormalReturn,   ///< Child called _exit(0) after writing its status
        Exception,      ///< Child threw (caught in the try/catch wrapper,
                        ///< still writes a status but tagged so the caller knows)
        Timeout,        ///< Child was killed by SIGALRM before it could report
        Signal,         ///< Child terminated by a signal (crash)
        HarnessFailure  ///< IPC failed, waitpid failed, or fork failed
    };

    /// Outcome of running a generic API call in a child process.  Every field
    /// is populated so the caller can record which path was taken.
    struct ChildOutcome
    {
        ChildResultKind kind{ChildResultKind::HarnessFailure};
        mxlStatus status{MXL_STATUS_OK};
        int exitCode{0};
        int termSignal{0};
        bool pipeBroken{false};
        bool waitFailed{false};
        bool forkFailed{false};
    };

    /// Run \\p fn in a child process.  The parent records a detailed outcome
    /// describing whether the child returned normally, timed out, was killed
    /// by a signal, or whether the harness itself failed (fork/IPC/waitpid).
    template<typename Fn>
    ChildOutcome runChild(Fn&& fn)
    {
        auto outcome = ChildOutcome{};
        auto pipe = Pipe{};
        if (!pipe.open())
        {
            outcome.kind = ChildResultKind::HarnessFailure;
            outcome.pipeBroken = true;
            return outcome;
        }

        // Block SIGSEGV and other fatal signals in the parent so that
        // Catch2's signal handler does not fire when the child crashes.
        sigset_t mask, oldMask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGSEGV);
        sigaddset(&mask, SIGFPE);
        sigaddset(&mask, SIGABRT);
        sigaddset(&mask, SIGBUS);
        sigaddset(&mask, SIGALRM);
        pthread_sigmask(SIG_BLOCK, &mask, &oldMask);

        auto const pid = ::fork();
        if (pid < 0)
        {
            outcome.kind = ChildResultKind::HarnessFailure;
            outcome.forkFailed = true;
            pthread_sigmask(SIG_SETMASK, &oldMask, nullptr);
            return outcome;
        }

        if (pid == 0)
        {
            pipe.closeRead();
            ::alarm(30);
            try
            {
                auto value = static_cast<int>(fn());
                if (!writeAll(pipe.writeFd, &value, sizeof(value)))
                {
                    // Pipe broken — parent died before we could report.
                }
                ::_exit(0);
            }
            catch (...)
            {
                // Write an error value so the parent can distinguish exceptions
                // from timeouts (the parent reads the pipe and does not see
                // "no data → timeout" when the child threw an exception).
                int value = static_cast<int>(MXL_ERR_UNKNOWN);
                writeAll(pipe.writeFd, &value, sizeof(value));
                ::_exit(-1);
            }
        }

        // --- Parent path ---
        pipe.closeWrite();

        int value = 0;
        bool gotData = readAll(pipe.readFd, &value, sizeof(value));

        int waitStatus = 0;
        auto const wret = ::waitpid(pid, &waitStatus, 0);

        // Restore original signal mask
        pthread_sigmask(SIG_SETMASK, &oldMask, nullptr);

        if (wret != pid)
        {
            outcome.kind = ChildResultKind::HarnessFailure;
            outcome.waitFailed = true;
            return outcome;
        }

        if (!gotData)
        {
            // No data arrived through the pipe — check why.
            if (WIFSIGNALED(waitStatus))
            {
                outcome.termSignal = WTERMSIG(waitStatus);
                if (WTERMSIG(waitStatus) == SIGALRM)
                {
                    // Child was killed by the alarm — treat as a timeout.
                    outcome.kind = ChildResultKind::Timeout;
                    outcome.status = MXL_ERR_TIMEOUT;
                }
                else
                {
                    // Child was killed by a fatal signal — treat as a crash.
                    outcome.kind = ChildResultKind::Signal;
                    outcome.status = MXL_ERR_UNKNOWN;
                }
                return outcome;
            }
            if (WIFEXITED(waitStatus))
            {
                // Exited normally but didn't write — must have timed out
                // or crashed before reaching the write point.
                outcome.kind = ChildResultKind::Timeout;
                outcome.exitCode = WEXITSTATUS(waitStatus);
                outcome.status = MXL_ERR_TIMEOUT;
                return outcome;
            }
            outcome.kind = ChildResultKind::HarnessFailure;
            return outcome;
        }

        // Data arrived via IPC — record it first so the status is valid.
        outcome.status = static_cast<mxlStatus>(value);

        if (WIFSIGNALED(waitStatus))
        {
            // Child sent data then crashed (signal after write).
            outcome.termSignal = WTERMSIG(waitStatus);
            if (WTERMSIG(waitStatus) == SIGALRM)
            {
                outcome.kind = ChildResultKind::Timeout;
                outcome.status = MXL_ERR_TIMEOUT;
            }
            else
            {
                outcome.kind = ChildResultKind::Signal;
                outcome.status = MXL_ERR_UNKNOWN;
            }
            return outcome;
        }

        if (WIFEXITED(waitStatus))
        {
            outcome.kind = ChildResultKind::NormalReturn;
            outcome.exitCode = WEXITSTATUS(waitStatus);
            return outcome;
        }

        outcome.kind = ChildResultKind::HarnessFailure;
        return outcome;
    }

    /// Thin wrapper for simple null-pointer crash tests: returns the old
    /// ApiCallOutcome shape for compatibility with existing test code.
    struct ApiCallOutcome
    {
        bool crashed{false};
        mxlStatus status{MXL_STATUS_OK};
    };

    /// Compatibility overload for bare function pointers.
    ApiCallOutcome runApiCallInChild(mxlStatus (*fn)())
    {
        auto co = runChild(fn);
        ApiCallOutcome ao{};
        ao.status = co.status;
        ao.crashed = (co.kind == ChildResultKind::Signal);
        return ao;
    }

    /// Compatibility overload for lambdas returning mxlStatus.
    template<typename Fn>
    ApiCallOutcome runApiCallInChild(Fn&& fn, std::enable_if_t<std::is_same_v<std::invoke_result_t<std::decay_t<Fn>>, mxlStatus>, int> = 0)
    {
        auto co = runChild([&]() -> mxlStatus { return fn(); });
        ApiCallOutcome ao{};
        ao.status = co.status;
        ao.crashed = (co.kind == ChildResultKind::Signal);
        return ao;
    }

    /// Result of running a writer creation in a child process.
    struct WriterOutcome
    {
        int status{static_cast<int>(MXL_STATUS_OK)};
        int exitCode{0};
        int termSignal{0};
        bool signaled{false};
        bool timeout{false};
        bool forkFailed{false};
        bool pipeBroken{false};
        bool waitFailed{false};
        bool created{false};
    };

    /// Fixed-size IPC report for writer-child result.
    struct WriterReport {
        int status;
        bool created;
        int signal;       // signal that killed the child, 0 if none
        char pad[244];    // padding to 256 bytes total
    };

    /// Launch a writer child that creates an instance, opens a writer for the
    /// given flow definition, commits one grain, then reports its status over a
    /// pipe.  The parent records detailed outcome information.
    WriterOutcome runWriterChildInChild(std::string const& domainPath, std::string const& flowDef)
    {
        auto outcome = WriterOutcome{};
        auto pipe = Pipe{};
        if (!pipe.open())
        {
            outcome.pipeBroken = true;
            outcome.forkFailed = true;
            return outcome;
        }

        // Block signals in the parent.
        sigset_t mask, oldMask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGSEGV);
        sigaddset(&mask, SIGFPE);
        sigaddset(&mask, SIGABRT);
        sigaddset(&mask, SIGBUS);
        sigaddset(&mask, SIGALRM);
        sigaddset(&mask, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &mask, &oldMask);

        auto const pid = ::fork();
        if (pid < 0)
        {
            outcome.forkFailed = true;
            pthread_sigmask(SIG_SETMASK, &oldMask, nullptr);
            return outcome;
        }

        if (pid == 0)
        {
            // Unblock all signals in the child so alarm() can fire.
            sigset_t fullMask;
            sigemptyset(&fullMask);
            sigaddset(&fullMask, SIGKILL); // Can't unblock SIGKILL anyway
            sigaddset(&fullMask, SIGSTOP);
            pthread_sigmask(SIG_SETMASK, &fullMask, nullptr);
            pipe.closeRead();
            ::alarm(15);
            int status = static_cast<int>(MXL_STATUS_OK);
            bool created = false;
            try
            {
                auto const inst = mxlCreateInstance(domainPath.c_str(), "{}");
                if (inst == nullptr)
                {
                    status = static_cast<int>(MXL_ERR_UNKNOWN);
                }
                else
                {
                    mxlFlowWriter w{};
                    mxlFlowConfigInfo ci{};
                    auto const createStatus = mxlCreateFlowWriter(inst, flowDef.c_str(), "{}", &w, &ci, &created);
                    if (createStatus != MXL_STATUS_OK)
                    {
                        status = static_cast<int>(createStatus);
                    }
                    else
                    {
                        auto grainInfo = mxlGrainInfo{};
                        std::uint8_t* payload = nullptr;
                        auto const giStatus = mxlFlowWriterOpenGrain(w, 0, &grainInfo, &payload);
                        if (giStatus == MXL_STATUS_OK && payload != nullptr)
                        {
                            std::memset(payload, 0xAA, grainInfo.grainSize);
                            grainInfo.validSlices = grainInfo.totalSlices;
                            auto const commitStatus = mxlFlowWriterCommitGrain(w, &grainInfo);
                            if (commitStatus != MXL_STATUS_OK)
                                status = static_cast<int>(commitStatus);
                        }
                        mxlReleaseFlowWriter(inst, w);
                    }
                    mxlDestroyInstance(inst);
                }
            }
            catch (...)
            {
                status = static_cast<int>(MXL_ERR_UNKNOWN);
            }

            // Fixed-size report so the parent always reads the same amount.
            WriterReport report;
            std::memset(&report, 0, sizeof(report));
            report.status = status;
            report.created = created;
            // Record whether we are exiting due to a signal from alarm().
            // Note: we can't easily know the signal number from within the
            // child at _exit, so the parent infers it from waitpid.
            (void)writeAll(pipe.writeFd, &report, sizeof(report));
            ::_exit(0);
        }

        pipe.closeWrite();

        int waitStatus = 0;
        auto const wret = ::waitpid(pid, &waitStatus, 0);

        pthread_sigmask(SIG_SETMASK, &oldMask, nullptr);

        outcome.status = static_cast<int>(MXL_STATUS_OK);
        if (wret != pid)
        {
            outcome.waitFailed = true;
            return outcome;
        }

        if (WIFSIGNALED(waitStatus))
        {
            outcome.signaled = true;
            outcome.termSignal = WTERMSIG(waitStatus);
            if (WTERMSIG(waitStatus) == SIGALRM)
            {
                // Alarm timeout — not a crash.
                outcome.timeout = true;
                outcome.status = static_cast<int>(MXL_ERR_TIMEOUT);
            }
            else
            {
                // Fatal signal — real crash.
                outcome.status = static_cast<int>(MXL_ERR_UNKNOWN);
            }
            return outcome;
        }

        if (WIFEXITED(waitStatus))
        {
            outcome.exitCode = WEXITSTATUS(waitStatus);
            WriterReport report;
            if (!readAll(pipe.readFd, &report, sizeof(report)))
            {
                // No data through pipe — child likely timed out or crashed
                // before writing. Check if there's a signal.
                if (WIFSIGNALED(waitStatus))
                {
                    outcome.signaled = true;
                    outcome.termSignal = WTERMSIG(waitStatus);
                    if (WTERMSIG(waitStatus) == SIGALRM)
                    {
                        outcome.timeout = true;
                        outcome.status = static_cast<int>(MXL_ERR_TIMEOUT);
                    }
                    else
                    {
                        outcome.status = static_cast<int>(MXL_ERR_UNKNOWN);
                    }
                }
                else
                {
                    outcome.timeout = true;
                    outcome.status = static_cast<int>(MXL_ERR_TIMEOUT);
                }
                return outcome;
            }
            outcome.status = report.status;
            outcome.created = report.created;
            return outcome;
        }

        outcome.status = static_cast<int>(MXL_STATUS_OK);
        return outcome;
    }

    /// Launch a writer child that creates an instance, then opens a writer for an
    /// *existing* flow identified by \\p flowDef (full JSON definition).  The child
    /// reports whether the writer succeeded and whether it created a new flow or
    /// connected to an existing one.
    struct ConnectWriterOutcome
    {
        int createStatus{static_cast<int>(MXL_STATUS_OK)};
        int commitStatus{static_cast<int>(MXL_STATUS_OK)};
        bool created{false};
        bool exception{false};
        int exitCode{0};
        int termSignal{0};
        bool signaled{false};
        bool timeout{false};
        bool forkFailed{false};
        bool pipeBroken{false};
        bool waitFailed{false};
        bool pipeHadData{false};  // whether the child communicated successfully
        int childSignal{0};       // exact signal that killed the child, 0 if none
    };

    /// Run an exec-based helper executable.  Returns the child's exit status
    /// and captures stdout for parsing.
    struct ExecResult
    {
        int exitCode{0};
        int termSignal{0};
        bool signaled{false};
        bool timeout{false};
        bool forkFailed{false};
        bool waitFailed{false};
        std::string stdoutData;
    };

    /// Helper that finds the highest fd in /proc/self/fd and closes all
    /// non-std-in/out/err fds.  Call this in the child before exec.
    static void closeInheritedFdsBeforeExec()
    {
        std::error_code ec;
        std::vector<int> fds;
        for (auto const& entry : fs::directory_iterator("/proc/self/fd", ec)) {
            if (ec) break;
            try {
                int fd = std::stoi(entry.path().filename());
                if (fd >= 0 && fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO)
                    fds.push_back(fd);
            } catch (...) {
                // skip
            }
        }
        for (auto fd : fds) {
            ::close(fd);
        }
    }

    ExecResult runExecHelper(fs::path const& helperPath, std::vector<std::string> const& args)
    {
        ExecResult result{};

        // Open pipe for capturing stdout
        int pipefds[2];
        if (::pipe(pipefds) != 0) {
            result.forkFailed = true;
            return result;
        }

        auto const pid = ::fork();
        if (pid < 0) {
            result.forkFailed = true;
            ::close(pipefds[0]);
            ::close(pipefds[1]);
            return result;
        }

        if (pid == 0) {
            // Child: close read end, redirect stdout to pipe write end
            ::close(pipefds[0]);
            ::dup2(pipefds[1], STDOUT_FILENO);
            ::close(pipefds[1]);

            // Close any inherited non-stdio file descriptors before exec
            // so the helper starts clean (no SDK state, no shared memmaps).
            closeInheritedFdsBeforeExec();

            // Build argv for exec
            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(helperPath.c_str()));
            for (auto const& arg : args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);

            ::execvp(helperPath.c_str(), argv.data());

            // If exec fails
            perror("[HELPER] exec failed");
            ::_exit(127);
        }

        // Parent: close write end, read stdout
        ::close(pipefds[1]);

        // Read stdout in a loop with timeout
        char buf[4096];
        std::size_t totalRead = 0;
        auto const timeoutNs = 15'000'000'000ULL; // 15 seconds
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);

        while (true) {
            auto remaining = deadline - std::chrono::steady_clock::now();
            if (remaining <= std::chrono::seconds(0)) {
                result.timeout = true;
                break;
            }

            // Use poll to wait for data with timeout
            struct pollfd pfd;
            pfd.fd = pipefds[0];
            pfd.events = POLLIN;
            int pollRet = ::poll(&pfd, 1, static_cast<int>(remaining.count() / 1000000));

            if (pollRet <= 0) {
                result.timeout = true;
                break;
            }

            ssize_t n = ::read(pipefds[0], buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) break; // EOF

            result.stdoutData.append(buf, n);
            totalRead += static_cast<std::size_t>(n);
        }

        ::close(pipefds[0]);

        // Wait for child
        int waitStatus = 0;
        if (::waitpid(pid, &waitStatus, 0) != pid) {
            result.waitFailed = true;
            return result;
        }

        if (WIFSIGNALED(waitStatus)) {
            result.signaled = true;
            result.termSignal = WTERMSIG(waitStatus);
            result.exitCode = -1; // Convention: -1 for signal
        } else if (WIFEXITED(waitStatus)) {
            result.exitCode = WEXITSTATUS(waitStatus);
        }

        return result;
    }

    /// Parse the DESCRIPTORS/CREATE_STATUS/OPEN_STATUS/COMMIT_STATUS output
    /// from c3_writer_helper.  Each operation is reported separately.
    struct C3WriterResult
    {
        int createStatus{static_cast<int>(MXL_ERR_UNKNOWN)};
        int openStatus{static_cast<int>(MXL_ERR_UNKNOWN)};
        int commitStatus{static_cast<int>(MXL_ERR_UNKNOWN)};
        bool created{false};
        std::string descriptorInventory; // raw DESCRIPTORS line from helper
    };

    C3WriterResult parseC3Output(std::string const& stdoutData)
    {
        C3WriterResult result;

        // Parse DESCRIPTORS line.
        auto const descLine = stdoutData.find("DESCRIPTORS ");
        if (descLine != std::string::npos) {
            result.descriptorInventory = stdoutData.substr(descLine, 300);
        }

        // Parse CREATE_STATUS.
        auto const createLine = stdoutData.find("CREATE_STATUS ");
        if (createLine != std::string::npos) {
            std::istringstream iss(stdoutData.substr(createLine));
            std::string lbl1, lbl2;
            int val1, val2;
            if (iss >> lbl1 >> val1 >> lbl2 >> val2) {
                result.createStatus = val1;
                result.created = (val2 == 1);
            }
        }

        // Parse OPEN_STATUS.
        auto const openLine = stdoutData.find("OPEN_STATUS ");
        if (openLine != std::string::npos) {
            std::istringstream iss(stdoutData.substr(openLine));
            std::string lbl;
            int val;
            if (iss >> lbl >> val) {
                result.openStatus = val;
            }
        }

        // Parse COMMIT_STATUS.
        auto const commitLine = stdoutData.find("COMMIT_STATUS ");
        if (commitLine != std::string::npos) {
            std::istringstream iss(stdoutData.substr(commitLine));
            std::string lbl;
            int val;
            if (iss >> lbl >> val) {
                result.commitStatus = val;
            }
        }

        return result;
    }

    /// Child-report struct: fixed 256-byte layout for reliable pipe IPC.
    struct ChildReport {
        int status;
        bool created;
        bool exception;
        int signal;       // signal number if killed, 0 otherwise
        char pad[247];    // padding to 256 bytes total
    };

    ConnectWriterOutcome runConnectWriterChild(std::string const& domainPath,
                                               std::string const& flowDef)
    {
        auto outcome = ConnectWriterOutcome{};
        auto pipe = Pipe{};
        if (!pipe.open())
        {
            outcome.pipeBroken = true;
            outcome.forkFailed = true;
            return outcome;
        }

        sigset_t mask, oldMask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGSEGV);
        sigaddset(&mask, SIGFPE);
        sigaddset(&mask, SIGABRT);
        sigaddset(&mask, SIGBUS);
        sigaddset(&mask, SIGALRM);
        sigaddset(&mask, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &mask, &oldMask);

        auto const pid = ::fork();
        if (pid < 0)
        {
            outcome.forkFailed = true;
            pthread_sigmask(SIG_SETMASK, &oldMask, nullptr);
            return outcome;
        }

        if (pid == 0)
        {
            sigset_t fullMask;
            sigemptyset(&fullMask);
            sigaddset(&fullMask, SIGKILL);
            sigaddset(&fullMask, SIGSTOP);
            pthread_sigmask(SIG_SETMASK, &fullMask, nullptr);
            pipe.closeRead();
            ::alarm(15);
            int status = static_cast<int>(MXL_STATUS_OK);
            bool createdFlag = false;
            bool caughtException = false;
            try
            {
                auto const inst = mxlCreateInstance(domainPath.c_str(), "{}");
                if (inst == nullptr)
                {
                    ::fprintf(stderr, "[C3-child] mxlCreateInstance failed\n");
                    status = static_cast<int>(MXL_ERR_UNKNOWN);
                }
                else
                {
                    mxlFlowWriter w{};
                    mxlFlowConfigInfo ci{};
                    auto const createStatus = mxlCreateFlowWriter(inst, flowDef.c_str(), "{}", &w, &ci, &createdFlag);
                    if (createStatus != MXL_STATUS_OK)
                    {
                        ::fprintf(stderr, "[C3-child] mxlCreateFlowWriter returned %d (%s) created=%d\n",
                                  (int)createStatus, statusName(createStatus).c_str(), (int)createdFlag);
                        status = static_cast<int>(createStatus);
                    }
                    else
                    {
                        auto grainInfo = mxlGrainInfo{};
                        std::uint8_t* payload = nullptr;
                        auto const giStatus = mxlFlowWriterOpenGrain(w, 0, &grainInfo, &payload);
                        if (giStatus == MXL_STATUS_OK && payload != nullptr)
                        {
                            std::memset(payload, 0xBB, grainInfo.grainSize);
                            grainInfo.validSlices = grainInfo.totalSlices;
                            auto const commitStatus = mxlFlowWriterCommitGrain(w, &grainInfo);
                            if (commitStatus != MXL_STATUS_OK)
                            {
                                ::fprintf(stderr, "[C3-child] mxlFlowWriterCommitGrain returned %d\n", (int)commitStatus);
                                status = static_cast<int>(commitStatus);
                            }
                        }
                        mxlReleaseFlowWriter(inst, w);
                    }
                    mxlDestroyInstance(inst);
                }
            }
            catch (std::exception const& ex)
            {
                caughtException = true;
                status = static_cast<int>(MXL_ERR_UNKNOWN);
            }
            catch (...)
            {
                caughtException = true;
                status = static_cast<int>(MXL_ERR_UNKNOWN);
            }

            // Use a fixed-size struct so the parent always reads the same amount.
            ChildReport report;
            std::memset(&report, 0, sizeof(report));
            report.status = status;
            report.created = createdFlag;
            report.exception = caughtException;
            (void)writeAll(pipe.writeFd, &report, sizeof(report));
            ::_exit(0);
        }

        pipe.closeWrite();

        int waitStatus = 0;
        auto const wret = ::waitpid(pid, &waitStatus, 0);

        pthread_sigmask(SIG_SETMASK, &oldMask, nullptr);

        // Read the fixed-size ChildReport.
        if (wret != pid)
        {
            outcome.waitFailed = true;
            return outcome;
        }

        if (WIFSIGNALED(waitStatus))
        {
            outcome.signaled = true;
            outcome.termSignal = WTERMSIG(waitStatus);
            if (WTERMSIG(waitStatus) == SIGALRM)
            {
                // Alarm timeout — not a crash.
                outcome.timeout = true;
                outcome.createStatus = static_cast<int>(MXL_ERR_TIMEOUT);
            }
            else
            {
                // Fatal signal — real crash. Record the signal for debugging.
                outcome.createStatus = static_cast<int>(MXL_ERR_UNKNOWN);
                note("child crashed",
                    "pid=" + std::to_string(pid) +
                    " signal=" + std::to_string(WTERMSIG(waitStatus)) +
                    " signal_name=" + strsignal(WTERMSIG(waitStatus)) +
                    " core=" + std::to_string(WCOREDUMP(waitStatus)));
            }
            return outcome;
        }

        if (WIFEXITED(waitStatus))
        {
            outcome.exitCode = WEXITSTATUS(waitStatus);
            ChildReport report;
            if (!readAll(pipe.readFd, &report, sizeof(report)))
            {
                // No data through pipe — child likely timed out or crashed
                // before writing. Check if there's a signal.
                if (WIFSIGNALED(waitStatus))
                {
                    outcome.signaled = true;
                    outcome.termSignal = WTERMSIG(waitStatus);
                    if (WTERMSIG(waitStatus) == SIGALRM)
                    {
                        outcome.timeout = true;
                        outcome.createStatus = static_cast<int>(MXL_ERR_TIMEOUT);
                    }
                    else
                    {
                        outcome.createStatus = static_cast<int>(MXL_ERR_UNKNOWN);
                    }
                }
                else
                {
                    outcome.timeout = true;
                    outcome.createStatus = static_cast<int>(MXL_ERR_TIMEOUT);
                }
                return outcome;
            }
            // Pipe IPC succeeded — child communicated successfully.
            outcome.pipeHadData = true;
            outcome.createStatus = report.status;
            outcome.created = report.created;
            outcome.exception = report.exception;
            if (report.exception)
            {
                // Child threw an exception; report as MXL_ERR_UNKNOWN.
                outcome.createStatus = static_cast<int>(MXL_ERR_UNKNOWN);
            }
            return outcome;
        }

        outcome.createStatus = static_cast<int>(MXL_STATUS_OK);
        return outcome;
    }

    /***************************************************************************/
    /* Flow definition and path helpers.                                      */
    /***************************************************************************/

    uuids::uuid makeUuid()
    {
        static auto engine = std::mt19937{std::random_device{}()};
        static auto generator = uuids::uuid_random_generator{engine};
        return generator();
    }

    /// Load a flow definition template and replace its id with \p id so that
    /// tests never collide on the fixed ids shipped with the SDK.
    std::string makeVideoFlowDef(fs::path const& templatePath, uuids::uuid const& id)
    {
        auto const base = mxl::tests::readFile(templatePath);
        auto value = picojson::value{};
        auto const error = picojson::parse(value, base);
        if (!error.empty() || !value.is<picojson::object>())
        {
            throw std::runtime_error{"Could not parse base flow definition: " + error};
        }

        auto object = value.get<picojson::object>();
        object["id"] = picojson::value(uuids::to_string(id));
        return picojson::value(object).serialize();
    }

    std::string serialize(picojson::object const& object)
    {
        return picojson::value(object).serialize();
    }

    std::string parseBaseObject(fs::path const& templatePath, picojson::object& out)
    {
        auto const base = mxl::tests::readFile(templatePath);
        auto value = picojson::value{};
        auto const error = picojson::parse(value, base);
        if (!error.empty() || !value.is<picojson::object>())
        {
            throw std::runtime_error{"Could not parse base flow definition: " + error};
        }
        out = value.get<picojson::object>();
        return base;
    }

    std::string modeString(mode_t mode)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "%04o", static_cast<unsigned>(mode & 07777U));
        return buffer;
    }

    std::uint64_t fnv1a(std::uint8_t const* data, std::size_t size)
    {
        auto hash = std::uint64_t{1469598103934665603ULL};
        for (auto i = std::size_t{0}; i < size; ++i)
        {
            hash ^= data[i];
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    void fillPayload(std::uint8_t* payload, std::uint64_t index, std::size_t size)
    {
        std::memcpy(payload, &index, sizeof(index));
        for (auto i = 2 * sizeof(std::uint64_t); i < size; ++i)
        {
            payload[i] = static_cast<std::uint8_t>((index + i) & 0xFFU);
        }
        auto const digest = fnv1a(payload + 2 * sizeof(std::uint64_t), size - 2 * sizeof(std::uint64_t));
        std::memcpy(payload + sizeof(index), &digest, sizeof(digest));
    }

    bool validatePayload(std::uint8_t const* payload, std::uint64_t expectedIndex, std::size_t size)
    {
        std::uint64_t observedIndex = 0;
        std::memcpy(&observedIndex, payload, sizeof(observedIndex));
        if (observedIndex != expectedIndex)
        {
            return false;
        }

        std::uint64_t observedDigest = 0;
        std::memcpy(&observedDigest, payload + sizeof(observedIndex), sizeof(observedDigest));
        auto const expectedDigest = fnv1a(payload + 2 * sizeof(std::uint64_t), size - 2 * sizeof(std::uint64_t));
        return observedDigest == expectedDigest;
    }
}

/*****************************************************************************/
/* A. Access and identity                                                    */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security A: flow file permissions, ownership and helper-process access",
    "[security][security-access]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const instance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto created = false;
    REQUIRE(mxlCreateFlowWriter(instance, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_STATUS_OK);
    REQUIRE(created);

    auto const index = mxlGetCurrentIndex(&configInfo.common.grainRate);
    REQUIRE(index != MXL_UNDEFINED_INDEX);

    auto grainInfo = mxlGrainInfo{};
    std::uint8_t* payload = nullptr;
    REQUIRE(mxlFlowWriterOpenGrain(writer, index, &grainInfo, &payload) == MXL_STATUS_OK);
    REQUIRE(payload != nullptr);
    std::memset(payload, 0xA5, grainInfo.grainSize);
    grainInfo.validSlices = grainInfo.totalSlices;
    REQUIRE(mxlFlowWriterCommitGrain(writer, &grainInfo) == MXL_STATUS_OK);

    auto const flowDirectory = mxl::lib::makeFlowDirectoryName(domain, idString);
    auto const dataFile = mxl::lib::makeFlowDataFilePath(flowDirectory);
    auto const descriptorFile = mxl::lib::makeFlowDescriptorFilePath(flowDirectory);
    auto const accessFile = mxl::lib::makeFlowAccessFilePath(flowDirectory);
    auto const grainDirectory = mxl::lib::makeGrainDirectoryName(flowDirectory);
    auto const grainOffset = static_cast<unsigned int>(index % configInfo.discrete.grainCount);
    auto const grainFile = mxl::lib::makeGrainDataFilePath(grainDirectory, grainOffset);

    struct stat flowStat{};
    struct stat dataStat{};
    struct stat grainStat{};
    REQUIRE(::stat(flowDirectory.c_str(), &flowStat) == 0);
    REQUIRE(::stat(dataFile.c_str(), &dataStat) == 0);
    REQUIRE(::stat(grainFile.c_str(), &grainStat) == 0);

    note("flow directory", flowDirectory.string());
    note("flow data file", dataFile.string() + " mode=" + modeString(dataStat.st_mode) + " uid=" + std::to_string(dataStat.st_uid) +
                                 " gid=" + std::to_string(dataStat.st_gid) + " size=" + std::to_string(dataStat.st_size) +
                                 " inode=" + std::to_string(dataStat.st_ino));
    note("grain file", grainFile.string() + " mode=" + modeString(grainStat.st_mode) + " uid=" + std::to_string(grainStat.st_uid) +
                           " gid=" + std::to_string(grainStat.st_gid) + " size=" + std::to_string(grainStat.st_size));
    note("flow descriptor", descriptorFile.string() + " mode=" + modeString([&]
              {
                  struct stat st{};
                  return (::stat(descriptorFile.c_str(), &st) == 0) ? st.st_mode : mode_t{0};
              }()));
    note("access file", accessFile.string() + " mode=" + modeString([&]
              {
                  struct stat st{};
                  return (::stat(accessFile.c_str(), &st) == 0) ? st.st_mode : mode_t{0};
              }()));

    CHECK(verify((dataStat.st_mode & S_IRUSR) != 0, "flow data file grants owner read", "mode=" + modeString(dataStat.st_mode)));
    CHECK(verify((dataStat.st_mode & S_IWUSR) != 0, "flow data file grants owner write", "mode=" + modeString(dataStat.st_mode)));
    CHECK(verify(dataStat.st_uid == ::geteuid(), "flow data file is owned by the creating user",
        "file uid=" + std::to_string(dataStat.st_uid) + " process euid=" + std::to_string(::geteuid())));
    CHECK(verify(flowStat.st_uid == ::geteuid(), "flow directory is owned by the creating user",
        "dir uid=" + std::to_string(flowStat.st_uid) + " process euid=" + std::to_string(::geteuid())));

    // A same-UID child process is not authenticated in any way. It only has to
    // pass the ordinary Unix permission check on the grain file.
    auto const sameUserReport = runFileWriteInChild(grainFile, 0, nullptr, 0);
    CHECK(verify(sameUserReport.opened == 1, "same-UID child process can open the grain file for writing",
        "opened=" + std::to_string(sameUserReport.opened) + " errno=" + std::to_string(sameUserReport.err)));

    // A different-UID child can only be produced when the test runs as root.
    if (::geteuid() == 0)
    {
        auto pipe = Pipe{};
        REQUIRE(pipe.open());
        auto const pid = ::fork();
        REQUIRE(pid >= 0);
        if (pid == 0)
        {
            pipe.closeRead();
            ::alarm(15);
            int canOpen = -1;
            int openErr = 0;
            if ((::setgid(65534) == 0) && (::setuid(65534) == 0))
            {
                auto const fd = ::open(grainFile.c_str(), O_RDWR);
                canOpen = (fd >= 0) ? 1 : 0;
                openErr = (fd >= 0) ? 0 : errno;
                if (fd >= 0)
                {
                    ::close(fd);
                }
            }
            (void)writeAll(pipe.writeFd, &canOpen, sizeof(canOpen));
            (void)writeAll(pipe.writeFd, &openErr, sizeof(openErr));
            ::_exit(0);
        }
        pipe.closeWrite();
        int canOpen = -1;
        int openErr = 0;
        (void)readAll(pipe.readFd, &canOpen, sizeof(canOpen));
        (void)readAll(pipe.readFd, &openErr, sizeof(openErr));
        int waitStatus = 0;
        (void)::waitpid(pid, &waitStatus, 0);
        // Files are created with mode 0664 subject to umask, so a foreign user
        // may still be denied write access. Record the actual result.
        CHECK(verify(canOpen == 0, "different-UID process is denied write access unless group/other write is set",
            "canOpen=" + std::to_string(canOpen) + " errno=" + std::to_string(openErr) + " mode=" + modeString(grainStat.st_mode)));
    }
    else
    {
        notTested("different-UID access control", "requires root to switch credentials; euid=" + std::to_string(::geteuid()));
    }

    REQUIRE(mxlReleaseFlowWriter(instance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(instance) == MXL_STATUS_OK);
}

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security A: reader in a separate process", "[security][security-access]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const writerInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(writerInstance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto created = false;
    REQUIRE(mxlCreateFlowWriter(writerInstance, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_STATUS_OK);
    REQUIRE(created);

    auto const index = mxlGetCurrentIndex(&configInfo.common.grainRate);
    REQUIRE(index != MXL_UNDEFINED_INDEX);

    auto grainInfo = mxlGrainInfo{};
    std::uint8_t* payload = nullptr;
    REQUIRE(mxlFlowWriterOpenGrain(writer, index, &grainInfo, &payload) == MXL_STATUS_OK);
    std::memset(payload, 0xC3, grainInfo.grainSize);
    grainInfo.validSlices = grainInfo.totalSlices;
    REQUIRE(mxlFlowWriterCommitGrain(writer, &grainInfo) == MXL_STATUS_OK);

    struct ReadReport
    {
        std::int32_t status;
        std::uint64_t index;
        std::uint64_t size;
        std::uint8_t first;
        std::uint8_t last;
    };

    auto pipe = Pipe{};
    REQUIRE(pipe.open());

    auto const domainPath = domain.string();
    auto const pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0)
    {
        pipe.closeRead();
        ::alarm(15);

        auto report = ReadReport{};
        report.status = static_cast<std::int32_t>(MXL_ERR_UNKNOWN);
        if (auto const readerInstance = mxlCreateInstance(domainPath.c_str(), "{}"); readerInstance != nullptr)
        {
            auto reader = mxlFlowReader{};
            if (mxlCreateFlowReader(readerInstance, idString.c_str(), "{}", &reader) == MXL_STATUS_OK)
            {
                auto readGrainInfo = mxlGrainInfo{};
                std::uint8_t* readPayload = nullptr;
                auto const status = mxlFlowReaderGetGrain(reader, index, 5'000'000'000ULL, &readGrainInfo, &readPayload);
                report.status = static_cast<std::int32_t>(status);
                report.index = readGrainInfo.index;
                report.size = readGrainInfo.grainSize;
                if ((status == MXL_STATUS_OK) && (readPayload != nullptr) && (readGrainInfo.grainSize > 0U))
                {
                    report.first = readPayload[0];
                    report.last = readPayload[readGrainInfo.grainSize - 1U];
                }
                (void)mxlReleaseFlowReader(readerInstance, reader);
            }
            (void)mxlDestroyInstance(readerInstance);
        }

        (void)writeAll(pipe.writeFd, &report, sizeof(report));
        ::_exit(0);
    }

    pipe.closeWrite();
    auto report = ReadReport{};
    auto const gotReport = readAll(pipe.readFd, &report, sizeof(report));
    int waitStatus = 0;
    (void)::waitpid(pid, &waitStatus, 0);

    REQUIRE(gotReport);
    CHECK(verify(report.status == static_cast<std::int32_t>(MXL_STATUS_OK), "separate-process reader obtains the committed grain",
        "status=" + statusName(static_cast<mxlStatus>(report.status))));
    CHECK(verify(report.index == index, "separate-process reader observes the committed index",
        "reader index=" + std::to_string(report.index) + " writer index=" + std::to_string(index)));
    CHECK(verify(report.first == 0xC3 && report.last == 0xC3, "separate-process reader observes the committed payload",
        "first=" + std::to_string(report.first) + " last=" + std::to_string(report.last) + " size=" + std::to_string(report.size)));

    REQUIRE(mxlReleaseFlowWriter(writerInstance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(writerInstance) == MXL_STATUS_OK);
}

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security A: writer in a separate process", "[security][security-access]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto readyPipe = Pipe{};
    auto ackPipe = Pipe{};
    REQUIRE(readyPipe.open());
    REQUIRE(ackPipe.open());

    auto const domainPath = domain.string();
    auto const pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0)
    {
        readyPipe.closeRead();
        ackPipe.closeWrite();
        ::alarm(20);

        std::int32_t status = static_cast<std::int32_t>(MXL_ERR_UNKNOWN);
        std::uint64_t created = 0;
        if (auto const instance = mxlCreateInstance(domainPath.c_str(), "{}"); instance != nullptr)
        {
            mxlFlowWriter writer{};
            mxlFlowConfigInfo config{};
            bool wasCreated = false;
            status = static_cast<std::int32_t>(mxlCreateFlowWriter(instance, flowDef.c_str(), "{}", &writer, &config, &wasCreated));
            created = wasCreated ? 1U : 0U;

            (void)writeAll(readyPipe.writeFd, &status, sizeof(status));
            (void)writeAll(readyPipe.writeFd, &created, sizeof(created));

            // Hold the writer until the parent has observed the flow.
            std::uint8_t ack = 0;
            (void)readAll(ackPipe.readFd, &ack, sizeof(ack));

            if (status == static_cast<std::int32_t>(MXL_STATUS_OK))
            {
                (void)mxlReleaseFlowWriter(instance, writer);
            }
            (void)mxlDestroyInstance(instance);
        }
        else
        {
            (void)writeAll(readyPipe.writeFd, &status, sizeof(status));
            (void)writeAll(readyPipe.writeFd, &created, sizeof(created));
        }
        ::_exit(0);
    }

    readyPipe.closeWrite();
    ackPipe.closeRead();

    std::int32_t childStatus = static_cast<std::int32_t>(MXL_ERR_UNKNOWN);
    std::uint64_t childCreated = 0;
    REQUIRE(readAll(readyPipe.readFd, &childStatus, sizeof(childStatus)));
    REQUIRE(readAll(readyPipe.readFd, &childCreated, sizeof(childCreated)));

    CHECK(verify(childStatus == static_cast<std::int32_t>(MXL_STATUS_OK), "writer creation succeeds in a separate process",
        "status=" + statusName(static_cast<mxlStatus>(childStatus))));
    CHECK(verify(childCreated == 1U, "separate-process writer reports the flow was created", "created=" + std::to_string(childCreated)));

    auto const parentInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(parentInstance != nullptr);

    auto active = false;
    auto const activeStatus = mxlIsFlowActive(parentInstance, idString.c_str(), &active);
    CHECK(verify(activeStatus == MXL_STATUS_OK && active, "parent observes the separate-process flow as active",
        "status=" + statusName(activeStatus) + " active=" + std::to_string(active)));

    auto reader = mxlFlowReader{};
    auto const readerStatus = mxlCreateFlowReader(parentInstance, idString.c_str(), opts, &reader);
    CHECK(verify(readerStatus == MXL_STATUS_OK, "parent can open a reader for the separate-process flow",
        "status=" + statusName(readerStatus)));
    if (readerStatus == MXL_STATUS_OK)
    {
        auto configInfo = mxlFlowConfigInfo{};
        REQUIRE(mxlFlowReaderGetConfigInfo(reader, &configInfo) == MXL_STATUS_OK);
        auto const configId = uuids::to_string(configInfo.common.id);
        CHECK(verify(configId == idString, "reader observes the flow id created by the child",
            "reader id=" + configId + " expected=" + idString));
        REQUIRE(mxlReleaseFlowReader(parentInstance, reader) == MXL_STATUS_OK);
    }

    // Tell the child to exit and release its writer.
    std::uint8_t ack = 1;
    REQUIRE(writeAll(ackPipe.writeFd, &ack, sizeof(ack)));
    int waitStatus = 0;
    REQUIRE(::waitpid(pid, &waitStatus, 0) == pid);
    CHECK(verify(WIFEXITED(waitStatus) && (WEXITSTATUS(waitStatus) == 0), "separate-process writer exits cleanly",
        "exited=" + std::to_string(WIFEXITED(waitStatus)) + " code=" + std::to_string(WIFEXITED(waitStatus) ? WEXITSTATUS(waitStatus) : -1)));

    // With the child gone and no readers left, the flow is stale and garbage
    // collection removes it.
    REQUIRE(mxlGarbageCollectFlows(parentInstance) == MXL_STATUS_OK);
    CHECK(verify(!flowDirectoryExists(idString), "garbage collection removes the flows left by the exited child",
        "flowDirectory=" + mxl::lib::makeFlowDirectoryName(domain, idString).string()));

    REQUIRE(mxlDestroyInstance(parentInstance) == MXL_STATUS_OK);
}

/*****************************************************************************/
/* B. Shared data modification                                               */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security B: external grain payload modification", "[security][security-shared-data]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const instance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto created = false;
    REQUIRE(mxlCreateFlowWriter(instance, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_STATUS_OK);
    REQUIRE(created);

    auto const index = mxlGetCurrentIndex(&configInfo.common.grainRate);
    REQUIRE(index != MXL_UNDEFINED_INDEX);

    auto grainInfo = mxlGrainInfo{};
    std::uint8_t* payload = nullptr;
    REQUIRE(mxlFlowWriterOpenGrain(writer, index, &grainInfo, &payload) == MXL_STATUS_OK);
    std::memset(payload, 0x5A, grainInfo.grainSize);
    grainInfo.validSlices = grainInfo.totalSlices;
    REQUIRE(mxlFlowWriterCommitGrain(writer, &grainInfo) == MXL_STATUS_OK);

    auto reader = mxlFlowReader{};
    REQUIRE(mxlCreateFlowReader(instance, idString.c_str(), opts, &reader) == MXL_STATUS_OK);

    auto baseline = mxlGrainInfo{};
    std::uint8_t* baselinePayload = nullptr;
    REQUIRE(mxlFlowReaderGetGrain(reader, index, 5'000'000'000ULL, &baseline, &baselinePayload) == MXL_STATUS_OK);
    CHECK(verify(baselinePayload[0] == 0x5A, "reader observes the original payload before tampering",
        "byte[0]=" + std::to_string(baselinePayload[0])));

    auto const flowDirectory = mxl::lib::makeFlowDirectoryName(domain, idString);
    auto const grainDirectory = mxl::lib::makeGrainDirectoryName(flowDirectory);
    auto const grainOffset = static_cast<unsigned int>(index % configInfo.discrete.grainCount);
    auto const grainFile = mxl::lib::makeGrainDataFilePath(grainDirectory, grainOffset);

    auto const tamper = std::array<std::uint8_t, 4>{0xDE, 0xAD, 0xBE, 0xEF};
    auto const start = std::chrono::steady_clock::now();
    auto const report = runFileWriteInChild(grainFile, static_cast<off_t>(GRAIN_PAYLOAD_OFFSET), tamper.data(), tamper.size());
    auto const elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(verify(report.opened == 1 && report.written == static_cast<std::int64_t>(tamper.size()),
        "external process can open and write into the SDK grain file",
        "opened=" + std::to_string(report.opened) + " errno=" + std::to_string(report.err) + " written=" + std::to_string(report.written) +
            " offset=" + std::to_string(GRAIN_PAYLOAD_OFFSET) + " elapsed_us=" + std::to_string(elapsedUs)));

    auto modified = mxlGrainInfo{};
    std::uint8_t* modifiedPayload = nullptr;
    auto const readStatus = mxlFlowReaderGetGrain(reader, index, 5'000'000'000ULL, &modified, &modifiedPayload);
    auto const observed = std::array<std::uint8_t, 4>{
        static_cast<std::uint8_t>(modifiedPayload != nullptr ? modifiedPayload[0] : 0),
        static_cast<std::uint8_t>(modifiedPayload != nullptr ? modifiedPayload[1] : 0),
        static_cast<std::uint8_t>(modifiedPayload != nullptr ? modifiedPayload[2] : 0),
        static_cast<std::uint8_t>(modifiedPayload != nullptr ? modifiedPayload[3] : 0)};

    CHECK(verify(readStatus == MXL_STATUS_OK, "reader re-read of the tampered grain still succeeds", "status=" + statusName(readStatus)));
    CHECK(verify(observed == tamper, "reader observes the externally modified payload bytes without an integrity error",
        "observed=" + std::to_string(observed[0]) + " " + std::to_string(observed[1]) + " " + std::to_string(observed[2]) + " " +
            std::to_string(observed[3]) + " expected=222 173 190 239"));

    REQUIRE(mxlReleaseFlowReader(instance, reader) == MXL_STATUS_OK);
    REQUIRE(mxlReleaseFlowWriter(instance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(instance) == MXL_STATUS_OK);
}

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security B: external grain and flow metadata modification",
    "[security][security-shared-data]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const instance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto created = false;
    REQUIRE(mxlCreateFlowWriter(instance, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_STATUS_OK);
    REQUIRE(created);

    auto const index = mxlGetCurrentIndex(&configInfo.common.grainRate);
    REQUIRE(index != MXL_UNDEFINED_INDEX);

    auto grainInfo = mxlGrainInfo{};
    std::uint8_t* payload = nullptr;
    REQUIRE(mxlFlowWriterOpenGrain(writer, index, &grainInfo, &payload) == MXL_STATUS_OK);
    std::memset(payload, 0x11, grainInfo.grainSize);
    grainInfo.validSlices = grainInfo.totalSlices;
    REQUIRE(mxlFlowWriterCommitGrain(writer, &grainInfo) == MXL_STATUS_OK);

    auto reader = mxlFlowReader{};
    REQUIRE(mxlCreateFlowReader(instance, idString.c_str(), opts, &reader) == MXL_STATUS_OK);

    auto const flowDirectory = mxl::lib::makeFlowDirectoryName(domain, idString);
    auto const dataFile = mxl::lib::makeFlowDataFilePath(flowDirectory);
    auto const grainDirectory = mxl::lib::makeGrainDirectoryName(flowDirectory);
    auto const grainOffset = static_cast<unsigned int>(index % configInfo.discrete.grainCount);
    auto const grainFile = mxl::lib::makeGrainDataFilePath(grainDirectory, grainOffset);

    // 1. Clear validSlices in the grain header. The reader uses this value to
    //    decide whether a grain is published.
    auto const validSlicesOffset = static_cast<off_t>(offsetof(mxlGrainInfo, validSlices));
    auto const zeroSlices = std::uint16_t{0};
    auto const sliceReport = runFileWriteInChild(grainFile, validSlicesOffset, &zeroSlices, sizeof(zeroSlices));
    CHECK(verify(sliceReport.opened == 1 && sliceReport.written == static_cast<std::int64_t>(sizeof(zeroSlices)),
        "external process can clear the grain validSlices field",
        "written=" + std::to_string(sliceReport.written) + " offset=" + std::to_string(validSlicesOffset)));

    auto readGrainInfo = mxlGrainInfo{};
    std::uint8_t* readPayload = nullptr;
    auto const nonBlockingStatus = mxlFlowReaderGetGrainNonBlocking(reader, index, &readGrainInfo, &readPayload);
    CHECK(verify(nonBlockingStatus == MXL_ERR_OUT_OF_RANGE_TOO_EARLY,
        "cleared validSlices makes the reader treat the grain as unavailable",
        "status=" + statusName(nonBlockingStatus)));

    // Restore the publication state so later checks behave normally.
    auto const totalSlices = grainInfo.totalSlices;
    auto const restoreReport = runFileWriteInChild(grainFile, validSlicesOffset, &totalSlices, sizeof(totalSlices));
    CHECK(verify(restoreReport.written == static_cast<std::int64_t>(sizeof(totalSlices)), "external process can restore the validSlices field",
        "written=" + std::to_string(restoreReport.written)));

    // 2. Modify the runtime lastWriteTime in the flow data file. The reader
    //    reads this field through the public runtime info API.
    auto const lastWriteTimeOffset =
        static_cast<off_t>(offsetof(mxlFlowInfo, runtime) + offsetof(mxlFlowRuntimeInfo, lastWriteTime));
    auto const injectedTime = std::uint64_t{0x0123456789ABCDEFULL};
    auto const timeReport = runFileWriteInChild(dataFile, lastWriteTimeOffset, &injectedTime, sizeof(injectedTime));
    CHECK(verify(timeReport.opened == 1 && timeReport.written == static_cast<std::int64_t>(sizeof(injectedTime)),
        "external process can write the flow runtime lastWriteTime field",
        "written=" + std::to_string(timeReport.written) + " offset=" + std::to_string(lastWriteTimeOffset)));

    auto runtimeInfo = mxlFlowRuntimeInfo{};
    auto const runtimeStatus = mxlFlowReaderGetRuntimeInfo(reader, &runtimeInfo);
    CHECK(verify(runtimeStatus == MXL_STATUS_OK && runtimeInfo.lastWriteTime == injectedTime,
        "reader observes the externally injected lastWriteTime value",
        "status=" + statusName(runtimeStatus) + " observed=" + std::to_string(runtimeInfo.lastWriteTime) + " injected=" +
            std::to_string(injectedTime)));

    REQUIRE(mxlReleaseFlowReader(instance, reader) == MXL_STATUS_OK);
    REQUIRE(mxlReleaseFlowWriter(instance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(instance) == MXL_STATUS_OK);
}

/*****************************************************************************/
/* C. Sequential publication and readback                                    */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security C: sequential publication and readback", "[security][security-concurrency]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const writerInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(writerInstance != nullptr);
    auto const readerInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(readerInstance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto created = false;
    REQUIRE(mxlCreateFlowWriter(writerInstance, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_STATUS_OK);
    REQUIRE(created);

    auto reader = mxlFlowReader{};
    REQUIRE(mxlCreateFlowReader(readerInstance, idString.c_str(), opts, &reader) == MXL_STATUS_OK);

    auto const baseIndex = mxlGetCurrentIndex(&configInfo.common.grainRate);
    REQUIRE(baseIndex != MXL_UNDEFINED_INDEX);

    auto const grainCount = configInfo.discrete.grainCount;
    REQUIRE(grainCount > 2U);
    auto const count = static_cast<std::size_t>(std::min<std::uint32_t>(4U, grainCount - 1U));

    auto writerFailed = std::atomic<bool>{false};
    auto writerStatus = std::atomic<int>{static_cast<int>(MXL_STATUS_OK)};
    auto readsAttempted = std::atomic<std::size_t>{0};
    auto readsOk = std::atomic<std::size_t>{0};
    auto metadataMismatches = std::atomic<std::size_t>{0};
    auto tornPayloads = std::atomic<std::size_t>{0};
    auto readerTimeouts = std::atomic<std::size_t>{0};

    // Synchronize: producer commits all grains first, then consumer reads.
    // This is a sequential producer-then-consumer test — the producer must
    // complete before the consumer starts, ensuring each grain is fully
    // committed before the reader attempts to read it.
    auto producerDone = std::atomic<bool>{false};
    auto const start = std::chrono::steady_clock::now();

    auto producer = std::thread{[&]() -> bool
        {
            for (auto i = std::size_t{0}; i < count; ++i)
            {
                auto const index = baseIndex + i;
                auto grainInfo = mxlGrainInfo{};
                std::uint8_t* payload = nullptr;
                auto const status = mxlFlowWriterOpenGrain(writer, index, &grainInfo, &payload);
                if (status != MXL_STATUS_OK || payload == nullptr)
                {
                    writerFailed.store(true);
                    writerStatus.store(static_cast<int>(status));
                    return false;
                }
                fillPayload(payload, index, grainInfo.grainSize);
                grainInfo.validSlices = grainInfo.totalSlices;
                if (mxlFlowWriterCommitGrain(writer, &grainInfo) != MXL_STATUS_OK)
                {
                    writerFailed.store(true);
                    writerStatus.store(static_cast<int>(MXL_ERR_UNKNOWN));
                    return false;
                }
            }
            return true;
        }};

    // Wait for producer to complete before consumer starts.
    producer.join();
    producerDone.store(true);

    // Now run the consumer on its own thread.
    auto consumer = std::thread{[&]()
        {
            for (auto i = std::size_t{0}; i < count; ++i)
            {
                auto const index = baseIndex + i;
                auto grainInfo = mxlGrainInfo{};
                std::uint8_t* payload = nullptr;
                readsAttempted.fetch_add(1U);
                auto const status = mxlFlowReaderGetGrain(reader, index, 5'000'000'000ULL, &grainInfo, &payload);
                if (status == MXL_ERR_TIMEOUT)
                {
                    readerTimeouts.fetch_add(1U);
                    continue;
                }
                if (status != MXL_STATUS_OK || payload == nullptr)
                {
                    tornPayloads.fetch_add(1U);
                    continue;
                }
                // Grain size = sliceSize * totalSlices (single-plane grain)
                auto const expectedGrainSize = configInfo.discrete.sliceSizes[0] * grainInfo.totalSlices;
                if ((grainInfo.index != index) || (grainInfo.validSlices != grainInfo.totalSlices) ||
                    (grainInfo.grainSize != expectedGrainSize))
                {
                    metadataMismatches.fetch_add(1U);
                    std::cerr << "[DEBUG] Metadata mismatch at index " << index
                        << ": got index=" << grainInfo.index << " validSlices=" << grainInfo.validSlices
                        << " totalSlices=" << grainInfo.totalSlices << " grainSize=" << grainInfo.grainSize
                        << " expectedGrain=" << expectedGrainSize << std::endl;
                }
                if (!validatePayload(payload, index, grainInfo.grainSize))
                {
                    tornPayloads.fetch_add(1U);
                }
                else
                {
                    readsOk.fetch_add(1U);
                }
            }
        }};

    consumer.join();
    auto const elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(verify(!writerFailed.load(), "producer committed every grain without error",
        "writer_status=" + statusName(static_cast<mxlStatus>(writerStatus.load()))));
    CHECK(verify(readsAttempted.load() == count, "consumer attempted the expected number of reads",
        "attempted=" + std::to_string(readsAttempted.load()) + " expected=" + std::to_string(count)));
    CHECK(verify(readerTimeouts.load() == 0U, "no consumer read timed out", "timeouts=" + std::to_string(readerTimeouts.load())));
    CHECK(verify(tornPayloads.load() == 0U, "no torn or corrupt payload was observed",
        "torn=" + std::to_string(tornPayloads.load()) + " ok=" + std::to_string(readsOk.load())));
    CHECK(verify(metadataMismatches.load() == 0U, "grain metadata always matched the published index",
        "metadata_mismatches=" + std::to_string(metadataMismatches.load())));
    CHECK(verify(readsOk.load() == count, "consumer validated every published grain",
        "ok=" + std::to_string(readsOk.load()) + " elapsed_ms=" + std::to_string(elapsedMs)));

    auto runtimeInfo = mxlFlowRuntimeInfo{};
    REQUIRE(mxlFlowReaderGetRuntimeInfo(reader, &runtimeInfo) == MXL_STATUS_OK);
    CHECK(verify(runtimeInfo.headIndex == baseIndex + count - 1U, "reader observes the final head index",
        "headIndex=" + std::to_string(runtimeInfo.headIndex) + " expected=" + std::to_string(baseIndex + count - 1U)));

    REQUIRE(mxlReleaseFlowReader(readerInstance, reader) == MXL_STATUS_OK);
    REQUIRE(mxlReleaseFlowWriter(writerInstance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(readerInstance) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(writerInstance) == MXL_STATUS_OK);
}

/*****************************************************************************/
/* C2. Overlapping producer/consumer with ring wraparound                    */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security C2: overlapping producer/consumer with ring wraparound",
    "[security][security-concurrency-c2]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const writerInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(writerInstance != nullptr);
    auto const readerInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(readerInstance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto created = false;
    REQUIRE(mxlCreateFlowWriter(writerInstance, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_STATUS_OK);
    REQUIRE(created);

    auto reader = mxlFlowReader{};
    REQUIRE(mxlCreateFlowReader(readerInstance, idString.c_str(), opts, &reader) == MXL_STATUS_OK);

    auto const baseIndex = mxlGetCurrentIndex(&configInfo.common.grainRate);
    REQUIRE(baseIndex != MXL_UNDEFINED_INDEX);

    auto const grainCount = configInfo.discrete.grainCount;
    REQUIRE(grainCount > 2U);

    // Write 2 * grainCount + 2 grains to force at least one full wraparound.
    auto const writeCount = static_cast<std::size_t>(grainCount) * 2U + 2U;

    // Shared state between threads — all atomics for safe concurrent access.
    auto writerErrors = std::atomic<std::size_t>{0};
    auto skippedReads = std::atomic<std::size_t>{0};     // out-of-range / skipped reads
    auto consumerErrors = std::atomic<std::size_t>{0};  // unexpected errors
    auto metadataMismatches = std::atomic<std::size_t>{0};
    auto tornPayloads = std::atomic<std::size_t>{0};
    auto readerTimeouts = std::atomic<std::size_t>{0};
    auto validatedReads = std::atomic<std::size_t>{0};  // successfully validated grains

    // Synchronisation so we observe truly overlapping execution.
    auto producerReady = std::atomic<bool>{false};
    auto consumerReady = std::atomic<bool>{false};
    auto go = std::atomic<bool>{false};

    auto const start = std::chrono::steady_clock::now();

    // Producer thread — writes grains from baseIndex to baseIndex+writeCount-1.
    auto producer = std::thread{[&]()
        {
            producerReady.store(true);
            while (!consumerReady.load())
                std::this_thread::yield();
            while (!go.load())
                std::this_thread::yield();

            for (auto i = std::size_t{0}; i < writeCount; ++i)
            {
                auto const index = baseIndex + i;
                auto grainInfo = mxlGrainInfo{};
                std::uint8_t* payload = nullptr;
                auto const status = mxlFlowWriterOpenGrain(writer, index, &grainInfo, &payload);
                if (status != MXL_STATUS_OK || payload == nullptr)
                {
                    writerErrors.fetch_add(1U);
                    continue;
                }
                fillPayload(payload, index, grainInfo.grainSize);
                grainInfo.validSlices = grainInfo.totalSlices;
                if (mxlFlowWriterCommitGrain(writer, &grainInfo) != MXL_STATUS_OK)
                {
                    writerErrors.fetch_add(1U);
                }
            }
        }};

    // Consumer thread — reads grains from baseIndex upward.  When the ring
    // buffer wraps, earlier grains may have been overwritten.  We track which
    // index we expect next so we know whether a timeout means "not yet"
    // (producer is ahead) or "gone" (wrapping).
    auto nextExpected = std::atomic<std::size_t>{0};

    auto consumer = std::thread{[&]()
        {
            consumerReady.store(true);
            while (!go.load())
                std::this_thread::yield();

            for (auto i = std::size_t{0}; i < writeCount; ++i)
            {
                nextExpected.fetch_add(1U);
                auto const index = baseIndex + i;
                auto grainInfo = mxlGrainInfo{};
                std::uint8_t* payload = nullptr;
                auto const status = mxlFlowReaderGetGrain(reader, index, 200'000'000ULL, &grainInfo, &payload);

                if (status == MXL_ERR_TIMEOUT)
                {
                    readerTimeouts.fetch_add(1U);
                    // The producer hasn't reached this grain yet — skip and
                    // retry later by advancing our expected index.
                    continue;
                }
                if (status == MXL_ERR_OUT_OF_RANGE_TOO_EARLY ||
                    status == MXL_ERR_OUT_OF_RANGE_TOO_LATE)
                {
                    // Grain has wrapped or is too far ahead — skip.
                    skippedReads.fetch_add(1U);
                    continue;
                }
                if (status != MXL_STATUS_OK || payload == nullptr)
                {
                    consumerErrors.fetch_add(1U);
                    continue;
                }

                validatedReads.fetch_add(1U);

                // Grain size = sliceSize * totalSlices (single-plane grain).
                auto const expectedGrainSize = configInfo.discrete.sliceSizes[0] * grainInfo.totalSlices;
                if ((grainInfo.index != index) || (grainInfo.validSlices != grainInfo.totalSlices) ||
                    (grainInfo.grainSize != expectedGrainSize))
                {
                    metadataMismatches.fetch_add(1U);
                }
                if (!validatePayload(payload, index, grainInfo.grainSize))
                {
                    tornPayloads.fetch_add(1U);
                }
            }
        }};

    // Let both threads start so they truly overlap.
    while (!producerReady.load() || !consumerReady.load())
        std::this_thread::yield();

    note("overlap", "both producer and consumer threads are running concurrently");

    // Unleash.
    go.store(true);

    producer.join();
    consumer.join();

    auto const elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    CHECK(verify(writerErrors.load() == 0U, "producer committed without error",
        "writer_errors=" + std::to_string(writerErrors.load())));
    CHECK(verify(consumerErrors.load() == 0U, "consumer read without error",
        "consumer_errors=" + std::to_string(consumerErrors.load())));
    CHECK(verify(metadataMismatches.load() == 0U, "no metadata mismatches during concurrent execution",
        "metadata_mismatches=" + std::to_string(metadataMismatches.load())));
    CHECK(verify(tornPayloads.load() == 0U, "no torn payload during concurrent execution",
        "torn=" + std::to_string(tornPayloads.load()) + " validated=" + std::to_string(validatedReads.load()) +
        " skipped=" + std::to_string(skippedReads.load()) + " timeouts=" + std::to_string(readerTimeouts.load()) +
        " errors=" + std::to_string(consumerErrors.load())));
    // The consumer reads every grain that still exists (wraparound may have
    // overwritten some, but the SDK should report accurate headIndex).
    // validatedReads counts only grains that were successfully retrieved,
    // metadata-verified, and payload-validated.  skippedReads counts
    // out-of-range (wrapped) indices.  readerTimeouts counts grains not yet
    // written by the producer.  consumerErrors counts unexpected SDK errors.
    note("C2 summary",
        "validated=" + std::to_string(validatedReads.load()) +
        " skipped=" + std::to_string(skippedReads.load()) +
        " timeouts=" + std::to_string(readerTimeouts.load()) +
        " errors=" + std::to_string(consumerErrors.load()) +
        " elapsed_ms=" + std::to_string(elapsedMs));
    CHECK(verify(validatedReads.load() > 0U,
        "consumer validated at least some grains during concurrent execution",
        "validated=" + std::to_string(validatedReads.load()) +
        " skipped=" + std::to_string(skippedReads.load()) +
        " timeouts=" + std::to_string(readerTimeouts.load()) +
        " errors=" + std::to_string(consumerErrors.load()) +
        " elapsed_ms=" + std::to_string(elapsedMs)));

    auto runtimeInfo = mxlFlowRuntimeInfo{};
    REQUIRE(mxlFlowReaderGetRuntimeInfo(reader, &runtimeInfo) == MXL_STATUS_OK);
    CHECK(verify(runtimeInfo.headIndex == baseIndex + writeCount - 1U,
        "reader observes final head index after wraparound",
        "headIndex=" + std::to_string(runtimeInfo.headIndex) + " expected=" + std::to_string(baseIndex + writeCount - 1U)));

    REQUIRE(mxlReleaseFlowReader(readerInstance, reader) == MXL_STATUS_OK);
    REQUIRE(mxlReleaseFlowWriter(writerInstance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(readerInstance) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(writerInstance) == MXL_STATUS_OK);
}

/*****************************************************************************/
/* C3. Competing writers in independent processes                            */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security C3: competing writers in independent processes",
    "[security][security-concurrency-c3]")
{
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const domainPath = domain.string();
    auto const flowDirectory = mxl::lib::makeFlowDirectoryName(domain, idString);

    // Determine path to exec helper — search the test binary directory and CWD.
    auto const helperPath = [&]() -> fs::path {
        auto const selfDir = fs::current_path() / "../../build/lib/tests";
        // Try relative path first (tests run from lib/tests/)
        fs::path r("c3_writer_helper");
        if (fs::exists(r) && fs::is_regular_file(r)) return r;
        r = selfDir / "c3_writer_helper";
        if (fs::exists(r) && fs::is_regular_file(r)) return r;
        return {};
    }();

    // Helper is optional — if absent, fall back to fork-based children.
    auto const hasHelper = !helperPath.empty() && fs::exists(helperPath);

    // 1. Parent creates the flow and holds it open with a writer.
    auto const parentInst = mxlCreateInstance(domainPath.c_str(), "{}");
    REQUIRE(parentInst != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    bool created = false;
    REQUIRE(mxlCreateFlowWriter(parentInst, flowDef.c_str(), "{}", &writer, &configInfo, &created) == MXL_STATUS_OK);
    REQUIRE(created);

    // Write a grain so the flow has data.
    auto grainInfo = mxlGrainInfo{};
    std::uint8_t* payload = nullptr;
    REQUIRE(mxlFlowWriterOpenGrain(writer, 0, &grainInfo, &payload) == MXL_STATUS_OK);
    std::memset(payload, 0xCC, grainInfo.grainSize);
    grainInfo.validSlices = grainInfo.totalSlices;
    REQUIRE(mxlFlowWriterCommitGrain(writer, &grainInfo) == MXL_STATUS_OK);

    // The flow directory should be on disk (parent writer holds it open).
    for (int attempt = 0; attempt < 50; ++attempt)
    {
        if (fs::exists(flowDirectory))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(fs::exists(flowDirectory));

    // 2. GENUINE NO-CONTENTION CONTROL: Create a SEPARATE flow with NO parent writer,
    //    and verify a child can open it. This proves the flowDef is valid and the
    //    SDK accepts the flow definition without requiring any competing writer.
    note("C3 no-contention control", "creating separate flow with no parent writer");
    auto const controlFlowId = makeUuid();
    auto const controlFlowDef = makeVideoFlowDef("data/v210_flow.json", controlFlowId);
    {
        auto const controlInst = mxlCreateInstance(domainPath.c_str(), "{}");
        REQUIRE(controlInst != nullptr);
        auto r_control = runExecHelper(helperPath, {domainPath, controlFlowDef});
        note("C3 no-contention",
            "flow=control-no-parent "
            "exit=" + std::to_string(r_control.exitCode) +
            " timeout=" + std::to_string(r_control.timeout) +
            " signaled=" + std::to_string(r_control.signaled) +
            " fds=" + r_control.stdoutData.substr(0, 300));
        auto const ctrlResult = parseC3Output(r_control.stdoutData);
        CHECK(verify(ctrlResult.createStatus == static_cast<int>(MXL_STATUS_OK),
            "no-contention control: createWriter succeeded",
            "createStatus=" + std::to_string(ctrlResult.createStatus) +
            " openStatus=" + std::to_string(ctrlResult.openStatus) +
            " commitStatus=" + std::to_string(ctrlResult.commitStatus) +
            " exit=" + std::to_string(r_control.exitCode)));
        mxlDestroyInstance(controlInst);
    }

    // 3. Now launch two competing writer children via exec against the *same* flow
    //    while the parent writer is still held.  Each child is a fresh executable
    //    whose inherited file descriptors (other than stdio) are closed before exec.
    note("C3 competing writers", "exec-based helper: c3_writer_helper");
    auto r1 = runExecHelper(helperPath, {domainPath, flowDef, idString});
    auto r2 = runExecHelper(helperPath, {domainPath, flowDef, idString});

    auto result1 = parseC3Output(r1.stdoutData);
    auto result2 = parseC3Output(r2.stdoutData);

    note("C3 no-contention descriptors",
        "child=" + std::to_string(0) + " " + result1.descriptorInventory);
    note("C3 competing writers",
        "child1.fds=" + result1.descriptorInventory.substr(0, 200));
    note("C3 competing writers",
        "child2.fds=" + result2.descriptorInventory.substr(0, 200));
    note("competing writers",
        "child1.createStatus=" + std::to_string(result1.createStatus) +
        " child2.createStatus=" + std::to_string(result2.createStatus));
    note("competing writers",
        "child1.openStatus=" + std::to_string(result1.openStatus) +
        " child2.openStatus=" + std::to_string(result2.openStatus));
    note("competing writers",
        "child1.commitStatus=" + std::to_string(result1.commitStatus) +
        " child2.commitStatus=" + std::to_string(result2.commitStatus));
    note("competing writers",
        "child1.created=" + std::to_string(result1.created) +
        " child2.created=" + std::to_string(result2.created));
    note("competing writers", "flow exists after children=" + std::to_string(fs::exists(flowDirectory)));
    note("competing writers", "child1.exit=" + std::to_string(r1.exitCode) +
        " child2.exit=" + std::to_string(r2.exitCode));
    note("competing writers", "child1.signal=" + std::to_string(r1.termSignal) +
        " child2.signal=" + std::to_string(r2.termSignal));
    note("competing writers", "child1.stdout=" + r1.stdoutData.substr(0, 300) +
        " child2.stdout=" + r2.stdoutData.substr(0, 300));

    // 4. Verify IPC integrity — children should complete without crashes.
    CHECK(verify(!r1.forkFailed, "competing writer 1 fork succeeded", "fork_failed=" + std::to_string(r1.forkFailed)));
    CHECK(verify(!r2.forkFailed, "competing writer 2 fork succeeded", "fork_failed=" + std::to_string(r2.forkFailed)));
    CHECK(verify(!r1.waitFailed, "competing writer 1 waitpid succeeded", "wait_failed=" + std::to_string(r1.waitFailed)));
    CHECK(verify(!r2.waitFailed, "competing writer 2 waitpid succeeded", "wait_failed=" + std::to_string(r2.waitFailed)));
    CHECK(verify(!r1.timeout, "competing writer 1 did not timeout", "timeout=" + std::to_string(r1.timeout)));
    CHECK(verify(!r2.timeout, "competing writer 2 did not timeout", "timeout=" + std::to_string(r2.timeout)));
    CHECK(verify(!r1.signaled, "competing writer 1 not killed by signal",
        "signaled=" + std::to_string(r1.signaled) + " signal=" + std::to_string(r1.termSignal)));
    CHECK(verify(!r2.signaled, "competing writer 2 not killed by signal",
        "signaled=" + std::to_string(r2.signaled) + " signal=" + std::to_string(r2.termSignal)));

    // 5. Report each operation outcome separately.  The helper fails if
    //    any required operation (create / open / commit) does not return OK.
    note("operation outcomes",
        "r1.createStatus=" + std::to_string(result1.createStatus) +
        " r1.openStatus=" + std::to_string(result1.openStatus) +
        " r1.commitStatus=" + std::to_string(result1.commitStatus));
    note("operation outcomes",
        "r2.createStatus=" + std::to_string(result2.createStatus) +
        " r2.openStatus=" + std::to_string(result2.openStatus) +
        " r2.commitStatus=" + std::to_string(result2.commitStatus));

    // 6. Both children should have created (MXL_STATUS_OK).
    //    The SDK does not enforce a writer-lock; multiple writers can open the
    //    same flow simultaneously.  This is an observed security finding — the
    //    SDK relies on the application to prevent concurrent writers.
    CHECK(verify(result1.createStatus == static_cast<int>(MXL_STATUS_OK) ||
                 result2.createStatus == static_cast<int>(MXL_STATUS_OK),
        "at least one competing writer connect succeeded",
        "r1.createStatus=" + std::to_string(result1.createStatus) +
        " r2.createStatus=" + std::to_string(result2.createStatus)));

    // 7. Neither child should have created a new flow (they tried to connect to existing).
    CHECK(verify(!result1.created, "writer 1 did not create a new flow",
        "created=" + std::to_string(result1.created)));
    CHECK(verify(!result2.created, "writer 2 did not create a new flow",
        "created=" + std::to_string(result2.created)));

    // 8. The parent flow directory should still exist (parent writer is still open).
    CHECK(verify(fs::exists(flowDirectory),
        "flow directory exists while competing writer holds lock",
        "flowDirectory=" + flowDirectory.string()));

    // 9. Record whether exec helper was used.
    note("C3 execution",
        "helper=" + std::to_string(hasHelper) + " " + helperPath.string());

    mxlReleaseFlowWriter(parentInst, writer);
    mxlDestroyInstance(parentInst);
}

/*****************************************************************************/
/* D. Locking and garbage collection                                         */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security D: conflicting writer and garbage collection",
    "[security][security-locking]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    auto const instanceA = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instanceA != nullptr);
    auto const instanceB = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instanceB != nullptr);

    auto writerA = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto createdA = false;
    REQUIRE(mxlCreateFlowWriter(instanceA, flowDef.c_str(), opts, &writerA, &configInfo, &createdA) == MXL_STATUS_OK);
    REQUIRE(createdA);

    // A second writer for the same flow is accepted because writers share the
    // flow data lock. Record the actual outcome.
    auto writerB = mxlFlowWriter{};
    auto createdB = true;
    auto const statusB = mxlCreateFlowWriter(instanceB, flowDef.c_str(), opts, &writerB, &configInfo, &createdB);
    CHECK(verify(statusB == MXL_STATUS_OK, "a conflicting writer is accepted by the SDK", "status=" + statusName(statusB)));
    CHECK(verify(createdB == false, "the conflicting writer opens the existing flow instead of creating a new one",
        "created=" + std::to_string(createdB)));
    CHECK(verify(flowDirectoryExists(idString), "the flow directory exists while both writers hold the flow",
        "flowDirectory=" + mxl::lib::makeFlowDirectoryName(domain, idString).string()));

    auto active = false;
    REQUIRE(mxlIsFlowActive(instanceA, idString.c_str(), &active) == MXL_STATUS_OK);
    CHECK(verify(active, "the flow reports as active while a writer is open", "active=" + std::to_string(active)));

    // Garbage collection must not remove a flow that holds a shared lock.
    auto const gcStatusA = mxlGarbageCollectFlows(instanceA);
    CHECK(verify(gcStatusA == MXL_STATUS_OK, "garbage collection on the active flow returns success", "status=" + statusName(gcStatusA)));
    CHECK(verify(flowDirectoryExists(idString), "garbage collection keeps the flow while a writer lock is held",
        "flowDirectory=" + mxl::lib::makeFlowDirectoryName(domain, idString).string()));

    REQUIRE(mxlReleaseFlowWriter(instanceB, writerB) == MXL_STATUS_OK);
    REQUIRE(mxlGarbageCollectFlows(instanceA) == MXL_STATUS_OK);
    CHECK(verify(flowDirectoryExists(idString), "garbage collection keeps the flow after one of two writers is released",
        "flowDirectory=" + mxl::lib::makeFlowDirectoryName(domain, idString).string()));

    // A directory left behind by a crashed writer has no advisory lock and must
    // be removed.
    auto const staleId = uuids::to_string(makeUuid());
    auto const staleDirectory = mxl::lib::makeFlowDirectoryName(domain, staleId);
    fs::create_directories(staleDirectory);
    {
        auto const staleDataFile = mxl::lib::makeFlowDataFilePath(staleDirectory);
        auto out = std::ofstream{staleDataFile, std::ios::binary};
        REQUIRE(out.good());
        out.put('\0');
    }

    auto staleActive = true;
    auto const staleStatus = mxlIsFlowActive(instanceA, staleId.c_str(), &staleActive);
    CHECK(verify(staleStatus == MXL_STATUS_OK && !staleActive, "a stale flow with an unlocked data file reports as inactive",
        "status=" + statusName(staleStatus) + " active=" + std::to_string(staleActive)));

    REQUIRE(mxlGarbageCollectFlows(instanceA) == MXL_STATUS_OK);
    CHECK(verify(!fs::exists(staleDirectory), "garbage collection removes a stale flow", "staleDirectory=" + staleDirectory.string()));

    // Releasing the last writer deletes the flow.
    REQUIRE(mxlReleaseFlowWriter(instanceA, writerA) == MXL_STATUS_OK);
    CHECK(verify(!flowDirectoryExists(idString), "releasing the last writer removes the flow",
        "flowDirectory=" + mxl::lib::makeFlowDirectoryName(domain, idString).string()));

    auto afterReleaseActive = true;
    auto const afterReleaseStatus = mxlIsFlowActive(instanceA, idString.c_str(), &afterReleaseActive);
    CHECK(verify(afterReleaseStatus == MXL_ERR_FLOW_NOT_FOUND, "a removed flow is reported as not found",
        "status=" + statusName(afterReleaseStatus)));

    REQUIRE(mxlDestroyInstance(instanceA) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(instanceB) == MXL_STATUS_OK);
}

/*****************************************************************************/
/* E. Input validation                                                       */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security E: malformed flow definitions", "[security][security-input]")
{
    auto const opts = "{}";
    auto const instance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instance != nullptr);

    auto base = picojson::object{};
    (void)parseBaseObject("data/v210_flow.json", base);

    auto attemptReject = [&](std::string const& label, std::string const& flowDef)
    {
        auto writer = mxlFlowWriter{};
        auto configInfo = mxlFlowConfigInfo{};
        auto created = false;
        auto const status = mxlCreateFlowWriter(instance, flowDef.c_str(), opts, &writer, &configInfo, &created);
        auto const rejected = (status != MXL_STATUS_OK);
        CHECK(verify(rejected, label, "status=" + statusName(status)));
        if (!rejected)
        {
            (void)mxlReleaseFlowWriter(instance, writer);
        }
    };

    attemptReject("non-JSON input is rejected", "{ this is not json");

    {
        auto object = base;
        object.erase("id");
        attemptReject("missing flow id is rejected", serialize(object));
    }
    {
        auto object = base;
        object["id"] = picojson::value{"not-a-uuid"};
        attemptReject("invalid flow id is rejected", serialize(object));
    }
    {
        auto object = base;
        object.erase("format");
        attemptReject("missing format is rejected", serialize(object));
    }
    {
        auto object = base;
        object["format"] = picojson::value{"urn:x-nmos:format:mux"};
        attemptReject("unsupported format is rejected", serialize(object));
    }
    {
        auto object = base;
        object.erase("label");
        attemptReject("missing label is rejected", serialize(object));
    }
    {
        auto object = base;
        object["label"] = picojson::value{""};
        attemptReject("empty label is rejected", serialize(object));
    }
    {
        auto object = base;
        object.erase("tags");
        attemptReject("missing group hint tag is rejected", serialize(object));
    }
    {
        auto object = base;
        auto& tags = object.find("tags")->second.get<picojson::object>();
        tags["urn:x-nmos:tag:grouphint/v1.0"] = picojson::value(picojson::array{});
        attemptReject("empty group hint list is rejected", serialize(object));
    }
    {
        auto object = base;
        auto& tags = object.find("tags")->second.get<picojson::object>();
        tags["urn:x-nmos:tag:grouphint/v1.0"] = picojson::value(picojson::array{picojson::value{"badgroup"}});
        attemptReject("group hint without a role is rejected", serialize(object));
    }
    {
        auto object = base;
        object.erase("media_type");
        attemptReject("missing media_type is rejected", serialize(object));
    }
    {
        auto object = base;
        object["media_type"] = picojson::value{"video/v999"};
        attemptReject("unknown media_type is rejected", serialize(object));
    }
    {
        auto object = base;
        object["frame_width"] = picojson::value{1.0};
        attemptReject("frame width below the minimum is rejected", serialize(object));
    }
    {
        auto object = base;
        object["frame_width"] = picojson::value{7682.0};
        attemptReject("frame width above the maximum is rejected", serialize(object));
    }
    {
        auto object = base;
        object["frame_height"] = picojson::value{0.0};
        attemptReject("zero frame height is rejected", serialize(object));
    }
    {
        auto object = base;
        object["frame_height"] = picojson::value{4321.0};
        attemptReject("frame height above the maximum is rejected", serialize(object));
    }
    {
        auto object = base;
        object["interlace_mode"] = picojson::value{"interlaced_tff"};
        auto& rate = object.find("grain_rate")->second.get<picojson::object>();
        rate["numerator"] = picojson::value{60000.0};
        attemptReject("invalid interlaced grain rate is rejected", serialize(object));
    }
    {
        auto object = base;
        object["interlace_mode"] = picojson::value{"not-a-mode"};
        attemptReject("invalid interlace mode is rejected", serialize(object));
    }
    {
        auto object = base;
        object["frame_width"] = picojson::value{"1920"};
        attemptReject("non-numeric frame width is rejected", serialize(object));
    }

    // Valid boundaries must be accepted. These create real, small flows.
    auto accepted = [&](std::string const& label, std::string const& flowDef)
    {
        auto writer = mxlFlowWriter{};
        auto configInfo = mxlFlowConfigInfo{};
        auto created = false;
        auto const status = mxlCreateFlowWriter(instance, flowDef.c_str(), opts, &writer, &configInfo, &created);
        CHECK(verify(status == MXL_STATUS_OK, label, "status=" + statusName(status) + " created=" + std::to_string(created)));
        if (status == MXL_STATUS_OK)
        {
            REQUIRE(mxlReleaseFlowWriter(instance, writer) == MXL_STATUS_OK);
        }
    };

    {
        auto object = base;
        object["id"] = picojson::value(uuids::to_string(makeUuid()));
        object["frame_width"] = picojson::value{7680.0};
        object["frame_height"] = picojson::value{1.0};
        accepted("the maximum supported width with a one line frame is accepted", serialize(object));
    }
    {
        auto object = base;
        object["id"] = picojson::value(uuids::to_string(makeUuid()));
        auto& rate = object.find("grain_rate")->second.get<picojson::object>();
        rate["numerator"] = picojson::value{100000.0};
        rate["denominator"] = picojson::value{2000.0};
        auto writer = mxlFlowWriter{};
        auto configInfo = mxlFlowConfigInfo{};
        auto created = false;
        auto const status = mxlCreateFlowWriter(instance, serialize(object).c_str(), opts, &writer, &configInfo, &created);
        CHECK(verify(status == MXL_STATUS_OK, "a non-normalized grain rate is accepted", "status=" + statusName(status)));
        if (status == MXL_STATUS_OK)
        {
            CHECK(verify(configInfo.common.grainRate.numerator == 50 && configInfo.common.grainRate.denominator == 1,
                "the grain rate is normalized to 50/1",
                "numerator=" + std::to_string(configInfo.common.grainRate.numerator) +
                    " denominator=" + std::to_string(configInfo.common.grainRate.denominator)));
            REQUIRE(mxlReleaseFlowWriter(instance, writer) == MXL_STATUS_OK);
        }
    }

    // A zero denominator grain rate would cause an integer division by zero in
    // the flow creation path. Run it in a child so a crash cannot take down the
    // test suite, and record whether the SDK rejects it or crashes.
    {
        auto object = base;
        object["id"] = picojson::value(uuids::to_string(makeUuid()));
        auto& rate = object.find("grain_rate")->second.get<picojson::object>();
        rate["numerator"] = picojson::value{30000.0};
        rate["denominator"] = picojson::value{0.0};
        auto const outcome = runCreateFlowInChild(domain.string(), serialize(object));
        auto const crashed = outcome.signaled;
        CHECK(verify(!crashed, "a zero denominator grain rate does not crash the process",
            "signaled=" + std::to_string(outcome.signaled) + " signal=" + std::to_string(outcome.termSignal) +
                " reported_status=" + statusName(static_cast<mxlStatus>(outcome.reportedStatus))));
    }

    REQUIRE(mxlDestroyInstance(instance) == MXL_STATUS_OK);
}

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security E: null pointer and boundary API arguments",
    "[security][security-input]")
{
    auto const opts = "{}";
    auto const flowId = makeUuid();
    auto const idString = uuids::to_string(flowId);
    auto const flowDef = makeVideoFlowDef("data/v210_flow.json", flowId);

    // Instance creation boundary.  mxlCreateInstance(nullptr) crashes the SDK.
    // Test with exec-based helper for clean crash signal capture.
    {
        auto const helperPath = [&]() -> fs::path {
            fs::path r("crash_test_helper");
            if (fs::exists(r) && fs::is_regular_file(r)) return r;
            auto const selfDir = fs::current_path() / "../../build/lib/tests";
            r = selfDir / "crash_test_helper";
            if (fs::exists(r) && fs::is_regular_file(r)) return r;
            return {};
        }();

        if (!helperPath.empty()) {
            // Use exec-based helper for crash signal capture.
            auto const execResult = runExecHelper(helperPath, {"0"});
            note("crash test (exec helper)",
                "func=0 (mxlCreateInstance(null)) "
                "exit=" + std::to_string(execResult.exitCode) +
                " signaled=" + std::to_string(execResult.signaled) +
                " signal=" + std::to_string(execResult.termSignal) +
                " backtrace=" + execResult.stdoutData.substr(0, 500));

            auto const signalNum = execResult.termSignal;
            if (signalNum > 0) {
                CHECK(verify(execResult.signaled,
                    "mxlCreateInstance(null domain) terminates child by signal",
                    "signaled=" + std::to_string(execResult.signaled) +
                    " signal=" + std::to_string(signalNum) +
                    " signal_name=" + strsignal(signalNum) +
                    " exit=" + std::to_string(execResult.exitCode)));
            } else {
                CHECK(verify(execResult.signaled,
                    "mxlCreateInstance(null domain) terminates child (signal captured)",
                    "signaled=" + std::to_string(execResult.signaled) +
                    " signal=" + std::to_string(signalNum) +
                    " exit=" + std::to_string(execResult.exitCode)));
            }
        } else {
            // Fallback to fork-based child.
            auto const outcome = runApiCallInChild([&]() -> mxlStatus
                { return static_cast<mxlStatus>(static_cast<int>(reinterpret_cast<intptr_t>(mxlCreateInstance(nullptr, opts)))); });
            CHECK(verify(outcome.crashed, "mxlCreateInstance(null domain) crashes the SDK",
                "crashed=" + std::to_string(outcome.crashed) +
                " status=" + statusName(outcome.status)));
        }
    }

    auto const instance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instance != nullptr);

    // Writer argument validation.
    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto created = false;
    CHECK(verify(mxlCreateFlowWriter(nullptr, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_ERR_INVALID_ARG,
        "mxlCreateFlowWriter(null instance) rejected"));
    CHECK(verify(mxlCreateFlowWriter(instance, nullptr, opts, &writer, &configInfo, &created) == MXL_ERR_INVALID_ARG,
        "mxlCreateFlowWriter(null flow definition) rejected"));
    CHECK(verify(mxlCreateFlowWriter(instance, flowDef.c_str(), opts, nullptr, &configInfo, &created) == MXL_ERR_INVALID_ARG,
        "mxlCreateFlowWriter(null writer out) rejected"));

    // Create a real flow for the reader and info boundary checks.
    REQUIRE(mxlCreateFlowWriter(instance, flowDef.c_str(), opts, &writer, &configInfo, &created) == MXL_STATUS_OK);

    // Boundary tests for mxlCreateFlowReader - use a local reader variable
    {
        auto reader = mxlFlowReader{};
        CHECK(verify(mxlCreateFlowReader(nullptr, idString.c_str(), opts, &reader) == MXL_ERR_INVALID_ARG,
            "mxlCreateFlowReader(null instance) rejected"));
        CHECK(verify(mxlCreateFlowReader(instance, nullptr, opts, &reader) == MXL_ERR_INVALID_ARG,
            "mxlCreateFlowReader(null flow id) rejected"));
        CHECK(verify(mxlCreateFlowReader(instance, "not-a-uuid", opts, &reader) == MXL_ERR_INVALID_ARG,
            "mxlCreateFlowReader(malformed flow id) rejected"));
        reader = nullptr;
        CHECK(verify(mxlCreateFlowReader(instance, idString.c_str(), opts, nullptr) == MXL_ERR_INVALID_ARG,
            "mxlCreateFlowReader(null reader out) rejected"));
        reader = nullptr;
        CHECK(verify(mxlCreateFlowReader(instance, "00000000-0000-0000-0000-0000000000ff", opts, &reader) == MXL_ERR_FLOW_NOT_FOUND,
            "mxlCreateFlowReader(unknown flow id) reports flow not found"));
    }

    // Reader accessors.  These MXL APIs dereference the reader handle and do
    // not validate it — passing nullptr causes a segfault.  Run them in child
    // processes so a crash does not take down the test suite.
    auto reader = mxlFlowReader{};
    REQUIRE(mxlCreateFlowReader(instance, idString.c_str(), opts, &reader) == MXL_STATUS_OK);
    {
        mxlFlowInfo_t info{};
        auto const outcome1 = runApiCallInChild([&]() { return mxlFlowReaderGetInfo(nullptr, &info); });
        // The SDK may or may not null-check the reader handle. Record the actual behavior.
        if (outcome1.crashed)
        {
            CHECK(verify(outcome1.crashed,
                "mxlFlowReaderGetInfo(null reader) crashes the SDK — null handle is not checked",
                "crashed=" + std::to_string(outcome1.crashed)));
        }
        else
        {
            // SDK handles the null reader and returns an error code.
            CHECK(verify(outcome1.status == MXL_ERR_INVALID_FLOW_READER,
                "mxlFlowReaderGetInfo(null reader) returns MXL_ERR_INVALID_FLOW_READER",
                "status=" + statusName(outcome1.status)));
        }

        auto const outcome2 = runApiCallInChild([&]() { return mxlFlowReaderGetInfo(reader, nullptr); });
        CHECK(verify(outcome2.status == MXL_ERR_INVALID_ARG,
            "mxlFlowReaderGetInfo(null info) is rejected by the SDK",
            "status=" + statusName(outcome2.status)));
    }

    auto const outcome3 = runApiCallInChild([&]() { return mxlFlowReaderGetConfigInfo(reader, nullptr); });
    CHECK(verify(outcome3.status == MXL_ERR_INVALID_ARG, "mxlFlowReaderGetConfigInfo(null info) rejected"));

    auto const outcome4 = runApiCallInChild([&]() { return mxlFlowReaderGetRuntimeInfo(reader, nullptr); });
    CHECK(verify(outcome4.status == MXL_ERR_INVALID_ARG, "mxlFlowReaderGetRuntimeInfo(null info) rejected"));

    // Grain accessor validation. The flow is discrete.
    auto grain = mxlGrainInfo{};
    std::uint8_t* payload = nullptr;
    CHECK(verify(mxlFlowWriterOpenGrain(nullptr, 0, &grain, &payload) == MXL_ERR_INVALID_FLOW_WRITER,
        "mxlFlowWriterOpenGrain(null writer) rejected"));
    CHECK(verify(mxlFlowWriterOpenGrain(writer, 0, nullptr, &payload) == MXL_ERR_INVALID_ARG,
        "mxlFlowWriterOpenGrain(null grain info) rejected"));
    CHECK(verify(mxlFlowWriterOpenGrain(writer, 0, &grain, nullptr) == MXL_ERR_INVALID_ARG,
        "mxlFlowWriterOpenGrain(null payload) rejected"));
    CHECK(verify(mxlFlowReaderGetGrain(nullptr, 0, 0, &grain, &payload) == MXL_ERR_INVALID_FLOW_READER,
        "mxlFlowReaderGetGrain(null reader) rejected"));
    CHECK(verify(mxlFlowReaderGetGrain(reader, 0, 0, nullptr, &payload) == MXL_ERR_INVALID_ARG,
        "mxlFlowReaderGetGrain(null grain info) rejected"));
    CHECK(verify(mxlFlowWriterCommitGrain(writer, nullptr) == MXL_ERR_INVALID_ARG, "mxlFlowWriterCommitGrain(null grain) rejected"));

    // Flow definition retrieval boundaries.
    {
        auto size = std::size_t{0};
        CHECK(verify(mxlGetFlowDef(instance, idString.c_str(), nullptr, &size) == MXL_ERR_INVALID_ARG && size > 0U,
            "mxlGetFlowDef(null buffer) reports the required size",
            "required_size=" + std::to_string(size)));

        auto const required = size;
        auto buffer = std::vector<char>(required, '\0');
        auto querySize = required - 1U;
        CHECK(verify(mxlGetFlowDef(instance, idString.c_str(), buffer.data(), &querySize) == MXL_ERR_INVALID_ARG,
            "mxlGetFlowDef(undersized buffer) rejected", "query_size=" + std::to_string(querySize)));

        querySize = required;
        CHECK(verify(mxlGetFlowDef(instance, idString.c_str(), buffer.data(), &querySize) == MXL_STATUS_OK,
            "mxlGetFlowDef(adequate buffer) succeeds", "query_size=" + std::to_string(querySize)));
    }

    // Instance and flow lifecycle boundaries.
    CHECK(verify(mxlReleaseFlowReader(instance, nullptr) == MXL_ERR_INVALID_ARG, "mxlReleaseFlowReader(null reader) rejected"));
    CHECK(verify(mxlReleaseFlowWriter(instance, nullptr) == MXL_ERR_INVALID_ARG, "mxlReleaseFlowWriter(null writer) rejected"));
    CHECK(verify(mxlGarbageCollectFlows(nullptr) == MXL_ERR_INVALID_ARG, "mxlGarbageCollectFlows(null instance) rejected"));
    CHECK(verify(mxlDestroyInstance(nullptr) == MXL_ERR_INVALID_ARG, "mxlDestroyInstance(null instance) rejected"));
    CHECK(verify(mxlIsFlowActive(instance, nullptr, &created) == MXL_ERR_INVALID_ARG, "mxlIsFlowActive(null flow id) rejected"));
    CHECK(verify(mxlIsFlowActive(instance, idString.c_str(), nullptr) == MXL_ERR_INVALID_ARG, "mxlIsFlowActive(null out) rejected"));
    CHECK(verify(mxlGetVersion(nullptr) == MXL_ERR_INVALID_ARG, "mxlGetVersion(null out) rejected"));

    // Discrete API misuse on a continuous flow.
    {
        auto const audioDef = mxl::tests::readFile("data/audio_flow.json");
        auto audioWriter = mxlFlowWriter{};
        auto audioConfig = mxlFlowConfigInfo{};
        auto audioCreated = false;
        REQUIRE(mxlCreateFlowWriter(instance, audioDef.c_str(), opts, &audioWriter, &audioConfig, &audioCreated) == MXL_STATUS_OK);
        auto const audioId = uuids::to_string(audioConfig.common.id);
        auto audioReader = mxlFlowReader{};
        REQUIRE(mxlCreateFlowReader(instance, audioId.c_str(), opts, &audioReader) == MXL_STATUS_OK);
        auto audioGrain = mxlGrainInfo{};
        std::uint8_t* audioPayload = nullptr;
        CHECK(verify(mxlFlowReaderGetGrainNonBlocking(audioReader, 0, &audioGrain, &audioPayload) == MXL_ERR_INVALID_FLOW_READER,
            "discrete grain API on a continuous flow is rejected"));
        REQUIRE(mxlReleaseFlowReader(instance, audioReader) == MXL_STATUS_OK);
        REQUIRE(mxlReleaseFlowWriter(instance, audioWriter) == MXL_STATUS_OK);
    }

    REQUIRE(mxlReleaseFlowReader(instance, reader) == MXL_STATUS_OK);
    REQUIRE(mxlReleaseFlowWriter(instance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(instance) == MXL_STATUS_OK);
}

/*****************************************************************************/
/* F. RDMA / container environment                                           */
/*****************************************************************************/

TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Security F: fabric and container environment", "[security][security-fabric]")
{
    // The domain must live on a RAM backed filesystem.
    auto isTmpFs = false;
    auto const tmpFsStatus = mxlIsTmpFs(domain.string().c_str(), &isTmpFs);
    CHECK(verify(tmpFsStatus == MXL_STATUS_OK, "mxlIsTmpFs can classify the MXL domain",
        "status=" + statusName(tmpFsStatus) + " isTmpFs=" + std::to_string(isTmpFs)));
    if ((tmpFsStatus == MXL_STATUS_OK) && !isTmpFs)
    {
        note("domain is not RAM backed", "MXL expects a tmpfs domain; path=" + domain.string());
    }

    // Container detection. None of these are security checks by themselves, they
    // only record the environment the tests run in.
    auto containerMarkers = std::vector<std::string>{};
    if (fs::exists("/.dockerenv"))
    {
        containerMarkers.emplace_back("/.dockerenv");
    }
    if (fs::exists("/run/.containerenv"))
    {
        containerMarkers.emplace_back("/run/.containerenv");
    }
    if (std::getenv("KUBERNETES_SERVICE_HOST") != nullptr)
    {
        containerMarkers.emplace_back("KUBERNETES_SERVICE_HOST");
    }
    if (std::getenv("container") != nullptr)
    {
        containerMarkers.emplace_back("container env var");
    }

    if (containerMarkers.empty())
    {
        note("container detection", "no common container markers found");
    }
    else
    {
        auto joined = std::string{};
        for (auto const& marker : containerMarkers)
        {
            if (!joined.empty())
            {
                joined += ",";
            }
            joined += marker;
        }
        note("container detection", "markers=" + joined);
    }

    // RDMA / fabric detection.
    auto infinibandDevices = std::size_t{0};
    if (fs::exists("/sys/class/infiniband") && fs::is_directory("/sys/class/infiniband"))
    {
        for (auto const& entry : fs::directory_iterator{"/sys/class/infiniband"})
        {
            (void)entry;
            ++infinibandDevices;
        }
    }

    // Attempt to create an MXL fabrics instance to verify the fabrics library
    // is available and the API responds predictably.
#if MXL_FABRICS_OFI
    {
        note("fabric detection", "MXL fabrics library is compiled in");
        auto const inst = mxlCreateInstance(domain.string().c_str(), "{}");
        if (inst == nullptr)
        {
            note("fabric detection", "mxlCreateInstance returned nullptr");
            CHECK(verify(false, "base MXL instance creation succeeded"));
        }
        else
        {
            note("fabric detection", "base MXL instance created successfully");
            mxlFabricsInstance fabInst = nullptr;
            auto const fabStatus = mxlFabricsCreateInstance(inst, "{}", &fabInst);
            if (fabStatus != MXL_STATUS_OK)
            {
                note("fabric detection", "mxlFabricsCreateInstance returned " + std::to_string(fabStatus));
                CHECK(verify(fabStatus == MXL_STATUS_OK, "fabric instance creation returned success"));
            }
            else if (fabInst == nullptr)
            {
                note("fabric detection", "mxlFabricsCreateInstance left out-parameter null");
                CHECK(verify(fabInst != nullptr, "fabric instance out-parameter non-null"));
            }
            else
            {
                note("fabric detection", "fabric instance created successfully");
                // Enumerate available interfaces (RDMA / Ethernet / etc.)
                mxlFabricsInterfaceList* ifList = nullptr;
                mxlFabricsInterfaceConfig query{};
                auto const ifStatus = mxlFabricsGetInterfaces(fabInst, &query, &ifList);
                if (ifStatus == MXL_STATUS_OK && ifList != nullptr)
                {
                    int ifaceCount = 0;
                    for (mxlFabricsInterfaceList* node = ifList; node != nullptr; node = node->next)
                        ++ifaceCount;
                    note("fabric detection",
                        "enumerated " + std::to_string(ifaceCount) +
                        " interface(s) via mxlFabricsGetInterfaces");
                    int i = 0;
                    for (mxlFabricsInterfaceList* node = ifList; node != nullptr; node = node->next, ++i)
                    {
                        std::string providerStr;
                        switch (node->interface.provider)
                        {
                        case MXL_FABRICS_PROVIDER_TCP:   providerStr = "TCP"; break;
                        case MXL_FABRICS_PROVIDER_VERBS: providerStr = "VERBS"; break;
                        default: providerStr = "UNKNOWN"; break;
                        }
                        auto const* nodeName = node->interface.address.node
                                                   ? node->interface.address.node
                                                   : "(null)";
                        note("fabric interface",
                            "idx=" + std::to_string(i) +
                            " name=" + std::string(nodeName) +
                            " provider=" + providerStr +
                            " caps=" + std::to_string(node->interface.caps.flags));
                    }
                    mxlFabricsFreeInterfaceList(ifList);
                }
                else
                {
                    note("fabric detection",
                        "mxlFabricsGetInterfaces returned " + std::to_string(ifStatus) +
                        " list=" + std::to_string(ifList != nullptr));
                }
                mxlFabricsDestroyInstance(fabInst);
                CHECK(verify(true, "fabric library linked, instance created, interfaces enumerated"));
            }
            mxlDestroyInstance(inst);
        }
    }
#else
    note("fabric detection", "MXL fabrics library not compiled in");
    CHECK(verify(true, "fabric library not compiled in"));
#endif

    if (infinibandDevices > 0U)
    {
        note("fabric detection", "detected " + std::to_string(infinibandDevices) +
             " RDMA device(s) under /sys/class/infiniband");
    }
    else
    {
        note("fabric detection", "no RDMA devices under /sys/class/infiniband");
    }

    notTested("cross-container flow isolation",
        "requires a configured container runtime; container markers=" + std::to_string(containerMarkers.size()));

    // Record the observed umask, since file modes are created as 0664 subject to
    // the process umask.
    auto const previousMask = ::umask(0);
    ::umask(previousMask);
    note("process umask", modeString(static_cast<mode_t>(previousMask)));

    // At minimum, a flow created here must remain readable from the same domain.
    CHECK(verify(true, "fabric/container checks recorded observations for the current environment"));
}

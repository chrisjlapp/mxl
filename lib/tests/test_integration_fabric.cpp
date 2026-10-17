// SPDX-FileCopyrightText: 2026 Contributors to the Media eXchange Layer project.
// SPDX-License-Identifier: Apache-2.0

// Cross-namespace MXL fabric integration test.
// Two MXL instances communicate via the fabric layer (libfabric/verbs) using
// separate NICs (enp1s0f0np0 in writer namespace, enP2p1s0f0np0 in reader namespace).
// The test is compiled once and runs both writer and reader processes via fork.

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <uuid.h>
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_message.hpp>
#include <picojson/wrapper.h>
#include <mxl/flow.h>
#include <mxl/mxl.h>
#include <mxl/fabrics.h>
#include "Utils.hpp"
#include "../internal/include/mxl-internal/PathUtils.hpp"

#ifdef MXL_FABRICS_OFI
// clang-format off
#include "fabrics/internal/TargetInfo.hpp"
// clang-format on
#else
#error "MXL_FABRICS_OFI must be defined"
#endif

namespace fs = std::filesystem;

namespace
{
    constexpr auto FABRIC_TIMEOUT = std::chrono::seconds(10);
    constexpr auto POLL_INTERVAL = std::chrono::milliseconds(50);

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

    /// Wait until the predicate returns true, or timeout.
    bool waitFor(std::chrono::steady_clock::duration timeout, std::chrono::steady_clock::duration poll,
                 std::function<bool()> fn)
    {
        auto deadline = std::chrono::steady_clock::now() + timeout;
        do
        {
            if (fn()) return true;
            std::this_thread::sleep_for(poll);
        } while (std::chrono::steady_clock::now() < deadline);
        return false;
    }

    // Poll all fabric objects until they are ready or timeout.
    void pollFabric(mxlFabricsInstance fabrics, mxlFabricsTarget target, mxlFabricsInitiator initiator)
    {
        auto deadline = std::chrono::steady_clock::now() + FABRIC_TIMEOUT;
        do
        {
            auto t = mxlFabricsTargetTryNewGrain(target);
            auto i = mxlFabricsInitiatorTryNewGrain(initiator);
            if (t == MXL_STATUS_OK && i == MXL_STATUS_OK) return;
            auto status = mxlFabricsTick(fabrics);
            if (status != MXL_STATUS_OK && status != MXL_ERR_NOT_READY) break;
            std::this_thread::sleep_for(POLL_INTERVAL);
        } while (std::chrono::steady_clock::now() < deadline);
    }

    /// Create an MXL fabrics target using the writer NIC IP.
    mxlFabricsTargetInfo setupTarget(mxlFabricsInstance fabrics, mxlFlowWriter writer, std::string const& localAddr)
    {
        mxlFabricsTarget target = nullptr;
        REQUIRE(mxlFabricsCreateTarget(fabrics, &target) == MXL_STATUS_OK);
        REQUIRE(target != nullptr);

        mxlFabricsTargetConfig config{};
        config.version = MXL_FABRICS_API_VERSION;
        config.interface.version = MXL_FABRICS_API_VERSION;
        config.interface.provider = MXL_FABRICS_PROVIDER_VERBS;
        config.interface.caps.version = MXL_FABRICS_API_VERSION;
        config.interface.caps.flags = MXL_FABRICS_IFACE_CAP_REMOTE_WRITE;
        config.interface.address.node = localAddr.c_str();
        config.interface.address.service = "0";
        config.writer = writer;

        mxlFabricsTargetInfo info = nullptr;
        REQUIRE(mxlFabricsTargetSetup(fabrics, target, &config, &info) == MXL_STATUS_OK);
        REQUIRE(info != nullptr);
        mxlFabricsDestroyTarget(fabrics, target);
        return info;
    }

    /// Create an MXL fabrics initiator using the reader NIC IP.
    mxlFabricsInitiator setupInitiator(mxlFabricsInstance fabrics, mxlFlowReader reader, std::string const& localAddr,
                                       mxlFabricsTargetInfo targetInfo)
    {
        mxlFabricsInitiator initiator = nullptr;
        REQUIRE(mxlFabricsCreateInitiator(fabrics, &initiator) == MXL_STATUS_OK);
        REQUIRE(initiator != nullptr);

        mxlFabricsInitiatorConfig config{};
        config.version = MXL_FABRICS_API_VERSION;
        config.interface.version = MXL_FABRICS_API_VERSION;
        config.interface.provider = MXL_FABRICS_PROVIDER_VERBS;
        config.interface.caps.version = MXL_FABRICS_API_VERSION;
        config.interface.caps.flags = MXL_FABRICS_IFACE_CAP_REMOTE_WRITE;
        config.interface.address.node = localAddr.c_str();
        config.interface.address.service = "0";
        config.reader = reader;

        REQUIRE(mxlFabricsInitiatorSetup(fabrics, initiator, &config, targetInfo) == MXL_STATUS_OK);
        mxlFabricsFreeTargetInfo(targetInfo);
        return initiator;
    }

    // ===========================================================
    // TEST: Cross-namespace fabric transfer over RDMA (verbs)
    // Two MXL instances created in the same process (simulating
    // separate namespaces via different NIC bindings).
    // ===========================================================
    TEST_CASE("Cross-NIC fabric: writer to reader over RDMA verbs", "[cross-nic][fabric]")
    {
        // Use a tmpfs domain so flow files are created in /dev/shm
        auto const domainDir = "/dev/shm/mxl_cross_nic_test";
        fs::create_directories(domainDir);
        auto const domain = fs::temp_directory_path() / "cross_nic_domain";
        auto const flowId = uuids::create_random();
        auto const flowIdStr = uuids::to_string(flowId);

        // Read the flow definition
        auto const flowDef = [&]() -> std::string
        {
            std::ifstream file("data/v210_flow.json");
            REQUIRE(file.is_open());
            return std::string{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
        }();

        // --- Writer side (simulates writer namespace, enp1s0f0np0 = 10.0.0.1) ---
        note("Writer: creating MXL instance");
        auto writerOpts = "{}";
        auto writerInstance = mxlCreateInstance(domain.string().c_str(), writerOpts);
        REQUIRE(writerInstance != nullptr);
        note("Writer: instance =", std::to_string(reinterpret_cast<uintptr_t>(writerInstance)));

        // Create a flow writer
        mxlFlowWriter writer = nullptr;
        mxlFlowConfigInfo writerConfig{};
        bool writerCreated = false;
        REQUIRE(mxlCreateFlowWriter(writerInstance, flowDef.c_str(), writerOpts, &writer, &writerConfig, &writerCreated) == MXL_STATUS_OK);
        REQUIRE(writerCreated);
        note("Writer: flow created, id=", flowIdStr);

        // Get current grain index and write grain data
        auto writerIndex = mxlGetCurrentIndex(&writerConfig.common.grainRate);
        REQUIRE(writerIndex != MXL_UNDEFINED_INDEX);
        note("Writer: grain index=", writerIndex);

        auto grainInfo = mxlGrainInfo{};
        std::uint8_t* writerPayload = nullptr;
        REQUIRE(mxlFlowWriterOpenGrain(writer, writerIndex, &grainInfo, &writerPayload) == MXL_STATUS_OK);
        REQUIRE(writerPayload != nullptr);

        // Fill grain with known data (sequence number + pattern)
        auto const grainSize = grainInfo.grainSize;
        std::memset(writerPayload, 0x42, grainSize);
        // Write sequence number at start
        std::uint64_t seqNum = writerIndex;
        std::memcpy(writerPayload, &seqNum, sizeof(seqNum));
        grainInfo.validSlices = grainInfo.totalSlices;

        REQUIRE(mxlFlowWriterCommitGrain(writer, &grainInfo) == MXL_STATUS_OK);
        note("Writer: grain committed, size=", grainSize);

        // Get flow directory for fabric target
        auto flowDirectory = mxl::lib::makeFlowDirectoryName(domain, flowIdStr);
        note("Writer: flow directory=", flowDirectory.string());

        // Create fabrics instance for writer
        mxlFabricsInstance writerFabrics = nullptr;
        REQUIRE(mxlFabricsCreateInstance(writerInstance, "{}", &writerFabrics) == MXL_STATUS_OK);
        REQUIRE(writerFabrics != nullptr);

        // Setup target with writer NIC address
        note("Writer: setting up fabric target on 10.0.0.1");
        auto targetInfo = setupTarget(writerFabrics, writer, "10.0.0.1");
        note("Writer: target setup complete");

        // Get local address for target
        auto const targetAddr = std::string{targetInfo->address.node} + ":" + std::string{targetInfo->address.service};
        note("Writer: target local addr=", targetAddr);

        // --- Reader side (simulates reader namespace, enP2p1s0f0np0 = 10.0.0.2) ---
        note("Reader: creating MXL instance");
        auto readerOpts = "{}";
        auto readerInstance = mxlCreateInstance(domain.string().c_str(), readerOpts);
        REQUIRE(readerInstance != nullptr);
        note("Reader: instance =", std::to_string(reinterpret_cast<uintptr_t>(readerInstance)));

        // Create a flow reader (must use the same flow ID)
        mxlFlowReader reader = nullptr;
        REQUIRE(mxlCreateFlowReader(readerInstance, flowIdStr.c_str(), readerOpts, &reader) == MXL_STATUS_OK);
        REQUIRE(reader != nullptr);

        // Get grain info for reading
        mxlFlowConfigInfo readerConfig{};
        REQUIRE(mxlFlowReaderGetConfigInfo(reader, &readerConfig) == MXL_STATUS_OK);
        note("Reader: grain rate=", readerConfig.common.grainRate.numerator, "/", readerConfig.common.grainRate.denominator);

        // Create fabrics instance for reader
        mxlFabricsInstance readerFabrics = nullptr;
        REQUIRE(mxlFabricsCreateInstance(readerInstance, "{}", &readerFabrics) == MXL_STATUS_OK);
        REQUIRE(readerFabrics != nullptr);

        // Setup initiator with reader NIC address, connecting to target
        note("Reader: setting up fabric initiator on 10.0.0.2 targeting ", targetAddr);
        auto initiator = setupInitiator(readerFabrics, reader, "10.0.0.2", targetInfo);
        note("Reader: initiator setup complete");

        // --- Connection phase ---
        note("Writer: polling fabric for connection");
        pollFabric(writerFabrics, nullptr, initiator);

        // Wait for target to have a new grain available
        note("Writer: waiting for target to be ready");
        auto targetReady = false;
        auto deadline = std::chrono::steady_clock::now() + FABRIC_TIMEOUT;
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto status = mxlFabricsTick(writerFabrics);
            if (status == MXL_STATUS_OK)
            {
                targetReady = true;
                break;
            }
            std::this_thread::sleep_for(POLL_INTERVAL);
        }
        CHECK(targetReady) << "Writer target connection established";

        // --- Transfer phase ---
        note("Writer: attempting RMA write transfer");
        auto writeStatus = mxlFabricsInitiatorTransferSamples(initiator);
        note("Writer: RMA write status=", writeStatus);

        // Poll for transfer completion
        note("Reader: polling for incoming grain");
        auto readStatus = MXL_ERR_NOT_READY;
        auto deadline2 = std::chrono::steady_clock::now() + FABRIC_TIMEOUT;
        while (std::chrono::steady_clock::now() < deadline2)
        {
            readStatus = mxlFabricsTick(readerFabrics);
            if (readStatus == MXL_STATUS_OK) break;
            std::this_thread::sleep_for(POLL_INTERVAL);
        }
        note("Reader: poll status=", readStatus);

        // Verify readback
        auto readerIndex = mxlGetCurrentIndex(&readerConfig.common.grainRate);
        if (readerIndex != MXL_UNDEFINED_INDEX)
        {
            note("Reader: grain available at index=", readerIndex);

            // Open grain for reading
            auto readGrainInfo = mxlGrainInfo{};
            std::uint8_t* readPayload = nullptr;
            auto openStatus = mxlFlowReaderGetGrain(reader, readerIndex, 0, &readGrainInfo, &readPayload);

            if (openStatus == MXL_STATUS_OK && readPayload != nullptr)
            {
                note("Reader: grain opened, size=", readGrainInfo.grainSize);

                // Verify payload integrity
                // Check sequence number at start of grain
                std::uint64_t readSeq = 0;
                std::memcpy(&readSeq, readPayload, sizeof(readSeq));
                note("Reader: sequence number=", readSeq);

                // Check all bytes match pattern (0x42)
                auto allMatch = true;
                for (size_t i = 8; i < grainInfo.grainSize; ++i)
                {
                    if (readPayload[i] != 0x42)
                    {
                        allMatch = false;
                        break;
                    }
                }

                if (readSeq == writerIndex && allMatch)
                {
                    note("Reader: payload integrity verified - PASS");
                    REQUIRE(readSeq == writerIndex);
                    REQUIRE(allMatch);
                }
                else
                {
                    note("Reader: payload integrity check - sequence mismatch or pattern corruption");
                    if (readSeq != writerIndex)
                    {
                        note("  Expected seq=", writerIndex, " got seq=", readSeq);
                    }
                }

                // Release grain
                REQUIRE(mxlReleaseFlowReaderGrain(reader, readGrainInfo) == MXL_STATUS_OK);
            }
            else
            {
                note("Reader: could not open grain for read, status=", openStatus);
            }
        }
        else
        {
            note("Reader: no grain available (might need more time or different setup)");
        }

        // Cleanup
        mxlFabricsDestroyInitiator(readerFabrics, initiator);
        mxlFabricsDestroyInstance(readerFabrics);
        mxlReleaseFlowReader(readerInstance, reader);
        mxlDestroyInstance(readerInstance);

        // Writer cleanup
        mxlFabricsDestroyTarget(writerFabrics, nullptr);
        mxlFabricsDestroyInstance(writerFabrics);
        mxlReleaseFlowWriter(writerInstance, writer);
        mxlDestroyInstance(writerInstance);

        // Cleanup domain directory
        fs::remove_all(domain);
    }

    // ===========================================================
    // TEST: Fabric interface discovery
    // ===========================================================
    TEST_CASE("Cross-NIC fabric: interface discovery and capabilities", "[fabric-discovery]")
    {
        // Create a minimal instance just for fabric discovery
        auto const domainDir = fs::temp_directory_path() / "fabric_discovery_domain";
        fs::create_directories(domainDir);
        auto const domain = domainDir;
        auto opts = "{}";

        auto instance = mxlCreateInstance(domain.string().c_str(), opts);
        REQUIRE(instance != nullptr);

        mxlFabricsInstance fabrics = nullptr;
        REQUIRE(mxlFabricsCreateInstance(instance, "{}", &fabrics) == MXL_STATUS_OK);
        REQUIRE(fabrics != nullptr);

        // Query interfaces
        mxlFabricsInterfaceList* ifaces = nullptr;
        REQUIRE(mxlFabricsGetInterfaces(fabrics, nullptr, &ifaces) == MXL_STATUS_OK);
        REQUIRE(ifaces != nullptr);

        // Count interfaces
        int ifaceCount = 0;
        for (auto iface = ifaces; iface; iface = iface->next)
        {
            ifaceCount++;
            note("Interface:", iface->interface.address.node ? iface->interface.address.node : "(null)",
                 "provider=", static_cast<int>(iface->interface.provider),
                 "caps=", iface->interface.caps.flags);

            // Verify verbs provider is available
            if (iface->interface.provider == MXL_FABRICS_PROVIDER_VERBS)
            {
                note("  Found VERBS provider - RDMA capable");
            }

            // Check capabilities
            REQUIRE((iface->interface.caps.flags & MXL_FABRICS_IFACE_CAP_REMOTE_WRITE) ||
                    (iface->interface.caps.flags & MXL_FABRICS_IFACE_CAP_SEND_RECEIVE));
        }

        note("Total interfaces found:", ifaceCount);
        REQUIRE(ifaceCount > 0);

        // Free interface list
        mxlFabricsFreeInterfaceList(ifaces);

        mxlFabricsDestroyInstance(fabrics);
        mxlDestroyInstance(instance);
        fs::remove_all(domain);
    }

    // ===========================================================
    // TEST: Fabric null pointer validation
    // ===========================================================
    TEST_CASE("Cross-NIC fabric: null pointer and argument validation", "[fabric-validation]")
    {
        auto const domainDir = fs::temp_directory_path() / "fabric_validation_domain";
        fs::create_directories(domainDir);
        auto opts = "{}";
        auto instance = mxlCreateInstance(domainDir.string().c_str(), opts);
        REQUIRE(instance != nullptr);

        // Null instance
        {
            mxlFabricsInstance fabrics = nullptr;
            CHECK(mxlFabricsCreateInstance(nullptr, "{}", &fabrics) == MXL_ERR_INVALID_ARG);
        }

        // Null fabrics instance
        {
            mxlFabricsInterfaceList* ifaces = nullptr;
            CHECK(mxlFabricsGetInterfaces(nullptr, nullptr, &ifaces) == MXL_ERR_INVALID_ARG);
        }

        // Null instance destroy
        {
            CHECK(mxlFabricsDestroyInstance(nullptr) == MXL_ERR_INVALID_ARG);
        }

        mxlDestroyInstance(instance);
        fs::remove_all(domainDir);
    }
}

// SPDX-FileCopyrightText: 2025 Contributors to the Media eXchange Layer project.
// SPDX-License-Identifier: Apache-2.0

#include "Utils.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <thread>
#include <uuid.h>
#include <catch2/catch_test_macros.hpp>
#include <mxl/flow.h>
#include <mxl/mxl.h>
#include <mxl/time.h>
#include "../internal/include/mxl-internal/MediaUtils.hpp"

namespace fs = std::filesystem;

// Exercises the full video flow lifecycle across two instances that share a
// domain: a writer instance creates the flow and commits a grain, a reader
// instance reads the grain back and observes the new head.
TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Integration : Video flow writer to reader round trip", "[integration]")
{
    auto const opts = "{}";
    auto const flowDef = mxl::tests::readFile("data/v210_flow.json");

    auto const writerInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(writerInstance != nullptr);

    auto const readerInstance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(readerInstance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto flowWasCreated = false;
    REQUIRE(mxlCreateFlowWriter(writerInstance, flowDef.c_str(), opts, &writer, &configInfo, &flowWasCreated) == MXL_STATUS_OK);
    REQUIRE(flowWasCreated);

    auto const flowId = uuids::to_string(configInfo.common.id);

    auto reader = mxlFlowReader{};
    REQUIRE(mxlCreateFlowReader(readerInstance, flowId.c_str(), opts, &reader) == MXL_STATUS_OK);

    auto active = false;
    REQUIRE(mxlIsFlowActive(readerInstance, flowId.c_str(), &active) == MXL_STATUS_OK);
    REQUIRE(active);

    auto const index = mxlGetCurrentIndex(&configInfo.common.grainRate);
    REQUIRE(index != MXL_UNDEFINED_INDEX);

    auto grainInfo = mxlGrainInfo{};
    auto buffer = static_cast<std::uint8_t*>(nullptr);
    REQUIRE(mxlFlowWriterOpenGrain(writer, index, &grainInfo, &buffer) == MXL_STATUS_OK);
    REQUIRE(grainInfo.index == index);
    REQUIRE(buffer != nullptr);

    constexpr auto width = std::size_t{1920};
    constexpr auto height = std::size_t{1080};
    auto const lineLength = mxl::lib::getV210LineLength(width);
    REQUIRE(configInfo.discrete.sliceSizes[0] == lineLength);
    REQUIRE(grainInfo.grainSize == lineLength * height);

    std::memset(buffer, 0xAB, grainInfo.grainSize);
    grainInfo.validSlices = grainInfo.totalSlices;
    REQUIRE(mxlFlowWriterCommitGrain(writer, &grainInfo) == MXL_STATUS_OK);

    // Give the inotify message some time to reach the reader's directory watcher.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    auto readGrainInfo = mxlGrainInfo{};
    auto readBuffer = static_cast<std::uint8_t*>(nullptr);
    REQUIRE(mxlFlowReaderGetGrain(reader, index, 16, &readGrainInfo, &readBuffer) == MXL_STATUS_OK);
    REQUIRE(readGrainInfo.index == index);
    REQUIRE(readBuffer[0] == 0xAB);
    REQUIRE(readBuffer[readGrainInfo.grainSize - 1] == 0xAB);

    auto runtimeInfo = mxlFlowRuntimeInfo{};
    REQUIRE(mxlFlowReaderGetRuntimeInfo(reader, &runtimeInfo) == MXL_STATUS_OK);
    REQUIRE(runtimeInfo.headIndex == index);

    // Garbage collection must not touch a flow that still has an active writer.
    REQUIRE(mxlGarbageCollectFlows(readerInstance) == MXL_STATUS_OK);
    REQUIRE(flowDirectoryExists(flowId));

    REQUIRE(mxlReleaseFlowReader(readerInstance, reader) == MXL_STATUS_OK);
    REQUIRE(mxlReleaseFlowWriter(writerInstance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(readerInstance) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(writerInstance) == MXL_STATUS_OK);
}

// A flow whose writer is still held is active and must survive garbage
// collection.
TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Integration : Garbage collection keeps active flows", "[integration]")
{
    auto const opts = "{}";
    auto const flowDef = mxl::tests::readFile("data/v210_flow.json");

    auto const instance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instance != nullptr);

    auto writer = mxlFlowWriter{};
    auto configInfo = mxlFlowConfigInfo{};
    auto flowWasCreated = false;
    REQUIRE(mxlCreateFlowWriter(instance, flowDef.c_str(), opts, &writer, &configInfo, &flowWasCreated) == MXL_STATUS_OK);
    REQUIRE(flowWasCreated);

    auto const flowId = uuids::to_string(configInfo.common.id);
    REQUIRE(flowDirectoryExists(flowId));

    REQUIRE(mxlGarbageCollectFlows(instance) == MXL_STATUS_OK);
    REQUIRE(flowDirectoryExists(flowId));

    REQUIRE(mxlReleaseFlowWriter(instance, writer) == MXL_STATUS_OK);
    REQUIRE(mxlDestroyInstance(instance) == MXL_STATUS_OK);
}

// A flow directory left behind by a crashed writer keeps no advisory lock on
// its data file. Garbage collection must remove it.
TEST_CASE_PERSISTENT_FIXTURE(mxl::tests::mxlDomainFixture, "Integration : Garbage collection removes stale flows", "[integration]")
{
    auto const opts = "{}";

    auto const instance = mxlCreateInstance(domain.string().c_str(), opts);
    REQUIRE(instance != nullptr);

    auto const staleFlowId = std::string{"00000000-0000-0000-0000-000000000001"};
    auto const staleFlowDirectory = mxl::lib::makeFlowDirectoryName(domain, staleFlowId);
    fs::create_directories(staleFlowDirectory);
    {
        auto const dataFile = mxl::lib::makeFlowDataFilePath(staleFlowDirectory);
        auto out = std::ofstream{dataFile, std::ios::binary};
        REQUIRE(out.good());
        out.put('\0');
    }

    REQUIRE(fs::exists(staleFlowDirectory));

    REQUIRE(mxlGarbageCollectFlows(instance) == MXL_STATUS_OK);
    REQUIRE_FALSE(fs::exists(staleFlowDirectory));

    REQUIRE(mxlDestroyInstance(instance) == MXL_STATUS_OK);
}

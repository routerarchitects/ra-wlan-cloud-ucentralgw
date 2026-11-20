#pragma once

#include "framework/MemoryDiagnostics.h"
#include "Poco/JSON/Object.h"
#include "Poco/Process.h"
#include <fstream>
#include <sstream>
#include <string>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace OpenWifi::MemoryDiagnostics {

inline std::uint64_t Read(const Counter &counter) noexcept {
    return counter.load(std::memory_order_relaxed);
}

inline Poco::JSON::Object QueueJson(const QueueCounters &q, const char *byteBasis) {
    Poco::JSON::Object result;
    result.set("constructedTotal", Read(q.constructed));
    result.set("processingStartedTotal", Read(q.started));
    result.set("destroyedTotal", Read(q.destroyed));
    result.set("retainedNotifications", Read(q.retained));
    result.set("awaitingProcessing", Read(q.awaitingProcessing));
    result.set("retainedAfterProcessingStarted", Read(q.retainedAfterStart));
    result.set("retainedAccountedBytes", Read(q.retainedBytes));
    result.set("peakRetainedAccountedBytes", Read(q.peakRetainedBytes));
    result.set("constructedAccountedBytesTotal", Read(q.constructedBytes));
    result.set("byteBasis", std::string(byteBasis));
    return result;
}

inline Poco::JSON::Object OperationJson(const OperationCounters &op) {
    Poco::JSON::Object result;
    result.set("callsTotal", Read(op.calls));
    result.set("completedTotal", Read(op.completed));
    result.set("totalNs", Read(op.totalNs));
    result.set("maximumNs", Read(op.maximumNs));
    const auto started = Read(op.activeSinceNs);
    result.set("activeSinceMonotonicNs", started);
    const auto now = NowNs();
    result.set("activeElapsedNs", started != 0 && now >= started ? now - started : 0);
    return result;
}

inline Poco::JSON::Object Snapshot() {
    Poco::JSON::Object result, queues, kafka, connections, events;
    result.set("schemaVersion", 1);
    result.set("pid", static_cast<std::uint64_t>(Poco::Process::id()));
    result.set("sampleMonotonicNs", NowNs());
    result.set("snapshotIsAtomic", false);
    queues.set("kafka", QueueJson(Kafka, "key + payload string sizes; excludes capacity/overhead"));
    queues.set("telemetry", QueueJson(Telemetry, "data string size; excludes capacity/overhead"));
    queues.set("commandResults", QueueJson(CommandResults, "pointer + serial envelope only; excludes JSON tree/overhead"));
    queues.set("radius", QueueJson(Radius, "embedded RadiusPacket + string sizes; excludes dynamic attributes/overhead"));
    queues.set("venue", QueueJson(Venue, "source serial string + JSON pointer + timestamp; excludes JSON tree/overhead"));
    result.set("queues", queues);
    Poco::JSON::Object logging;
    const auto logIn = Read(Logging.ingressed), logOut = Read(Logging.completed);
    const auto logBytesIn = Read(Logging.ingressedBytes), logBytesOut = Read(Logging.completedBytes);
    logging.set("ingressedTotal", logIn);
    logging.set("completedTotal", logOut);
    logging.set("ingressRejectedTotal", Read(Logging.ingressRejected));
    logging.set("queueFullDroppedTotal", Read(Logging.queueFullDropped));
    logging.set("queueLimitMessages", MaxPendingLogMessages);
    logging.set("pendingAdmissionSlots", Read(Logging.pendingSlots));
    logging.set("sinkFailedTotal", Read(Logging.sinkFailed));
    const auto terminal = logOut + Read(Logging.ingressRejected);
    const auto terminalBytes = logBytesOut + Read(Logging.ingressRejectedBytes);
    logging.set("queuedOrInFlightApprox", logIn >= terminal ? logIn - terminal : 0);
    logging.set("queuedOrInFlightAccountedBytesApprox", logBytesIn >= terminalBytes ? logBytesIn - terminalBytes : 0);
    logging.set("byteBasis", "message source + original message text; excludes formatting/capacity/overhead");
    logging.set("depthIsExact", false);
    result.set("logging", logging);
    kafka.set("produce", OperationJson(KafkaProduce));
    kafka.set("flush", OperationJson(KafkaFlush));
    kafka.set("acceptedByLibrdkafkaTotal", Read(KafkaAccepted));
    kafka.set("produceExceptionsTotal", Read(KafkaProduceExceptions));
    kafka.set("flushExceptionsTotal", Read(KafkaFlushExceptions));
    kafka.set("deliveryReportsInstrumented", false);
    kafka.set("consumerCallbacksTotal", Read(KafkaConsumed));
    Poco::JSON::Object topics;
    for (std::size_t i = 0; i < KafkaTopicNames.size(); ++i) {
        Poco::JSON::Object topic;
        topic.set("admittedTotal", Read(KafkaTopicAdmissions[i]));
        topic.set("admittedAccountedBytesTotal", Read(KafkaTopicAdmittedBytes[i]));
        topics.set(KafkaTopicNames[i], topic);
    }
    kafka.set("applicationAdmissionsByTopic", topics);
    kafka.set("nativeOutqSample", KafkaNativeOutq.load(std::memory_order_relaxed));
    kafka.set("nativeOutqSampleMonotonicNs", Read(KafkaNativeSampleNs));
    result.set("kafka", kafka);
    connections.set("constructedTotal", Read(ConnectionsConstructed));
    connections.set("destructorEnteredTotal", Read(DestructorsEntered));
    connections.set("destructorBodyFinishedTotal", Read(DestructorBodiesFinished));
    connections.set("disconnectStartedTotal", Read(DisconnectsStarted));
    connections.set("cleanupEnqueuedTotal", Read(CleanupEnqueued));
    connections.set("cleanupDequeuedTotal", Read(CleanupDequeued));
    connections.set("cleanupCompletedTotal", Read(CleanupCompleted));
    const auto created = Read(ConnectionsConstructed);
    const auto destructEntered = Read(DestructorsEntered);
    connections.set("activeBeforeDestructorApprox", created >= destructEntered ? created - destructEntered : 0);
    const auto cleanupIn = Read(CleanupEnqueued), cleanupOut = Read(CleanupDequeued);
    const auto cleanupDone = Read(CleanupCompleted);
    connections.set("cleanupAwaitingWorkerApprox", cleanupIn >= cleanupOut ? cleanupIn - cleanupOut : 0);
    connections.set("cleanupPendingOrInProgressApprox", cleanupIn >= cleanupDone ? cleanupIn - cleanupDone : 0);
    result.set("connections", connections);
    events.set("connectTotal", Read(ConnectEvents));
    events.set("pingTotal", Read(PingEvents));
    events.set("stateTotal", Read(StateEvents));
    events.set("healthcheckTotal", Read(HealthcheckEvents));
    events.set("telemetryTotal", Read(TelemetryEvents));
    events.set("rpcResultTotal", Read(RpcResults));
    result.set("events", events);
#if defined(__linux__)
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        std::istringstream input(line);
        std::string key;
        std::uint64_t kib;
        if (input >> key >> kib) {
            if (key == "RssAnon:") result.set("rssAnonBytes", kib * 1024);
            if (key == "VmRSS:") result.set("rssBytes", kib * 1024);
            if (key == "VmData:") result.set("vmDataBytes", kib * 1024);
            if (key == "RssFile:") result.set("rssFileBytes", kib * 1024);
        }
    }
#endif
#if defined(__GLIBC__)
#if __GLIBC_PREREQ(2, 33)
    const auto heap = mallinfo2();
    Poco::JSON::Object allocator;
    allocator.set("arenaUsedBytes", static_cast<std::uint64_t>(heap.uordblks));
    allocator.set("arenaFreeBytes", static_cast<std::uint64_t>(heap.fordblks));
    allocator.set("mmapBytes", static_cast<std::uint64_t>(heap.hblkhd));
    allocator.set("estimatedAllocatedViaGlibcBytes",
                  static_cast<std::uint64_t>(heap.uordblks) + static_cast<std::uint64_t>(heap.hblkhd));
    allocator.set("exactLiveHeapBytes", false);
    result.set("glibcMallinfo2", allocator);
#endif
#endif
    return result;
}

} // namespace OpenWifi::MemoryDiagnostics

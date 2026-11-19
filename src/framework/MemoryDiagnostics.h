// Aggregate, observation-only counters for the OWGW memory investigation.
// No payload copies, background threads, logging, or delivery-policy changes.
#pragma once

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>

namespace OpenWifi::MemoryDiagnostics {

using Counter = std::atomic<std::uint64_t>;

inline std::uint64_t NowNs() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

inline void UpdatePeak(Counter &peak, std::uint64_t value) noexcept {
    auto previous = peak.load(std::memory_order_relaxed);
    while (previous < value && !peak.compare_exchange_weak(
               previous, value, std::memory_order_relaxed)) {}
}

struct QueueCounters {
    Counter constructed{0}, started{0}, destroyed{0};
    Counter retained{0}, retainedBytes{0}, peakRetainedBytes{0};
    Counter awaitingProcessing{0}, retainedAfterStart{0};
    Counter constructedBytes{0};
};

// Counts notification ownership, including the consumer's current AutoPtr.
// A worker can retain its last processed notification while waiting for another.
// Byte counts describe the supplied byte basis, not the complete heap allocation.
class NotificationLifetime {
public:
    NotificationLifetime(QueueCounters &counters, std::uint64_t bytes) noexcept
        : counters_(counters), bytes_(bytes) {
        counters_.constructed.fetch_add(1, std::memory_order_relaxed);
        counters_.constructedBytes.fetch_add(bytes_, std::memory_order_relaxed);
        counters_.retained.fetch_add(1, std::memory_order_relaxed);
        counters_.awaitingProcessing.fetch_add(1, std::memory_order_relaxed);
        const auto current = counters_.retainedBytes.fetch_add(bytes_, std::memory_order_relaxed) + bytes_;
        UpdatePeak(counters_.peakRetainedBytes, current);
    }

    ~NotificationLifetime() {
        if (started_) counters_.retainedAfterStart.fetch_sub(1, std::memory_order_relaxed);
        else counters_.awaitingProcessing.fetch_sub(1, std::memory_order_relaxed);
        counters_.retainedBytes.fetch_sub(bytes_, std::memory_order_relaxed);
        counters_.retained.fetch_sub(1, std::memory_order_relaxed);
        counters_.destroyed.fetch_add(1, std::memory_order_relaxed);
    }

    void Started() noexcept {
        if (!started_) {
            started_ = true;
            counters_.awaitingProcessing.fetch_sub(1, std::memory_order_relaxed);
            counters_.retainedAfterStart.fetch_add(1, std::memory_order_relaxed);
            counters_.started.fetch_add(1, std::memory_order_relaxed);
        }
    }

    NotificationLifetime(const NotificationLifetime &) = delete;
    NotificationLifetime &operator=(const NotificationLifetime &) = delete;

private:
    QueueCounters &counters_;
    std::uint64_t bytes_;
    bool started_ = false; // Accessed only by this notification's owner.
};

struct OperationCounters {
    Counter calls{0}, completed{0}, totalNs{0}, maximumNs{0}, activeSinceNs{0};
};

// Use one instance of OperationCounters per serial worker operation.
class OperationScope {
public:
    explicit OperationScope(OperationCounters &counters) noexcept
        : counters_(counters), start_(NowNs()) {
        counters_.calls.fetch_add(1, std::memory_order_relaxed);
        counters_.activeSinceNs.store(start_, std::memory_order_relaxed);
    }
    ~OperationScope() {
        const auto elapsed = NowNs() - start_;
        counters_.totalNs.fetch_add(elapsed, std::memory_order_relaxed);
        UpdatePeak(counters_.maximumNs, elapsed);
        counters_.completed.fetch_add(1, std::memory_order_relaxed);
        counters_.activeSinceNs.store(0, std::memory_order_relaxed);
    }
    OperationScope(const OperationScope &) = delete;
    OperationScope &operator=(const OperationScope &) = delete;
private:
    OperationCounters &counters_;
    std::uint64_t start_;
};

inline QueueCounters Kafka, Telemetry, CommandResults, Radius, Venue;
// Observed logging ingresses and completed downstream deliveries. In-flight
// includes the actual async queue plus the currently executing sink; an async
// channel replaced or closed while holding messages can leave a residual.
struct LogCounters {
    Counter ingressed{0}, completed{0}, ingressRejected{0}, sinkFailed{0};
    Counter ingressedBytes{0}, completedBytes{0}, ingressRejectedBytes{0};
};
inline LogCounters Logging;
inline OperationCounters KafkaProduce, KafkaFlush;
inline Counter KafkaAccepted{0}, KafkaProduceExceptions{0}, KafkaFlushExceptions{0};
inline Counter KafkaConsumed{0};
inline constexpr std::array<const char *, 6> KafkaTopicNames{
    "state", "healthcheck", "connection", "device_telemetry", "service_events", "other"};
inline std::array<Counter, KafkaTopicNames.size()> KafkaTopicAdmissions{};
inline std::array<Counter, KafkaTopicNames.size()> KafkaTopicAdmittedBytes{};
inline void RecordKafkaAdmission(const char *topic, std::uint64_t bytes) noexcept {
    const std::string_view name = topic ? topic : "";
    auto index = KafkaTopicNames.size() - 1;
    for (std::size_t i = 0; i < index; ++i) {
        if (name == KafkaTopicNames[i]) { index = i; break; }
    }
    KafkaTopicAdmissions[index].fetch_add(1, std::memory_order_relaxed);
    KafkaTopicAdmittedBytes[index].fetch_add(bytes, std::memory_order_relaxed);
}
inline std::atomic<int> KafkaNativeOutq{-1};
inline Counter KafkaNativeSampleNs{0};
inline Counter ConnectionsConstructed{0}, DestructorsEntered{0}, DestructorBodiesFinished{0};
inline Counter DisconnectsStarted{0}, CleanupEnqueued{0}, CleanupDequeued{0}, CleanupCompleted{0};
inline Counter ConnectEvents{0}, PingEvents{0}, StateEvents{0}, HealthcheckEvents{0};
inline Counter TelemetryEvents{0}, RpcResults{0};

} // namespace OpenWifi::MemoryDiagnostics

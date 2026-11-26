#pragma once

#include <atomic>
#include <array>
#include <chrono>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstddef>
#include <system_error>
#include <string_view>
#include <algorithm>

namespace OpenWifi::BoundedLogging {

using Counter = std::atomic<std::uint64_t>;

inline std::uint64_t NowNs() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

inline constexpr std::uint64_t DefaultPendingLogMessages = 10000;
inline constexpr std::uint64_t MaximumPendingLogMessages = 1000000;

// Strict decimal parsing: no zero (unbounded/disabled), signs, whitespace,
// trailing characters, overflow, or values above the safety ceiling.
inline bool ParseLoggingQueueLimit(std::string_view text, std::uint64_t &limit) noexcept {
    if (text.empty()) return false;
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()
        || parsed == 0 || parsed > MaximumPendingLogMessages) return false;
    limit = parsed;
    return true;
}

// Read the process environment once, before installing the async channel.
// All producers and the diagnostics snapshot use the same immutable limit.
inline std::uint64_t LoggingQueueLimit() noexcept {
    static const std::uint64_t limit = []() noexcept {
        const char *value = std::getenv("LOGGING_QUEUE_LIMIT");
        if (!value || !*value) return DefaultPendingLogMessages;
        std::uint64_t parsed = 0;
        if (ParseLoggingQueueLimit(value, parsed)) return parsed;
        // Do not log through the channel being initialized.
        std::fputs("OWGW: invalid LOGGING_QUEUE_LIMIT (expected 1..1000000); using 10000\n", stderr);
        return DefaultPendingLogMessages;
    }();
    return limit;
}
// All budgets are process-wide and immutable after first use. Byte accounting
// covers source + original text, not allocator overhead or sink formatting.
inline std::uint64_t ReadLoggingBudget(const char *name, std::uint64_t fallback,
                                      std::uint64_t maximum) noexcept {
    const char *value = std::getenv(name);
    if (!value || !*value) return fallback;
    const std::string_view text(value);
    std::uint64_t parsed = 0;
    const auto r = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (r.ec == std::errc{} && r.ptr == text.data() + text.size()
        && parsed != 0 && parsed <= maximum) return parsed;
    std::fprintf(stderr, "OWGW: invalid %s; using %llu\n", name,
                 static_cast<unsigned long long>(fallback));
    return fallback;
}
inline std::uint64_t LoggingQueueBytesLimit() noexcept {
    static const auto limit = ReadLoggingBudget("LOGGING_QUEUE_BYTES_LIMIT", 64ULL * 1024 * 1024,
                                                512ULL * 1024 * 1024);
    return limit;
}
inline std::uint64_t LoggingMessageBytesLimit() noexcept {
    static const auto limit = std::min(LoggingQueueBytesLimit(),
        ReadLoggingBudget("LOGGING_MESSAGE_BYTES_LIMIT", 16384, 1024 * 1024));
    return limit;
}
inline std::uint64_t LoggingVerboseRateLimit() noexcept {
    static const auto limit = ReadLoggingBudget("LOGGING_VERBOSE_RATE_LIMIT", 20000, 1000000);
    return limit;
}

enum class LogSeverity : std::size_t {
    fatal, critical, error, warning, notice, information, debug, trace, other
};
inline bool IsVerbose(LogSeverity severity) noexcept {
    return severity == LogSeverity::debug || severity == LogSeverity::trace;
}
inline std::uint64_t SeverityBudget(std::uint64_t limit, LogSeverity severity) noexcept {
    if (limit <= 1 || severity <= LogSeverity::warning) return limit;
    // Reserve roughly 20% for normal/higher priority and 10% for warning+.
    const auto reserve = IsVerbose(severity) ? limit / 5 : limit / 10;
    return limit - std::max<std::uint64_t>(1, reserve);
}
inline bool ReserveLogBudget(Counter &counter, std::uint64_t amount, std::uint64_t limit) noexcept {
    auto current = counter.load(std::memory_order_relaxed);
    while (current <= limit && amount <= limit - current) {
        if (counter.compare_exchange_weak(current, current + amount,
                std::memory_order_acq_rel, std::memory_order_relaxed)) return true;
    }
    return false;
}
// Fixed one-second windows, packed epoch/count in one atomic. Delayed
// producers never reset a newer window. No per-device storage or locks.
inline bool AdmitVerboseLog(Counter &window, std::uint64_t second, std::uint64_t limit) noexcept {
    constexpr std::uint64_t mask = 0xffffffffULL;
    auto previous = window.load(std::memory_order_relaxed);
    while (true) {
        const auto epoch = previous >> 32;
        const auto currentEpoch = std::max(epoch, second & mask);
        const auto count = currentEpoch == epoch ? previous & mask : 0;
        if (count >= limit) return false;
        const auto next = (currentEpoch << 32) | (count + 1);
        if (window.compare_exchange_weak(previous, next, std::memory_order_relaxed,
                                         std::memory_order_relaxed)) return true;
    }
}
struct AdmissionState {
    Counter pendingSlots{0}, pendingBytes{0}, verboseWindow{0};
};
inline AdmissionState Logging;

// Lightweight production telemetry. No per-device keys or retained log payloads.
inline constexpr std::array<const char *, 9> SeverityNames{
    "fatal", "critical", "error", "warning", "notice", "information", "debug", "trace", "other"};
struct LoggingMetrics {
    std::atomic_bool enabled{false};
    Counter ingressed{0}, completed{0}, rejected{0}, sinkFailed{0};
    Counter countLimited{0}, byteLimited{0}, oversized{0}, rateLimited{0};
    Counter enqueueFailed{0}, closedRejected{0}, peakPendingBytes{0};
    Counter criticalFallbackAttempted{0}, criticalFallbackSuppressed{0}, fallbackWindow{0};
    std::array<Counter, SeverityNames.size()> droppedBySeverity{};
};
inline LoggingMetrics Metrics;

inline void UpdatePendingBytesPeak() noexcept {
    const auto pending = Logging.pendingBytes.load(std::memory_order_relaxed);
    auto peak = Metrics.peakPendingBytes.load(std::memory_order_relaxed);
    while (pending > peak && !Metrics.peakPendingBytes.compare_exchange_weak(
            peak, pending, std::memory_order_relaxed, std::memory_order_relaxed)) {}
}

} // namespace OpenWifi::BoundedLogging

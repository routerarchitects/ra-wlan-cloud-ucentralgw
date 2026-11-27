// Bounded asynchronous log admission for OWGW memory safety.
#pragma once
#include "framework/BoundedLoggingPolicy.h"
#include "Poco/AsyncChannel.h"
#include "Poco/AutoPtr.h"
#include "Poco/Channel.h"
#include "Poco/Message.h"
#include <cstdint>
#include <mutex>
#include <shared_mutex>

namespace OpenWifi::BoundedLogging {

class BoundedLoggingChannel final : public Poco::Channel {
public:
    BoundedLoggingChannel(Poco::Channel *next, bool ingress)
        : next_(next, true), ingress_(ingress), queueLimit_(LoggingQueueLimit()),
          byteLimit_(LoggingQueueBytesLimit()), messageLimit_(LoggingMessageBytesLimit()),
          verboseRate_(LoggingVerboseRateLimit()) {}

    void open() override { next_->open(); }
    void close() override {
        if (ingress_) {
            // Poco silently ignores log() after close. Fence admission before
            // closing it, without holding this lock while the worker drains.
            std::unique_lock lock(lifecycleMutex_);
            if (closed_) return;
            closed_ = true;
        }
        next_->close();
    }

    void log(const Poco::Message &message) override {
        const auto bytes = static_cast<std::uint64_t>(message.getSource().size()
                                                      + message.getText().size());
        const auto severity = Severity(message.getPriority());
        if (ingress_) {
            Metrics.ingressed.fetch_add(1, std::memory_order_relaxed);
            std::shared_lock lock(lifecycleMutex_);
            if (closed_) {
                Reject(message, severity, Metrics.closedRejected);
                return;
            }
            if (bytes > messageLimit_) {
                Reject(message, severity, Metrics.oversized);
                return;
            }
            if (IsVerbose(severity) && !AdmitVerboseLog(Logging.verboseWindow,
                    NowNs() / 1000000000ULL, verboseRate_)) {
                Reject(message, severity, Metrics.rateLimited);
                return;
            }
            // Reserve slots and accounted bytes before the async channel copies
            // the message. Release the slot if byte admission fails.
            if (!ReserveLogBudget(Logging.pendingSlots, 1, SeverityBudget(queueLimit_, severity))) {
                Reject(message, severity, Metrics.countLimited);
                return;
            }
            if (!ReserveLogBudget(Logging.pendingBytes, bytes, SeverityBudget(byteLimit_, severity))) {
                Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
                Reject(message, severity, Metrics.byteLimited);
                return;
            }
            UpdatePendingBytesPeak();

            try {
                next_->log(message);
            } catch (...) {
                Release(bytes);
                Reject(message, severity, Metrics.enqueueFailed);
                // Logging failure must not interrupt device/session processing.
            }
        } else {
            try {
                next_->log(message);
            } catch (...) {
                // An escaping sink exception would terminate Poco's async
                // worker, leaving admitted messages permanently queued.
                Metrics.sinkFailed.fetch_add(1, std::memory_order_relaxed);
                CriticalFallback(message, severity);
            }
            Metrics.completed.fetch_add(1, std::memory_order_relaxed);
            Release(bytes);
        }
    }

private:
    static void Release(std::uint64_t bytes) noexcept {
        Logging.pendingBytes.fetch_sub(bytes, std::memory_order_acq_rel);
        Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
    }
    static void CriticalFallback(const Poco::Message &message, LogSeverity severity) noexcept {
        if (severity > LogSeverity::error) return;
        // Best effort, bounded output outside the logging channel: avoid
        // recursion, allocations, and an unbounded emergency queue.
        if (!AdmitVerboseLog(Metrics.fallbackWindow, NowNs() / 1000000000ULL, 1)) {
            Metrics.criticalFallbackSuppressed.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        Metrics.criticalFallbackAttempted.fetch_add(1, std::memory_order_relaxed);
        const auto &source = message.getSource();
        const auto &body = message.getText();
        std::fprintf(stderr, "OWGW logging fallback [%s] %.*s: %.*s\n",
            SeverityNames[static_cast<std::size_t>(severity)],
            static_cast<int>(std::min<std::size_t>(source.size(), 96)), source.c_str(),
            static_cast<int>(std::min<std::size_t>(body.size(), 512)), body.c_str());
    }
    static void Reject(const Poco::Message &message, LogSeverity severity, Counter &reason) noexcept {
        reason.fetch_add(1, std::memory_order_relaxed);
        Metrics.rejected.fetch_add(1, std::memory_order_relaxed);
        Metrics.droppedBySeverity[static_cast<std::size_t>(severity)].fetch_add(
            1, std::memory_order_relaxed);
        CriticalFallback(message, severity);
    }
    static LogSeverity Severity(Poco::Message::Priority p) noexcept {
        switch (p) {
            case Poco::Message::PRIO_FATAL: return LogSeverity::fatal;
            case Poco::Message::PRIO_CRITICAL: return LogSeverity::critical;
            case Poco::Message::PRIO_ERROR: return LogSeverity::error;
            case Poco::Message::PRIO_WARNING: return LogSeverity::warning;
            case Poco::Message::PRIO_NOTICE: return LogSeverity::notice;
            case Poco::Message::PRIO_INFORMATION: return LogSeverity::information;
            case Poco::Message::PRIO_DEBUG: return LogSeverity::debug;
            case Poco::Message::PRIO_TRACE: return LogSeverity::trace;
            default: return LogSeverity::other;
        }
    }
    Poco::AutoPtr<Poco::Channel> next_;
    bool ingress_;
    const std::uint64_t queueLimit_, byteLimit_, messageLimit_, verboseRate_;
    std::shared_mutex lifecycleMutex_;
    bool closed_ = false; // guarded by lifecycleMutex_ on the ingress channel
};

template <typename T>
inline Poco::AutoPtr<Poco::Channel> MakeLoggingAsyncChannel(Poco::AutoPtr<T> sink) {
    Poco::AutoPtr<Poco::Channel> observedSink(new BoundedLoggingChannel(sink.get(), false));
    Poco::AutoPtr<Poco::Channel> async(new Poco::AsyncChannel(observedSink));
    Poco::AutoPtr<Poco::Channel> ingress(new BoundedLoggingChannel(async.get(), true));
    Metrics.enabled.store(true, std::memory_order_relaxed);
    return ingress;
}

} // namespace OpenWifi::BoundedLogging

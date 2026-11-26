// Bounded asynchronous log admission for OWGW memory safety.
#pragma once
#include "framework/BoundedLoggingPolicy.h"
#include "Poco/AsyncChannel.h"
#include "Poco/AutoPtr.h"
#include "Poco/Channel.h"
#include "Poco/Message.h"
#include <cstdint>

namespace OpenWifi::BoundedLogging {

class BoundedLoggingChannel final : public Poco::Channel {
public:
    BoundedLoggingChannel(Poco::Channel *next, bool ingress)
        : next_(next, true), ingress_(ingress), queueLimit_(LoggingQueueLimit()),
          byteLimit_(LoggingQueueBytesLimit()), messageLimit_(LoggingMessageBytesLimit()),
          verboseRate_(LoggingVerboseRateLimit()) {}

    void open() override { next_->open(); }
    void close() override { next_->close(); }

    void log(const Poco::Message &message) override {
        const auto bytes = static_cast<std::uint64_t>(message.getSource().size()
                                                      + message.getText().size());
        if (ingress_) {

            const auto severity = Severity(message.getPriority());
            if (bytes > messageLimit_) {
                return;
            }
            if (IsVerbose(severity) && !AdmitVerboseLog(Logging.verboseWindow,
                    NowNs() / 1000000000ULL, verboseRate_)) {
                return;
            }
            // Reserve slots and accounted bytes before the async channel
            // copies the message. Release the slot if byte admission fails.
            if (!ReserveLogBudget(Logging.pendingSlots, 1, SeverityBudget(queueLimit_, severity))) {
                return;
            }
            if (!ReserveLogBudget(Logging.pendingBytes, bytes, SeverityBudget(byteLimit_, severity))) {
                Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
                return;
            }

            try {
                next_->log(message);
            } catch (...) {
                // The async channel did not accept this message. Release the
                // reserved slot and retain the original exception semantics.
                Logging.pendingBytes.fetch_sub(bytes, std::memory_order_acq_rel);
                Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
                throw;
            }
        } else {
            try {
                next_->log(message);
            } catch (...) {
                Logging.pendingBytes.fetch_sub(bytes, std::memory_order_acq_rel);
                Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
                throw;
            }
            Logging.pendingBytes.fetch_sub(bytes, std::memory_order_acq_rel);
            Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
        }
    }

private:
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
};

template <typename T>
inline Poco::AutoPtr<Poco::Channel> MakeLoggingAsyncChannel(Poco::AutoPtr<T> sink) {
    Poco::AutoPtr<Poco::Channel> observedSink(new BoundedLoggingChannel(sink.get(), false));
    Poco::AutoPtr<Poco::Channel> async(new Poco::AsyncChannel(observedSink));
    return Poco::AutoPtr<Poco::Channel>(new BoundedLoggingChannel(async.get(), true));
}

} // namespace OpenWifi::BoundedLogging

// Bounded asynchronous log admission and accounting for OWGW memory safety.
#pragma once
#include "framework/MemoryDiagnostics.h"
#include "Poco/AsyncChannel.h"
#include "Poco/AutoPtr.h"
#include "Poco/Channel.h"
#include "Poco/Message.h"
#include <cstdint>

namespace OpenWifi::MemoryDiagnostics {

class LoggingProbeChannel final : public Poco::Channel {
public:
    LoggingProbeChannel(Poco::Channel *next, bool ingress)
        : next_(next, true), ingress_(ingress) {}

    void open() override { next_->open(); }
    void close() override { next_->close(); }

    void log(const Poco::Message &message) override {
        const auto bytes = static_cast<std::uint64_t>(message.getSource().size()
                                                      + message.getText().size());
        if (ingress_) {
            Logging.ingressed.fetch_add(1, std::memory_order_relaxed);
            Logging.ingressedBytes.fetch_add(bytes, std::memory_order_relaxed);

            // Reserve a slot before the Poco AsyncChannel allocates a queued
            // notification. The CAS keeps admission bounded across threads.
            auto pending = Logging.pendingSlots.load(std::memory_order_relaxed);
            while (true) {
                if (pending >= MaxPendingLogMessages) {
                    Logging.queueFullDropped.fetch_add(1, std::memory_order_relaxed);
                    Logging.ingressRejected.fetch_add(1, std::memory_order_relaxed);
                    Logging.ingressRejectedBytes.fetch_add(bytes, std::memory_order_relaxed);
                    return;
                }
                if (Logging.pendingSlots.compare_exchange_weak(
                        pending, pending + 1, std::memory_order_acq_rel,
                        std::memory_order_relaxed)) {
                    break;
                }
            }

            try {
                next_->log(message);
            } catch (...) {
                // The async channel did not accept this message. Release the
                // reserved slot and retain the original exception semantics.
                Logging.ingressRejected.fetch_add(1, std::memory_order_relaxed);
                Logging.ingressRejectedBytes.fetch_add(bytes, std::memory_order_relaxed);
                Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
                throw;
            }
        } else {
            try {
                next_->log(message);
            } catch (...) {
                Logging.sinkFailed.fetch_add(1, std::memory_order_relaxed);
                Logging.completed.fetch_add(1, std::memory_order_relaxed);
                Logging.completedBytes.fetch_add(bytes, std::memory_order_relaxed);
                Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
                throw;
            }
            Logging.completed.fetch_add(1, std::memory_order_relaxed);
            Logging.completedBytes.fetch_add(bytes, std::memory_order_relaxed);
            Logging.pendingSlots.fetch_sub(1, std::memory_order_acq_rel);
        }
    }

private:
    Poco::AutoPtr<Poco::Channel> next_;
    bool ingress_;
};

template <typename T>
inline Poco::AutoPtr<Poco::Channel> MakeLoggingAsyncChannel(Poco::AutoPtr<T> sink) {
    Poco::AutoPtr<Poco::Channel> observedSink(new LoggingProbeChannel(sink.get(), false));
    Poco::AutoPtr<Poco::Channel> async(new Poco::AsyncChannel(observedSink));
    return Poco::AutoPtr<Poco::Channel>(new LoggingProbeChannel(async.get(), true));
}

} // namespace OpenWifi::MemoryDiagnostics

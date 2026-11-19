// Observation-only accounting for Poco AsyncChannel. No queue caps or log drops.
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
            try {
                next_->log(message);
            } catch (...) {
                // Submission failed; do not treat it as permanently queued.
                Logging.ingressRejected.fetch_add(1, std::memory_order_relaxed);
                Logging.ingressRejectedBytes.fetch_add(bytes, std::memory_order_relaxed);
                throw;
            }
        } else {
            try {
                next_->log(message);
            } catch (...) {
                Logging.sinkFailed.fetch_add(1, std::memory_order_relaxed);
                Logging.completed.fetch_add(1, std::memory_order_relaxed);
                Logging.completedBytes.fetch_add(bytes, std::memory_order_relaxed);
                throw;
            }
            Logging.completed.fetch_add(1, std::memory_order_relaxed);
            Logging.completedBytes.fetch_add(bytes, std::memory_order_relaxed);
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

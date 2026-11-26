// AP WebSocket fragmented-message validation, independent of Poco and other services.
#pragma once

#include <cstddef>

namespace OpenWifi {

class AP_WS_FramePolicy {
public:
    static constexpr std::size_t MaxMessageBytes = 512000;

    enum class Decision { accept, invalidSequence, tooLarge };

    // Control frames do not enter this method: a PING/PONG can interrupt an
    // in-progress fragmented text message without affecting its content.
    Decision AcceptData(bool continuation, bool finalFrame,
                        std::size_t accumulatedBytes, std::size_t incomingBytes) noexcept {
        if (continuation != awaitingContinuation_) return Decision::invalidSequence;
        if (accumulatedBytes > MaxMessageBytes ||
            incomingBytes > MaxMessageBytes - accumulatedBytes) return Decision::tooLarge;
        awaitingContinuation_ = !finalFrame;
        return Decision::accept;
    }

private:
    bool awaitingContinuation_ = false;
};

} // namespace OpenWifi

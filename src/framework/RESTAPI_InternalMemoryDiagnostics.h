// Strictly internal, opt-in, read-only memory diagnostics route.
#pragma once
#include "framework/RESTAPI_Handler.h"
#include "framework/MemoryDiagnosticsJson.h"
#include "framework/MicroServiceFuncs.h"
#include "framework/utils.h"

namespace OpenWifi {
class RESTAPI_internal_memory_diagnostics final : public RESTAPIHandler {
public:
    RESTAPI_internal_memory_diagnostics(const RESTAPIHandler::BindingMap &bindings,
                                       Poco::Logger &logger,
                                       RESTAPI_GenericServerAccounting &server,
                                       std::uint64_t tid, bool internal)
        : RESTAPIHandler(bindings, logger,
                         std::vector<std::string>{Poco::Net::HTTPRequest::HTTP_GET,
                                                  Poco::Net::HTTPRequest::HTTP_OPTIONS},
                         server, tid, internal, true, true,
                         RateLimit{.Interval = 1000, .MaxCalls = 10}) {}

    static auto PathName() { return std::list<std::string>{"/api/v1/system"}; }

    void DoGet() final {
        // handleRequest() has already checked MicroServiceIsValidAPIKEY() for
        // the internal X-INTERNAL-NAME authentication path; a bearer token
        // alone is not sufficient to enter this branch.
        if (!Internal_ || !Request->has("X-INTERNAL-NAME")) {
            return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
        }
        if (!MicroServiceConfigGetBool("openwifi.memoryDiagnostics.enable", false)) {
            return NotFound();
        }
        std::string command, diagnostics;
        if (!HasParameter("command", command) || command != "resources" ||
            !HasParameter("diagnostics", diagnostics) || diagnostics != "memory") {
            return BadRequest(RESTAPI::Errors::InvalidCommand);
        }
        Poco::JSON::Object answer;
        answer.set("numberOfFileDescriptors", Utils::get_open_fds());
        std::uint64_t real, peakReal, virt, peakVirt;
        Utils::getMemory(real, peakReal, virt, peakVirt);
        answer.set("currRealMem", real);
        answer.set("peakRealMem", peakReal);
        answer.set("currVirtMem", virt);
        answer.set("peakVirtMem", peakVirt);
        answer.set("memoryDiagnostics", MemoryDiagnostics::Snapshot());
        answer.set("version", MicroServiceVersion());
        return ReturnObject(answer);
    }
    void DoPost() final { return BadRequest(RESTAPI::Errors::InvalidCommand); }
    void DoPut() final { return BadRequest(RESTAPI::Errors::InvalidCommand); }
    void DoDelete() final { return BadRequest(RESTAPI::Errors::InvalidCommand); }
};
} // namespace OpenWifi

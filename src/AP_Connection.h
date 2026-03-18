/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2022-02-03.
//

#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <Poco/Data/Session.h>
#include <Poco/JSON/Object.h>
#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>

#include "RESTObjects/RESTAPI_GWobjects.h"
#include "framework/utils.h"

namespace Poco {
	class Exception;
}

namespace OpenWifi {

	class LockedDbSession;

	class AP_Connection {
	  public:
		virtual ~AP_Connection() = default;

		virtual void Start() = 0;
		virtual void EndConnection() = 0;
		[[nodiscard]] virtual bool ValidatedDevice() = 0;
		virtual void ProcessIncomingFrame() = 0;
		[[nodiscard]] virtual bool Send(const std::string &Payload,std::chrono::milliseconds WaitTimeInMs = std::chrono::milliseconds{30000}) = 0;

		void ProcessJSONRPCEvent(Poco::JSON::Object::Ptr &Doc);
		void ProcessJSONRPCResult(Poco::JSON::Object::Ptr Doc);
		void ProcessIncomingRadiusData(const Poco::JSON::Object::Ptr &Doc);

		bool SendRadiusAuthenticationData(const unsigned char *buffer, std::size_t size);
		bool SendRadiusAccountingData(const unsigned char *buffer, std::size_t size);
		bool SendRadiusCoAData(const unsigned char *buffer, std::size_t size);

		bool SetWebSocketTelemetryReporting(uint64_t RPCID, uint64_t interval,
											uint64_t TelemetryWebSocketTimer,
											const std::vector<std::string> &TelemetryTypes);
		bool SetKafkaTelemetryReporting(uint64_t RPCID, uint64_t interval,
										uint64_t TelemetryKafkaTimer,
										const std::vector<std::string> &TelemetryTypes);
		bool StopWebSocketTelemetry(uint64_t RPCID);
		bool StopKafkaTelemetry(uint64_t RPCID);

		inline void GetLastStats(std::string &LastStats) {
			if (!Dead_) {
				std::lock_guard G(ConnectionMutex_);
				LastStats = RawLastStats_;
			}
		}

		inline void GetLastHealthCheck(GWObjects::HealthCheck &H) {
			if (!Dead_) {
				std::lock_guard G(ConnectionMutex_);
				H = RawLastHealthcheck_;
			}
		}

		inline void GetState(GWObjects::ConnectionState &State) {
			if (!Dead_) {
				std::lock_guard G(ConnectionMutex_);
				State = State_;
			}
		}

		inline GWObjects::DeviceRestrictions GetRestrictions() {
			std::lock_guard G(ConnectionMutex_);
			return Restrictions_;
		}

		[[nodiscard]] inline bool HasGPS() const { return hasGPS_; }
		[[nodiscard]] inline bool MustBeSecureRTTY() const { return RTTYMustBeSecure_; }

		inline bool GetTelemetryParameters(bool &Reporting, uint64_t &Interval,
										   uint64_t &WebSocketTimer, uint64_t &KafkaTimer,
										   uint64_t &WebSocketCount, uint64_t &KafkaCount,
										   uint64_t &WebSocketPackets,
										   uint64_t &KafkaPackets) const {
			Reporting = TelemetryReporting_;
			WebSocketTimer = TelemetryWebSocketTimer_;
			KafkaTimer = TelemetryKafkaTimer_;
			WebSocketCount = TelemetryWebSocketRefCount_;
			KafkaCount = TelemetryKafkaRefCount_;
			Interval = TelemetryInterval_;
			WebSocketPackets = TelemetryWebSocketPackets_;
			KafkaPackets = TelemetryKafkaPackets_;
			return true;
		}

		bool LookForUpgrade(Poco::Data::Session &Session, uint64_t UUID, uint64_t &UpgradedUUID);
		void LogException(const Poco::Exception &E);
		inline Poco::Logger &Logger() { return Logger_; }

		friend class AP_Server;
		friend class AP_WS_Server;
		friend class AP_KAFKA_Server;

	  protected:
		AP_Connection(Poco::Logger &L, std::shared_ptr<LockedDbSession> session,
					  uint64_t connection_id);

		bool StartTelemetry(uint64_t RPCID, const std::vector<std::string> &TelemetryTypes);
		bool StopTelemetry(uint64_t RPCID);
		void UpdateCounts();
		void DeviceDisconnectionCleanup(const std::string &SerialNumber, std::uint64_t uuid);
		void SetLastStats(const std::string &LastStats);
		std::string Base64Encode(const unsigned char *buffer, std::size_t size);
		std::string Base64Decode(const std::string &F);

		mutable std::recursive_mutex ConnectionMutex_;
		std::mutex TelemetryMutex_;
		Poco::Logger &Logger_;
		std::shared_ptr<LockedDbSession> DbSession_;
		std::string SerialNumber_;
		uint64_t SerialNumberInt_ = 0;
		std::string Compatible_;
		std::string CId_;
		std::string CN_;
		uint64_t Errors_ = 0;
		Poco::Net::IPAddress PeerAddress_;
		std::string Address_;
		volatile bool TelemetryReporting_ = false;
		std::atomic_uint64_t TelemetryWebSocketRefCount_ = 0;
		std::atomic_uint64_t TelemetryKafkaRefCount_ = 0;
		std::atomic_uint64_t TelemetryWebSocketTimer_ = 0;
		std::atomic_uint64_t TelemetryKafkaTimer_ = 0;
		std::atomic_uint64_t TelemetryInterval_ = 0;
		std::atomic_uint64_t TelemetryWebSocketPackets_ = 0;
		std::atomic_uint64_t TelemetryKafkaPackets_ = 0;
		GWObjects::ConnectionState State_;
		Utils::CompressedString RawLastStats_;
		GWObjects::HealthCheck RawLastHealthcheck_;
		std::chrono::time_point<std::chrono::high_resolution_clock> ConnectionStart_ =
			std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> ConnectionCompletionTime_{0.0};
		std::atomic<bool> Dead_ = false;
		std::atomic_bool DeviceValidated_ = false;
		OpenWifi::GWObjects::DeviceRestrictions Restrictions_;
		bool RTTYMustBeSecure_ = false;
		bool hasGPS_ = false;
		std::double_t memory_used_ = 0.0, cpu_load_ = 0.0, temperature_ = 0.0;
		std::uint64_t uuid_ = 0;
		uint64_t InfraGroupId_ = 0;
		bool Simulated_ = false;
		std::atomic_uint64_t LastContact_ = 0;

		static inline std::atomic_uint64_t ConcurrentStartingDevices_ = 0;

	  private:
		void Process_connect(Poco::JSON::Object::Ptr ParamsObj, const std::string &Serial);
		void Process_state(Poco::JSON::Object::Ptr ParamsObj);
		void Process_healthcheck(Poco::JSON::Object::Ptr ParamsObj);
		void Process_log(Poco::JSON::Object::Ptr ParamsObj);
		void Process_crashlog(Poco::JSON::Object::Ptr ParamsObj);
		void Process_ping(Poco::JSON::Object::Ptr ParamsObj);
		void Process_cfgpending(Poco::JSON::Object::Ptr ParamsObj);
		void Process_recovery(Poco::JSON::Object::Ptr ParamsObj);
		void Process_deviceupdate(Poco::JSON::Object::Ptr ParamsObj, std::string &Serial);
		void Process_telemetry(Poco::JSON::Object::Ptr ParamsObj);
		void Process_venuebroadcast(Poco::JSON::Object::Ptr ParamsObj);
		void Process_event(Poco::JSON::Object::Ptr ParamsObj);
		void Process_wifiscan(Poco::JSON::Object::Ptr ParamsObj);
		void Process_alarm(Poco::JSON::Object::Ptr ParamsObj);
		void Process_rebootLog(Poco::JSON::Object::Ptr ParamsObj);

		inline void SetLastHealthCheck(const GWObjects::HealthCheck &H) { RawLastHealthcheck_ = H; }
	};

} // namespace OpenWifi

/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2024-04-30.
//

#pragma once

#include <array>
#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "AP_Connection.h"
#include "RESTObjects/RESTAPI_GWobjects.h"
#include "framework/SubSystemServer.h"
#include "framework/utils.h"
#include "framework/MicroServiceFuncs.h"
#include "UI_GW_WebSocketNotifications.h"
#include "framework/KafkaManager.h"
#include "framework/KafkaTopics.h"

namespace OpenWifi {

	constexpr uint MACHashMax = 256;
	constexpr uint MACHashMask = MACHashMax - 1;
	class MACHash {
	  public:
		[[nodiscard]] static inline uint16_t Hash(std::uint64_t value) {
			uint8_t hash = 0, i = 6;
			while (i) {
				hash ^= (value & MACHashMask) + 1;
				value >>= 8;
				--i;
			}
			return hash;
		}

		[[nodiscard]] static inline uint16_t Hash(const std::string &value) {
			return Hash(Utils::MACToInt(value));
		}

		[[nodiscard]] static inline uint16_t HashMax() { return MACHashMax; }
	};

	constexpr uint SessionHashMax = 256;
	constexpr uint SessionHashMask = SessionHashMax - 1;
	class SessionHash {
	  public:
		[[nodiscard]] static inline uint16_t Hash(std::uint64_t value) {
			return (value & SessionHashMask);
		}

		[[nodiscard]] static inline uint16_t HashMax() { return SessionHashMax; }
	};

	class AP_Server : public SubSystemServer, public Poco::Runnable {
	  public:
		virtual ~AP_Server();
		void run() override;
		virtual bool ValidateCertificate(const std::string &ConnectionId,
										   const Poco::Crypto::X509Certificate &Certificate)=0;
		bool GetHealthDevices(std::uint64_t lowLimit, std::uint64_t highLimit,
							  std::vector<std::string> &SerialNumbers);

		bool GetStatistics(uint64_t SerialNumber, std::string &Statistics) const;
		inline bool GetStatistics(const std::string &SerialNumber, std::string &Statistics) const {
			return GetStatistics(Utils::SerialNumberToInt(SerialNumber), Statistics);
		}

		bool GetState(uint64_t SerialNumber, GWObjects::ConnectionState &State) const;
		inline bool GetState(const std::string &SerialNumber,
							 GWObjects::ConnectionState &State) const {
			return GetState(Utils::SerialNumberToInt(SerialNumber), State);
		}

		bool GetHealthcheck(uint64_t SerialNumber, GWObjects::HealthCheck &CheckData) const;
		inline bool GetHealthcheck(const std::string &SerialNumber,
								   GWObjects::HealthCheck &CheckData) const {
			return GetHealthcheck(Utils::SerialNumberToInt(SerialNumber), CheckData);
		}

		void StartSession(uint64_t session_id, uint64_t SerialNumber);
		bool EndSession(uint64_t session_id, uint64_t SerialNumber);
		bool Disconnect(uint64_t SerialNumber);
		void CleanupSessions();
		bool Connected(uint64_t SerialNumber, GWObjects::DeviceRestrictions &Restrictions) const;
		bool Connected(uint64_t SerialNumber) const;
		inline bool Connected(const std::string &SerialNumber,
							  GWObjects::DeviceRestrictions &Restrictions) const {
			return Connected(Utils::SerialNumberToInt(SerialNumber), Restrictions);
		}
		inline bool Connected(const std::string &SerialNumber) const {
			return Connected(Utils::SerialNumberToInt(SerialNumber));
		}

		bool SendFrame(uint64_t SerialNumber, const std::string &Payload,std::chrono::milliseconds WaitTimeInMs) const;
		inline bool SendFrame(const std::string &SerialNumber, const std::string &Payload,std::chrono::milliseconds WaitTimeInMs = std::chrono::milliseconds{30000}) const {
			return SendFrame(Utils::SerialNumberToInt(SerialNumber), Payload,WaitTimeInMs);
		}

		[[nodiscard]] inline std::shared_ptr<AP_Connection>
		GetConnection(uint64_t SerialNumber) const {
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto it = SerialNumbers_[hashIndex].find(SerialNumber);
			if (it == end(SerialNumbers_[hashIndex])) {
				return nullptr;
			}
			return it->second;
		}

		void SetWebSocketTelemetryReporting(uint64_t RPCID, uint64_t SerialNumber,
											uint64_t Interval, uint64_t Lifetime,
											const std::vector<std::string> &TelemetryTypes);
		void StopWebSocketTelemetry(uint64_t RPCID, uint64_t SerialNumber);
		void SetKafkaTelemetryReporting(uint64_t RPCID, uint64_t SerialNumber, uint64_t Interval,
										uint64_t Lifetime,
										const std::vector<std::string> &TelemetryTypes);
		void StopKafkaTelemetry(uint64_t RPCID, uint64_t SerialNumber);
		void GetTelemetryParameters(uint64_t SerialNumber, bool &TelemetryRunning,
									uint64_t &TelemetryInterval, uint64_t &TelemetryWebSocketTimer,
									uint64_t &TelemetryKafkaTimer,
									uint64_t &TelemetryWebSocketCount,
									uint64_t &TelemetryKafkaCount,
									uint64_t &TelemetryWebSocketPackets,
									uint64_t &TelemetryKafkaPackets);

		bool SendRadiusAuthenticationData(const std::string &SerialNumber,
										  const unsigned char *buffer, std::size_t size);
		bool SendRadiusAccountingData(const std::string &SerialNumber, const unsigned char *buffer,
									  std::size_t size);
		bool SendRadiusCoAData(const std::string &SerialNumber, const unsigned char *buffer,
							   std::size_t size);

		inline void AddConnection(std::shared_ptr<AP_Connection> Connection) {
			std::uint64_t sessionHash = SessionHash::Hash(Connection->State_.sessionId);
			std::lock_guard SessionLock(SessionMutex_[sessionHash]);
			if (Sessions_[sessionHash].find(Connection->State_.sessionId) ==
				end(Sessions_[sessionHash])) {
				Sessions_[sessionHash][Connection->State_.sessionId] = std::move(Connection);
			}
		}

		inline void AddCleanupSession(uint64_t session_id, uint64_t SerialNumber) {
			std::lock_guard G(CleanupMutex_);
			CleanupSessions_.emplace_back(session_id, SerialNumber);
		}

		inline void IncrementConnectionCount() { ++NumberOfConnectedDevices_; }
		inline void DecrementConnectionCount() { --NumberOfConnectedDevices_; }

		inline void AddRX(std::uint64_t bytes) { RX_ += bytes; }
		inline void AddTX(std::uint64_t bytes) { TX_ += bytes; }

		inline void GetTotalDataStatistics(std::uint64_t &TX, std::uint64_t &RX) const {
			TX = TX_;
			RX = RX_;
		}

		inline void AverageDeviceStatistics(uint64_t &Connections, uint64_t &AverageConnectionTime,
											uint64_t &NumberOfConnectingDevices) const {
			Connections = NumberOfConnectedDevices_;
			AverageConnectionTime = AverageDeviceConnectionTime_;
			NumberOfConnectingDevices = NumberOfConnectingDevices_;
		}

		[[nodiscard]] inline bool Running() const { return Running_; }
		bool KafkaDisableState() const { return KafkaDisableState_; }
		bool KafkaDisableHealthChecks() const { return KafkaDisableHealthChecks_; }
		[[nodiscard]] inline bool DeviceRequiresSecureRTTY(uint64_t serialNumber) const {
			std::shared_ptr<AP_Connection> Connection;
			{
				auto hashIndex = MACHash::Hash(serialNumber);
				std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
				auto DeviceHint = SerialNumbers_[hashIndex].find(serialNumber);
				if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr)
					return false;
				Connection = DeviceHint->second;
			}
			return Connection->RTTYMustBeSecure_;
		}
		inline bool IsSimSerialNumber(const std::string &SerialNumber) const {
			return IsSim(SerialNumber) &&
				   SerialNumber == SimulatorId_;
		}

		inline static bool IsSim(const std::string &SerialNumber) {
			return SerialNumber.substr(0, 6) == "53494d";
		}

		[[nodiscard]] inline bool IsSimEnabled() const { return SimulatorEnabled_; }
		[[nodiscard]] inline bool AllowSerialNumberMismatch() const {
			return AllowSerialNumberMismatch_;
		}
		[[nodiscard]] inline uint64_t MismatchDepth() const { return MismatchDepth_; }
		[[nodiscard]] inline bool UseProvisioning() const { return LookAtProvisioning_; }
		[[nodiscard]] inline bool UseDefaults() const { return UseDefaultConfig_; }

	  protected:
		explicit AP_Server(const std::string &Name, const std::string &ShortName,
						   const std::string &SubSystem);
		
		void ReadEnvironment();
		void SetJanitor(const std::string &garbageName);
		using SerialNumberMap = std::map<uint64_t, std::shared_ptr<AP_Connection>>;

		std::array<std::mutex, SessionHashMax> SessionMutex_;
		std::array<std::map<std::uint64_t, std::shared_ptr<AP_Connection>>, SessionHashMax>
			Sessions_;
		std::array<SerialNumberMap, MACHashMax> SerialNumbers_;
		mutable std::array<std::mutex, MACHashMax> SerialNumbersMutex_;

		std::mutex CleanupMutex_;
		std::deque<std::pair<uint64_t, uint64_t>> CleanupSessions_;

		std::atomic_bool Running_ = false;
		std::uint64_t SessionTimeOut_ = 10 * 60;
		std::uint64_t LeftOverSessions_ = 0;
		std::atomic_uint64_t TX_ = 0, RX_ = 0;

		std::atomic_uint64_t NumberOfConnectedDevices_ = 0;
		std::atomic_uint64_t AverageDeviceConnectionTime_ = 0;
		std::uint64_t NumberOfConnectingDevices_ = 0;

		std::atomic_bool KafkaDisableState_ = false;
		std::atomic_bool KafkaDisableHealthChecks_ = false;
		std::string SimulatorId_;
		bool LookAtProvisioning_ = false;
		bool UseDefaultConfig_ = true;
		bool SimulatorEnabled_ = false;
		bool AllowSerialNumberMismatch_ = true;
		std::uint64_t MismatchDepth_ = 2;
		Poco::Thread CleanupThread_;
		Poco::Thread GarbageCollector_;
		std::string GarbageCollectorName;
	};

} // namespace OpenWifi

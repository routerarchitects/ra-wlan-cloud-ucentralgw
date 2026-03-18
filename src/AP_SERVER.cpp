/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2024-04-30.
//

#include "AP_SERVER.h"

#include <fmt/format.h>

namespace OpenWifi {

	AP_Server::AP_Server(const std::string &Name, const std::string &ShortName,
						 const std::string &SubSystem)
		: SubSystemServer(Name, ShortName, SubSystem) {}

	AP_Server::~AP_Server() = default;

	bool AP_Server::GetHealthDevices(std::uint64_t lowLimit, std::uint64_t highLimit,
									 std::vector<std::string> &SerialNumbers) {
		SerialNumbers.clear();
		for (int i = 0; i < SessionHash::HashMax(); i++) {
			std::lock_guard Lock(SessionMutex_[i]);
			for (const auto &connection : Sessions_[i]) {
				if (connection.second->RawLastHealthcheck_.Sanity >= lowLimit &&
					connection.second->RawLastHealthcheck_.Sanity <= highLimit) {
					SerialNumbers.push_back(connection.second->SerialNumber_);
				}
			}
		}
		return true;
	}

	bool AP_Server::GetStatistics(uint64_t SerialNumber, std::string &Statistics) const {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == SerialNumbers_[hashIndex].end() || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}
		Connection->GetLastStats(Statistics);
		return true;
	}

	bool AP_Server::GetState(uint64_t SerialNumber, GWObjects::ConnectionState &State) const {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == SerialNumbers_[hashIndex].end() || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}
		Connection->GetState(State);
		return true;
	}

	bool AP_Server::GetHealthcheck(uint64_t SerialNumber, GWObjects::HealthCheck &CheckData) const {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto Device = SerialNumbers_[hashIndex].find(SerialNumber);
			if (Device == SerialNumbers_[hashIndex].end() || Device->second == nullptr) {
				return false;
			}
			Connection = Device->second;
		}
		Connection->GetLastHealthCheck(CheckData);
		return true;
	}

	void AP_Server::StartSession(uint64_t session_id, uint64_t SerialNumber) {
		auto sessionHash = SessionHash::Hash(session_id);
		std::shared_ptr<AP_Connection> Connection;
		{
			std::lock_guard SessionLock(SessionMutex_[sessionHash]);
			auto SessionHint = Sessions_[sessionHash].find(session_id);
			if (SessionHint == end(Sessions_[sessionHash])) {
				return;
			}
			Connection = SessionHint->second;
			Sessions_[sessionHash].erase(SessionHint);
		}

		auto deviceHash = MACHash::Hash(SerialNumber);
		std::lock_guard DeviceLock(SerialNumbersMutex_[deviceHash]);
		SerialNumbers_[deviceHash][SerialNumber] = Connection;
	}

	bool AP_Server::EndSession(uint64_t session_id, uint64_t SerialNumber) {
		{
			poco_trace(Logger(), fmt::format("Ending session 1: {} for device: {}", session_id,
											 Utils::IntToSerialNumber(SerialNumber)));
			auto sessionHash = SessionHash::Hash(session_id);
			std::lock_guard SessionLock(SessionMutex_[sessionHash]);
			Sessions_[sessionHash].erase(session_id);
			poco_trace(Logger(), fmt::format("Ended session 1: {} for device: {}", session_id,
											 Utils::IntToSerialNumber(SerialNumber)));
		}

		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			poco_trace(Logger(), fmt::format("Ending session 2.0: {} for device: {} hi:{}",
											 session_id, Utils::IntToSerialNumber(SerialNumber),
											 hashIndex));
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			poco_trace(Logger(), fmt::format("Ending session 2.1: {} for device: {} hi:{}",
											 session_id, Utils::IntToSerialNumber(SerialNumber),
											 hashIndex));
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			poco_trace(Logger(), fmt::format("Ending session 2.2: {} for device: {} hi:{}",
											 session_id, Utils::IntToSerialNumber(SerialNumber),
											 hashIndex));
			if (DeviceHint == SerialNumbers_[hashIndex].end() ||
				DeviceHint->second == nullptr ||
				DeviceHint->second->State_.sessionId != session_id) {
				poco_trace(Logger(), fmt::format("Did not end session 2: {} for device: {}",
												 session_id,
												 Utils::IntToSerialNumber(SerialNumber)));
				return false;
			}
			SerialNumbers_[hashIndex].erase(DeviceHint);
			poco_trace(Logger(), fmt::format("Ended session 2: {} for device: {}", session_id,
											 Utils::IntToSerialNumber(SerialNumber)));
		}
		return true;
	}

	bool AP_Server::Connected(uint64_t SerialNumber,
							  GWObjects::DeviceRestrictions &Restrictions) const {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}

		if (Connection->Dead_) {
			return false;
		}
		Restrictions = Connection->GetRestrictions();
		return Connection->State_.Connected;
	}

	bool AP_Server::Connected(uint64_t SerialNumber) const {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}

		if (Connection->Dead_) {
			return false;
		}
		return Connection->State_.Connected;
	}
	
	bool AP_Server::Disconnect(uint64_t SerialNumber) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == SerialNumbers_[hashIndex].end() || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
			SerialNumbers_[hashIndex].erase(DeviceHint);
		}

		{
			auto H = SessionHash::Hash(Connection->State_.sessionId);
			std::lock_guard SessionLock(SessionMutex_[H]);
			Sessions_[H].erase(Connection->State_.sessionId);
		}

		return true;
	}

	void AP_Server::CleanupSessions() {

		while(Running_) {
			std::this_thread::sleep_for(std::chrono::seconds(10));

			while(Running_) {
				std::pair<uint64_t, uint64_t> Session;
				{
					std::lock_guard G(CleanupMutex_);
					auto isEmpty = CleanupSessions_.empty();
					if (isEmpty) {
						break;
					}
					Session = CleanupSessions_.front();
					CleanupSessions_.pop_front();
				}
				poco_trace(this->Logger(),fmt::format("Cleaning up session: {} for device: {}", Session.first, Utils::IntToSerialNumber(Session.second)));
				EndSession(Session.first, Session.second);
			}
		}
	}

	bool AP_Server::SendFrame(uint64_t SerialNumber, const std::string &Payload) const {
		auto hashIndex = MACHash::Hash(SerialNumber);

		std::shared_ptr<AP_Connection> Connection;
		{
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}

		if (Connection->Dead_) {
			return false;
		}

		try {
			return Connection->Send(Payload);
		} catch (...) {
			poco_debug(Logger(), fmt::format(": SendFrame: Could not send data to device '{}'",
											 Utils::IntToSerialNumber(SerialNumber)));
		}
		return false;
	}

	void AP_Server::StopWebSocketTelemetry(uint64_t RPCID, uint64_t SerialNumber) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto Device = SerialNumbers_[hashIndex].find(SerialNumber);
			if (Device == end(SerialNumbers_[hashIndex]) || Device->second == nullptr) {
				return;
			}
			Connection = Device->second;
		}
		Connection->StopWebSocketTelemetry(RPCID);
	}

	void AP_Server::SetWebSocketTelemetryReporting(uint64_t RPCID, uint64_t SerialNumber,
												   uint64_t Interval, uint64_t Lifetime,
												   const std::vector<std::string> &TelemetryTypes) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return;
			}
			Connection = DeviceHint->second;
		}
		Connection->SetWebSocketTelemetryReporting(RPCID, Interval, Lifetime, TelemetryTypes);
	}

	void AP_Server::SetKafkaTelemetryReporting(uint64_t RPCID, uint64_t SerialNumber,
											   uint64_t Interval, uint64_t Lifetime,
											   const std::vector<std::string> &TelemetryTypes) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return;
			}
			Connection = DeviceHint->second;
		}
		Connection->SetKafkaTelemetryReporting(RPCID, Interval, Lifetime, TelemetryTypes);
	}

	void AP_Server::StopKafkaTelemetry(uint64_t RPCID, uint64_t SerialNumber) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DevicesLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return;
			}
			Connection = DeviceHint->second;
		}
		Connection->StopKafkaTelemetry(RPCID);
	}

	void AP_Server::GetTelemetryParameters(uint64_t SerialNumber, bool &TelemetryRunning,
										   uint64_t &TelemetryInterval,
										   uint64_t &TelemetryWebSocketTimer,
										   uint64_t &TelemetryKafkaTimer,
										   uint64_t &TelemetryWebSocketCount,
										   uint64_t &TelemetryKafkaCount,
										   uint64_t &TelemetryWebSocketPackets,
										   uint64_t &TelemetryKafkaPackets) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto hashIndex = MACHash::Hash(SerialNumber);
			std::lock_guard DevicesLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return;
			}
			Connection = DeviceHint->second;
		}
		Connection->GetTelemetryParameters(TelemetryRunning, TelemetryInterval,
										   TelemetryWebSocketTimer, TelemetryKafkaTimer,
										   TelemetryWebSocketCount, TelemetryKafkaCount,
										   TelemetryWebSocketPackets, TelemetryKafkaPackets);
	}

	bool AP_Server::SendRadiusAccountingData(const std::string &SerialNumber,
											 const unsigned char *buffer, std::size_t size) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto IntSerialNumber = Utils::SerialNumberToInt(SerialNumber);
			auto hashIndex = MACHash::Hash(IntSerialNumber);
			std::lock_guard DevicesLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(IntSerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}

		if(Connection->Dead_) {
			return false;
		}

		try {
			return Connection->SendRadiusAccountingData(buffer, size);
		} catch (...) {
			poco_debug(
				Logger(),
				fmt::format(": SendRadiusAccountingData: Could not send data to device '{}'",
							SerialNumber));
		}
		return false;
	}

	bool AP_Server::SendRadiusAuthenticationData(const std::string &SerialNumber,
												 const unsigned char *buffer, std::size_t size) {
		std::shared_ptr<AP_Connection> Connection;
		{
			auto IntSerialNumber = Utils::SerialNumberToInt(SerialNumber);
			auto hashIndex = MACHash::Hash(IntSerialNumber);
			std::lock_guard DevicesLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(IntSerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}

		if(Connection->Dead_) {
			return false;
		}

		try {
			return Connection->SendRadiusAuthenticationData(buffer, size);
		} catch (...) {
			poco_debug(
				Logger(),
				fmt::format(": SendRadiusAuthenticationData: Could not send data to device '{}'",
							SerialNumber));
		}
		return false;
	}

	bool AP_Server::SendRadiusCoAData(const std::string &SerialNumber,
									  const unsigned char *buffer, std::size_t size) {
		std::shared_ptr<AP_Connection> Connection;
		{
		auto IntSerialNumber = Utils::SerialNumberToInt(SerialNumber);
			auto hashIndex = MACHash::Hash(IntSerialNumber);
			std::lock_guard DeviceLock(SerialNumbersMutex_[hashIndex]);
			auto DeviceHint = SerialNumbers_[hashIndex].find(IntSerialNumber);
			if (DeviceHint == end(SerialNumbers_[hashIndex]) || DeviceHint->second == nullptr) {
				return false;
			}
			Connection = DeviceHint->second;
		}

		if(Connection->Dead_) {
			return false;
		}
		try {
			return Connection->SendRadiusCoAData(buffer, size);
		} catch (...) {
			poco_debug(Logger(),
					   fmt::format(": SendRadiusCoAData: Could not send data to device '{}'",
								   SerialNumber));
		}
		return false;
	}

} // namespace OpenWifi

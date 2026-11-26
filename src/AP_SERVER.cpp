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

	AP_Server::~AP_Server() {
		Running_ = false;
		StopCleanupWorker();
	}

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

	bool AP_Server::StartSession(uint64_t session_id, uint64_t SerialNumber) {
		const auto sessionHash = SessionHash::Hash(session_id);
		const auto deviceHash = MACHash::Hash(SerialNumber);
		std::shared_ptr<AP_Connection> retired;
		for (;;) {
			std::shared_ptr<AP_Connection> previous;
			{
				std::scoped_lock maps(SessionMutex_[sessionHash], SerialNumbersMutex_[deviceHash]);
				if (!Running_) return false;
				auto &sessions = Sessions_[sessionHash];
				auto &devices = SerialNumbers_[deviceHash];
				auto it = sessions.find(session_id);
				auto existing = devices.find(SerialNumber);
				if (it == sessions.end()) {
					return existing != devices.end() && existing->second &&
						existing->second->State_.sessionId == session_id && !existing->second->Dead_;
				}
				if (it->second->Dead_) return false;
				std::lock_guard cleanup(CleanupMutex_);
				if (CleanupScheduledSessions_.count(session_id)) return false;
				if (existing != devices.end() && existing->second && existing->second != retired) {
					previous = existing->second;
				} else {
					auto &slot = devices[SerialNumber];
					// The old connection has completed its synchronous teardown.
					// Keep retired ownership outside all locks until return.
					slot = std::move(it->second);
					slot->DeviceSessionStarted_ = true;
					sessions.erase(it);
					return true;
				}
			}
			// Never acquire a connection lock while holding map locks.
			// If another session won during teardown, recheck before promotion.
			previous->EndConnection();
			retired = std::move(previous);
		}
	}

	bool AP_Server::EndSession(uint64_t session_id, uint64_t SerialNumber) {
		std::shared_ptr<AP_Connection> removedSession, removedDevice;
		const auto started = std::chrono::steady_clock::now();
		const auto sessionHash = SessionHash::Hash(session_id);
		const auto hashIndex = MACHash::Hash(SerialNumber);
		bool sessionErased = false, deviceErased = false;
		const char *deviceOutcome = "not_found";
		{
			std::scoped_lock maps(SessionMutex_[sessionHash], SerialNumbersMutex_[hashIndex]);
			auto sessionIt = Sessions_[sessionHash].find(session_id);
			if (sessionIt != Sessions_[sessionHash].end()) removedSession = sessionIt->second;
			auto device = SerialNumbers_[hashIndex].find(SerialNumber);
			if (device != SerialNumbers_[hashIndex].end() && device->second &&
				device->second->State_.sessionId == session_id)
				removedDevice = device->second;
		}
		// Leave the active map entry visible until teardown completes so
		// promotion cannot bypass old-session disconnect side effects.
		if (removedSession) removedSession->EndConnection();
		if (removedDevice && removedDevice != removedSession) removedDevice->EndConnection();
		{
			std::scoped_lock maps(SessionMutex_[sessionHash], SerialNumbersMutex_[hashIndex]);
			auto sessionIt = Sessions_[sessionHash].find(session_id);
			if (removedSession && sessionIt != Sessions_[sessionHash].end() &&
				sessionIt->second == removedSession) {
				Sessions_[sessionHash].erase(sessionIt);
				sessionErased = true;
			}
			auto DeviceHint = SerialNumbers_[hashIndex].find(SerialNumber);
			if (DeviceHint != SerialNumbers_[hashIndex].end()) {
				if (!DeviceHint->second) {
					deviceOutcome = "null_entry";
				} else if (DeviceHint->second->State_.sessionId != session_id ||
					(DeviceHint->second != removedSession && DeviceHint->second != removedDevice)) {
					deviceOutcome = "different_session_preserved";
				} else {
					SerialNumbers_[hashIndex].erase(DeviceHint);
					deviceErased = true;
					deviceOutcome = "removed";
				}
			}
		}
		poco_trace(Logger(), fmt::format(
			"SESSION-CLEANUP session={} serial={} session_hash={} device_hash={} session_erased={} "
			"device_erased={} device_outcome={} map_cleanup_us={}",
			session_id, Utils::IntToSerialNumber(SerialNumber), sessionHash, hashIndex,
			sessionErased, deviceErased, deviceOutcome,
			std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - started).count()));
		return deviceErased;
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
		auto connection = GetConnection(SerialNumber);
		if (!connection) return false;
		return EndSession(connection->State_.sessionId, SerialNumber);
	}

	void AP_Server::CleanupSessions() {
		for (;;) {
			std::pair<uint64_t, uint64_t> Session;
			{
				std::unique_lock G(CleanupMutex_);
				CleanupReady_.wait(G, [this]() {
					return CleanupStopping_ || !CleanupSessions_.empty();
				});
				if (CleanupSessions_.empty()) {
					if (CleanupStopping_) break;
					continue;
				}
				Session = CleanupSessions_.front();
				CleanupSessions_.pop_front();
			}
			try {
				EndSession(Session.first, Session.second);
			} catch (...) {
				try { poco_error(Logger(), fmt::format("Session cleanup {} failed", Session.first)); } catch (...) {}
			}
			{
				std::lock_guard G(CleanupMutex_);
				CleanupScheduledSessions_.erase(Session.first);
			}
		}
	}

	void AP_Server::StopCleanupWorker() {
		// Stop transport producers before closing admission. The worker drains
		// pending work even though Running_ has already become false.
		{
			std::lock_guard G(CleanupMutex_);
			CleanupStopping_ = true;
		}
		CleanupReady_.notify_all();
		if (CleanupThread_.joinable()) CleanupThread_.join();

		// Handle remaining map-owned sessions without allocating a new queue
		// or destroying connections while a map lock is held.
		auto releaseMap = [](auto &map, auto &mutex) {
			for (;;) {
				std::shared_ptr<AP_Connection> connection;
				{
					std::lock_guard G(mutex);
					if (map.empty()) break;
					auto it = map.begin();
					connection = std::move(it->second);
					map.erase(it);
				}
				if (connection) connection->EndConnection();
			}
		};
		for (std::size_t i = 0; i < Sessions_.size(); ++i)
			releaseMap(Sessions_[i], SessionMutex_[i]);
		for (std::size_t i = 0; i < SerialNumbers_.size(); ++i)
			releaseMap(SerialNumbers_[i], SerialNumbersMutex_[i]);
	}

	bool AP_Server::SendFrame(uint64_t SerialNumber, const std::string &Payload,std::chrono::milliseconds WaitTimeInMs) const {
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
			return Connection->Send(Payload,WaitTimeInMs);
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

	void AP_Server::ReadEnvironment(){

		AllowSerialNumberMismatch_ =	MicroServiceConfigGetBool("openwifi.certificates.allowmismatch", true);
		MismatchDepth_ = MicroServiceConfigGetInt("openwifi.certificates.mismatchdepth", 2);
		SessionTimeOut_ = MicroServiceConfigGetInt("openwifi.session.timeout", 10*60);
		KafkaDisableState_ = MicroServiceConfigGetBool("openwifi.kafka.disablestate", false);
		KafkaDisableHealthChecks_ = MicroServiceConfigGetBool("openwifi.kafka.disablehealthchecks", false);
	}

	void AP_Server::SetJanitor(const std::string &garbageName){

		auto ProvString = MicroServiceConfigGetString("autoprovisioning.process", "default");
		if (ProvString != "default") {
			auto Tokens = Poco::StringTokenizer(ProvString, ",");
			for (const auto &i : Tokens) {
				if (i == "prov")
				LookAtProvisioning_ = true;
				else
				UseDefaultConfig_ = true;
			}
		} else {
			UseDefaultConfig_ = true;
		}
		
		SimulatorId_ = Poco::toLower(MicroServiceConfigGetString("simulatorid", ""));
		SimulatorEnabled_ = !SimulatorId_.empty();
		{
			std::lock_guard G(CleanupMutex_);
			CleanupStopping_ = false;
		}
		Running_ = true;

		GarbageCollector_.setName(garbageName);
		GarbageCollector_.start(*this);

		CleanupThread_ = std::thread([this](){ CleanupSessions(); });
	}

	void AP_Server::run() {
		uint64_t last_log = Utils::Now(),
				 last_zombie_run = 0,
				 last_garbage_run = 0;

		Poco::Logger &LocalLogger = Poco::Logger::create(
			GarbageCollectorName, Poco::Logger::root().getChannel(), Poco::Logger::root().getLevel());

		while(Running_) {

			if(!Poco::Thread::trySleep(30000)) {
				break;
			}


			uint64_t total_connected_time = 0, now = Utils::Now();
			std::uint64_t idleDeviceEntries = 0, idleSessionEntries = 0, deadEntries = 0, nullEntries = 0;
			const auto scanStarted = std::chrono::steady_clock::now();

			if(now-last_zombie_run > 60) {
				try {
					NumberOfConnectingDevices_ = 0;
					AverageDeviceConnectionTime_ = 0;
					int waits = 0;
					for (int hashIndex = 0; hashIndex < MACHash::HashMax(); hashIndex++) {
						last_zombie_run = now;
						waits = 0;
						while (true) {
							if (SerialNumbersMutex_[hashIndex].try_lock()) {
								waits = 0;
								auto hint = SerialNumbers_[hashIndex].begin();
								while (hint != end(SerialNumbers_[hashIndex])) {
									if (hint->second == nullptr) {
										++nullEntries;
										poco_debug(LocalLogger, fmt::format("Dead device found in hash index {}", hashIndex));
										hint = SerialNumbers_[hashIndex].erase(hint);
									} else {
										auto Device = hint->second;
										auto RightNow = Utils::Now();
										if (Device->Dead_) {
											++deadEntries;
											AddCleanupSession(Device->State_.sessionId, Device->SerialNumberInt_);
											++hint;
											// hint = SerialNumbers_[hashIndex].erase(hint);
										} else if (RightNow > Device->LastContact_ &&
												   (RightNow - Device->LastContact_) > SessionTimeOut_) {
											++idleDeviceEntries;
											poco_debug(
												LocalLogger,
												fmt::format(
													"{}: Session seems idle. Controller disconnecting device.",
													Device->SerialNumber_));
											// hint = SerialNumbers_[hashIndex].erase(hint);
											AddCleanupSession(Device->State_.sessionId, Device->SerialNumberInt_);
											++hint;
										} else {
											if (Device->State_.Connected) {
												total_connected_time +=
													(RightNow - Device->State_.started);
											}
											++hint;
										}
									}
								}
								SerialNumbersMutex_[hashIndex].unlock();
								break;
							} else if (waits < 5) {
								waits++;
								Poco::Thread::trySleep(10);
							} else {
								break;
							}
						}
					}

					LeftOverSessions_ = 0;
					for (int i = 0; i < SessionHash::HashMax(); i++) {
						waits = 0;
						while (true) {
							if (SessionMutex_[i].try_lock()) {
								waits = 0;
								auto hint = Sessions_[i].begin();
								auto RightNow = Utils::Now();
								while (hint != end(Sessions_[i])) {
									if (hint->second == nullptr) {
										++nullEntries;
										hint = Sessions_[i].erase(hint);
									} else if (hint->second->Dead_) {
										++deadEntries;
										// hint = Sessions_[i].erase(hint);
										AddCleanupSession(hint->second->State_.sessionId, hint->second->SerialNumberInt_);
										++hint;
									} else if (RightNow > hint->second->LastContact_ &&
											   (RightNow - hint->second->LastContact_) >
												   SessionTimeOut_) {
										++idleSessionEntries;
										poco_debug(
											LocalLogger,
											fmt::format("{}: Session seems idle. Controller disconnecting device.",
														hint->second->SerialNumber_));
										AddCleanupSession(hint->second->State_.sessionId, hint->second->SerialNumberInt_);
										++hint;
										// hint = Sessions_[i].erase(hint);
									} else {
										++LeftOverSessions_;
										++hint;
									}
								}
								SessionMutex_[i].unlock();
								break;
							} else if (waits < 5) {
								Poco::Thread::trySleep(10);
								waits++;
							} else {
								break;
							}
						}
					}

					AverageDeviceConnectionTime_ = NumberOfConnectedDevices_ > 0
													   ? total_connected_time / NumberOfConnectedDevices_
													   : 0;
					poco_debug(LocalLogger, fmt::format(
						"GARBAGE-COLLECTION idle_device_entries={} idle_session_entries={} dead_entries={} null_entries={} scan_ms={}",
						idleDeviceEntries, idleSessionEntries, deadEntries, nullEntries,
						std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - scanStarted).count()));
				} catch (const Poco::Exception &E) {
					poco_error(LocalLogger, fmt::format("Poco::Exception: Garbage collecting zombies failed: {}", E.displayText()));
				} catch (const std::exception &E) {
					poco_error(LocalLogger, fmt::format("std::exception: Garbage collecting zombies failed: {}", E.what()));
				} catch (...) {
					poco_error(LocalLogger, fmt::format("exception:Garbage collecting zombies failed: {}", "unknown"));
				}

			}

			if(NumberOfConnectedDevices_) {
				if (last_garbage_run > 0) {
					AverageDeviceConnectionTime_ += (now - last_garbage_run);
				}
			}

			try {
				if ((now - last_log) > 60) {
					last_log = now;
					poco_information(
						LocalLogger,
						fmt::format("Active AP connections: {} Connecting: {} Average connection time: {} seconds. Left Over Sessions: {}",
									NumberOfConnectedDevices_, NumberOfConnectingDevices_,
									AverageDeviceConnectionTime_, LeftOverSessions_));
				}

				GWWebSocketNotifications::NumberOfConnection_t Notification;
				Notification.content.numberOfConnectingDevices = NumberOfConnectingDevices_;
				Notification.content.numberOfDevices = NumberOfConnectedDevices_;
				Notification.content.averageConnectedTime = AverageDeviceConnectionTime_;
				GetTotalDataStatistics(Notification.content.tx, Notification.content.rx);
				GWWebSocketNotifications::NumberOfConnections(Notification);

				Poco::JSON::Object KafkaNotification;
				Notification.to_json(KafkaNotification);

				Poco::JSON::Object FullEvent;
				FullEvent.set("type", "load-update");
				FullEvent.set("timestamp", now);
				FullEvent.set("payload", KafkaNotification);

				KafkaManager()->PostMessage(KafkaTopics::DEVICE_EVENT_QUEUE, "system", FullEvent);
				last_garbage_run = now;
			} catch (const Poco::Exception &E) {
				LocalLogger.error(fmt::format("Poco::Exception: Garbage collecting failed: {}", E.displayText()));
			} catch (const std::exception &E) {
				LocalLogger.error(fmt::format("std::exception: Garbage collecting failed: {}", E.what()));
			} catch (...) {
				LocalLogger.error(fmt::format("exception:Garbage collecting failed: {}", "unknown"));
			}
		}
		LocalLogger.information(fmt::format("Garbage collector done for the day."	));
	}

} // namespace OpenWifi

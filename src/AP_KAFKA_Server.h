/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "AP_SERVER.h"
#include "Poco/Thread.h"

namespace OpenWifi {
	class LockedDbSession;
	class AP_KAFKA_Connection;
	class AP_KAFKA_Server : public AP_Server {
	  public:
		static auto instance() {
			static auto instance_ = new AP_KAFKA_Server;
			return instance_;
		}

		int Start() override;
		void Stop() override;
		bool ValidateCertificate(const std::string &ConnectionId,
								 const Poco::Crypto::X509Certificate &Certificate) override;

	//	void run() override; // Garbage collector thread.

	  private:
		std::uint64_t WatcherId_ = 0;
		inline static std::atomic_uint64_t session_id_ = 0;
		std::mutex DbSessionMutex_;
		std::uint64_t NextDbSession_ = 0;
		std::vector<std::shared_ptr<LockedDbSession>> DbSessions_;

		void OnKafkaMessage(const std::string &key, const std::string &payload);
		void HandleInfraJoin(Poco::JSON::Object::Ptr msg, const std::string &key);
		void HandleInfraPing(Poco::JSON::Object::Ptr msg, const std::string &key);
		void HandleInfraLeave(Poco::JSON::Object::Ptr msg, const std::string &key);
		void HandleDeviceMessage(Poco::JSON::Object::Ptr msg, const std::string &key,
								 const std::string &payload);
	 	bool validateResult(Poco::JSON::Object::Ptr msg, std::string &serial,const std::string &key);
		bool validateMethod(Poco::JSON::Object::Ptr msg, std::string &serial,const std::string &key);
		bool recreateConnection(std::shared_ptr<AP_KAFKA_Connection> &KafkaConn, std::string &serial);
		void InitDbSessions();
		void HandleGroupIDChange(Poco::JSON::Object::Ptr msg, const std::string &key, const std::string &type);
		std::shared_ptr<LockedDbSession> NextDbSession();


		AP_KAFKA_Server() noexcept : AP_Server("KafkaServer", "KAFKA-SERVER", "ucentral.kafka") {}
	};

	inline auto AP_KAFKA_Server() { return AP_KAFKA_Server::instance(); }

} // namespace OpenWifi

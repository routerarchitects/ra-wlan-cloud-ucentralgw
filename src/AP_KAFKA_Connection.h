/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
#pragma once

#include <atomic>
#include <memory>
#include <string>

#include "AP_Connection.h"
#include "Poco/Net/SocketNotification.h"

namespace OpenWifi {

	class AP_KAFKA_Server;

	class AP_KAFKA_Connection : public AP_Connection {
		static constexpr int BufSize = 256000;

	  public:
		explicit AP_KAFKA_Connection(Poco::Logger &L,
									 std::shared_ptr<LockedDbSession> session,
									 uint64_t connection_id);
		~AP_KAFKA_Connection() override;

		void Start() override;
		void EndConnection() override;
		[[nodiscard]] bool ValidatedDevice() override;
		void ProcessIncomingFrame() override;
		[[nodiscard]] bool Send(const std::string &Payload,std::chrono::milliseconds waitTime = std::chrono::milliseconds{30000}) override;
		void setEssentials(const std::string &IP, const std::string &InfraSerial,
						   uint64_t InfraGroupId);
		void setRecreation(GWObjects::Device &DeviceInfo);
		void UpdateGroupID(uint64_t InfraGroupId, const std::string &SerialNumber);

	  private:
		friend class AP_KAFKA_Server;
		std::string PendingPayload_;
	};

} // namespace OpenWifi

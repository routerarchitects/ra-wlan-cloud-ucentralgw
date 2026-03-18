/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2022-02-03.
//

#pragma once

#include <memory>

#include "AP_Connection.h"
#include "Poco/Net/SocketNotification.h"
#include "Poco/Net/SocketReactor.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/WebSocket.h"
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>

#include "AP_WS_Reactor_Pool.h"

namespace OpenWifi {

	class AP_WS_Connection : public AP_Connection {
		static constexpr int BufSize = 512000;

	  public:
		explicit AP_WS_Connection(Poco::Net::HTTPServerRequest &request,
								  Poco::Net::HTTPServerResponse &response, uint64_t connection_id,
								  Poco::Logger &L, std::pair<std::shared_ptr<Poco::Net::SocketReactor>, std::shared_ptr<LockedDbSession>> R);
		~AP_WS_Connection() override;

		void EndConnection() override;
		void ProcessIncomingFrame() override;
		[[nodiscard]] bool Send(const std::string &Payload,std::chrono::milliseconds waitTime = std::chrono::milliseconds{30000}) override;
		void ProcessWSFinalPayload();
		[[nodiscard]] bool ValidatedDevice() override;

		void OnSocketReadable(const Poco::AutoPtr<Poco::Net::ReadableNotification> &pNf);
		void OnSocketShutdown(const Poco::AutoPtr<Poco::Net::ShutdownNotification> &pNf);
		void OnSocketError(const Poco::AutoPtr<Poco::Net::ErrorNotification> &pNf);
		void Start() override;

	  private:
		std::shared_ptr<Poco::Net::SocketReactor> Reactor_;
		std::unique_ptr<Poco::Net::WebSocket> WS_;
		std::atomic_bool Registered_ = false;
		Poco::Buffer<char> IncomingFrame_;
	};

} // namespace OpenWifi

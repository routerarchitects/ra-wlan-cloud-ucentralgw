/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
//	License type: BSD 3-Clause License
//	License copy: https://github.com/Telecominfraproject/wlan-cloud-ucentralgw/blob/master/LICENSE
//
//	Created by Stephane Bourque on 2021-03-04.
//	Arilia Wireless Inc.
//

#pragma once

#include <array>
#include <ctime>
#include <mutex>
#include <thread>

#include "Poco/AutoPtr.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/ParallelSocketAcceptor.h"
#include "Poco/Net/SocketAcceptor.h"
#include "Poco/Net/SocketReactor.h"
#include "Poco/Timer.h"

#include "AP_SERVER.h"
#include "AP_WS_Connection.h"
#include "AP_WS_Reactor_Pool.h"

namespace OpenWifi {

	class AP_WS_Server : public AP_Server {
	  public:
		static auto instance() {
			static auto instance_ = new AP_WS_Server;
			return instance_;
		}

		int Start() override;
		void Stop() override;
		bool IsCertOk() { return IssuerCert_ != nullptr; }
		bool ValidateCertificate(const std::string &ConnectionId,
								 const Poco::Crypto::X509Certificate &Certificate);

		
		[[nodiscard]] inline std::pair<std::shared_ptr<Poco::Net::SocketReactor>,
									   std::shared_ptr<LockedDbSession>>
		NextReactor() {
			return Reactor_pool_->NextReactor();
		}

	  private:
		std::unique_ptr<Poco::Crypto::X509Certificate> IssuerCert_;
		std::vector<Poco::Crypto::X509Certificate> ClientCasCerts_;
		std::list<std::unique_ptr<Poco::Net::HTTPServer>> WebServers_;
		Poco::ThreadPool DeviceConnectionPool_{"ws:dev-pool", 4, 256};
		Poco::Net::SocketReactor Reactor_;
		Poco::Thread ReactorThread_;
		std::unique_ptr<AP_WS_ReactorThreadPool> Reactor_pool_;

		AP_WS_Server() noexcept
			: AP_Server("WebSocketServer", "WS-SVR", "ucentral.websocket") {}
	};

	inline auto AP_WS_Server() { return AP_WS_Server::instance(); }

} // namespace OpenWifi

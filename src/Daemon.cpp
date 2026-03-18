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

#include "Poco/Environment.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Util/Application.h"
#include "Poco/Util/Option.h"

#include <framework/ConfigurationValidator.h>
#include <framework/UI_WebSocketClientServer.h>
#include <framework/default_device_types.h>

#include "AP_ServerProvider.h"
#include "AP_KAFKA_Server.h"
#include "AP_WS_Server.h"
#include "CommandManager.h"
#include "Daemon.h"
#include "FileUploader.h"
#include "FindCountry.h"
#include "OUIServer.h"
#include "RADIUSSessionTracker.h"
#include "RADIUS_proxy_server.h"
#include "RegulatoryInfo.h"
#include "ScriptManager.h"
#include "SerialNumberCache.h"
#include "SignatureMgr.h"
#include "StorageArchiver.h"
#include "StorageService.h"
#include "TelemetryStream.h"
#include "GenericScheduler.h"
#include "UI_GW_WebSocketNotifications.h"
#include "VenueBroadcaster.h"
#include "AP_WS_ConfigAutoUpgrader.h"
#include "rttys/RTTYS_server.h"
#include "firmware_revision_cache.h"

namespace OpenWifi {

	static SubSystemVec GetDaemonSubSystems() {
		SubSystemVec V = {GenericScheduler(),
						  StorageService(),
						  SerialNumberCache(),
						  ConfigurationValidator(),
						  UI_WebSocketClientServer(),
						  OUIServer(),
						  FindCountryFromIP(),
						  CommandManager(),
						  FileUploader(),
						  StorageArchiver(),
						  TelemetryStream(),
						  RTTYS_server(),
						  RADIUS_proxy_server(),
						  VenueBroadcaster(),
						  ScriptManager(),
						  SignatureManager(),
						  RegulatoryInfo(),
						  RADIUSSessionTracker(),
						  AP_WS_ConfigAutoUpgradeAgent(),
						  FirmwareRevisionCache()};

		std::string SvrType = Poco::Environment::get("OPENWIFI_SERVER_TYPE", "websocket");
		if (SvrType == "kafka") {
			V.push_back(AP_KAFKA_Server());
		} else {
			V.push_back(AP_WS_Server());
		}
		return V;
	}
	class Daemon *Daemon::instance() {
		static Daemon instance(
			vDAEMON_PROPERTIES_FILENAME, vDAEMON_ROOT_ENV_VAR, vDAEMON_CONFIG_ENV_VAR,
			vDAEMON_APP_NAME, vDAEMON_BUS_TIMER,
			GetDaemonSubSystems());
		return &instance;
	}

	static std::string ALBHealthCallback() {
		uint64_t Connections, AverageConnectionTime, NumberOfConnectingDevices;
		GetAPServer()->AverageDeviceStatistics(Connections, AverageConnectionTime,
								NumberOfConnectingDevices);
		std::ostringstream os;
		os << 	"Connections: " << Connections << std::endl <<
				"ConnectingDevices: " << NumberOfConnectingDevices << std::endl <<
				"ConnectionTime: " << AverageConnectionTime << std::endl;
		return os.str();
	}

	void Daemon::PostInitialization([[maybe_unused]] Poco::Util::Application &self) {
		AutoProvisioning_ = config().getBool("openwifi.autoprovisioning", false);
		DeviceTypes_ = DefaultDeviceTypeList;
		WebSocketProcessor_ = std::make_unique<GwWebSocketClient>(logger());
		MicroServiceALBCallback(ALBHealthCallback);
		std::string SvrType = Poco::Environment::get("OPENWIFI_SERVER_TYPE", "websocket");
		if (SvrType == "kafka") {
			AP_ServerProvider::Register(AP_KAFKA_Server());
		} else {
			AP_ServerProvider::Register(AP_WS_Server());
		}
	}

	[[nodiscard]] std::string Daemon::IdentifyDevice(const std::string &Id) const {
		for (const auto &[DeviceType, Type] : DeviceTypes_) {
			if (Id == DeviceType)
				return Type;
		}
		return Platforms::AP;
	}

	void DaemonPostInitialization(Poco::Util::Application &self) {
		Daemon()->PostInitialization(self);
		GWWebSocketNotifications::Register();
	}
} // namespace OpenWifi

int main(int argc, char **argv) {
	int ExitCode;
	try {
		Poco::Net::SSLManager::instance().initializeServer(nullptr, nullptr, nullptr);
		auto App = OpenWifi::Daemon::instance();
		ExitCode = App->run(argc, argv);
		Poco::Net::SSLManager::instance().shutdown();
	} catch (Poco::Exception &exc) {
		ExitCode = Poco::Util::Application::EXIT_SOFTWARE;
		std::cout << exc.displayText() << std::endl;
	} catch (std::exception &exc) {
		ExitCode = Poco::Util::Application::EXIT_TEMPFAIL;
		std::cout << exc.what() << std::endl;
	} catch (...) {
		ExitCode = Poco::Util::Application::EXIT_TEMPFAIL;
		std::cout << "Exception on closure" << std::endl;
	}

	std::cout << "Exitcode: " << ExitCode << std::endl;
	return ExitCode;
}

// end of namespace

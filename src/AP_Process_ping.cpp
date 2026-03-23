/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2022-07-26.
//

#include "AP_Connection.h"

#include <Poco/String.h>

#include "FindCountry.h"
#include "fmt/format.h"
#include "framework/KafkaManager.h"
#include "framework/KafkaTopics.h"
#include "framework/ow_constants.h"
#include "framework/utils.h"

namespace OpenWifi {
	void AP_Connection::Process_ping(Poco::JSON::Object::Ptr ParamsObj) {
		if (!ParamsObj->has(uCentralProtocol::UUID) || !ParamsObj->has(uCentralProtocol::SERIAL)) {
			poco_warning(Logger_, fmt::format("PING({}): Missing required uuid or serial.", CId_));
			return;
		}

		auto serial = Poco::trim(Poco::toLower(ParamsObj->get(uCentralProtocol::SERIAL).toString()));
		if (!Utils::NormalizeMac(serial) || !Utils::ValidSerialNumber(serial)) {
			poco_warning(Logger_, fmt::format("PING({}): Invalid serial {}.", CId_, serial));
			return;
		}

		std::uint64_t UUID = ParamsObj->get(uCentralProtocol::UUID);
		auto firmware = ParamsObj->has(uCentralProtocol::FIRMWARE)
							? ParamsObj->get(uCentralProtocol::FIRMWARE).toString()
							: State_.Firmware;
		auto compatible = ParamsObj->has(uCentralProtocol::COMPATIBLE)
							  ? ParamsObj->get(uCentralProtocol::COMPATIBLE).toString()
							  : Compatible_;

		std::string connectionIp;
		if (ParamsObj->has(uCentralProtocol::CONNECTIONIP)) {
			connectionIp = ParamsObj->get(uCentralProtocol::CONNECTIONIP).toString();
		} else if (!Address_.empty()) {
			connectionIp = serial + "@" + Address_;
		} else {
			connectionIp = CId_;
		}

		std::string locale;
		if (ParamsObj->has("locale")) {
			locale = ParamsObj->get("locale").toString();
		} else {
			auto IP = Address_;
			if (IP.empty()) {
				auto atPos = connectionIp.find('@');
				IP = atPos == std::string::npos ? connectionIp : connectionIp.substr(atPos + 1);
			}
			if (!IP.empty() && IP.substr(0, 7) == "::ffff:") {
				IP = IP.substr(7);
			}
			locale = IP.empty() ? State_.locale : FindCountryFromIP()->Get(IP);
		}

		SerialNumber_ = serial;
		SerialNumberInt_ = Utils::SerialNumberToInt(serial);
		if (!firmware.empty()) {
			State_.Firmware = firmware;
		}
		if (!compatible.empty()) {
			Compatible_ = compatible;
			State_.Compatible = compatible;
		}
		if (!locale.empty()) {
			State_.locale = locale;
		}
		if (!connectionIp.empty()) {
			CId_ = connectionIp;
			auto atPos = connectionIp.find('@');
			Address_ = atPos == std::string::npos ? connectionIp : connectionIp.substr(atPos + 1);
			State_.Address = Address_;
		}

		poco_trace(Logger_, fmt::format("PING({}): received uuid={} serial={}", CId_, UUID, serial));

		if (!KafkaManager()->Enabled()) {
			return;
		}

		Poco::JSON::Object PingObject;
		Poco::JSON::Object PingDetails;
		PingDetails.set(uCentralProtocol::FIRMWARE, firmware);
		PingDetails.set(uCentralProtocol::SERIALNUMBER, serial);
		PingDetails.set(uCentralProtocol::COMPATIBLE, compatible);
		PingDetails.set(uCentralProtocol::CONNECTIONIP, connectionIp);
		PingDetails.set(uCentralProtocol::TIMESTAMP, Utils::Now());
		PingDetails.set(uCentralProtocol::UUID, UUID);
		if (!locale.empty()) {
			PingDetails.set("locale", locale);
		}
		PingObject.set(uCentralProtocol::PING, PingDetails);

		poco_trace(Logger_, fmt::format("PING({}): sending kafka event for {}", CId_, serial));
		KafkaManager()->PostMessage(KafkaTopics::CONNECTION, serial, PingObject);
	}
} // namespace OpenWifi

/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2022-02-03.
//

#include "AP_Connection.h"

#include <Poco/Base64Decoder.h>
#include <Poco/JSON/Parser.h>

#include <fmt/format.h>

#include "CommandManager.h"
#include "GWKafkaEvents.h"
#include "RADIUSSessionTracker.h"
#include "RADIUS_proxy_server.h"
#include "StorageService.h"
#include "UI_GW_WebSocketNotifications.h"
#include "framework/KafkaManager.h"
#include "framework/MicroServiceFuncs.h"
#include "framework/ow_constants.h"
#include "framework/utils.h"
#include "framework/MemoryDiagnostics.h"

namespace OpenWifi {

	AP_Connection::AP_Connection(Poco::Logger &L, std::shared_ptr<LockedDbSession> session,
								 uint64_t connection_id)
		: Logger_(L), DbSession_(std::move(session)) {
		State_.sessionId = connection_id;
	}

	void AP_Connection::LogException(const Poco::Exception &E) {
		poco_information(Logger_, fmt::format("EXCEPTION({}): {}", CId_, E.displayText()));
	}

	namespace {
		void NotifyKafkaDisconnect(const std::string &SerialNumber, std::uint64_t uuid) {
			try {
				Poco::JSON::Object Disconnect;
				Poco::JSON::Object Details;
				Details.set(uCentralProtocol::SERIALNUMBER, SerialNumber);
				Details.set(uCentralProtocol::TIMESTAMP, Utils::Now());
				Details.set(uCentralProtocol::UUID, uuid);
				Disconnect.set(uCentralProtocol::DISCONNECTION, Details);
				KafkaManager()->PostMessage(KafkaTopics::CONNECTION, SerialNumber, Disconnect);
			} catch (...) {
			}
		}
	} // namespace

	void AP_Connection::DeviceDisconnectionCleanup(const std::string &SerialNumber,
												   std::uint64_t uuid) {
		if (KafkaManager()->Enabled()) {
			NotifyKafkaDisconnect(SerialNumber, uuid);
		}
		RADIUSSessionTracker()->DeviceDisconnect(SerialNumber);
		GWWebSocketNotifications::SingleDevice_t N;
		N.content.serialNumber = SerialNumber;
		GWWebSocketNotifications::DeviceDisconnected(N);
	}

	void AP_Connection::ProcessJSONRPCResult(Poco::JSON::Object::Ptr Doc) {
		++MemoryDiagnostics::RpcResults;
		poco_trace(Logger_, fmt::format("RECEIVED-RPC({}): {}.", CId_,
										Doc->get(uCentralProtocol::ID).toString()));
		CommandManager()->PostCommandResult(SerialNumber_, Doc);
	}

	void AP_Connection::ProcessJSONRPCEvent(Poco::JSON::Object::Ptr &Doc) {
		auto Method = Doc->get(uCentralProtocol::METHOD).toString();
		auto EventType = uCentralProtocol::Events::EventFromString(Method);
		if (EventType == uCentralProtocol::Events::ET_UNKNOWN) {
			poco_warning(Logger_, fmt::format("ILLEGAL-PROTOCOL({}): Unknown message type '{}'",
											  CId_, Method));
			Errors_++;
			return;
		}

		if (!Doc->isObject(uCentralProtocol::PARAMS)) {
			poco_warning(Logger_,
						 fmt::format("MISSING-PARAMS({}): params must be an object.", CId_));
			Errors_++;
			return;
		}

		auto ParamsObj = Doc->get(uCentralProtocol::PARAMS).extract<Poco::JSON::Object::Ptr>();
		if (ParamsObj->has(uCentralProtocol::COMPRESS_64)) {
			std::string UncompressedData;
			try {
				auto CompressedData = ParamsObj->get(uCentralProtocol::COMPRESS_64).toString();
				uint64_t compress_sz = 0;
				if (ParamsObj->has("compress_sz")) {
					compress_sz = ParamsObj->get("compress_sz");
				}

				if (Utils::ExtractBase64CompressedData(CompressedData, UncompressedData,
													   compress_sz)) {
					poco_trace(Logger_,
							   fmt::format("EVENT({}): Found compressed payload expanded to '{}'.",
										   CId_, UncompressedData));
					Poco::JSON::Parser Parser;
					ParamsObj = Parser.parse(UncompressedData).extract<Poco::JSON::Object::Ptr>();
				} else {
					poco_warning(Logger_,
								 fmt::format("INVALID-COMPRESSED-DATA({}): Compressed cannot be "
											 "uncompressed - content must be corrupt..: size={}",
											 CId_, CompressedData.size()));
					Errors_++;
					return;
				}
			} catch (const Poco::Exception &E) {
				poco_warning(Logger_, fmt::format("INVALID-COMPRESSED-JSON-DATA({}): Compressed "
												  "cannot be parsed - JSON must be corrupt..",
												  CId_));
				Logger_.log(E);
				return;
			}
		}

		if (!ParamsObj->has(uCentralProtocol::SERIAL)) {
			poco_warning(
				Logger_,
				fmt::format("MISSING-PARAMS({}): Serial number is missing in message.", CId_));
			return;
		}

		auto Serial =
			Poco::trim(Poco::toLower(ParamsObj->get(uCentralProtocol::SERIAL).toString()));
		if (!Utils::ValidSerialNumber(Serial)) {
			Poco::Exception E(
				fmt::format(
					"ILLEGAL-DEVICE-NAME({}): device name is illegal and not allowed to connect.",
					Serial),
				EACCES);
			E.rethrow();
		}

		std::string reason, author;
		std::uint64_t created;
		if (StorageService()->IsBlackListed(SerialNumberInt_, reason, author, created)) {
			DeviceBlacklistedKafkaEvent KE(Utils::SerialNumberToInt(CN_), Utils::Now(), reason,
										   author, created, CId_);
			Poco::Exception E(
				fmt::format("BLACKLIST({}): device is blacklisted and not allowed to connect.",
							Serial),
				EACCES);
			E.rethrow();
		}

		switch (EventType) {
		case uCentralProtocol::Events::ET_CONNECT: {
			++MemoryDiagnostics::ConnectEvents;
			Process_connect(ParamsObj, Serial);
		} break;

		case uCentralProtocol::Events::ET_STATE: {
			++MemoryDiagnostics::StateEvents;
			Process_state(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_HEALTHCHECK: {
			++MemoryDiagnostics::HealthcheckEvents;
			Process_healthcheck(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_LOG: {
			Process_log(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_CRASHLOG: {
			Process_crashlog(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_PING: {
			++MemoryDiagnostics::PingEvents;
			Process_ping(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_CFGPENDING: {
			Process_cfgpending(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_RECOVERY: {
			Process_recovery(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_DEVICEUPDATE: {
			Process_deviceupdate(ParamsObj, Serial);
		} break;

		case uCentralProtocol::Events::ET_TELEMETRY: {
			++MemoryDiagnostics::TelemetryEvents;
			Process_telemetry(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_VENUEBROADCAST: {
			Process_venuebroadcast(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_EVENT: {
			Process_event(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_ALARM: {
			Process_alarm(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_WIFISCAN: {
			Process_wifiscan(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_REBOOTLOG: {
			Process_rebootLog(ParamsObj);
		} break;

		case uCentralProtocol::Events::ET_UNKNOWN: {
			poco_warning(Logger_, fmt::format("ILLEGAL-EVENT({}): Event '{}' unknown. CN={}", CId_,
											  Method, CN_));
			Errors_++;
		} break;
		}
	}

	bool AP_Connection::StartTelemetry(uint64_t RPCID,
									   const std::vector<std::string> &TelemetryTypes) {
		poco_information(Logger_, fmt::format("TELEMETRY({}): Starting.", CId_));
		Poco::JSON::Object StartMessage;
		StartMessage.set("jsonrpc", "2.0");
		StartMessage.set("method", "telemetry");
		Poco::JSON::Object Params;
		Params.set("serial", SerialNumber_);
		Params.set("interval", (uint64_t)TelemetryInterval_);
		Poco::JSON::Array Types;
		if (TelemetryTypes.empty()) {
			Types.add("wifi-frames");
			Types.add("dhcp-snooping");
			Types.add("state");
		} else {
			for (const auto &type : TelemetryTypes)
				Types.add(type);
		}
		Params.set(RESTAPI::Protocol::TYPES, Types);
		StartMessage.set("id", RPCID);
		StartMessage.set("params", Params);
		Poco::JSON::Stringifier Stringify;
		std::ostringstream OS;
		Stringify.condense(StartMessage, OS);
		return Send(OS.str());
	}

	bool AP_Connection::StopTelemetry(uint64_t RPCID) {
		poco_information(Logger_, fmt::format("TELEMETRY({}): Stopping.", CId_));
		Poco::JSON::Object StopMessage;
		StopMessage.set("jsonrpc", "2.0");
		StopMessage.set("method", "telemetry");
		Poco::JSON::Object Params;
		Params.set("serial", SerialNumber_);
		Params.set("interval", 0);
		StopMessage.set("id", RPCID);
		StopMessage.set("params", Params);
		Poco::JSON::Stringifier Stringify;
		std::ostringstream OS;
		Stringify.condense(StopMessage, OS);
		TelemetryKafkaPackets_ = TelemetryWebSocketPackets_ = TelemetryInterval_ =
			TelemetryKafkaTimer_ = TelemetryWebSocketTimer_ = 0;
		return Send(OS.str());
	}

	void AP_Connection::UpdateCounts() {
		State_.kafkaClients = TelemetryKafkaRefCount_;
		State_.webSocketClients = TelemetryWebSocketRefCount_;
	}

	bool AP_Connection::SetWebSocketTelemetryReporting(
		std::uint64_t RPCID, std::uint64_t Interval, std::uint64_t LifeTime,
		const std::vector<std::string> &TelemetryTypes) {
		std::unique_lock Lock(TelemetryMutex_);
		TelemetryWebSocketRefCount_++;
		TelemetryInterval_ =
			TelemetryInterval_
				? (Interval < (std::uint64_t)TelemetryInterval_ ? Interval
																: (std::uint64_t)TelemetryInterval_)
				: Interval;
		auto TelemetryWebSocketTimer = LifeTime + Utils::Now();
		TelemetryWebSocketTimer_ =
			TelemetryWebSocketTimer > (std::uint64_t)TelemetryWebSocketTimer_
				? (std::uint64_t)TelemetryWebSocketTimer
				: (std::uint64_t)TelemetryWebSocketTimer_;
		UpdateCounts();
		if (!TelemetryReporting_) {
			TelemetryReporting_ = true;
			return StartTelemetry(RPCID, TelemetryTypes);
		}
		return true;
	}

	bool AP_Connection::SetKafkaTelemetryReporting(uint64_t RPCID, uint64_t Interval,
												   uint64_t LifeTime,
												   const std::vector<std::string> &TelemetryTypes) {
		std::unique_lock Lock(TelemetryMutex_);
		TelemetryKafkaRefCount_++;
		TelemetryInterval_ =
			TelemetryInterval_
				? (Interval < (std::uint64_t)TelemetryInterval_
					   ? (std::uint64_t)Interval
					   : (std::uint64_t)TelemetryInterval_)
				: Interval;
		auto TelemetryKafkaTimer = LifeTime + Utils::Now();
		TelemetryKafkaTimer_ =
			TelemetryKafkaTimer > (std::uint64_t)TelemetryKafkaTimer_
				? (std::uint64_t)TelemetryKafkaTimer
				: (std::uint64_t)TelemetryKafkaTimer_;
		UpdateCounts();
		if (!TelemetryReporting_) {
			TelemetryReporting_ = true;
			return StartTelemetry(RPCID, TelemetryTypes);
		}
		return true;
	}

	bool AP_Connection::StopWebSocketTelemetry(uint64_t RPCID) {
		std::unique_lock Lock(TelemetryMutex_);
		if (TelemetryWebSocketRefCount_)
			TelemetryWebSocketRefCount_--;
		UpdateCounts();
		if (TelemetryWebSocketRefCount_ == 0 && TelemetryKafkaRefCount_ == 0) {
			TelemetryReporting_ = false;
			StopTelemetry(RPCID);
		}
		return true;
	}

	bool AP_Connection::StopKafkaTelemetry(uint64_t RPCID) {
		std::unique_lock Lock(TelemetryMutex_);
		if (TelemetryKafkaRefCount_)
			TelemetryKafkaRefCount_--;
		UpdateCounts();
		if (TelemetryWebSocketRefCount_ == 0 && TelemetryKafkaRefCount_ == 0) {
			TelemetryReporting_ = false;
			StopTelemetry(RPCID);
		}
		return true;
	}

	std::string AP_Connection::Base64Encode(const unsigned char *buffer, std::size_t size) {
		return Utils::base64encode(buffer, size);
	}

	std::string AP_Connection::Base64Decode(const std::string &F) {
		std::istringstream ifs(F);
		Poco::Base64Decoder b64in(ifs);
		std::ostringstream ofs;
		Poco::StreamCopier::copyStream(b64in, ofs);
		return ofs.str();
	}

	bool AP_Connection::SendRadiusAuthenticationData(const unsigned char *buffer,
													 std::size_t size) {
		Poco::JSON::Object Answer;
		Answer.set(uCentralProtocol::RADIUS, uCentralProtocol::RADIUSAUTH);
		Answer.set(uCentralProtocol::RADIUSDATA, Base64Encode(buffer, size));

		std::ostringstream Payload;
		Answer.stringify(Payload);
		return Send(Payload.str());
	}

	bool AP_Connection::SendRadiusAccountingData(const unsigned char *buffer, std::size_t size) {
		Poco::JSON::Object Answer;
		Answer.set(uCentralProtocol::RADIUS, uCentralProtocol::RADIUSACCT);
		Answer.set(uCentralProtocol::RADIUSDATA, Base64Encode(buffer, size));

		std::ostringstream Payload;
		Answer.stringify(Payload);
		return Send(Payload.str());
	}

	bool AP_Connection::SendRadiusCoAData(const unsigned char *buffer, std::size_t size) {
		Poco::JSON::Object Answer;
		Answer.set(uCentralProtocol::RADIUS, uCentralProtocol::RADIUSCOA);
		Answer.set(uCentralProtocol::RADIUSDATA, Base64Encode(buffer, size));

		std::ostringstream Payload;
		Answer.stringify(Payload);
		return Send(Payload.str());
	}

	void AP_Connection::ProcessIncomingRadiusData(const Poco::JSON::Object::Ptr &Doc) {
		if (Doc->has(uCentralProtocol::RADIUSDATA)) {
			auto Type = Doc->get(uCentralProtocol::RADIUS).toString();
			if (Type == uCentralProtocol::RADIUSACCT) {
				auto Data = Doc->get(uCentralProtocol::RADIUSDATA).toString();
				auto DecodedData = Base64Decode(Data);
				RADIUS_proxy_server()->SendAccountingData(SerialNumber_, DecodedData.c_str(),
														  DecodedData.size());
			} else if (Type == uCentralProtocol::RADIUSAUTH) {
				auto Data = Doc->get(uCentralProtocol::RADIUSDATA).toString();
				auto DecodedData = Base64Decode(Data);
				RADIUS_proxy_server()->SendAuthenticationData(SerialNumber_, DecodedData.c_str(),
															  DecodedData.size());
			} else if (Type == uCentralProtocol::RADIUSCOA) {
				auto Data = Doc->get(uCentralProtocol::RADIUSDATA).toString();
				auto DecodedData = Base64Decode(Data);
				RADIUS_proxy_server()->SendCoAData(SerialNumber_, DecodedData.c_str(),
												   DecodedData.size());
			}
		}
	}

	void AP_Connection::SetLastStats(const std::string &LastStats) {
		RawLastStats_ = LastStats;
		try {
			Poco::JSON::Parser P;
			auto Stats = P.parse(LastStats).extract<Poco::JSON::Object::Ptr>();
			State_.hasGPS = Stats->isObject("gps");
			auto Unit = Stats->getObject("unit");
			auto Memory = Unit->getObject("memory");
			std::uint64_t TotalMemory = Memory->get("total");
			std::uint64_t FreeMemory = Memory->get("free");
			if (TotalMemory > 0) {
				State_.memoryUsed =
					(100.0 * ((double)TotalMemory - (double)FreeMemory)) / (double)TotalMemory;
			}
			if (Unit->isArray("load")) {
				Poco::JSON::Array::Ptr Load = Unit->getArray("load");
				if (Load->size() > 1) {
					State_.load = Load->get(1);
				}
			}
			if (Unit->isArray("temperature")) {
				Poco::JSON::Array::Ptr Temperature = Unit->getArray("temperature");
				if (Temperature->size() > 1) {
					State_.temperature = Temperature->get(0);
				}
			}
		} catch (const Poco::Exception &E) {
			poco_error(Logger_, "Failed to parse last stats: " + E.displayText());
		}
	}

} // namespace OpenWifi

/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
#include "AP_KAFKA_Server.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <sstream>

#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Environment.h>
#include <Poco/String.h>
#include <Poco/Thread.h>

#include <fmt/format.h>

#include "AP_KAFKA_Connection.h"
#include "AP_ServerProvider.h"
#include "StorageService.h"
#include "framework/KafkaManager.h"
#include "framework/KafkaTopics.h"
#include "framework/MicroServiceFuncs.h"
#include "framework/utils.h"

namespace OpenWifi {

	bool AP_KAFKA_Server::ValidateCertificate([[maybe_unused]] const std::string &ConnectionId,
											 [[maybe_unused]] const Poco::Crypto::X509Certificate
												 &Certificate) {
		return true;
	}

	int AP_KAFKA_Server::Start() {

		if (!KafkaManager()->Enabled()) {
			poco_fatal(Logger(), "KafkaManager is disabled hence exiting............");
			std::exit(Poco::Util::Application::EXIT_CONFIG);
		}

		if (WatcherId_ == 0) {
			Types::TopicNotifyFunction F = [this](const std::string &Key,
												 const std::string &Payload) {
				this->OnKafkaMessage(Key, Payload);
			};
			WatcherId_ = KafkaManager()->RegisterTopicWatcher(KafkaTopics::CNC_RES, F);
		}
		GarbageCollectorName="KFK-Session-Janitor";
		ReadEnvironment();
		InitDbSessions();
		SetJanitor("kafka:garbage");
		poco_information(Logger(), fmt::format("Kafka server started."));
		return 0;
	}

	void AP_KAFKA_Server::Stop() {

		poco_information(Logger(), "Stopping...");
		Running_ = false;

		GarbageCollector_.wakeUp();
		GarbageCollector_.join();

		if (WatcherId_ != 0) {
			KafkaManager()->UnregisterTopicWatcher(KafkaTopics::CNC_RES, WatcherId_);
			WatcherId_ = 0;
		}

		poco_information(Logger(), "Stopped...");
	}

	bool AP_KAFKA_Server::validateMethod(Poco::JSON::Object::Ptr msg, std::string &serial,const std::string &key) {
		if (Poco::trim(msg->get(uCentralProtocol::METHOD).toString()).empty()) {
			poco_warning(Logger(), fmt::format("Missing/empty METHOD. key='{}'", key));
			return false;
		}

		Poco::JSON::Object::Ptr params;
		if (!msg->isObject(uCentralProtocol::PARAMS) ||
			!(params = msg->getObject(uCentralProtocol::PARAMS)) || params->size() == 0) {
			poco_warning(Logger(), fmt::format("Missing/empty PARAMS. key='{}'", key));
			return false;
		}
		if (!params->has(uCentralProtocol::SERIAL)) {
			poco_warning(Logger(), fmt::format("Missing PARAMS.SERIAL. key='{}'", key));
			return false;
		}
		serial = Poco::trim(Poco::toLower(params->get(uCentralProtocol::SERIAL).toString()));
		if (serial.empty()) {
			poco_warning(Logger(), fmt::format("Empty PARAMS.SERIAL. key='{}'", key));
			return false;
		}
		return true;
	}

	bool AP_KAFKA_Server::validateResult(Poco::JSON::Object::Ptr msg, std::string &serial,const std::string &key) {

		Poco::JSON::Object::Ptr result;
		if (!msg->isObject(uCentralProtocol::RESULT) ||
			!(result = msg->getObject(uCentralProtocol::RESULT)) || result->size() == 0) {
			poco_warning(Logger(), fmt::format("Missing/empty RESULT. key='{}'", key));
			return false;
		}
		if (!result->has(uCentralProtocol::SERIAL)) {
			poco_warning(Logger(), fmt::format("Missing RESULT.SERIAL. key='{}'", key));
			return false;
		}
		serial = Poco::trim(Poco::toLower(result->get(uCentralProtocol::SERIAL).toString()));
		if (serial.empty()) {
			poco_warning(Logger(), fmt::format("Empty RESULT.SERIAL. key='{}'", key));
			return false;
		}
		return true;
	}

	bool AP_KAFKA_Server::recreateConnection(std::shared_ptr<AP_KAFKA_Connection> &KafkaConn, std::string &serial) {

			GWObjects::Device DeviceInfo;
			auto Session = NextDbSession();
			if (!StorageService()->GetDevice(*Session, serial, DeviceInfo)) {
				poco_warning(Logger(),
							 fmt::format("Kafka msg for non-connected device: {}. Device record not found.", serial));
				return false;
			}


			auto sessionId = ++session_id_;
			KafkaConn = std::make_shared<AP_KAFKA_Connection>(Logger(), Session, sessionId);
			AddConnection(KafkaConn);
			KafkaConn->Start();
			KafkaConn->setEssentials(DeviceInfo.ipAddress, serial, DeviceInfo.infraGroupId);
			KafkaConn->setRecreation(DeviceInfo);
			StartSession(sessionId, KafkaConn->SerialNumberInt_);

			poco_information(Logger(),
							 fmt::format("Kafka msg: recreated connection for {} session={},infraGroupId:{}", serial, sessionId,DeviceInfo.infraGroupId));
			return true;

	}

	void AP_KAFKA_Server::OnKafkaMessage(const std::string &key, const std::string &payload) {
		if (!Running_) {
			return;
		}
		try {
			Poco::JSON::Parser parser;
			Poco::JSON::Object::Ptr msg;
			msg = parser.parse(payload).extract<Poco::JSON::Object::Ptr>();
			if (msg->has("type")) {
				auto type = msg->get("type").toString();
				if (type == "infra_join") {
					return HandleInfraJoin(msg, key);
				}
				if (type == "infra_ping") {
					return HandleInfraPing(msg, key);
				}
				if (type == "infra_leave") {
					return HandleInfraLeave(msg, key);
				}
				if ((type == "infrastructure_group_infras_add_response") ||  (type == "infrastructure_group_infras_del_response")) {
					return HandleGroupIDChange(msg, key, type);
				}
				poco_warning(Logger(), fmt::format("Message Type Invalid: {}",type));
				return;
			}

			return HandleDeviceMessage(msg, key, payload);
		} catch (const Poco::Exception &E) {
			Logger().log(E);
		}

	}

	void AP_KAFKA_Server::HandleInfraJoin(Poco::JSON::Object::Ptr msg, const std::string &key) {
		if (!msg->has("connect_message_payload")) {
			poco_warning(Logger(), "Infra_join missing 'connect'.");
			return;
		}
		auto ConnectPayload = msg->get("connect_message_payload").toString();
		auto IP = msg->has("infra_public_ip") ? msg->get("infra_public_ip").toString() : "";
		auto InfraSerial = msg->has("infra_group_infra") ? msg->get("infra_group_infra").toString() : "";
		uint64_t InfraGroupId = 0;
		if(!msg->has("infra_group_id")){
			poco_warning(Logger(), fmt::format("Infra_join Group Id not found for SerialNumber {}", InfraSerial));
			return;	
		}
		InfraGroupId = msg->get("infra_group_id");

		if(ConnectPayload.empty() || IP.empty() || InfraSerial.empty() )
		{
			poco_warning(Logger(), fmt::format("Infra_join empty field connectPayload: {} IP: {}, InfraSerial:{}", ConnectPayload,IP,InfraSerial));
			return;
		}
		Poco::JSON::Parser parser;
		auto connectParsed = parser.parse(ConnectPayload).extract<Poco::JSON::Object::Ptr>();
		if (!connectParsed || !connectParsed->isObject(uCentralProtocol::PARAMS)) {
			poco_warning(Logger(), "Infra_join has invalid 'connect' payload.");
			return;
		}
		auto params = connectParsed->getObject(uCentralProtocol::PARAMS);
		if (!params->has("serial")) {
			poco_warning(Logger(), "Infra_join connect payload missing params.serial.");
			return;
		}

		auto serial = Poco::trim(Poco::toLower(params->get(uCentralProtocol::SERIAL).toString())); 
		
		if (serial.empty()){
			poco_warning(Logger(), fmt::format("Infra_join serial empty for this IP: {}", IP));
			return;	
		}	
		
		if (!Utils::NormalizeMac(InfraSerial)) {
			poco_warning(Logger(), fmt::format("Infra_join Invalid infra_group_infra: {}", InfraSerial));
			return;
		}

		if(!Utils::ValidSerialNumber(serial)){
			poco_warning(Logger(), fmt::format("Infra_join Invalid serial: {}", serial));
			return;	
		}

		if (InfraSerial != serial) {
			poco_warning(Logger(), fmt::format("Infra_join serial mismatch: infra='{}' connect='{}'", InfraSerial, serial));
			return;
		}
		if (Connected(Utils::SerialNumberToInt(serial))) {
			poco_information(Logger(),
							 fmt::format("Infra_join: device already connected: {}", serial));
			return;
		}
		auto sessionId = ++session_id_;
		auto Session = NextDbSession();
		auto NewConnection = std::make_shared<AP_KAFKA_Connection>( Logger(), Session, sessionId);
		AddConnection(NewConnection);
		NewConnection->Start();
		NewConnection->setEssentials(IP, InfraSerial, InfraGroupId);
		{
			std::lock_guard G(NewConnection->ConnectionMutex_);
			if (!NewConnection->PendingPayload_.empty()) {
				poco_warning(Logger(),
							 fmt::format("Infra_join overwriting pending payload for {}", serial));
			}
			NewConnection->PendingPayload_ = ConnectPayload;
		}
		NewConnection->ProcessIncomingFrame();
		poco_trace(Logger(),
						 fmt::format("Infra_join: connected {} session={} key='{}'", serial, sessionId,
									 key));
	}

	void AP_KAFKA_Server::HandleInfraPing(Poco::JSON::Object::Ptr msg, const std::string &key) {
		if (!msg->has("ping_message_payload")) {
			poco_warning(Logger(), "Infra_ping missing 'ping_message_payload'.");
			return;
		}

		auto PingPayload = msg->get("ping_message_payload").toString();
		auto IP = msg->has("infra_public_ip") ? msg->get("infra_public_ip").toString() : "";
		auto InfraSerial = msg->has("infra_group_infra") ? msg->get("infra_group_infra").toString() : "";

		if (PingPayload.empty() || InfraSerial.empty()) {
			poco_warning(Logger(), fmt::format("Infra_ping empty field pingPayload: {} InfraSerial:{}", PingPayload, InfraSerial));
			return;
		}

		if (!Utils::NormalizeMac(InfraSerial) || !Utils::ValidSerialNumber(InfraSerial)) {
			poco_warning(Logger(), fmt::format("Infra_ping Invalid infra_group_infra: {}", InfraSerial));
			return;
		}

		Poco::JSON::Parser parser;
		auto pingParsed = parser.parse(PingPayload).extract<Poco::JSON::Object::Ptr>();
		if (!pingParsed || !pingParsed->has(uCentralProtocol::METHOD) ||
				Poco::icompare(pingParsed->get(uCentralProtocol::METHOD).toString(), uCentralProtocol::PING) != 0) {
			poco_warning(Logger(), "Infra_ping has invalid 'ping_message_payload' method.");
			return;
		}

		Poco::JSON::Object::Ptr params;
		if (!pingParsed->isObject(uCentralProtocol::PARAMS) ||
			!(params = pingParsed->getObject(uCentralProtocol::PARAMS)) || params->size() == 0) {
			poco_warning(Logger(), "Infra_ping has invalid 'ping_message_payload' params.");
			return;
		}

		if (!params->has(uCentralProtocol::SERIAL)) {
			poco_warning(Logger(), "Infra_ping payload missing params.serial.");
			return;
		}

		auto serial = Poco::trim(Poco::toLower(params->get(uCentralProtocol::SERIAL).toString()));
		if (!Utils::NormalizeMac(serial) || !Utils::ValidSerialNumber(serial)) {
			poco_warning(Logger(), fmt::format("Infra_ping Invalid serial: {}", serial));
			return;
		}

		if (InfraSerial != serial) {
			poco_warning(Logger(), fmt::format("Infra_ping serial mismatch: infra='{}' ping='{}'", InfraSerial, serial));
			return;
		}

		params->set(uCentralProtocol::SERIAL, serial);
		if (!params->has(uCentralProtocol::CONNECTIONIP) && !IP.empty()) {
			params->set(uCentralProtocol::CONNECTIONIP, serial + "@" + IP);
		}

		std::ostringstream normalizedPayload;
		pingParsed->stringify(normalizedPayload);
		HandleDeviceMessage(pingParsed, key, normalizedPayload.str());
	}

	void AP_KAFKA_Server::InitDbSessions() {
		std::uint64_t NumberOfSessions = Poco::Environment::processorCount() * 4;
		if (NumberOfSessions == 0) {
			NumberOfSessions = 8;
		}
		NumberOfSessions = std::min<std::uint64_t>(NumberOfSessions, 128);
		DbSessions_.reserve(NumberOfSessions);
		for (std::uint64_t i = 0; i < NumberOfSessions; ++i) {
			DbSessions_.emplace_back(std::make_shared<LockedDbSession>());
		}
		poco_information(Logger(),
						 fmt::format("Kafka DB session pool: {} sessions.", NumberOfSessions));
	}

	std::shared_ptr<LockedDbSession> AP_KAFKA_Server::NextDbSession() {
		std::lock_guard Lock(DbSessionMutex_);
		if (DbSessions_.empty()) {
			DbSessions_.emplace_back(std::make_shared<LockedDbSession>());
		}
		NextDbSession_++;
		NextDbSession_ %= DbSessions_.size();
		return DbSessions_[NextDbSession_];
	}

	void AP_KAFKA_Server::HandleInfraLeave(Poco::JSON::Object::Ptr msg, const std::string &key) {
		auto InfraSerial = msg->has("infra_group_infra") ? msg->get("infra_group_infra").toString() : "";
		if (InfraSerial.empty()){
			poco_warning(Logger(), fmt::format("Infra_leave serials empty"));
			return;
		}

		if (!Utils::NormalizeMac(InfraSerial) || !Utils::ValidSerialNumber(InfraSerial)) {
			poco_warning(Logger(), fmt::format("Invalid serial: {}", InfraSerial));
			return;
		}

		auto serialInt = Utils::SerialNumberToInt(InfraSerial);
		if (!Connected(serialInt)) {
			poco_information(Logger(),
							 fmt::format("Infra_leave: Device Not Connected: {}", InfraSerial));
			return;
		}

		auto Conn = GetConnection(serialInt);
		if (!Conn) {
			poco_information(Logger(), fmt::format("Infra_leave:AP_Connection not found: {}", InfraSerial));
			return;
		}

		Conn->EndConnection();
		poco_information(Logger(), fmt::format("Infra_leave: disconnected {}", InfraSerial));
	}

	void AP_KAFKA_Server::HandleDeviceMessage(Poco::JSON::Object::Ptr msg, const std::string &key,
											 const std::string &payload) {  
		if (!msg) {
			poco_warning(Logger(), fmt::format("Kafka msg: null JSON object. key='{}'", key));
			return;
		}

		std::string serial;
		if (msg->has(uCentralProtocol::METHOD)) {

			if(!validateMethod(msg,serial,key))
				return;
		} else {
			if(!validateResult(msg,serial,key))
				return;
		}

		if (!Utils::NormalizeMac(serial) || !Utils::ValidSerialNumber(serial)) {
			poco_warning(Logger(), fmt::format("Invalid serial: {}", serial));
			return;
		}

		auto serialInt = Utils::SerialNumberToInt(serial);
		auto Conn = GetConnection(serialInt);
		std::shared_ptr<AP_KAFKA_Connection> KafkaConn;

		if (!Conn) {
			poco_warning(Logger(), fmt::format("Kafka msg for non-connected device: {}", serial));
			if (!recreateConnection(KafkaConn,serial))
				return;
			
		} else {
			KafkaConn = std::static_pointer_cast<AP_KAFKA_Connection>(Conn);
		}

		{
			std::lock_guard G(KafkaConn->ConnectionMutex_);
			if (!KafkaConn->PendingPayload_.empty()) {
				poco_warning(Logger(), fmt::format("Overwriting pending payload for {}", serial));
			}
			KafkaConn->PendingPayload_ = payload;
		}
		KafkaConn->ProcessIncomingFrame();

	}
		
	void AP_KAFKA_Server::HandleGroupIDChange(Poco::JSON::Object::Ptr msg, const std::string &key,const std::string &type) {  
		if (!msg) {
			poco_warning(Logger(), fmt::format("Kafka msg: null JSON object. key='{}'", key));
			return;
		}
		std::string InfraSerial;
		if (msg->has("infra_group_infra") && msg->isArray("infra_group_infra")) {
			auto Infras = msg->getArray("infra_group_infra");
			if (Infras != nullptr && !Infras->empty()) {
				InfraSerial = Infras->getElement<std::string>(0);
			}
		}
		const auto InfraGroupId = msg->has("infra_group_id")? msg->get("infra_group_id").convert<std::uint64_t>() : 0ULL;
		if (InfraSerial.empty() || InfraGroupId == 0){
			poco_warning(Logger(), fmt::format("GroupID Change: serials empty or group id missing for serial: {} , group id: {}", InfraSerial, InfraGroupId));
			return;
		}

		if (!Utils::NormalizeMac(InfraSerial) || !Utils::ValidSerialNumber(InfraSerial)) {
			poco_warning(Logger(), fmt::format("Invalid serial: {}", InfraSerial));
			return;
		}

		auto serialInt = Utils::SerialNumberToInt(InfraSerial);
		if (!Connected(serialInt)) {
			poco_information(Logger(), fmt::format("GroupID Change: Device Not Connected: {}", InfraSerial));
			return;
		}

		auto Conn = GetConnection(serialInt);
		if (!Conn) {
			poco_information(Logger(), fmt::format("GroupID Change:AP_Connection not found: {}", InfraSerial));
			return;
		}

		auto KafkaConn = std::static_pointer_cast<AP_KAFKA_Connection>(Conn);
		if (!KafkaConn) {
			poco_warning(Logger(), fmt::format("GroupID Change: connection type mismatch for {}", InfraSerial));
			return;
		}
		
		const auto GroupId = type == "infrastructure_group_infras_del_response" ? 0ULL : InfraGroupId;

		KafkaConn->UpdateGroupID(GroupId, InfraSerial);
	
	}

} // namespace OpenWifi

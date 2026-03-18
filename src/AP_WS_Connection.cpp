/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2022-02-03.
//


#include <Poco/JSON/Parser.h>
#include <Poco/JSON/JSONException.h>
#include <Poco/Net/Context.h>
#include <Poco/Net/HTTPServerRequestImpl.h>
#include <Poco/Net/HTTPServerResponseImpl.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SSLException.h>
#include <Poco/Net/SecureStreamSocketImpl.h>
#include <Poco/Net/WebSocketImpl.h>

#include <framework/KafkaManager.h>
#include <framework/MicroServiceFuncs.h>
#include <framework/utils.h>
#include <framework/ow_constants.h>

#include <fmt/format.h>

#include <AP_WS_Connection.h>
#include <AP_WS_Server.h>
#include <AP_ServerProvider.h>
#include <StorageService.h>
#include <GWKafkaEvents.h>

namespace OpenWifi {

	AP_WS_Connection::AP_WS_Connection(Poco::Net::HTTPServerRequest &request,
									   Poco::Net::HTTPServerResponse &response,
									   uint64_t session_id, Poco::Logger &L,
									   std::pair<std::shared_ptr<Poco::Net::SocketReactor>, std::shared_ptr<LockedDbSession>> R)
		: AP_Connection(L, R.second, session_id),IncomingFrame_(0) {

		Reactor_ = R.first;

		WS_ = std::make_unique<Poco::Net::WebSocket>(request, response);

		auto TS = Poco::Timespan(360, 0);

		WS_->setMaxPayloadSize(BufSize);
		WS_->setReceiveTimeout(TS);
		WS_->setNoDelay(false);
		WS_->setKeepAlive(true);
		WS_->setBlocking(false);
		IncomingFrame_.resize(0);
		uuid_ = MicroServiceRandom(std::numeric_limits<std::uint64_t>::max()-1);

		GetAPServer()->IncrementConnectionCount();
	}

	void AP_WS_Connection::Start() {
		Registered_ = true;
		LastContact_ = Utils::Now();

		Reactor_->addEventHandler(*WS_,
								  Poco::NObserver<AP_WS_Connection, Poco::Net::ReadableNotification>(
									  *this, &AP_WS_Connection::OnSocketReadable));
		Reactor_->addEventHandler(*WS_,
								  Poco::NObserver<AP_WS_Connection, Poco::Net::ShutdownNotification>(
									  *this, &AP_WS_Connection::OnSocketShutdown));
		Reactor_->addEventHandler(*WS_,
								  Poco::NObserver<AP_WS_Connection, Poco::Net::ErrorNotification>(
									  *this, &AP_WS_Connection::OnSocketError));

	}

	AP_WS_Connection::~AP_WS_Connection() {
		std::lock_guard G(ConnectionMutex_);
		GetAPServer()->DecrementConnectionCount();
		EndConnection();
		poco_debug(Logger_, fmt::format("TERMINATION({}): Session={}, Connection removed.", SerialNumber_,
										State_.sessionId));
	}

	void AP_WS_Connection::EndConnection() {
		bool expectedValue=false;
		if (Dead_.compare_exchange_strong(expectedValue,true,std::memory_order_release,std::memory_order_relaxed)) {

			if(!SerialNumber_.empty() && State_.LastContact!=0) {
				StorageService()->SetDeviceLastRecordedContact(SerialNumber_, State_.LastContact);
			}

			if (Registered_) {
				Registered_ = false;
				Reactor_->removeEventHandler(
					*WS_, Poco::NObserver<AP_WS_Connection, Poco::Net::ReadableNotification>(
							  *this, &AP_WS_Connection::OnSocketReadable));
				Reactor_->removeEventHandler(
					*WS_, Poco::NObserver<AP_WS_Connection, Poco::Net::ShutdownNotification>(
							  *this, &AP_WS_Connection::OnSocketShutdown));
				Reactor_->removeEventHandler(
					*WS_, Poco::NObserver<AP_WS_Connection, Poco::Net::ErrorNotification>(
							  *this, &AP_WS_Connection::OnSocketError));
				Registered_=false;
			}
			WS_->close();

			if(!SerialNumber_.empty()) {
				DeviceDisconnectionCleanup(SerialNumber_, uuid_);
			}
			GetAPServer()->AddCleanupSession(State_.sessionId, SerialNumberInt_);
		}
	}

	bool AP_WS_Connection::ValidatedDevice() {

		if(Dead_)
			return false;

		if (DeviceValidated_)
			return true;

		try {
			auto SockImpl = dynamic_cast<Poco::Net::WebSocketImpl *>(WS_->impl());
			auto SS =
				dynamic_cast<Poco::Net::SecureStreamSocketImpl *>(SockImpl->streamSocketImpl());
			Address_ = Utils::FormatIPv6(WS_->peerAddress().toString());
			PeerAddress_ = SS->peerAddress().host();
			CId_ = Utils::FormatIPv6(SS->peerAddress().toString());

			State_.started = Utils::Now();

			if (!SS->secure()) {
				poco_warning(Logger_, fmt::format("TLS-CONNECTION({}): Session={} Connection is "
												  "NOT secure. Device is not allowed.",
												  CId_, State_.sessionId));
				return false;
			}

			poco_trace(Logger_, fmt::format("TLS-CONNECTION({}): Session={} Connection is secure.",
											CId_, State_.sessionId));

			if (!SS->havePeerCertificate()) {
				State_.VerifiedCertificate = GWObjects::NO_CERTIFICATE;
				poco_warning(
					Logger_,
					fmt::format("TLS-CONNECTION({}): Session={} No certificates available..", CId_,
								State_.sessionId));
				return false;
			}

			Poco::Crypto::X509Certificate PeerCert(SS->peerCertificate());
			if (!GetAPServer()->ValidateCertificate(CId_, PeerCert)) {
				State_.VerifiedCertificate = GWObjects::NO_CERTIFICATE;
				poco_warning(Logger_,
							 fmt::format("TLS-CONNECTION({}): Session={} Device certificate is not "
										 "valid. Device is not allowed.",
										 CId_, State_.sessionId));
				return false;
			}

			CN_ = Poco::trim(Poco::toLower(PeerCert.commonName()));
			if(!Utils::ValidSerialNumber(CN_)) {
				poco_trace(Logger_,
						   fmt::format("TLS-CONNECTION({}): Session={} Invalid serial number: CN={}", CId_,
									   State_.sessionId, CN_));
				return false;
			}
			SerialNumber_ = CN_;
			SerialNumberInt_ = Utils::SerialNumberToInt(SerialNumber_);

			State_.VerifiedCertificate = GWObjects::VALID_CERTIFICATE;
			poco_trace(Logger_,
					   fmt::format("TLS-CONNECTION({}): Session={} Valid certificate: CN={}", CId_,
								   State_.sessionId, CN_));

			if (GetAPServer()->IsSim(CN_) && !GetAPServer()->IsSimEnabled()) {
				poco_warning(Logger_, fmt::format("TLS-CONNECTION({}): Session={} Sim Device {} is "
												  "not allowed. Disconnecting.",
												  CId_, State_.sessionId, CN_));
				return false;
			}

			if(GetAPServer()->IsSim(SerialNumber_)) {
				State_.VerifiedCertificate = GWObjects::SIMULATED;
				Simulated_ = true;
			}

			std::string reason, author;
			std::uint64_t created;
			if (!CN_.empty() && StorageService()->IsBlackListed(SerialNumberInt_, reason, author, created)) {
				DeviceBlacklistedKafkaEvent KE(Utils::SerialNumberToInt(CN_), Utils::Now(), reason, author, created, CId_);
				poco_warning(
					Logger_,
					fmt::format(
						"TLS-CONNECTION({}): Session={} Device {} is black listed. Disconnecting.",
						CId_, State_.sessionId, CN_));
				return false;
			}

			State_.certificateExpiryDate = PeerCert.expiresOn().timestamp().epochTime();
			State_.certificateIssuerName = PeerCert.issuerName();

			poco_trace(Logger_,
					   fmt::format("TLS-CONNECTION({}): Session={} CN={} Completed. (t={})", CId_,
								   State_.sessionId, CN_, ConcurrentStartingDevices_));
			DeviceValidated_ = true;
			return true;

		} catch (const Poco::Net::CertificateValidationException &E) {
			poco_error(
				Logger_,
				fmt::format(
					"CONNECTION({}): Session:{} Poco::CertificateValidationException Certificate "
					"Validation failed during connection. Device will have to retry.",
					CId_, State_.sessionId));
			Logger_.log(E);
		} catch (const Poco::Net::WebSocketException &E) {
			poco_error(Logger_,
					   fmt::format("CONNECTION({}): Session:{} Poco::WebSocketException WebSocket "
								   "error during connection. Device will have to retry.",
								   CId_, State_.sessionId));
			Logger_.log(E);
		} catch (const Poco::Net::ConnectionAbortedException &E) {
			poco_error(
				Logger_,
				fmt::format("CONNECTION({}):Session:{}  Poco::ConnectionAbortedException "
							"Connection was aborted during connection. Device will have to retry.",
							CId_, State_.sessionId));
			Logger_.log(E);
		} catch (const Poco::Net::ConnectionResetException &E) {
			poco_error(
				Logger_,
				fmt::format("CONNECTION({}): Session:{} Poco::ConnectionResetException Connection "
							"was reset during connection. Device will have to retry.",
							CId_, State_.sessionId));
			Logger_.log(E);
		} catch (const Poco::Net::InvalidCertificateException &E) {
			poco_error(Logger_,
					   fmt::format("CONNECTION({}): Session:{} Poco::InvalidCertificateException "
								   "Invalid certificate. Device will have to retry.",
								   CId_, State_.sessionId));
			Logger_.log(E);
		} catch (const Poco::Net::SSLException &E) {
			poco_error(Logger_,
					   fmt::format("CONNECTION({}): Session:{} Poco::SSLException SSL Exception "
								   "during connection. Device will have to retry.",
								   CId_, State_.sessionId));
			Logger_.log(E);
		} catch (const Poco::Exception &E) {
			poco_error(Logger_, fmt::format("CONNECTION({}): Session:{} Poco::Exception caught "
											"during device connection. Device will have to retry.",
											CId_, State_.sessionId));
			Logger_.log(E);
		} catch (...) {
			poco_error(
				Logger_,
				fmt::format("CONNECTION({}): Session:{} Exception caught during device connection. "
							"Device will have to retry. Unsecure connect denied.",
							CId_, State_.sessionId));
		}
		EndConnection();
		return false;
	}

	void AP_WS_Connection::OnSocketShutdown(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ShutdownNotification> &pNf) {
		poco_trace(Logger_, fmt::format("SOCKET-SHUTDOWN({}): Closing.", CId_));
//		std::lock_guard	G(ConnectionMutex_);
		return EndConnection();
	}

	void AP_WS_Connection::OnSocketError(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ErrorNotification> &pNf) {
		poco_trace(Logger_, fmt::format("SOCKET-ERROR({}): Closing.", CId_));
//		std::lock_guard	G(ConnectionMutex_);
		return EndConnection();
	}

	void AP_WS_Connection::OnSocketReadable(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ReadableNotification> &pNf) {

		if (Dead_) //	we are dead, so we do not process anything.
			return;

		std::lock_guard	G(ConnectionMutex_);

		State_.LastContact = LastContact_ = Utils::Now();
		if (GetAPServer()->Running() && (DeviceValidated_ || ValidatedDevice())) {
			try {
				return ProcessIncomingFrame();
			} catch (const Poco::Exception &E) {
				Logger_.log(E);
			} catch (const std::exception &E) {
				std::string W = E.what();
				poco_information(
					Logger_, fmt::format("std::exception caught: {}. Connection terminated with {}",
										 W, CId_));
			} catch (...) {
				poco_information(
					Logger_, fmt::format("Unknown exception for {}. Connection terminated.", CId_));
			}
		}
		EndConnection();
	}

	void AP_WS_Connection::ProcessWSFinalPayload() {
		auto IncomingSize = IncomingFrame_.size();

		if (IncomingSize == 0) {
			poco_debug(Logger_,
						 fmt::format("ProcessWSFrame({}): Final Acc. Frame received but empty",
									 CId_));
			return;
		}
		IncomingFrame_.append(0);

		poco_trace(Logger_,
				   fmt::format("ProcessWSFrame({}): Final Acc. Frame received (len={}, Msg={}",
							   CId_, IncomingSize, IncomingFrame_.begin()));

		Poco::JSON::Parser parser;
		auto ParsedMessage = parser.parse(IncomingFrame_.begin());
		auto IncomingJSON = ParsedMessage.extract<Poco::JSON::Object::Ptr>();

		if (IncomingJSON->has(uCentralProtocol::JSONRPC)) {
			if (IncomingJSON->has(uCentralProtocol::METHOD) &&
				IncomingJSON->has(uCentralProtocol::PARAMS)) {
				ProcessJSONRPCEvent(IncomingJSON);
			} else if (IncomingJSON->has(uCentralProtocol::RESULT) &&
					   IncomingJSON->has(uCentralProtocol::ID)) {
				poco_trace(Logger_, fmt::format("RPC-RESULT({}): payload: {}", CId_,
												IncomingFrame_.begin()));
				ProcessJSONRPCResult(IncomingJSON);
			} else {
				poco_warning(
					Logger_,
					fmt::format("INVALID-PAYLOAD({}): Payload is not JSON-RPC 2.0: {}",
								CId_, IncomingFrame_.begin()));
			}
		} else if (IncomingJSON->has(uCentralProtocol::RADIUS)) {
			ProcessIncomingRadiusData(IncomingJSON);
		} else {
			std::ostringstream iS;
			IncomingJSON->stringify(iS);
			poco_warning(
				Logger_,
				fmt::format("FRAME({}): illegal transaction header, missing 'jsonrpc': {}",
							CId_, iS.str()));
			Errors_++;
		}
		IncomingFrame_.clear();
		IncomingFrame_.resize(0);
	}

	void AP_WS_Connection::ProcessIncomingFrame() {
		Poco::Buffer<char> CurrentFrame(0);
		bool KillConnection = false;
		int flags = 0;
		int IncomingSize = 0;

		try {
			IncomingSize = WS_->receiveFrame(CurrentFrame, flags);
			int Op;

			Op = flags & Poco::Net::WebSocket::FRAME_OP_BITMASK;

			if (IncomingSize < 0 && flags == 0) {
				poco_trace(Logger_,
					fmt::format("EMPTY({}): Non-blocking try-again empty frame (len={}, flags={})",
							   CId_, IncomingSize, flags));
            } else if (IncomingSize == 0 && flags == 0) {
				poco_information(Logger_,
								 fmt::format("DISCONNECT({}): device has disconnected. Session={}",
											 CId_, State_.sessionId));
				return EndConnection();
			}

			if (IncomingSize > 0) {
				State_.RX += IncomingSize;
				GetAPServer()->AddRX(IncomingSize);
				IncomingFrame_.append(CurrentFrame);
			}
			State_.MessageCount++;
			State_.LastContact = Utils::Now();
			poco_trace(Logger_,
					   fmt::format("FRAME({}): Frame rx (op={} len={}, flags={}, acc.len={})",
								   CId_, Op, IncomingSize, flags, IncomingFrame_.size()));

			switch (Op) {
				case Poco::Net::WebSocket::FRAME_OP_PING: {
					poco_trace(Logger_, fmt::format("PING({}): received. PONG sent back.", CId_));
					WS_->sendFrame("", 0,
								   (int)Poco::Net::WebSocket::FRAME_OP_PONG |
								   (int)Poco::Net::WebSocket::FRAME_FLAG_FIN);

					if (KafkaManager()->Enabled()) {
						Poco::JSON::Object PingObject;
						Poco::JSON::Object PingDetails;
						PingDetails.set(uCentralProtocol::FIRMWARE, State_.Firmware);
						PingDetails.set(uCentralProtocol::SERIALNUMBER, SerialNumber_);
						PingDetails.set(uCentralProtocol::COMPATIBLE, Compatible_);
						PingDetails.set(uCentralProtocol::CONNECTIONIP, CId_);
						PingDetails.set(uCentralProtocol::TIMESTAMP, Utils::Now());
						PingDetails.set(uCentralProtocol::UUID, uuid_);
						PingDetails.set("locale", State_.locale);
						PingObject.set(uCentralProtocol::PING, PingDetails);
						poco_trace(Logger_,fmt::format("Sending PING for {}", SerialNumber_));
						KafkaManager()->PostMessage(KafkaTopics::CONNECTION, SerialNumber_,
													PingObject);
					}
					return;
				} break;

				case Poco::Net::WebSocket::FRAME_OP_PONG: {
					poco_trace(Logger_, fmt::format("PONG({}): received and ignored.", CId_));
					return;
				} break;

				case Poco::Net::WebSocket::FRAME_OP_CONT: {
					poco_trace(Logger_, fmt::format("CONTINUATION({}): registered.", CId_));
				} break;

				case Poco::Net::WebSocket::FRAME_OP_BINARY: {
					poco_trace(Logger_, fmt::format("BINARY({}): Invalid frame type.", CId_));
					KillConnection=true;
					return;
				} break;

				case Poco::Net::WebSocket::FRAME_OP_TEXT: {
					poco_trace(Logger_,
							   fmt::format("TEXT({}): Frame received (len={}, flags={}). Msg={}",
										   CId_, IncomingSize, flags,
										   CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin()));
				} break;

				case Poco::Net::WebSocket::FRAME_OP_CLOSE: {
					poco_information(Logger_,
									 fmt::format("CLOSE({}): Device is closing its connection.", CId_));
					KillConnection=true;
				} break;

				default: {
					poco_warning(Logger_, fmt::format("UNKNOWN({}): unknown WS Frame operation: {}",
													  CId_, std::to_string(Op)));
					Errors_++;
					return;
				}
			}

			// Check for final frame and process accumulated payload
			if (!KillConnection && (flags & Poco::Net::WebSocket::FRAME_FLAG_FIN) != 0) {
				ProcessWSFinalPayload();
			}

		} catch (const Poco::Net::ConnectionResetException &E) {
			poco_warning(Logger_,
						 fmt::format("ConnectionResetException({}): Text:{} Payload:{} Session:{}",
									 CId_, E.displayText(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::JSON::JSONException &E) {
			poco_warning(Logger_,
						 fmt::format("JSONException({}): Text:{} Payload:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::WebSocketException &E) {
			poco_warning(Logger_,
						 fmt::format("WebSocketException({}): Text:{} Payload:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::SSLConnectionUnexpectedlyClosedException &E) {
			poco_warning(
				Logger_,
				fmt::format(
					"SSLConnectionUnexpectedlyClosedException({}): Text:{} Payload:{} Session:{}",
					CId_, E.displayText(),
					CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
					State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::SSLException &E) {
			poco_warning(Logger_,
						 fmt::format("SSLException({}): Text:{} Payload:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::NetException &E) {
			poco_warning(Logger_,
						 fmt::format("NetException({}): Text:{} Payload:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::IOException &E) {
			poco_warning(Logger_,
						 fmt::format("IOException({}): Text:{} Payload:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Exception &E) {
			poco_warning(Logger_,
						 fmt::format("Exception({}): Text:{} Payload:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const std::exception &E) {
			poco_warning(Logger_,
						 fmt::format("std::exception({}): Text:{} Payload:{} Session:{}", CId_,
									 E.what(),
									 CurrentFrame.begin() == nullptr ? "" : CurrentFrame.begin(),
									 State_.sessionId));
			KillConnection=true;
		} catch (...) {
			poco_error(Logger_, fmt::format("UnknownException({}): Device must be disconnected. "
											"Unknown exception.  Session:{}",
											CId_, State_.sessionId));
			KillConnection=true;
		}

		if (!KillConnection && Errors_ < 10)
			return;

		poco_warning(Logger_,
				fmt::format("DISCONNECTING({}): ConnectionException: {} Errors: {}",
							CId_, KillConnection, Errors_ ));
		EndConnection();
	}

	bool AP_WS_Connection::Send(const std::string &Payload,std::chrono::milliseconds WaitTimeInMs ) {
		try {
			size_t BytesSent = WS_->sendFrame(Payload.c_str(), (int)Payload.size());

			/*
			 * 	There is a possibility to actually try and send data but the device is no longer
			 * listening. This code attempts to wait 5 seconds to see if the device is actually
			 * still listening. if the data is not acked under 5 seconds, then we consider that the
			 * data never made it or the device is disconnected somehow.
			 */
#if defined(__APPLE__)
			tcp_connection_info info;
			int timeout = 4000;
			auto expireAt = std::chrono::system_clock::now() + std::chrono::milliseconds(timeout);
			do {
				std::this_thread::sleep_for(std::chrono::milliseconds(50));
				socklen_t opt_len = sizeof(info);
				getsockopt(WS_->impl()->sockfd(), SOL_SOCKET, TCP_CONNECTION_INFO, (void *)&info,
						   &opt_len);
			} while (!info.tcpi_tfo_syn_data_acked && expireAt > std::chrono::system_clock::now());
			if (!info.tcpi_tfo_syn_data_acked)
				return false;
#else
			tcp_info info;
			int timeout = 4000;
			auto expireAt = std::chrono::system_clock::now() + std::chrono::milliseconds(timeout);
			do {
				std::this_thread::sleep_for(std::chrono::milliseconds(20));
				socklen_t opt_len = sizeof(info);
				getsockopt(WS_->impl()->sockfd(), SOL_TCP, TCP_INFO, (void *)&info, &opt_len);
			} while (info.tcpi_unacked > 0 && expireAt > std::chrono::system_clock::now());

			if (info.tcpi_unacked > 0) {
				return false;
			}
#endif
			State_.TX += BytesSent;
			GetAPServer()->AddTX(BytesSent);
			return BytesSent == Payload.size();
		} catch (const Poco::Exception &E) {
			Logger_.log(E);
		}
		return false;
	}

} // namespace OpenWifi

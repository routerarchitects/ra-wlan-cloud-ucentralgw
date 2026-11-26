/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 * Portions copyright (c) Telecom Infra Project (TIP), BSD-3-Clause
 */
//
// Created by stephane bourque on 2022-02-03.
//


#include <Poco/AbstractObserver.h>
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

	namespace {
		// A registered observer owns only a weak reference. A callback takes a
		// strong reference for its duration; failed observer removal cannot
		// result in a callback dereferencing a destroyed AP. No callback mutex
		// is held across connection processing (avoids a lock-order inversion).
		template <typename N> class WeakAPObserver final : public Poco::AbstractObserver {
			using Handler = void (AP_WS_Connection::*)(const Poco::AutoPtr<N> &);
		  public:
			WeakAPObserver(std::weak_ptr<AP_WS_Connection> connection, Handler handler)
				: connection_(std::move(connection)), handler_(handler) {}
			void notify(Poco::Notification *notification) const override {
				if (!enabled_) return;
				if (auto connection = connection_.lock()) {
					if (auto *n = dynamic_cast<N *>(notification); n && enabled_)
						(connection.get()->*handler_)(Poco::AutoPtr<N>(n, true));
				}
			}
			bool equals(const Poco::AbstractObserver &other) const override {
				auto *o = dynamic_cast<const WeakAPObserver *>(&other);
				return o && handler_ == o->handler_ &&
					!connection_.owner_before(o->connection_) && !o->connection_.owner_before(connection_);
			}
			bool accepts(Poco::Notification *n, const char *name) const override {
				return enabled_ && n && (!name || n->name() == name) && dynamic_cast<N *>(n);
			}
			bool accepts(const Poco::Notification::Ptr &n) const override {
				return enabled_ && dynamic_cast<N *>(n.get());
			}
			Poco::AbstractObserver *clone() const override {
				return new WeakAPObserver(connection_, handler_);
			}
			void disable() override { enabled_ = false; }
		  private:
			std::weak_ptr<AP_WS_Connection> connection_;
			Handler handler_;
			std::atomic_bool enabled_{true};
		};
	}

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
		std::lock_guard G(ConnectionMutex_);
		if (Dead_ || !GetAPServer()->Running()) {
			EndConnection();
			return;
		}
		Registered_ = true;
		LastContact_ = Utils::Now();
		try {
			Reactor_->addEventHandler(*WS_, WeakAPObserver<Poco::Net::ReadableNotification>(
				weak_from_this(), &AP_WS_Connection::OnSocketReadable));
			Reactor_->addEventHandler(*WS_, WeakAPObserver<Poco::Net::ShutdownNotification>(
				weak_from_this(), &AP_WS_Connection::OnSocketShutdown));
			Reactor_->addEventHandler(*WS_, WeakAPObserver<Poco::Net::ErrorNotification>(
				weak_from_this(), &AP_WS_Connection::OnSocketError));
		} catch (...) {
			// Registration can fail after installing some observers.
			EndConnection();
			throw;
		}
	}

	AP_WS_Connection::~AP_WS_Connection() {
		// Callbacks hold a strong reference. Remove observers independently
		// while the descriptor is valid, even if an earlier operation fails.
		if (Registered_.exchange(false)) {
			TeardownStep("Remove readable observer failed", [&] {
				Reactor_->removeEventHandler(*WS_, WeakAPObserver<Poco::Net::ReadableNotification>(
					weak_from_this(), &AP_WS_Connection::OnSocketReadable));
			});
			TeardownStep("Remove shutdown observer failed", [&] {
				Reactor_->removeEventHandler(*WS_, WeakAPObserver<Poco::Net::ShutdownNotification>(
					weak_from_this(), &AP_WS_Connection::OnSocketShutdown));
			});
			TeardownStep("Remove error observer failed", [&] {
				Reactor_->removeEventHandler(*WS_, WeakAPObserver<Poco::Net::ErrorNotification>(
					weak_from_this(), &AP_WS_Connection::OnSocketError));
			});
		}
		TeardownStep("End connection failed", [&] { EndConnection(); });
		TeardownStep("Close socket failed", [&] {
			std::lock_guard write(SocketWriteMutex_);
			WS_->close();
		});
		GetAPServer()->DecrementConnectionCount();
		TeardownStep("Termination log failed", [&] {
			poco_debug(Logger_, fmt::format("TERMINATION({}): Session={}, Connection removed.",
				SerialNumber_, State_.sessionId));
		});
	}

	void AP_WS_Connection::ShutdownTransportLocked() noexcept {
		WritesDisabled_ = true;
		// WebSocket::shutdown sends a CLOSE frame; virtual TLS shutdown may
		// require a retry. This is forced teardown: use native TCP shutdown,
		// preserving the descriptor for reactor removal and final close.
		TeardownStep("TCP shutdown failed", [&] {
			using Poco::Net::SocketImpl;
			WS_->impl()->SocketImpl::shutdown();
		});
	}

	bool AP_WS_Connection::WriteFrame(const void *payload, int length, int flags) {
		std::lock_guard write(SocketWriteMutex_);
		if (Dead_ || WritesDisabled_ || !GetAPServer()->Running()) return false;
		try {
			if (WS_->sendFrame(payload, length, flags) == length) return true;
		} catch (const Poco::Exception &e) {
			TeardownStep("WebSocket send error log failed", [&] { Logger_.log(e); });
		} catch (...) {
			TeardownStep("WebSocket send error log failed", [&] { Logger_.error("WebSocket send failed"); });
		}
		// Poco retains an incomplete nonblocking frame and requires the same
		// payload on retry. Do not allow a later command/PONG to reuse that
		// pending frame. Fail this send and wake the reactor for teardown.
		ShutdownTransportLocked();
		return false;
	}

	void AP_WS_Connection::EndConnection() {
		std::lock_guard G(ConnectionMutex_);
		bool expectedValue = false;
		if (!Dead_.compare_exchange_strong(expectedValue, true,
				std::memory_order_acq_rel)) return;

		TeardownStep("Transport shutdown failed", [&] {
			std::lock_guard write(SocketWriteMutex_);
			ShutdownTransportLocked();
		});
		if (!SessionAdmitted_) return;
		TeardownStep("Persist last contact failed", [&] {
			if (!SerialNumber_.empty() && State_.LastContact != 0)
				StorageService()->SetDeviceLastRecordedContact(SerialNumber_, State_.LastContact);
		});
		if (!SerialNumber_.empty()) DeviceDisconnectionCleanup(SerialNumber_, uuid_);
		GetAPServer()->AddCleanupSession(State_.sessionId, SerialNumberInt_);
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
		// The observer must remain registered until safe destruction. Avoid
		// formatting logs or taking the connection lock for already-dead sockets.
		if (Dead_.load(std::memory_order_acquire)) {
			return;
		}
		std::lock_guard G(ConnectionMutex_);
		// Recheck under the recursive mutex shared with EndConnection() so only
		// the callback that actually initiates teardown can emit this log.
		if (Dead_.load(std::memory_order_acquire)) {
			return;
		}
		poco_trace(Logger_, fmt::format("SOCKET-SHUTDOWN({}): Closing.", CId_));
		return EndConnection();
	}

	void AP_WS_Connection::OnSocketError(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ErrorNotification> &pNf) {
		// The observer must remain registered until safe destruction. Avoid
		// formatting logs or taking the connection lock for already-dead sockets.
		if (Dead_.load(std::memory_order_acquire)) {
			return;
		}
		std::lock_guard G(ConnectionMutex_);
		// Recheck under the recursive mutex shared with EndConnection() so only
		// the callback that actually initiates teardown can emit this log.
		if (Dead_.load(std::memory_order_acquire)) {
			return;
		}
		poco_trace(Logger_, fmt::format("SOCKET-ERROR({}): Closing.", CId_));
		return EndConnection();
	}

	void AP_WS_Connection::OnSocketReadable(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ReadableNotification> &pNf) {

		std::lock_guard G(ConnectionMutex_);
		if (Dead_) return;
		if (WritesDisabled_) return EndConnection();
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


		Poco::JSON::Parser parser;
		auto ParsedMessage = parser.parse(IncomingFrame_.begin());
		auto IncomingJSON = ParsedMessage.extract<Poco::JSON::Object::Ptr>();
		// Trace metadata once per assembled message; never dump raw payloads.
		// A diagnostic conversion must not change protocol processing.
		try {
			if (Logger_.trace()) {
				poco_trace(Logger_, fmt::format(
			"WS-MESSAGE({}): session={} bytes={} method={:.128} rpc_id={:.128} jsonrpc={} radius={}",
			CId_, State_.sessionId, IncomingSize,
			IncomingJSON->has(uCentralProtocol::METHOD)
				? IncomingJSON->get(uCentralProtocol::METHOD).toString() : "-",
			IncomingJSON->has(uCentralProtocol::ID)
				? IncomingJSON->get(uCentralProtocol::ID).toString() : "-",
			IncomingJSON->has(uCentralProtocol::JSONRPC), IncomingJSON->has(uCentralProtocol::RADIUS)));
			}
		} catch (...) {
			// Best-effort metadata only; retain existing dispatch semantics.
		}

		if (IncomingJSON->has(uCentralProtocol::JSONRPC)) {
			if (IncomingJSON->has(uCentralProtocol::METHOD) &&
				IncomingJSON->has(uCentralProtocol::PARAMS)) {
				ProcessJSONRPCEvent(IncomingJSON);
			} else if (IncomingJSON->has(uCentralProtocol::RESULT) &&
					   IncomingJSON->has(uCentralProtocol::ID)) {
				ProcessJSONRPCResult(IncomingJSON);
			} else {
				poco_warning(
					Logger_,
					fmt::format("INVALID-PAYLOAD({}): invalid JSON-RPC envelope session={} bytes={}",
								CId_, State_.sessionId, IncomingSize));
			}
		} else if (IncomingJSON->has(uCentralProtocol::RADIUS)) {
			ProcessIncomingRadiusData(IncomingJSON);
		} else {
			poco_warning(Logger_, fmt::format(
				"FRAME({}): missing jsonrpc header session={} bytes={}", CId_, State_.sessionId, IncomingSize));
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

			if (IncomingSize < 0) {
				// EAGAIN from a non-blocking socket: there is no frame to process.
				return;
			} else if (IncomingSize == 0 && flags == 0) {
				poco_debug(Logger_,
								 fmt::format("DISCONNECT({}): device has disconnected. Session={}",
											 CId_, State_.sessionId));
				return EndConnection();
			}

			if (IncomingSize > 0) {
				State_.RX += IncomingSize;
				GetAPServer()->AddRX(IncomingSize);
			}
			State_.MessageCount++;
			State_.LastContact = LastContact_ = Utils::Now();

			switch (Op) {
				case Poco::Net::WebSocket::FRAME_OP_PING: {
					if (!WriteFrame(IncomingSize > 0 ? CurrentFrame.begin() : "", IncomingSize,
							Poco::Net::WebSocket::FRAME_OP_PONG | Poco::Net::WebSocket::FRAME_FLAG_FIN))
						return EndConnection();

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
						KafkaManager()->PostMessage(KafkaTopics::CONNECTION, SerialNumber_,
													PingObject);
					}
					poco_trace(Logger_, fmt::format("PING({}): session={} bytes={} flags={} reply=pong kafka_enabled={}", CId_, State_.sessionId, IncomingSize, flags, KafkaManager()->Enabled()));
					return;
				} break;

				case Poco::Net::WebSocket::FRAME_OP_PONG: {
					poco_trace(Logger_, fmt::format("PONG({}): session={} bytes={} flags={} outcome=ignored", CId_, State_.sessionId, IncomingSize, flags));
					return;
				} break;

				case Poco::Net::WebSocket::FRAME_OP_CONT: {
				} break;

				case Poco::Net::WebSocket::FRAME_OP_BINARY: {
					poco_trace(Logger_, fmt::format("BINARY({}): Invalid frame type.", CId_));
					KillConnection=true;
					break;
				} break;

				case Poco::Net::WebSocket::FRAME_OP_TEXT: {
				} break;

				case Poco::Net::WebSocket::FRAME_OP_CLOSE: {
					poco_debug(Logger_,
									 fmt::format("CLOSE({}): session={} bytes={} flags={} errors={}", CId_, State_.sessionId, IncomingSize, flags, Errors_));
					KillConnection=true;
				} break;

				default: {
					poco_warning(Logger_, fmt::format("UNKNOWN({}): unknown WS Frame operation: {}",
													  CId_, std::to_string(Op)));
					Errors_++;
					return;
				}
			}

			// Only data frames belong in the JSON message buffer. PING and
			// PONG can interrupt a fragmented text message without altering it.
			if (!KillConnection &&
				(Op == Poco::Net::WebSocket::FRAME_OP_TEXT ||
				 Op == Poco::Net::WebSocket::FRAME_OP_CONT)) {
				const bool continuation = Op == Poco::Net::WebSocket::FRAME_OP_CONT;
				const bool finalFrame = (flags & Poco::Net::WebSocket::FRAME_FLAG_FIN) != 0;
				const auto decision = FramePolicy_.AcceptData(
					continuation, finalFrame, IncomingFrame_.size(),
					static_cast<std::size_t>(IncomingSize));
				if (decision != AP_WS_FramePolicy::Decision::accept) {
					poco_warning(Logger_, fmt::format(
						"Invalid WebSocket message ({}) for {}: accumulated={} incoming={}",
						decision == AP_WS_FramePolicy::Decision::tooLarge ? "too large" : "frame sequence",
						CId_, IncomingFrame_.size(), IncomingSize));
					KillConnection = true;
				} else {
					if (IncomingSize > 0) IncomingFrame_.append(CurrentFrame);
					if (finalFrame) ProcessWSFinalPayload();
				}
			}

		} catch (const Poco::Net::ConnectionResetException &E) {
			poco_warning(Logger_,
						 fmt::format("ConnectionResetException({}): Text:{} FrameBytes:{} Session:{}",
									 CId_, E.displayText(),
									 CurrentFrame.size(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::JSON::JSONException &E) {
			poco_warning(Logger_,
						 fmt::format("JSONException({}): Text:{} FrameBytes:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.size(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::WebSocketException &E) {
			poco_warning(Logger_,
						 fmt::format("WebSocketException({}): Text:{} FrameBytes:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.size(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::SSLConnectionUnexpectedlyClosedException &E) {
			poco_warning(
				Logger_,
				fmt::format(
					"SSLConnectionUnexpectedlyClosedException({}): Text:{} FrameBytes:{} Session:{}",
					CId_, E.displayText(),
					CurrentFrame.size(),
					State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::SSLException &E) {
			poco_warning(Logger_,
						 fmt::format("SSLException({}): Text:{} FrameBytes:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.size(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Net::NetException &E) {
			poco_warning(Logger_,
						 fmt::format("NetException({}): Text:{} FrameBytes:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.size(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::IOException &E) {
			poco_warning(Logger_,
						 fmt::format("IOException({}): Text:{} FrameBytes:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.size(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const Poco::Exception &E) {
			poco_warning(Logger_,
						 fmt::format("Exception({}): Text:{} FrameBytes:{} Session:{}", CId_,
									 E.displayText(),
									 CurrentFrame.size(),
									 State_.sessionId));
			KillConnection=true;
		} catch (const std::exception &E) {
			poco_warning(Logger_,
						 fmt::format("std::exception({}): Text:{} FrameBytes:{} Session:{}", CId_,
									 E.what(),
									 CurrentFrame.size(),
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
			if (Payload.size() > static_cast<std::size_t>(std::numeric_limits<int>::max() - 16))
				return false;
			if (!WriteFrame(Payload.data(), static_cast<int>(Payload.size()),
					Poco::Net::WebSocket::FRAME_TEXT)) return false;
			const auto BytesSent = Payload.size();

			/*
			 * 	There is a possibility to actually try and send data but the device is no longer
			 * listening. This code attempts to wait 5 seconds to see if the device is actually
			 * still listening. if the data is not acked under 5 seconds, then we consider that the
			 * data never made it or the device is disconnected somehow.
			 */
#if defined(__APPLE__)
			tcp_connection_info info{};
			int timeout = 4000;
			auto expireAt = std::chrono::system_clock::now() + std::chrono::milliseconds(timeout);
			do {
				std::this_thread::sleep_for(std::chrono::milliseconds(50));
				socklen_t opt_len = sizeof(info);
				if (Dead_ || WritesDisabled_ || getsockopt(WS_->impl()->sockfd(), SOL_SOCKET,
						TCP_CONNECTION_INFO, (void *)&info, &opt_len) != 0) return false;
			} while (!info.tcpi_tfo_syn_data_acked && expireAt > std::chrono::system_clock::now());
			if (!info.tcpi_tfo_syn_data_acked)
				return false;
#else
			tcp_info info{};
			int timeout = 4000;
			auto expireAt = std::chrono::system_clock::now() + std::chrono::milliseconds(timeout);
			do {
				std::this_thread::sleep_for(std::chrono::milliseconds(20));
				socklen_t opt_len = sizeof(info);
				if (Dead_ || WritesDisabled_ || getsockopt(WS_->impl()->sockfd(), SOL_TCP,
						TCP_INFO, (void *)&info, &opt_len) != 0) return false;
			} while (info.tcpi_unacked > 0 && expireAt > std::chrono::system_clock::now());

			if (info.tcpi_unacked > 0) {
				return false;
			}
#endif
			SentBytes_.fetch_add(BytesSent, std::memory_order_relaxed);
			GetAPServer()->AddTX(BytesSent);
			return BytesSent == Payload.size();
		} catch (const Poco::Exception &E) {
			Logger_.log(E);
		}
		return false;
	}

} // namespace OpenWifi

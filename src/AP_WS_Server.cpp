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

#include <Poco/Net/Context.h>
#include <Poco/Net/HTTPHeaderStream.h>
#include <Poco/Net/HTTPServerRequest.h>

#include <AP_WS_Connection.h>
#include <AP_WS_Server.h>
#include <ConfigurationCache.h>
#include <TelemetryStream.h>

#include <fmt/format.h>

#include <framework/MicroServiceFuncs.h>
#include <framework/utils.h>
#include <framework/KafkaManager.h>

#include <UI_GW_WebSocketNotifications.h>

namespace OpenWifi {

	class AP_WS_RequestHandler : public Poco::Net::HTTPRequestHandler {
	  public:
		explicit AP_WS_RequestHandler(Poco::Logger &L, std::uint64_t session_id) : Logger_(L),
								   		session_id_(session_id) {
		 };

		void handleRequest(	Poco::Net::HTTPServerRequest &request,
						 	Poco::Net::HTTPServerResponse &response) override {
			try {
				auto NewConnection = std::make_shared<AP_WS_Connection>(request, response, session_id_, Logger_,
																		AP_WS_Server()->NextReactor());
				AP_WS_Server()->AddConnection(NewConnection);
				NewConnection->Start();
			} catch (...) {
				poco_warning(Logger_, "Exception during WS creation");
			}
		};

	  private:
		Poco::Logger &Logger_;
		std::uint64_t session_id_;
	};

	class AP_WS_RequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
	  public:
		inline explicit AP_WS_RequestHandlerFactory(Poco::Logger &L) : Logger_(L) {}

		inline Poco::Net::HTTPRequestHandler *
		createRequestHandler(const Poco::Net::HTTPServerRequest &request) override {
			if (request.find("Upgrade") != request.end() &&
				Poco::icompare(request["Upgrade"], "websocket") == 0) {
				Utils::SetThreadName("ws:conn-init");
				session_id_++;
				return new AP_WS_RequestHandler(Logger_, session_id_);
			} else {
				return nullptr;
			}
		}
	  private:
		Poco::Logger &Logger_;
		inline static std::atomic_uint64_t session_id_ = 0;
	};

	bool AP_WS_Server::ValidateCertificate(const std::string &ConnectionId,
										   const Poco::Crypto::X509Certificate &Certificate) {
		if (IsCertOk()) {
			if (!Certificate.issuedBy(*IssuerCert_)) {
				poco_warning(
					Logger(),
					fmt::format("CERTIFICATE({}): issuer mismatch. Local='{}' Incoming='{}'",
								ConnectionId, IssuerCert_->issuerName(), Certificate.issuerName()));
				return false;
			}
			return true;
		}
		return false;
	}

	int AP_WS_Server::Start() {

		AllowSerialNumberMismatch_ =
			MicroServiceConfigGetBool("openwifi.certificates.allowmismatch", true);
		MismatchDepth_ = MicroServiceConfigGetInt("openwifi.certificates.mismatchdepth", 2);

		SessionTimeOut_ = MicroServiceConfigGetInt("openwifi.session.timeout", 10*60);

		Reactor_pool_ = std::make_unique<AP_WS_ReactorThreadPool>(Logger());
		Reactor_pool_->Start();

		for (const auto &Svr : ConfigServersList_) {

			poco_notice(Logger(),
						fmt::format("Starting: {}:{} Keyfile:{} CertFile: {}", Svr.Address(),
									Svr.Port(), Svr.KeyFile(), Svr.CertFile()));

			Svr.LogCert(Logger());
			if (!Svr.RootCA().empty())
				Svr.LogCas(Logger());

			if (!IsCertOk()) {
				IssuerCert_ = std::make_unique<Poco::Crypto::X509Certificate>(Svr.IssuerCertFile());
				poco_information(
					Logger(), fmt::format("Certificate Issuer Name:{}", IssuerCert_->issuerName()));
			}

			Poco::Net::Context::Params P;

			P.verificationMode = Poco::Net::Context::VERIFY_ONCE;
			P.verificationDepth = 9;
			P.loadDefaultCAs = Svr.RootCA().empty();
			P.cipherList = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH";
			P.caLocation = Svr.Cas();

			auto Context = Poco::AutoPtr<Poco::Net::Context>(
				new Poco::Net::Context(Poco::Net::Context::TLS_SERVER_USE, P));

			Poco::Crypto::X509Certificate Cert(Svr.CertFile());
			Poco::Crypto::X509Certificate Root(Svr.RootCA());

			Context->useCertificate(Cert);
			Context->addChainCertificate(Root);

			Context->addCertificateAuthority(Root);
			Poco::Crypto::X509Certificate Issuing(Svr.IssuerCertFile());
			Context->addChainCertificate(Issuing);
			Context->addCertificateAuthority(Issuing);

			// add certificates from clientcas to trust chain
			ClientCasCerts_ = Poco::Net::X509Certificate::readPEM(Svr.ClientCas());
			for (const auto &cert : ClientCasCerts_) {
				Context->addChainCertificate(cert);
				Context->addCertificateAuthority(cert);
			}

			Poco::Crypto::RSAKey Key("", Svr.KeyFile(), Svr.KeyFilePassword());
			Context->usePrivateKey(Key);

			Context->setSessionCacheSize(0);
			Context->setSessionTimeout(120);
			Context->flushSessionCache();
			Context->enableSessionCache(true);
			Context->enableExtendedCertificateVerification(false);
			Context->disableProtocols(Poco::Net::Context::PROTO_TLSV1 |
									  Poco::Net::Context::PROTO_TLSV1_1);

			auto WebServerHttpParams = new Poco::Net::HTTPServerParams;
			WebServerHttpParams->setMaxThreads(50);
			WebServerHttpParams->setMaxQueued(200);
			WebServerHttpParams->setKeepAlive(true);
			WebServerHttpParams->setName("ws:ap_dispatch");

			if (Svr.Address() == "*") {
				Poco::Net::IPAddress Addr(Poco::Net::IPAddress::wildcard(
					Poco::Net::Socket::supportsIPv6() ? Poco::Net::AddressFamily::IPv6
													  : Poco::Net::AddressFamily::IPv4));
				Poco::Net::SocketAddress SockAddr(Addr, Svr.Port());
				auto NewWebServer = std::make_unique<Poco::Net::HTTPServer>(
					new AP_WS_RequestHandlerFactory(Logger()), DeviceConnectionPool_,
					Poco::Net::SecureServerSocket(SockAddr, Svr.Backlog(), Context),
					WebServerHttpParams);
				WebServers_.push_back(std::move(NewWebServer));
			} else {
				Poco::Net::IPAddress Addr(Svr.Address());
				Poco::Net::SocketAddress SockAddr(Addr, Svr.Port());
				auto NewWebServer = std::make_unique<Poco::Net::HTTPServer>(
					new AP_WS_RequestHandlerFactory(Logger()), DeviceConnectionPool_,
					Poco::Net::SecureServerSocket(SockAddr, Svr.Backlog(), Context),
					WebServerHttpParams);
				WebServers_.push_back(std::move(NewWebServer));
			}

			KafkaDisableState_ = MicroServiceConfigGetBool("openwifi.kafka.disablestate", false);
			KafkaDisableHealthChecks_ = MicroServiceConfigGetBool("openwifi.kafka.disablehealthchecks", false);
		}

		for (auto &server : WebServers_) {
			server->start();
		}

		ReactorThread_.start(Reactor_);

		auto ProvString = MicroServiceConfigGetString("autoprovisioning.process", "default");
		if (ProvString != "default") {
			auto Tokens = Poco::StringTokenizer(ProvString, ",");
			for (const auto &i : Tokens) {
				if (i == "prov")
					LookAtProvisioning_ = true;
				else
					UseDefaultConfig_ = true;
			}
		} else {
			UseDefaultConfig_ = true;
		}

		SimulatorId_ = Poco::toLower(MicroServiceConfigGetString("simulatorid", ""));
		SimulatorEnabled_ = !SimulatorId_.empty();
		Utils::SetThreadName(ReactorThread_, "dev:react:head");

		Running_ = true;
		GarbageCollector_.setName("ws:garbage");
		GarbageCollector_.start(*this);

		std::thread CleanupThread([this](){ CleanupSessions(); });
		CleanupThread.detach();

		return 0;
	}

	void AP_WS_Server::run() {
		uint64_t last_log = Utils::Now(),
				 last_zombie_run = 0,
				 last_garbage_run = 0;

		Poco::Logger &LocalLogger = Poco::Logger::create(
			"WS-Session-Janitor", Poco::Logger::root().getChannel(), Poco::Logger::root().getLevel());

		while(Running_) {

			if(!Poco::Thread::trySleep(30000)) {
				break;
			}

			LocalLogger.information(fmt::format("Garbage collecting starting run."	));

			uint64_t total_connected_time = 0, now = Utils::Now();

			if(now-last_zombie_run > 60) {
				try {
					poco_information(LocalLogger,
									 fmt::format("Garbage collecting zombies... (step 1)"));
					NumberOfConnectingDevices_ = 0;
					AverageDeviceConnectionTime_ = 0;
					int waits = 0;
					for (int hashIndex = 0; hashIndex < MACHash::HashMax(); hashIndex++) {
						last_zombie_run = now;
						waits = 0;
						while (true) {
							if (SerialNumbersMutex_[hashIndex].try_lock()) {
								waits = 0;
								auto hint = SerialNumbers_[hashIndex].begin();
								while (hint != end(SerialNumbers_[hashIndex])) {
									if (hint->second == nullptr) {
										poco_information(
											LocalLogger,
											fmt::format("Dead device found in hash index {}", hashIndex));
										hint = SerialNumbers_[hashIndex].erase(hint);
									} else {
										auto Device = hint->second;
										auto RightNow = Utils::Now();
										if (Device->Dead_) {
											AddCleanupSession(Device->State_.sessionId, Device->SerialNumberInt_);
											++hint;
											// hint = SerialNumbers_[hashIndex].erase(hint);
										} else if (RightNow > Device->LastContact_ &&
												   (RightNow - Device->LastContact_) > SessionTimeOut_) {
											poco_information(
												LocalLogger,
												fmt::format(
													"{}: Session seems idle. Controller disconnecting device.",
													Device->SerialNumber_));
											// hint = SerialNumbers_[hashIndex].erase(hint);
											AddCleanupSession(Device->State_.sessionId, Device->SerialNumberInt_);
											++hint;
										} else {
											if (Device->State_.Connected) {
												total_connected_time +=
													(RightNow - Device->State_.started);
											}
											++hint;
										}
									}
								}
								SerialNumbersMutex_[hashIndex].unlock();
								break;
							} else if (waits < 5) {
								waits++;
								Poco::Thread::trySleep(10);
							} else {
								break;
							}
						}
					}

					poco_information(LocalLogger, fmt::format("Garbage collecting zombies... (step 2)"));
					LeftOverSessions_ = 0;
					for (int i = 0; i < SessionHash::HashMax(); i++) {
						waits = 0;
						while (true) {
							if (SessionMutex_[i].try_lock()) {
								waits = 0;
								auto hint = Sessions_[i].begin();
								auto RightNow = Utils::Now();
								while (hint != end(Sessions_[i])) {
									if (hint->second == nullptr) {
										hint = Sessions_[i].erase(hint);
									} else if (hint->second->Dead_) {
										// hint = Sessions_[i].erase(hint);
										AddCleanupSession(hint->second->State_.sessionId, hint->second->SerialNumberInt_);
										++hint;
									} else if (RightNow > hint->second->LastContact_ &&
											   (RightNow - hint->second->LastContact_) >
												   SessionTimeOut_) {
										poco_information(
											LocalLogger,
											fmt::format("{}: Session seems idle. Controller disconnecting device.",
														hint->second->SerialNumber_));
										AddCleanupSession(hint->second->State_.sessionId, hint->second->SerialNumberInt_);
										++hint;
										// hint = Sessions_[i].erase(hint);
									} else {
										++LeftOverSessions_;
										++hint;
									}
								}
								SessionMutex_[i].unlock();
								break;
							} else if (waits < 5) {
								Poco::Thread::trySleep(10);
								waits++;
							} else {
								break;
							}
						}
					}

					AverageDeviceConnectionTime_ = NumberOfConnectedDevices_ > 0
													   ? total_connected_time / NumberOfConnectedDevices_
													   : 0;
					poco_information(LocalLogger, fmt::format("Garbage collecting zombies done..."));
				} catch (const Poco::Exception &E) {
					poco_error(LocalLogger, fmt::format("Poco::Exception: Garbage collecting zombies failed: {}", E.displayText()));
				} catch (const std::exception &E) {
					poco_error(LocalLogger, fmt::format("std::exception: Garbage collecting zombies failed: {}", E.what()));
				} catch (...) {
					poco_error(LocalLogger, fmt::format("exception:Garbage collecting zombies failed: {}", "unknown"));
				}

			}

			if(NumberOfConnectedDevices_) {
				if (last_garbage_run > 0) {
					AverageDeviceConnectionTime_ += (now - last_garbage_run);
				}
			}

			try {
				if ((now - last_log) > 60) {
					last_log = now;
					poco_information(
						LocalLogger,
						fmt::format("Active AP connections: {} Connecting: {} Average connection time: {} seconds. Left Over Sessions: {}",
									NumberOfConnectedDevices_, NumberOfConnectingDevices_,
									AverageDeviceConnectionTime_, LeftOverSessions_));
				}

				GWWebSocketNotifications::NumberOfConnection_t Notification;
				Notification.content.numberOfConnectingDevices = NumberOfConnectingDevices_;
				Notification.content.numberOfDevices = NumberOfConnectedDevices_;
				Notification.content.averageConnectedTime = AverageDeviceConnectionTime_;
				GetTotalDataStatistics(Notification.content.tx, Notification.content.rx);
				GWWebSocketNotifications::NumberOfConnections(Notification);

				Poco::JSON::Object KafkaNotification;
				Notification.to_json(KafkaNotification);

				Poco::JSON::Object FullEvent;
				FullEvent.set("type", "load-update");
				FullEvent.set("timestamp", now);
				FullEvent.set("payload", KafkaNotification);

				KafkaManager()->PostMessage(KafkaTopics::DEVICE_EVENT_QUEUE, "system", FullEvent);
				LocalLogger.information(fmt::format("Garbage collection finished run."));
				last_garbage_run = now;
			} catch (const Poco::Exception &E) {
				LocalLogger.error(fmt::format("Poco::Exception: Garbage collecting failed: {}", E.displayText()));
			} catch (const std::exception &E) {
				LocalLogger.error(fmt::format("std::exception: Garbage collecting failed: {}", E.what()));
			} catch (...) {
				LocalLogger.error(fmt::format("exception:Garbage collecting failed: {}", "unknown"));
			}
		}
		LocalLogger.information(fmt::format("Garbage collector done for the day."	));
	}

	void AP_WS_Server::Stop() {
		poco_information(Logger(), "Stopping...");
		Running_ = false;

		GarbageCollector_.wakeUp();
		GarbageCollector_.join();

		for (auto &server : WebServers_) {
			server->stopAll();
		}

		Reactor_pool_->Stop();
		Reactor_.stop();
		ReactorThread_.join();
		poco_information(Logger(), "Stopped...");
	}

} // namespace OpenWifi

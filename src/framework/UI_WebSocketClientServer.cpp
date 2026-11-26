//
// Created by stephane bourque on 2022-10-25.
//

#include <mutex>

#include "Poco/JSON/JSONException.h"
#include "Poco/JSON/Parser.h"
#include "Poco/Logger.h"
#include "Poco/NObserver.h"
#include "Poco/Net/SocketImpl.h"

#include "framework/AuthClient.h"
#include "framework/MicroServiceFuncs.h"
#include "framework/UI_WebSocketClientServer.h"

#include "fmt/format.h"

#if defined(TIP_SECURITY_SERVICE)
#include "AuthService.h"
#endif

#define DBG                                                                                        \
	{ std::cout << __LINE__ << std::endl; }

namespace OpenWifi {

	namespace {
		constexpr auto MaxIncompleteRead = std::chrono::seconds(60);
	}

	void UI_WebSocketClientServer::NewClient(Poco::Net::WebSocket &WS, const std::string &Id,
											 const std::string &UserName, std::uint64_t TID) {

		std::lock_guard G(LocalMutex_);
		if (!Running_) {
			WS.close();
			return;
		}
		auto Client = std::make_unique<UI_WebSocketClientInfo>(WS, Id, UserName);
		auto ClientSocket = Client->WS_->impl()->sockfd();
		TID_ = TID;
		Client->WS_->setNoDelay(true);
		Client->WS_->setKeepAlive(true);
		Client->WS_->setBlocking(false);
		Reactor_.addEventHandler(
			*Client->WS_,
			Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ReadableNotification>(
				*this, &UI_WebSocketClientServer::OnSocketReadable));
		Reactor_.addEventHandler(
			*Client->WS_,
			Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ShutdownNotification>(
				*this, &UI_WebSocketClientServer::OnSocketShutdown));
		Reactor_.addEventHandler(
			*Client->WS_, Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ErrorNotification>(
							  *this, &UI_WebSocketClientServer::OnSocketError));
		Client->SocketRegistered_ = true;
		Clients_[ClientSocket] = std::move(Client);
		UsersConnected_ = Clients_.size();
	}

	void UI_WebSocketClientServer::SetProcessor(UI_WebSocketClientProcessor *F) { Processor_ = F; }

	UI_WebSocketClientServer::UI_WebSocketClientServer() noexcept
		: SubSystemServer("WebSocketClientServer", "UI-WSCLNT-SVR", "websocketclients") {}

	void UI_WebSocketClientServer::run() {
		while (Running_) {
			if(!Poco::Thread::trySleep(2000)) {
                break;
            }
			std::lock_guard G(LocalMutex_);
			if (!Running_) break;
			for (const auto i : ToBeRemoved_) {
				// std::cout << "Erasing old WS UI connection..." << std::endl;
				Clients_.erase(i);
			}
			ToBeRemoved_.clear();
			const auto now = std::chrono::steady_clock::now();
			for (const auto &[fd, client] : Clients_) {
				if (!client->SocketRegistered_ ||
					client->IncompleteReadSince_ == std::chrono::steady_clock::time_point{} ||
					now - client->IncompleteReadSince_ < MaxIncompleteRead) continue;
				// Do not remove NObservers from the cleaner thread under LocalMutex_:
				// a callback may already be waiting for that mutex. Force TCP shutdown
				// and let the reactor callback perform its normal removal.
				try {
					using Poco::Net::SocketImpl;
					client->WS_->impl()->SocketImpl::shutdown();
				} catch (const Poco::Exception &e) {
					Logger().log(e);
				}
			}
			UsersConnected_ = Clients_.size();
		}
	}

	void UI_WebSocketClientServer::EndConnection(ClientList::iterator Client) {
		// Avoid inserting the same iterator twice when events race with removal.
		if (!Client->second->SocketRegistered_) return;
		Client->second->SocketRegistered_ = false;
		Reactor_.removeEventHandler(
			*Client->second->WS_,
			Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ReadableNotification>(
				*this, &UI_WebSocketClientServer::OnSocketReadable));
		Reactor_.removeEventHandler(
			*Client->second->WS_,
			Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ShutdownNotification>(
				*this, &UI_WebSocketClientServer::OnSocketShutdown));
		Reactor_.removeEventHandler(
			*Client->second->WS_,
			Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ErrorNotification>(
				*this, &UI_WebSocketClientServer::OnSocketError));
		ToBeRemoved_.push_back(Client);
	}

	int UI_WebSocketClientServer::Start() {
		std::lock_guard lifecycle(LifecycleMutex_);
		if (Running_) return 0;
		poco_information(Logger(), "Starting...");
		GoogleApiKey_ = MicroServiceConfigGetString("google.apikey", "");
		GeoCodeEnabled_ = !GoogleApiKey_.empty();
		std::unique_lock clients(LocalMutex_);
		bool reactorStarted = false;
		try {
			ReactorThread_.setName("ws:ui-reactor");
			CleanerThread_.setName("ws:ui-cleaner");
			ReactorThread_.start(Reactor_);
			reactorStarted = true;
			Running_ = true;
			CleanerThread_.start(*this);
		} catch (...) {
			Running_ = false;
			clients.unlock();
			if (reactorStarted) {
				Reactor_.stop();
				ReactorThread_.join();
			}
			throw;
		}
		return 0;
	};

	void UI_WebSocketClientServer::Stop() {
		std::lock_guard lifecycle(LifecycleMutex_);
		{
			// Close admission and synchronize with any in-flight client operation.
			std::lock_guard clients(LocalMutex_);
			if (!Running_.exchange(false)) return;
			UsersConnected_ = 0;
		}

		poco_information(Logger(), "Stopping...");
		// Do not hold LocalMutex_: reactor callbacks may be waiting for it.
		CleanerThread_.wakeUp();
		Reactor_.stop();
		CleanerThread_.join();
		ReactorThread_.join();

		std::lock_guard clients(LocalMutex_);
		// Both worker threads have exited; no callback can retain an iterator
		// or block observer removal. Remove each registration before closing.
		for (auto &entry : Clients_) {
			auto &client = *entry.second;
			auto remove = [&](const auto &observer) {
				try {
					Reactor_.removeEventHandler(*client.WS_, observer);
				} catch (...) {
					try { Logger().error("UI WebSocket observer removal failed during shutdown"); } catch (...) {}
				}
			};
			remove(Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ReadableNotification>(
				*this, &UI_WebSocketClientServer::OnSocketReadable));
			remove(Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ShutdownNotification>(
				*this, &UI_WebSocketClientServer::OnSocketShutdown));
			remove(Poco::NObserver<UI_WebSocketClientServer, Poco::Net::ErrorNotification>(
				*this, &UI_WebSocketClientServer::OnSocketError));
			client.SocketRegistered_ = false;
			try { client.WS_->close(); } catch (...) {
				try { Logger().error("UI WebSocket close failed during shutdown"); } catch (...) {}
			}
		}
		ToBeRemoved_.clear();
		Clients_.clear();
		UsersConnected_ = 0;
		poco_information(Logger(), "Stopped...");
	};

	bool UI_WebSocketClientServer::IsFiltered(std::uint64_t id,
											  const OpenWifi::UI_WebSocketClientInfo &Client) {
		return std::find(Client.Filter_.begin(), Client.Filter_.end(), id) != end(Client.Filter_);
	}

	bool UI_WebSocketClientServer::SendToUser(const std::string &UserName, std::uint64_t id,
											  const std::string &Payload) {
		std::lock_guard G(LocalMutex_);
		if (!Running_) return false;

		for (const auto &Client : Clients_) {
			if (Client.second->UserName_ == UserName) {
				try {
					if (!IsFiltered(id, *Client.second) && Client.second->Authenticated_) {
						return Client.second->WS_->sendFrame(
								   Payload.c_str(), (int)Payload.size()) == (int)Payload.size();
					} else {
						return false;
					}
				} catch (...) {
					return false;
				}
			}
		}
		return false;
	}

	void UI_WebSocketClientServer::SendToAll(std::uint64_t id, const std::string &Payload) {
		std::lock_guard G(LocalMutex_);
		if (!Running_) return;

		for (const auto &Client : Clients_) {
			try {
				if (!IsFiltered(id, *Client.second) && Client.second->Authenticated_)
					Client.second->WS_->sendFrame(Payload.c_str(), (int)Payload.size());
			} catch (...) {
			}
		}
	}

	UI_WebSocketClientServer::ClientList::iterator UI_WebSocketClientServer::FindWSClient(
		[[maybe_unused]] std::lock_guard<std::recursive_mutex> &G, int ClientSocket) {
		return Clients_.find(ClientSocket);
	}

	void UI_WebSocketClientServer::SortNotifications() {
		struct {
			bool operator()(const NotificationEntry &A, const NotificationEntry &B) const {
				return A.id < B.id;
			};
		} CompareNotifications;
		std::sort(NotificationTypes_.begin(), NotificationTypes_.end(), CompareNotifications);

		NotificationTypesJSON_.clear();
		Poco::JSON::Array AllNotifications;
		for (const auto &notification : NotificationTypes_) {
			Poco::JSON::Object Notification;
			Notification.set("id", notification.id);
			Notification.set("helper", notification.helper);
			AllNotifications.add(Notification);
		}
		NotificationTypesJSON_.set("notificationTypes", AllNotifications);
	}

	void UI_WebSocketClientServer::RegisterNotifications(
		const OpenWifi::UI_WebSocketClientServer::NotificationTypeIdVec &Notifications) {
		std::copy(Notifications.begin(), Notifications.end(),
				  std::back_inserter(NotificationTypes_));
		SortNotifications();
	}

	void UI_WebSocketClientServer::OnSocketError(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ErrorNotification> &pNf) {
		std::lock_guard G(LocalMutex_);
		if (!Running_) return;
		auto Client = Clients_.find(pNf->socket().impl()->sockfd());
		if (Client == end(Clients_))
			return;
		EndConnection(Client);
	}

	void UI_WebSocketClientServer::OnSocketReadable(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ReadableNotification> &pNf) {

		std::lock_guard G(LocalMutex_);
		if (!Running_) return;
		auto Client = Clients_.end();

		try {

			Client = Clients_.find(pNf->socket().impl()->sockfd());
			if (Client == end(Clients_) || !Client->second->SocketRegistered_)
				return;

			using Clock = std::chrono::steady_clock;
			if (Client->second->IncompleteReadSince_ != Clock::time_point{} &&
				Clock::now() - Client->second->IncompleteReadSince_ >= MaxIncompleteRead) {
				poco_warning(Logger(), fmt::format(
					"UI WebSocket {} incomplete read timeout; disconnecting.", Client->second->Id_));
				return EndConnection(Client);
			}

			Poco::Buffer<char> IncomingFrame(0);
			int flags = 0;
			const int n = Client->second->WS_->receiveFrame(IncomingFrame, flags);

			if (n == -1) {
				// Partial nonblocking reads are normal. Use an elapsed interval
				// rather than counting callbacks, and reset on a complete frame.
				const auto now = Clock::now();
				auto &since = Client->second->IncompleteReadSince_;
				if (since == Clock::time_point{}) since = now;
				else if (now - since >= MaxIncompleteRead) {
					poco_warning(Logger(), fmt::format(
						"UI WebSocket {} incomplete read timeout; disconnecting.",
						Client->second->Id_));
					return EndConnection(Client);
				}
				return;
			}
			Client->second->IncompleteReadSince_ = {};
			if (n == 0 && flags == 0) {
				poco_debug(Logger(),
					fmt::format("CLOSE({}): {} UI Client is closing WS connection.",
								Client->second->Id_, Client->second->UserName_));
				return EndConnection(Client);
			}

			const auto Op = flags & Poco::Net::WebSocket::FRAME_OP_BITMASK;
			switch (Op) {
			case Poco::Net::WebSocket::FRAME_OP_PING: {
				Client->second->WS_->sendFrame("", 0,
											   (int)Poco::Net::WebSocket::FRAME_OP_PONG |
											   (int)Poco::Net::WebSocket::FRAME_FLAG_FIN);
			} break;
			case Poco::Net::WebSocket::FRAME_OP_PONG: {
			} break;
			case Poco::Net::WebSocket::FRAME_OP_CLOSE: {
				poco_debug(Logger(),
						   fmt::format("CLOSE({}): {} UI Client is closing WS connection.",
									   Client->second->Id_, Client->second->UserName_));
				return EndConnection(Client);
			} break;
			case Poco::Net::WebSocket::FRAME_OP_CONT: {
				poco_warning(Logger(),
							 fmt::format("CONT({}): {} Unexpected CONT Frame - Ignoring.",
										 Client->second->Id_, Client->second->UserName_));
			} break;
			case Poco::Net::WebSocket::FRAME_OP_TEXT: {
				constexpr const char *DropMessagesCommand = "drop-notifications";
				IncomingFrame.append(0);
				if (!Client->second->Authenticated_) {
					std::string Frame{IncomingFrame.begin()};
					auto Tokens = Utils::Split(Frame, ':');
					bool Expired = false;
#if not defined(TIP_SECURITY_SERVICE)
					bool Contacted = false;
#endif
					if (Tokens.size() == 2 &&
#if defined(TIP_SECURITY_SERVICE)
						AuthService()->IsAuthorized(Tokens[1], Client->second->UserInfo_, TID_,
													Expired)) {
#else
						AuthClient()->IsAuthorized(Tokens[1], Client->second->UserInfo_, TID_,
												   Expired, Contacted)) {
#endif
						Client->second->Authenticated_ = true;
						Client->second->UserName_ = Client->second->UserInfo_.userinfo.email;
						poco_debug(Logger(),
								   fmt::format("START({}): {} UI Client is starting WS connection.",
											   Client->second->Id_, Client->second->UserName_));
						auto WelcomeMessage = NotificationTypesJSON_;
						WelcomeMessage.set("success", "Welcome! Bienvenue! Bienvenidos!");
						std::ostringstream OS;
						WelcomeMessage.stringify(OS);
						Client->second->WS_->sendFrame(OS.str().c_str(), (int)OS.str().size());
						Client->second->UserName_ = Client->second->UserInfo_.userinfo.email;
					} else {
						Poco::JSON::Object WelcomeMessage;
						WelcomeMessage.set("error", "Invalid token. Closing connection.");
						std::ostringstream OS;
						WelcomeMessage.stringify(OS);
						Client->second->WS_->sendFrame(OS.str().c_str(), (int)OS.str().size());
						return EndConnection(Client);
					}
				} else {
					Poco::JSON::Parser P;
					auto Obj = P.parse(IncomingFrame.begin()).extract<Poco::JSON::Object::Ptr>();

					if (Obj->has(DropMessagesCommand) && Obj->isArray(DropMessagesCommand)) {
						auto Filters = Obj->getArray(DropMessagesCommand);
						Client->second->Filter_.clear();
						for (const auto &Filter : *Filters) {
							Client->second->Filter_.emplace_back((std::uint64_t)Filter);
						}
						std::sort(begin(Client->second->Filter_), end(Client->second->Filter_));
						return;
					}

					std::string Answer;
					bool CloseConnection = false;
					if (Processor_ != nullptr) {
						Processor_->Processor(Obj, Answer, CloseConnection,
											  Client->second->UserInfo_.userinfo);
					}
					if (!Answer.empty())
						Client->second->WS_->sendFrame(Answer.c_str(), (int)Answer.size());
					else {
						Client->second->WS_->sendFrame("{}", 2);
					}

					if (CloseConnection) {
						return EndConnection(Client);
					}
				}
			} break;
			default: {
			}
			}
		} catch (...) {
			if (Client != Clients_.end()) EndConnection(Client);
		}
	}

	void UI_WebSocketClientServer::OnSocketShutdown(
		[[maybe_unused]] const Poco::AutoPtr<Poco::Net::ShutdownNotification> &pNf) {
		try {
			std::lock_guard G(LocalMutex_);
			if (!Running_) return;
			auto Client = Clients_.find(pNf->socket().impl()->sockfd());
			if (Client == end(Clients_))
				return;
			EndConnection(Client);
		} catch (...) {
		}
	}

} // namespace OpenWifi

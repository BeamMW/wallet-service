// Copyright 2020 The Beam Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#pragma once

#include <functional>
#include <string>
#include <memory>
#include <thread>
#include <boost/asio/ip/tcp.hpp>
#include "utility/io/reactor.h"

namespace beam::wallet {
    class WebSocketServer
    {
    public:
        using SendFunc = std::function<void (const std::string&)>;

        struct ClientHandler
        {
            using Ptr = std::unique_ptr<ClientHandler>;
            virtual void onWSDataReceived(const std::string&) = 0;
            virtual ~ClientHandler() = default;
        };

        WebSocketServer(io::Reactor::Ptr reactor, uint16_t port, std::string allowedOrigin = std::string());
        ~WebSocketServer();

    protected:
        //
        // ioThread callbacks are called in context of the IO Thread
        //
        virtual void ioThread_onWSStart() = 0;
        virtual ClientHandler::Ptr ioThread_onNewWSClient(SendFunc) = 0;

        io::Reactor::Ptr _reactor;

    private:
        boost::asio::io_context _ioc;
        std::shared_ptr<std::thread> _iocThread;
        std::string _allowedOrigin;
    };
}

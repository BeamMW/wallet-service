// Copyright 2018-2020 The Beam Team
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

#include <memory>
#include <queue>
#include "wallet/core/wallet_db.h"
#include "websocket_server.h"
#include "service_api.h"
#include "keykeeper_proxy.h"
#include "reactor.h"
#include "utility/logger.h"

namespace beam::wallet {
    struct WalletInfo
   {
        std::weak_ptr<Wallet> wallet;
        std::weak_ptr<IWalletDB> walletDB;

        WalletInfo(const Wallet::Ptr& wallet, const IWalletDB::Ptr& walletDB)
            : wallet(wallet)
            , walletDB(walletDB)
        {
        }

        WalletInfo() = default;
   };

   using WalletMap = std::unordered_map<std::string, WalletInfo>;

    //
    // This class must be always instantiated in context of the reactor thread
    // All callbacks must be called in context of the reactor thread
    // Must be destroyed in context of the reactor thread
    //
    class ServiceClient
        : public  WebSocketServer::ClientHandler  // We handle web socket client
        , public  IKeykeeperConnection            // We handle keykeeper connection via web socket
        , private WalletServiceApi               // We provide wallet service API
        , private WalletApiHandler::IWalletData  // We provide wallet data
        , public std::enable_shared_from_this<ServiceClient>
    {
    public:
        ServiceClient(bool withAssets,  const io::Address& nodeAddr, WebSocketServer::SendFunc wsSend, WalletMap& walletMap);
        ~ServiceClient() noexcept override;

        //
        //  WebSocketServer::ClientHandler
        //  Functions that utilize web socket
        //
        void ReactorThread_onWSDataReceived(const std::string& data) override;
        void serializeMsg(const json& msg) override;
        void socketSend(const std::string& data);
        void socketSend(const json& msg);

        //
        // WalletServiceApi
        //
        void onWalletApiMessage(const JsonRpcId& id, const CreateWallet& data) override;
        void onWalletApiMessage(const JsonRpcId& id, const OpenWallet& data) override;
        void onWalletApiMessage(const JsonRpcId& id, const wallet::Ping& data) override;
        void onWalletApiMessage(const JsonRpcId& id, const Release& data) override;
        void onWalletApiMessage(const JsonRpcId& id, const CalcChange& data) override;
        void onWalletApiMessage(const JsonRpcId& id, const ChangePassword& data) override;

        template<typename T>
        void sendApiResponse(const JsonRpcId& id, const T& response)
        {
            json msg;
            WalletServiceApi::getWalletApiResponse(id, response, msg);
            socketSend(msg.dump());
        }

        //
        // IKeykeeperConnection & keykeeper utilities
        //
        void invokeKeykeeperAsync(const json& msg, KeyKeeperFunc func) override {
            _keeperCallbacks.push(std::move(func));
            socketSend(msg);
        }

        //
        // WalletApiHandler::IWalletData methods
        //
        IWalletDB::Ptr getWalletDBPtr() override
        {
            return _walletDB;
        }

        Wallet::Ptr getWalletPtr() override
        {
            return _wallet;
        }

        #ifdef BEAM_ATOMIC_SWAP_SUPPORT
        const IAtomicSwapProvider& getAtomicSwapProvider() const override
        {
            // TODO: block methods that can cause this
            throw std::runtime_error("not supported");
        }
        #endif  // BEAM_ATOMIC_SWAP_SUPPORT

    private:
        std::queue<KeyKeeperFunc> _keeperCallbacks;
        IWalletDB::Ptr            _walletDB;
        Wallet::Ptr               _wallet;
        WalletMap&                _walletMap;
        io::Address               _nodeAddr;
        bool                      _withAssets;
        WebSocketServer::SendFunc _wsSend;
        bool                      _opening = false;

        using OptionalError = boost::optional<std::runtime_error>;
        using KeeperCompletion = std::function<void (IPrivateKeyKeeper2::Ptr, OptionalError)>;

        IPrivateKeyKeeper2::Ptr createKeyKeeper(const std::string& pass, const std::string& ownerKey);
        void createKeyKeeperFromDB(const std::string& id, const std::string& pass, const KeeperCompletion&) noexcept ;
        void createKeyKeeper(Key::IPKdf::Ptr ownerKdf, const KeeperCompletion&) noexcept;
    };
}

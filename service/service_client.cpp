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
#include "service_client.h"
#include "keykeeper/wasm_key_keeper.h"
#include "wallet/core/simple_transaction.h"
#include "node_connection.h"
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include "utils.h"

namespace beam::wallet {
    namespace {
        std::string makeDBPath(const std::string& name)
        {
            const char *DB_FOLDER = "wallets";
            auto path = boost::filesystem::system_complete(DB_FOLDER);

            if (!boost::filesystem::exists(path))
            {
                boost::filesystem::create_directories(path);
            }

            std::string fname = std::string(name) + ".db";
            path /= fname;
            return path.string();
        }

        std::string generateWalletID(Key::IPKdf::Ptr ownerKdf)
        {
            Key::ID kid(Zero);
            kid.m_Type = ECC::Key::Type::WalletID;

            ECC::Point::Native pt;
            ECC::Hash::Value hv;
            kid.get_Hash(hv);
            ownerKdf->DerivePKeyG(pt, hv);
            PeerID pid;
            pid.Import(pt);
            return pid.str();
        }

        static std::string generateUid()
        {
            std::array<uint8_t, 16> buf{};
            {
                boost::uuids::uuid uid = boost::uuids::random_generator()();
                std::copy(uid.begin(), uid.end(), buf.begin());
            }

            return to_hex(buf.data(), buf.size());
        }
    }

    ServiceClient::ServiceClient(bool withAssets, const io::Address& nodeAddr, WebSocketServer::SendFunc wsSend, WalletMap& walletMap)
        : WalletServiceApi(static_cast<WalletApiHandler::IWalletData&>(*this))
        , _walletMap(walletMap)
        , _nodeAddr(nodeAddr)
        , _withAssets(withAssets)
        , _wsSend(std::move(wsSend))
    {
        LOG_DEBUG () << "Service client create";
    }

    ServiceClient::~ServiceClient() noexcept
    {
        LOG_DEBUG () << "Service client destroy";
    }

    void ServiceClient::ReactorThread_onWSDataReceived(const std::string& data)
    {
        // Something came through websocket
        try
        {
            json msg = json::parse(data.c_str(), data.c_str() + data.size());

            if (WalletApi::existsJsonParam(msg, "result"))
            {
                if (_keeperCallbacks.empty())
                    return;

                auto cback = _keeperCallbacks.front();
                _keeperCallbacks.pop();
                cback(msg["result"]);
            }
            else if (WalletApi::existsJsonParam(msg, "error"))
            {
                const auto& error = msg["error"];
                LOG_ERROR() << "JSON RPC error " << error["message"];
            }
            else
            {
                // !TODO: don't forget to cache this request
                WalletServiceApi::parse(data.c_str(), data.size());
            }
        }
        catch (const nlohmann::detail::exception & e)
        {
            LOG_ERROR() << "json parse: " << e.what() << "\n";
        }
    }

    void ServiceClient::serializeMsg(const json& msg)
    {
        socketSend(msg);
    }

    void ServiceClient::socketSend(const std::string& data)
    {
        _wsSend(data);
    }

    void ServiceClient::socketSend(const json& msg)
    {
        socketSend(msg.dump());
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId& id, const CreateWallet& data)
    {
        try
        {
            LOG_DEBUG() << "CreateWallet(id = " << id << ")";

            beam::KeyString ks;
            ks.SetPassword(data.pass);
            ks.m_sRes = data.ownerKey;
            std::shared_ptr<ECC::HKdfPub> ownerKdf = std::make_shared<ECC::HKdfPub>();

            if (ks.Import(*ownerKdf))
            {
                auto dbName = generateWalletID(ownerKdf);
                auto walletDB = WalletDB::initNoKeepr(makeDBPath(dbName), SecString(data.pass));
                if (walletDB)
                {
                    WalletAddress address;
                    walletDB->createAddress(address);
                    address.m_label = "default";
                    walletDB->saveAddress(address);
                    return sendApiResponse(id, CreateWallet::Response{dbName});
                }
            }

            return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Wallet not created.");
        }
        catch (const DatabaseException& ex)
        {
             WalletServiceApi::doError(id, ApiError::DatabaseError, ex.what());
        }
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId &id, const OpenWallet &data)
    {
        LOG_DEBUG() << "Open wallet this " << this << "-" << _opening;

        if (_wallet) {
            return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Database already opened");
        }

        if (_opening) {
            return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Open operation is already pending");
        }

        _opening = true;
        LOG_INFO() << "Open wallet after guards this " << this << "-" << _opening;

        std::shared_ptr<Wallet> wallet;
        std::shared_ptr<IWalletDB> walletDB;

        auto it = _walletMap.find(data.id);
        if (it != _walletMap.end())
        {
            wallet = it->second.wallet.lock();
            if (wallet)
            {
                if (data.freshKeeper)
                {
                    // TODO: support multiple keykeepers OR support close of other sessions
                    _opening = false;
                    return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Wallet is opened in another session.");
                }

                // this should always succeed, wallet keeps db
                walletDB = it->second.walletDB.lock();
                assert(walletDB != nullptr);

                LOG_DEBUG() << "Found already opened wallet " << data.id;
                _wallet = wallet;
                _walletDB = walletDB;

                auto session = generateUid();
                _opening = false;
                return sendApiResponse(id, OpenWallet::Response{session});
            }
        }

        createKeyKeeperFromDB(data.id, data.pass, [sp = shared_from_this(), id, data, walletDB, wallet](IPrivateKeyKeeper2::Ptr keeper, OptionalError err) mutable {
            if (!keeper)
            {
                assert(false);
                std::string errmsg = "Failed to create keykeepr";

                if (err.has_value()) {
                    errmsg += std::string(": ") + err.value().what();
                }

                sp->_opening = false;
                return sp->doError(id, ApiError::InternalErrorJsonRpc, errmsg );
            }

            try
            {
                // open throws on error
                // open can initiate sync keeper calls, everything MUST be cached before this function call
                walletDB = WalletDB::open(makeDBPath(data.id), SecString(data.pass), keeper);

                // just in case somebody forgets to throw
                if (!walletDB)
                {
                    assert(false);
                    sp->_opening = false;
                    return sp->doError(id, ApiError::InternalErrorJsonRpc, "Failed to open database");
                }

                //
                // Create and start wallet
                //

                // throws on error
                wallet = std::make_shared<Wallet>(walletDB, sp->_withAssets);

                // just in case somebody forgets to throw
                if (!wallet)
                {
                    assert(false);
                    sp->_opening = false;
                    return sp->doError(id, ApiError::InternalErrorJsonRpc, "Failed to create wallet");
                }

                wallet->ResumeAllTransactions();
                if (data.freshKeeper)
                {
                    // We won't be able to sign with the fresh keykeeper, nonces are regenerated
                    wallet->VisitActiveTransaction([&](const TxID &txid, BaseTransaction::Ptr tx) {
                        if (tx->GetType() == TxType::Simple)
                        {
                            SimpleTransaction::State state = SimpleTransaction::State::Initial;
                            if (tx->GetParameter(TxParameterID::State, state))
                            {
                                if (state < SimpleTransaction::State::Registration)
                                {
                                    LOG_DEBUG() << "Fresh keykeeper transaction cancel, txid " << txid
                                                << " , state " << state;
                                    wallet->CancelTransaction(txid);
                                }
                            }
                        }
                    });
                }

                //
                // Spin up network connection
                //
                auto nnet = std::make_shared<ServiceNodeConnection>(*wallet);
                nnet->m_Cfg.m_PollPeriod_ms = 0;//options.pollPeriod_ms.value;

                if (nnet->m_Cfg.m_PollPeriod_ms)
                {
                    LOG_INFO() << "Node poll period = " << nnet->m_Cfg.m_PollPeriod_ms << " ms";
                    uint32_t timeout_ms = std::max(Rules::get().DA.Target_s * 1000, nnet->m_Cfg.m_PollPeriod_ms);
                    if (timeout_ms != nnet->m_Cfg.m_PollPeriod_ms)
                    {
                        LOG_INFO() << "Node poll period has been automatically rounded up to block rate: "
                                   << timeout_ms << " ms";
                    }
                }

                uint32_t responseTime_s = Rules::get().DA.Target_s * wallet::kDefaultTxResponseTime;
                if (nnet->m_Cfg.m_PollPeriod_ms >= responseTime_s * 1000)
                {
                    LOG_WARNING() << "The \"--node_poll_period\" parameter set to more than "
                                  << uint32_t(responseTime_s / 3600) << " hours may cause transaction problems.";
                }
                nnet->m_Cfg.m_vNodes.push_back(sp->_nodeAddr);
                nnet->Connect();

                auto wnet = std::make_shared<WalletNetworkViaBbs>(*wallet, nnet, walletDB);
                wallet->AddMessageEndpoint(wnet);
                wallet->SetNodeEndpoint(nnet);

                //
                // We're done!
                //
                LOG_DEBUG() << "Wallet successfully opened, wallet id " << data.id;
                sp->_wallet = wallet;
                sp->_walletDB = walletDB;
                sp->_walletMap[data.id].walletDB = sp->_walletDB; // weak ref
                sp->_walletMap[data.id].wallet = sp->_wallet; // weak ref

                auto session = generateUid();
                sp->_opening = false;
                return sp->sendApiResponse(id, OpenWallet::Response{session});
            }
            catch(const DatabaseNotFoundException& ex)
            {
                sp->_opening = false;
                return sp->doError(id, ApiError::DatabaseNotFound, ex.what());
            }
            catch(const DatabaseException& ex)
            {
                sp->_opening = false;
                return sp->doError(id, ApiError::DatabaseError, ex.what());
            }
            catch(const std::runtime_error& ex)
            {
                sp->_opening = false;
                return sp->doError(id, ApiError::InternalErrorJsonRpc, ex.what());
            }
        });
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId& id, const wallet::Ping& data)
    {
        LOG_DEBUG() << "Ping(id = " << id << ")";
        sendApiResponse(id, wallet::Ping::Response{});
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId& id, const Release& data)
    {
        LOG_DEBUG() << "Release(id = " << id << ")";
        sendApiResponse(id, Release::Response{});
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId& id, const CalcChange& data)
    {
        LOG_DEBUG() << "CalcChange(id = " << id << ")";
        if (!_walletDB) {
            return doError(id, ApiError::NotOpenedError);
        }

        auto coins = _walletDB->selectCoins(data.amount, Zero);
        Amount sum = 0;
        for (auto& c : coins)
        {
            sum += c.m_ID.m_Value;
        }

        Amount change = (sum > data.amount) ? (sum - data.amount) : 0UL;
        sendApiResponse(id, CalcChange::Response{change});
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId& id, const ChangePassword& data)
    {
        LOG_DEBUG() << "ChangePassword(id = " << id << ")";
        if (!_walletDB) {
            return doError(id, ApiError::NotOpenedError);
        }
        _walletDB->changePassword(data.newPassword);
        sendApiResponse(id, ChangePassword::Response{ });
    }

    IPrivateKeyKeeper2::Ptr ServiceClient::createKeyKeeper(const std::string& pass, const std::string& ownerKey)
    {
        beam::KeyString ks;

        ks.SetPassword(pass);
        ks.m_sRes = ownerKey;

        std::shared_ptr<ECC::HKdfPub> ownerKdf = std::make_shared<ECC::HKdfPub>();
        if (ks.Import(*ownerKdf))
        {
            /// TODO: Check if init needs cache
            return std::make_shared<WasmKeyKeeperProxy>(ownerKdf, shared_from_this());
        }

        return nullptr;
    }

    void ServiceClient::createKeyKeeperFromDB(const std::string& id, const std::string& pass, const KeeperCompletion& cback) noexcept
    {
        try
        {
            auto walletDB = WalletDB::open(makeDBPath(id), SecString(pass));
            Key::IPKdf::Ptr pKey = walletDB->get_OwnerKdf();
            return createKeyKeeper(pKey, cback);
        }
        catch(const std::runtime_error& err)
        {
            return cback(nullptr, err);
        }
    }

    void ServiceClient::createKeyKeeper(Key::IPKdf::Ptr ownerKdf, const KeeperCompletion& cback) noexcept
    {
        auto keeper = std::make_shared<WasmKeyKeeperProxy>(ownerKdf, shared_from_this());

        //
        // We need to cache some data to prevent sync locks in the future
        // TODO: remove this hack, make keykeeper fully async
        //
        struct baseHandler: public IPrivateKeyKeeper2::Handler {
            KeeperCompletion Completion;
            std::shared_ptr<ServiceClient> Client;
            std::shared_ptr<WasmKeyKeeperProxy> Keeper;
        };

        struct getSlotsHandler: public baseHandler {
            IPrivateKeyKeeper2::Method::get_NumSlots getSlots = {0};

            void OnDone(IPrivateKeyKeeper2::Status::Type status) override {
                if (status != IPrivateKeyKeeper2::Status::Success)
                {
                    return Completion(nullptr, std::runtime_error("Failed to get slots"));
                }

                Keeper->cacheSlots(getSlots.m_Count);
                return Completion(Keeper, boost::none);
            }
        };

        struct getSbbsKdfHandler: public baseHandler
        {
            IPrivateKeyKeeper2::Method::get_Kdf getKdf = {0};

            getSbbsKdfHandler () {
                getKdf.m_Root = false;
                getKdf.m_iChild = Key::Index(-1);
            }

            void OnDone(IPrivateKeyKeeper2::Status::Type status) override {
                if (status != IPrivateKeyKeeper2::Status::Success)
                {
                    return Completion(nullptr, std::runtime_error("Failed to get sbbs kdf"));
                }

                Keeper->cacheSbbsKdf(getKdf.m_iChild, getKdf.m_pPKdf);
                auto handler = std::make_shared<getSlotsHandler>();
                handler->Completion = Completion;
                handler->Client     = Client;
                handler->Keeper     = Keeper;
                Keeper->InvokeAsync(handler->getSlots, handler);
            }
        };

        auto handler = std::make_shared<getSbbsKdfHandler>();
        handler->Completion = cback;
        handler->Client     = shared_from_this();
        handler->Keeper     = keeper;
        keeper->InvokeAsync(handler->getKdf, handler);
    }
}

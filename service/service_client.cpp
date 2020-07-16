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
    }

    ServiceClient::~ServiceClient() noexcept
    {
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

                LOG_INFO() << "Keeper pop for id " << msg["id"] << ", method " << msg["method"];
                _keeperCallbacks.front()(msg["result"]);
                _keeperCallbacks.pop();
                LOG_INFO() << "Keeper pop OK for id " << msg["id"] << ", method " << msg["method"];
            }
            else if (WalletApi::existsJsonParam(msg, "error"))
            {
                const auto& error = msg["error"];
                LOG_ERROR() << "JSON RPC error id: " << error["id"] << " message: " << error["message"];
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

        const char* jsonError = "error";
        const char* jsonCode  = "code";

        if (existsJsonParam(msg, jsonError))
        {
            const auto& error = msg[jsonError];
            if (existsJsonParam(error, jsonCode))
            {
                const auto &code = error[jsonCode];
                if (code.is_number_integer() && code == ApiError::ThrottleError)
                {
                    int a = 0;
                    a++;
                }
            }
        }
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId& id, const CreateWallet& data)
    {
        if (_created) {
            return WalletServiceApi::doError(id, ApiError::ThrottleError, "Wallet has been created in this session. Reconnect and try again");
        }

        try
        {
            LOG_DEBUG() << "CreateWallet(id = " << id << ")";

            beam::KeyString ks;

            ks.SetPassword(data.pass);
            ks.m_sRes = data.ownerKey;

            std::shared_ptr<ECC::HKdfPub> ownerKdf = std::make_shared<ECC::HKdfPub>();

            if (ks.Import(*ownerKdf))
            {
                auto keyKeeper = createKeyKeeper(ownerKdf);
                auto dbName = generateWalletID(ownerKdf);
                IWalletDB::Ptr walletDB = WalletDB::init(makeDBPath(dbName), SecString(data.pass), keyKeeper);

                if (walletDB)
                {
                    _walletMap[dbName] = WalletInfo({}, walletDB);
                    // generate default address
                    WalletAddress address;
                    walletDB->createAddress(address);
                    address.m_label = "default";
                    walletDB->saveAddress(address);

                    sendApiResponse(id, CreateWallet::Response{dbName});
                    _created = true;
                    return;
                }
            }

            WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Wallet not created.");
        }
        catch (const DatabaseException& ex)
        {
             WalletServiceApi::doError(id, ApiError::DatabaseError, ex.what());
        }
    }

    void ServiceClient::onWalletApiMessage(const JsonRpcId &id, const OpenWallet &data)
    {
        if (_wallet) {
            return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Database already opened");
        }

        if (_opening) {
            return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Open operation is already pending");
        }

        OnUntilExit guard(_opening);

        try
        {
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
                        return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Wallet is opened in another session.");
                    }

                    // this should always succeed, wallet keeps db
                    walletDB = it->second.walletDB.lock();
                    assert(walletDB != nullptr);
                }
            }

            // throws on error
            auto keeper = createKeyKeeperFromDB(data.id, data.pass);

            // just in case somebody forgets to throw
            if (!keeper) {
                assert(false);
                return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Failed to create keykeeper");
            }

            // open throws on error
            // open can initiate async communication via socket (to get kdfs) and block until operation completes
            walletDB = WalletDB::open(makeDBPath(data.id), SecString(data.pass), keeper);

            // just in case somebody forgets to throw
            if (!walletDB) {
                assert(false);
                return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Failed to open database");
            }

            // throws on error
            wallet  = std::make_shared<Wallet>(walletDB, _withAssets);

            // just in case somebody forgets to throw
            if (!wallet) {
                assert(false);
                return WalletServiceApi::doError(id, ApiError::InternalErrorJsonRpc, "Failed to create wallet");
            }

            wallet->ResumeAllTransactions();
            if (data.freshKeeper) {
                // We won't be able to sign with the fresh keykeeper, nonces are regenerated
                wallet->VisitActiveTransaction([&](const TxID& txid, BaseTransaction::Ptr tx) {
                   if (tx->GetType() == TxType::Simple)
                   {
                       SimpleTransaction::State state = SimpleTransaction::State::Initial;
                       if (tx->GetParameter(TxParameterID::State, state))
                       {
                           if (state < SimpleTransaction::State::Registration)
                           {
                               LOG_DEBUG() << "Fresh keykeeper transaction cancel, txid " << txid << " , state " << state;
                               wallet->CancelTransaction(txid);
                           }
                       }
                   }
                });
            }

            auto nnet = std::make_shared<ServiceNodeConnection>(*_wallet);
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

            uint32_t responceTime_s = Rules::get().DA.Target_s * wallet::kDefaultTxResponseTime;
            if (nnet->m_Cfg.m_PollPeriod_ms >= responceTime_s * 1000)
            {
                LOG_WARNING() << "The \"--node_poll_period\" parameter set to more than "
                              << uint32_t(responceTime_s / 3600) << " hours may cause transaction problems.";
            }
            nnet->m_Cfg.m_vNodes.push_back(_nodeAddr);
            nnet->Connect();

            auto wnet = std::make_shared<WalletNetworkViaBbs>(*wallet, nnet, walletDB);
            wallet->AddMessageEndpoint(wnet);
            wallet->SetNodeEndpoint(nnet);

            LOG_DEBUG() << "Wallet successfully opened, wallet id " << data.id;
            _wallet = wallet;
            _walletDB = walletDB;
            _walletMap[data.id].walletDB = _walletDB; // weak ref
            _walletMap[data.id].wallet = _wallet; // weak ref

            auto session = generateUid();
            sendApiResponse(id, OpenWallet::Response{session});
        }
        catch(const DatabaseNotFoundException& ex)
        {
            return WalletServiceApi::doError(id, ApiError::DatabaseNotFound, ex.what());
        }
        catch(const DatabaseException& ex)
        {
            return WalletServiceApi::doError(id, ApiError::DatabaseError, ex.what());
        }
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
            return createKeyKeeper(ownerKdf);
        }

        return {};
    }

    IPrivateKeyKeeper2::Ptr ServiceClient::createKeyKeeperFromDB(const std::string& id, const std::string& pass)
    {
        auto walletDB = WalletDB::open(makeDBPath(id), SecString(pass));
        Key::IPKdf::Ptr pKey = walletDB->get_OwnerKdf();
        return createKeyKeeper(pKey);
    }

    IPrivateKeyKeeper2::Ptr ServiceClient::createKeyKeeper(Key::IPKdf::Ptr ownerKdf)
    {
        return std::make_shared<WasmKeyKeeperProxy>(ownerKdf, *this);
    }
}